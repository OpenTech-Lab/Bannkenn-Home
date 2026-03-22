use anyhow::{Context, Result};
use chrono::Utc;
use dashmap::DashMap;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::{Capture, Device as PcapDevice};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::models::{Alert, AlertType, FlowKey, FlowStats};

pub type FlowMap = Arc<DashMap<FlowKey, (FlowStats, Instant)>>;
pub type AlertSender = broadcast::Sender<Alert>;

pub fn new_flow_map() -> FlowMap {
    Arc::new(DashMap::new())
}

pub async fn run_capture(
    interface_name: String,
    flows: FlowMap,
    alert_tx: AlertSender,
) -> Result<()> {
    info!("Starting packet capture on {}", interface_name);

    tokio::task::spawn_blocking(move || {
        let cap_device = PcapDevice::list()
            .unwrap_or_default()
            .into_iter()
            .find(|d| d.name == interface_name);

        let open_capture = || -> Result<Capture<pcap::Active>> {
            match cap_device {
                Some(dev) => Capture::from_device(dev)
                    .context("open device")?
                    .promisc(true)
                    .snaplen(65535)
                    .timeout(100)
                    .open()
                    .context("open capture"),
                None => {
                    warn!("Interface {} not found, trying 'any'", interface_name);
                    Capture::from_device("any")
                        .context("open any device")?
                        .promisc(true)
                        .snaplen(65535)
                        .timeout(100)
                        .open()
                        .context("open capture on any")
                }
            }
        };

        let mut cap = match open_capture() {
            Ok(cap) => cap,
            Err(err) => {
                warn!("Packet capture unavailable: {}", err);
                return;
            }
        };

        cap.filter("tcp or udp", true).ok();

        loop {
            match cap.next_packet() {
                Ok(pkt) => {
                    process_packet(pkt.data, &flows, &alert_tx);
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => {
                    warn!("Capture error: {}", e);
                    break;
                }
            }
        }
    });

    Ok(())
}

fn process_packet(data: &[u8], flows: &FlowMap, alert_tx: &AlertSender) {
    let Ok(pkt) = SlicedPacket::from_ethernet(data) else {
        return;
    };

    let (src_ip, dst_ip) = match &pkt.net {
        Some(NetSlice::Ipv4(ipv4)) => {
            let hdr = ipv4.header();
            (format_ip(hdr.source()), format_ip(hdr.destination()))
        }
        _ => return,
    };

    let pkt_len = data.len() as u64;

    match &pkt.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            let key = FlowKey {
                src_ip: src_ip.clone(),
                dst_ip: dst_ip.clone(),
                src_port: tcp.source_port(),
                dst_port: tcp.destination_port(),
                protocol: "TCP".into(),
            };
            let is_syn = tcp.syn() && !tcp.ack();

            let mut entry = flows.entry(key.clone()).or_insert_with(|| {
                (
                    FlowStats {
                        key: key.clone(),
                        syn_count: 0,
                        total_bytes: 0,
                        packet_count: 0,
                        first_seen: Utc::now(),
                        last_seen: Utc::now(),
                        payload_snippet: None,
                    },
                    Instant::now(),
                )
            });

            let (stats, window_start) = entry.value_mut();
            stats.total_bytes += pkt_len;
            stats.packet_count += 1;
            stats.last_seen = Utc::now();
            if stats.payload_snippet.is_none() {
                let p = tcp.payload();
                if !p.is_empty() {
                    let chunk = &p[..p.len().min(256)];
                    stats.payload_snippet =
                        Some(chunk.iter().map(|b| format!("{:02x}", b)).collect());
                }
            }

            if is_syn {
                if window_start.elapsed() > Duration::from_secs(30) {
                    stats.syn_count = 0;
                    *window_start = Instant::now();
                }
                stats.syn_count += 1;

                if stats.syn_count > 10 {
                    let alert = Alert {
                        id: next_id(),
                        alert_type: AlertType::SynFlood,
                        src_ip: src_ip.clone(),
                        dst_ip: dst_ip.clone(),
                        message: format!(
                            "Possible SYN flood: {} -> {} ({} SYNs in 30s)",
                            src_ip, dst_ip, stats.syn_count
                        ),
                        timestamp: Utc::now(),
                    };
                    warn!("ALERT: {}", alert.message);
                    let _ = alert_tx.send(alert);
                    stats.syn_count = 0;
                }
            }
        }
        Some(TransportSlice::Udp(udp)) => {
            let key = FlowKey {
                src_ip,
                dst_ip,
                src_port: udp.source_port(),
                dst_port: udp.destination_port(),
                protocol: "UDP".into(),
            };
            let mut entry = flows.entry(key.clone()).or_insert_with(|| {
                (
                    FlowStats {
                        key: key.clone(),
                        syn_count: 0,
                        total_bytes: 0,
                        packet_count: 0,
                        first_seen: Utc::now(),
                        last_seen: Utc::now(),
                        payload_snippet: None,
                    },
                    Instant::now(),
                )
            });
            let (stats, _) = entry.value_mut();
            stats.total_bytes += pkt_len;
            stats.packet_count += 1;
            stats.last_seen = Utc::now();
            if stats.payload_snippet.is_none() {
                let p = udp.payload();
                if !p.is_empty() {
                    let chunk = &p[..p.len().min(256)];
                    stats.payload_snippet =
                        Some(chunk.iter().map(|b| format!("{:02x}", b)).collect());
                }
            }
        }
        _ => {}
    }
}

fn format_ip(b: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn next_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    format!("alert-{}", COUNTER.fetch_add(1, Ordering::Relaxed))
}

pub async fn evict_old_flows(flows: FlowMap) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        let before = flows.len();
        flows.retain(|_, (_, instant)| instant.elapsed() < Duration::from_secs(300));
        let evicted = before - flows.len();
        if evicted > 0 {
            info!("Evicted {} stale flows", evicted);
        }
    }
}
