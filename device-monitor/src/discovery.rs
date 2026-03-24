use anyhow::{Context, Result};
use chrono::Utc;
use dns_lookup::lookup_addr;
use pnet::datalink;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::models::{Device, PortService};

pub type DeviceMap = Arc<RwLock<Vec<Device>>>;

/// Load persisted devices from a JSON file (if it exists).
pub fn load_device_map(path: &str) -> DeviceMap {
    let devices = if std::path::Path::new(path).exists() {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str::<Vec<Device>>(&s).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    info!("Loaded {} persisted device(s) from {}", devices.len(), path);
    Arc::new(RwLock::new(devices))
}

async fn persist_devices(devices: &[Device], path: &Path) {
    match serde_json::to_string_pretty(devices) {
        Ok(json) => {
            let tmp = path.with_extension("tmp");
            let tmp2 = tmp.clone();
            let path2 = path.to_path_buf();
            tokio::task::spawn_blocking(move || {
                if std::fs::write(&tmp2, &json).is_ok() {
                    if let Err(e) = std::fs::rename(&tmp2, &path2) {
                        warn!("Failed to save devices: {}", e);
                    }
                }
            });
        }
        Err(e) => warn!("Failed to serialize devices: {}", e),
    }
}

const PROBE_PORTS: &[(u16, &str)] = &[
    (22, "SSH"),
    (23, "Telnet"),
    (53, "DNS"),
    (80, "HTTP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (548, "AFP"),
    (554, "RTSP"),
    (3389, "RDP"),
    (8080, "HTTP-alt"),
    (8443, "HTTPS-alt"),
    (9100, "Printer"),
];

/// Runs ARP scan repeatedly every `interval_secs`.
/// First scan fires immediately. Known devices (matched by MAC) get their
/// `last_seen` and `ip` updated; genuinely new devices get full enrichment.
/// If `devices_file` is set, the device list is persisted after every change.
pub async fn run_scan_loop(
    interface_name: String,
    subnet: String,
    devices: DeviceMap,
    interval_secs: u64,
    devices_file: Option<PathBuf>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if let Err(e) = scan_once(&interface_name, &subnet, devices.clone(), devices_file.as_deref()).await {
            warn!("Scan error: {}", e);
        }
    }
}

async fn scan_once(interface_name: &str, subnet: &str, devices: DeviceMap, devices_file: Option<&Path>) -> Result<()> {
    debug!("Starting ARP scan on {}...", subnet);
    let (host_ip, host_mac, mut raw) = arp_scan(interface_name, subnet).await?;

    // The host never replies to its own ARP — inject it manually.
    if host_ip != Ipv4Addr::UNSPECIFIED
        && !raw.iter().any(|(_, m)| m.eq_ignore_ascii_case(&host_mac))
    {
        raw.insert(0, (host_ip, host_mac));
    }

    debug!("ARP replied: {} hosts (including self)", raw.len());

    let now = Utc::now();
    let mut to_enrich: Vec<(Ipv4Addr, String)> = Vec::new();
    let mut changed = false;

    {
        let mut map = devices.write().await;
        for (ip, mac) in &raw {
            if let Some(dev) = map.iter_mut().find(|d| d.mac.eq_ignore_ascii_case(mac)) {
                // Known device — update presence info
                let ip_changed = dev.ip != *ip;
                dev.last_seen = now;
                if ip_changed {
                    info!("Device {} IP changed: {} → {}", dev.mac, dev.ip, ip);
                    dev.ip = *ip;
                    changed = true;
                }
            } else {
                // New device — schedule enrichment
                to_enrich.push((*ip, mac.clone()));
            }
        }

        // Persist last_seen updates for known devices
        if changed {
            if let Some(path) = devices_file {
                persist_devices(&map, path).await;
            }
        }
    }

    if to_enrich.is_empty() {
        return Ok(());
    }

    info!("{} new device(s) found, enriching...", to_enrich.len());
    let tasks: Vec<_> = to_enrich
        .into_iter()
        .map(|(ip, mac)| tokio::spawn(enrich_device(ip, mac)))
        .collect();

    let mut map = devices.write().await;
    for task in tasks {
        if let Ok(dev) = task.await {
            info!(
                "New device: {} | {} | hostname={} | ports={:?}",
                dev.ip,
                dev.mac,
                dev.hostname.as_deref().unwrap_or("—"),
                dev.open_ports.iter().map(|p| p.port).collect::<Vec<_>>(),
            );
            map.push(dev);
            changed = true;
        }
    }

    if changed {
        if let Some(path) = devices_file {
            persist_devices(&map, path).await;
        }
    }

    Ok(())
}

/// Send ARP requests to every IP in the subnet and collect replies for 2 s.
/// Returns (host_ip, host_mac, replies).
async fn arp_scan(
    interface_name: &str,
    subnet: &str,
) -> Result<(Ipv4Addr, String, Vec<(Ipv4Addr, String)>)> {
    let interfaces = datalink::interfaces();
    let iface = interfaces
        .iter()
        .find(|i| i.name == interface_name)
        .with_context(|| format!("Interface '{}' not found", interface_name))?
        .clone();

    let src_mac = iface.mac.unwrap_or(MacAddr::zero());
    let src_ip = iface
        .ips
        .iter()
        .find_map(|ip| match ip.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .unwrap_or(Ipv4Addr::UNSPECIFIED);

    let host_mac = src_mac.to_string();

    let targets = expand_cidr(subnet)?;

    let (mut tx, mut rx) = match datalink::channel(&iface, Default::default()) {
        Ok(datalink::Channel::Ethernet(t, r)) => (t, r),
        Ok(_) => anyhow::bail!("Unexpected channel type"),
        Err(e) => anyhow::bail!("Failed to open datalink channel: {}", e),
    };

    for target_ip in &targets {
        let mut eth_buf = [0u8; 42];
        let mut eth_pkt = MutableEthernetPacket::new(&mut eth_buf).unwrap();
        eth_pkt.set_destination(MacAddr::broadcast());
        eth_pkt.set_source(src_mac);
        eth_pkt.set_ethertype(EtherTypes::Arp);

        let mut arp_buf = [0u8; 28];
        let mut arp_pkt = MutableArpPacket::new(&mut arp_buf).unwrap();
        arp_pkt.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_pkt.set_protocol_type(EtherTypes::Ipv4);
        arp_pkt.set_hw_addr_len(6);
        arp_pkt.set_proto_addr_len(4);
        arp_pkt.set_operation(ArpOperations::Request);
        arp_pkt.set_sender_hw_addr(src_mac);
        arp_pkt.set_sender_proto_addr(src_ip);
        arp_pkt.set_target_hw_addr(MacAddr::zero());
        arp_pkt.set_target_proto_addr(*target_ip);

        eth_pkt.set_payload(arp_pkt.packet());
        let _ = tx.send_to(eth_pkt.packet(), None);
    }

    // Collect replies for 2 seconds in a blocking thread (pnet rx is sync)
    let found = tokio::task::spawn_blocking(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut found: Vec<(Ipv4Addr, String)> = Vec::new();
        while std::time::Instant::now() < deadline {
            match rx.next() {
                Ok(pkt) => {
                    let Some(eth) = EthernetPacket::new(pkt) else {
                        continue;
                    };
                    if eth.get_ethertype() != EtherTypes::Arp {
                        continue;
                    }
                    let Some(arp) = ArpPacket::new(eth.payload()) else {
                        continue;
                    };
                    if arp.get_operation() != ArpOperations::Reply {
                        continue;
                    }
                    let ip = arp.get_sender_proto_addr();
                    let mac = arp.get_sender_hw_addr().to_string();
                    if !found.iter().any(|(i, _)| *i == ip) {
                        found.push((ip, mac));
                    }
                }
                Err(_) => break,
            }
        }
        found
    })
    .await?;

    Ok((src_ip, host_mac, found))
}

async fn enrich_device(ip: Ipv4Addr, mac: String) -> Device {
    let hostname = tokio::task::spawn_blocking(move || lookup_addr(&IpAddr::V4(ip)).ok())
        .await
        .ok()
        .flatten()
        .map(|h| h.trim_end_matches('.').to_string())
        .filter(|h| !h.is_empty() && h != &ip.to_string());

    let port_tasks: Vec<_> = PROBE_PORTS
        .iter()
        .map(|(port, service)| {
            let addr = SocketAddr::new(IpAddr::V4(ip), *port);
            let (port, service) = (*port, *service);
            tokio::spawn(async move {
                let ok = tokio::time::timeout(Duration::from_millis(300), TcpStream::connect(addr))
                    .await;
                matches!(ok, Ok(Ok(_))).then_some(PortService {
                    port,
                    service: service.into(),
                })
            })
        })
        .collect();

    let mut open_ports = Vec::new();
    for t in port_tasks {
        if let Ok(Some(ps)) = t.await {
            open_ports.push(ps);
        }
    }

    let now = Utc::now();
    Device {
        ip,
        mac: mac.clone(),
        hostname,
        vendor: Some(oui_lookup(&mac)),
        open_ports,
        first_seen: now,
        last_seen: now,
    }
}

fn expand_cidr(cidr: &str) -> Result<Vec<Ipv4Addr>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid CIDR: {}", cidr);
    }
    let base: Ipv4Addr = parts[0].parse()?;
    let prefix: u32 = parts[1].parse()?;
    let base_u32 = u32::from(base);
    let mask = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    let network = base_u32 & mask;
    let broadcast = network | !mask;
    Ok((network + 1..broadcast).map(Ipv4Addr::from).collect())
}

fn oui_lookup(mac: &str) -> String {
    let prefix: String = mac
        .split(':')
        .take(3)
        .map(|s| s.to_uppercase())
        .collect::<Vec<_>>()
        .join(":");
    match prefix.as_str() {
        "DC:A6:32" | "B8:27:EB" | "E4:5F:01" | "28:CD:C1" | "D8:3A:DD" => "Raspberry Pi".into(),
        "AC:DE:48" | "00:03:93" | "00:0A:27" | "3C:22:FB" | "F0:18:98" | "00:17:F2"
        | "A4:C3:F0" | "F4:F1:5A" | "8C:85:90" | "DC:2B:2A" | "3C:06:30" | "B8:8D:12"
        | "18:65:90" | "AC:87:A3" | "F0:DB:F8" | "98:01:A7" | "28:CF:E9" | "70:73:CB"
        | "A8:51:AB" => "Apple".into(),
        "00:12:47" | "00:15:99" | "00:17:C9" | "2C:44:01" | "8C:77:12" | "50:85:69"
        | "CC:07:AB" | "F4:7B:5E" | "40:0E:85" => "Samsung".into(),
        "00:1A:11" | "54:EE:75" | "00:1D:7E" | "F4:F5:D8" | "48:D6:D5" | "20:DF:B9"
        | "A4:77:33" | "18:B4:30" => "Google/Nest".into(),
        "68:37:E9" | "FC:65:DE" | "74:C2:46" | "40:B4:CD" | "A4:08:F5" | "B4:7C:9C"
        | "44:65:0D" => "Amazon".into(),
        "00:50:56" | "00:0C:29" | "00:1C:14" => "VMware".into(),
        "08:00:27" => "VirtualBox".into(),
        "50:C7:BF" | "B0:BE:76" | "54:A7:03" | "98:DA:C4" | "8C:8D:28" | "EC:08:6B"
        | "60:32:B1" | "14:CC:20" | "D8:07:B6" => "TP-Link".into(),
        "00:1A:92" | "04:92:26" | "10:BF:48" | "2C:FD:A1" | "30:85:A9" | "4C:ED:FB"
        | "60:45:CB" | "88:D7:F6" | "AC:22:0B" | "BC:AE:C5" => "ASUS".into(),
        "00:09:5B" | "00:14:6C" | "00:18:4D" | "00:1B:2F" | "00:1E:2A" | "20:4E:7F"
        | "28:80:88" | "30:46:9A" | "6C:B0:CE" | "9C:3D:CF" => "Netgear".into(),
        "00:11:32" => "Synology".into(),
        "00:9E:C8" | "04:CF:8C" | "10:2A:B3" | "28:6C:07" | "34:CE:00" | "50:8F:4C"
        | "58:44:98" | "64:09:80" | "64:CC:2E" | "74:23:44" | "78:11:DC" | "8C:BE:BE"
        | "98:FA:E3" | "AC:F7:F3" | "F4:8B:32" => "Xiaomi".into(),
        "00:13:A9" | "00:1A:80" | "00:1D:0D" | "00:24:BE" | "04:98:F3" | "30:17:C8"
        | "AC:9B:0A" | "FC:0F:E6" => "Sony".into(),
        _ => "Unknown".into(),
    }
}
