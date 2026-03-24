mod api;
mod capture;
mod discovery;
mod geo;
mod labels;
mod models;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::info;
use tracing_subscriber::EnvFilter;

use api::{build_router, collect_alerts, AppState};
use capture::{evict_old_flows, new_flow_map, run_capture};
use discovery::{load_device_map, run_scan_loop};
use geo::GeoDb;
use labels::LabelStore;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("device_monitor=info".parse()?),
        )
        .init();

    let interface = std::env::var("INTERFACE").unwrap_or_else(|_| "eth0".into());
    let subnet = std::env::var("SUBNET").unwrap_or_else(|_| "192.168.1.0/24".into());
    let geo_dir = std::env::var("GEO_DATA_DIR").unwrap_or_else(|_| "/data".into());
    let labels_file =
        std::env::var("LABELS_FILE").unwrap_or_else(|_| format!("{}/labels.json", geo_dir));
    let devices_file =
        std::env::var("DEVICES_FILE").unwrap_or_else(|_| format!("{}/devices.json", geo_dir));
    let scan_interval: u64 = std::env::var("SCAN_INTERVAL")
        .unwrap_or_else(|_| "30".into())
        .parse()
        .unwrap_or(30);
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()
        .unwrap_or(8080);

    info!("Device Monitor starting...");
    info!(
        "Interface: {}  Subnet: {}  Scan interval: {}s",
        interface, subnet, scan_interval
    );

    let geo = Arc::new(GeoDb::load(&geo_dir));
    let labels = LabelStore::load(&labels_file);

    let devices = load_device_map(&devices_file);
    let flows = new_flow_map();
    let alerts_store = Arc::new(RwLock::new(Vec::new()));
    let (alert_tx, alert_rx) = broadcast::channel::<models::Alert>(256);

    // Periodic LAN discovery (fires immediately, then every scan_interval seconds)
    tokio::spawn(run_scan_loop(
        interface.clone(),
        subnet.clone(),
        devices.clone(),
        scan_interval,
        Some(std::path::PathBuf::from(&devices_file)),
    ));

    // Packet capture
    tokio::spawn({
        let (flows, tx, iface) = (flows.clone(), alert_tx.clone(), interface.clone());
        async move {
            if let Err(e) = run_capture(iface, flows, tx).await {
                tracing::warn!("Capture error (needs NET_RAW cap): {}", e);
            }
        }
    });

    tokio::spawn(evict_old_flows(flows.clone()));
    tokio::spawn(collect_alerts(alert_rx, alerts_store.clone()));

    let state = AppState {
        devices,
        flows,
        alerts: alerts_store,
        geo,
        labels,
        scan_interval,
    };
    let app = build_router(state);
    let addr = format!("0.0.0.0:{}", port);
    info!("API listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
