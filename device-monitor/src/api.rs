use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, Json},
    routing::{delete, get},
    Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tower_http::cors::CorsLayer;

use crate::capture::FlowMap;
use crate::discovery::DeviceMap;
use crate::geo::GeoDb;
use crate::labels::{find_label_name, LabelEntry, LabelStore};
use crate::models::Alert;

#[derive(Clone)]
pub struct AppState {
    pub devices:       DeviceMap,
    pub flows:         FlowMap,
    pub alerts:        Arc<RwLock<Vec<Alert>>>,
    pub geo:           Arc<GeoDb>,
    pub labels:        Arc<LabelStore>,
    pub scan_interval: u64,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/",              get(dashboard))
        .route("/health",        get(health))
        .route("/devices",       get(list_devices))
        .route("/flows",         get(list_flows))
        .route("/alerts",        get(list_alerts))
        .route("/labels",        get(list_labels).post(upsert_label))
        .route("/labels/:id",    delete(del_label))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

// ── handlers ────────────────────────────────────────────────────────────────

async fn health(State(s): State<AppState>) -> Json<Value> {
    Json(json!({ "status": "ok", "scan_interval": s.scan_interval }))
}

async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn list_devices(State(s): State<AppState>) -> Json<Value> {
    let devices = s.devices.read().await;
    let labels  = s.labels.list().await;
    let enriched: Vec<Value> = devices.iter().map(|dev| {
        let ip  = dev.ip.to_string();
        let mac = dev.mac.as_str();
        let label = labels.iter().find(|l| {
            l.ips.iter().any(|i| *i == ip)
            || l.macs.iter().any(|m| m.eq_ignore_ascii_case(mac))
        });
        json!({
            "ip":         dev.ip,
            "mac":        dev.mac,
            "hostname":   dev.hostname,
            "vendor":     dev.vendor,
            "open_ports": dev.open_ports,
            "first_seen": dev.first_seen,
            "last_seen":  dev.last_seen,
            "label_id":   label.map(|l| &l.id),
            "label_name": label.map(|l| &l.name),
        })
    }).collect();
    Json(json!({ "count": enriched.len(), "devices": enriched }))
}

async fn list_flows(State(s): State<AppState>) -> Json<Value> {
    let devices = s.devices.read().await;
    let labels  = s.labels.list().await;
    let flows: Vec<Value> = s.flows.iter().map(|e| {
        let stats = &e.value().0;
        let src_geo = enrich(&s.geo.lookup(&stats.key.src_ip, &devices), &stats.key.src_ip, &devices, &labels);
        let dst_geo = enrich(&s.geo.lookup(&stats.key.dst_ip, &devices), &stats.key.dst_ip, &devices, &labels);
        json!({
            "key":          stats.key,
            "syn_count":    stats.syn_count,
            "total_bytes":  stats.total_bytes,
            "packet_count": stats.packet_count,
            "first_seen":   stats.first_seen,
            "last_seen":    stats.last_seen,
            "src_geo":      src_geo,
            "dst_geo":      dst_geo,
        })
    }).collect();
    Json(json!({ "count": flows.len(), "flows": flows }))
}

async fn list_alerts(State(s): State<AppState>) -> Json<Value> {
    let alerts = s.alerts.read().await;
    Json(json!({ "count": alerts.len(), "alerts": *alerts }))
}

async fn list_labels(State(s): State<AppState>) -> Json<Value> {
    let labels = s.labels.list().await;
    Json(json!({ "count": labels.len(), "labels": labels }))
}

#[derive(Deserialize)]
struct UpsertReq {
    name: String,
    ip:   Option<String>,
    mac:  Option<String>,
}

async fn upsert_label(
    State(s): State<AppState>,
    Json(body): Json<UpsertReq>,
) -> Json<Value> {
    let entry = s.labels.upsert(&body.name, body.ip.as_deref(), body.mac.as_deref()).await;
    Json(json!(entry))
}

async fn del_label(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> StatusCode {
    if s.labels.delete(&id).await {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

// ── alert collector ──────────────────────────────────────────────────────────

pub async fn collect_alerts(mut rx: broadcast::Receiver<Alert>, store: Arc<RwLock<Vec<Alert>>>) {
    loop {
        match rx.recv().await {
            Ok(alert) => {
                let mut alerts = store.write().await;
                alerts.push(alert);
                if alerts.len() > 1000 { alerts.drain(0..100); }
            }
            Err(broadcast::error::RecvError::Closed) => break,
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!("Alert receiver lagged, dropped {} alerts", n);
            }
        }
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn enrich(
    base: &crate::geo::GeoInfo,
    ip: &str,
    devices: &[crate::models::Device],
    labels: &[LabelEntry],
) -> Value {
    let mut g = base.clone();
    if g.is_private {
        // 1. label by IP
        if let Some(name) = find_label_name(labels, ip, None) {
            g.device_name = Some(name.to_owned());
        } else if let Some(dev) = devices.iter().find(|d| d.ip.to_string() == ip) {
            // 2. label by MAC
            if let Some(name) = find_label_name(labels, ip, Some(&dev.mac)) {
                g.device_name = Some(name.to_owned());
            }
            // device_name already set from geo.rs as hostname fallback
        }
    }
    json!(g)
}

// ── dashboard HTML ────────────────────────────────────────────────────────────

static DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>Device Monitor</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    :root{
      --bg:#0d1117;--surface:#161b22;--border:#30363d;
      --text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;
      --green:#3fb950;--yellow:#d29922;--red:#f85149;--purple:#bc8cff;
    }
    body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}
    header{background:var(--surface);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;align-items:center;gap:12px}
    header h1{font-size:1.2rem;font-weight:600}
    .pulse{width:10px;height:10px;border-radius:50%;background:var(--green);animation:pulse 2s infinite;flex-shrink:0}
    @keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
    .status-bar{font-size:.8rem;color:var(--muted);margin-left:auto}
    main{padding:24px;display:grid;gap:24px}
    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px}
    .stat-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px 20px}
    .stat-card .label{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
    .stat-card .value{font-size:2rem;font-weight:700;margin-top:4px}
    .stat-card.alerts .value{color:var(--red)}
    .stat-card.devices .value{color:var(--accent)}
    .stat-card.flows .value{color:var(--green)}
    .section{background:var(--surface);border:1px solid var(--border);border-radius:8px;overflow:hidden}
    .section-header{padding:12px 20px;border-bottom:1px solid var(--border);font-weight:600;font-size:.9rem;display:flex;align-items:center;gap:8px}
    .badge{background:var(--border);color:var(--muted);border-radius:12px;padding:1px 8px;font-size:.75rem;font-weight:400}
    .table-wrap{overflow-x:auto}
    table{width:100%;border-collapse:collapse;font-size:.85rem}
    th{text-align:left;padding:10px 16px;color:var(--muted);font-weight:500;font-size:.75rem;text-transform:uppercase;border-bottom:1px solid var(--border);white-space:nowrap}
    td{padding:10px 16px;border-bottom:1px solid #21262d;vertical-align:top}
    tr:last-child td{border-bottom:none}
    tr:hover td{background:#1c2128}
    .empty{padding:32px;text-align:center;color:var(--muted);font-size:.85rem}
    .tag{display:inline-block;padding:2px 7px;border-radius:4px;font-size:.75rem;font-weight:500}
    .tag-tcp{background:#1f3a5c;color:#79c0ff}
    .tag-udp{background:#1f3a2a;color:#56d364}
    .tag-alert{background:#3d1f1f;color:var(--red)}
    .tag-port{background:#2d2a1f;color:#e3b341;margin:1px}
    .ip{font-family:'Courier New',monospace;color:var(--accent);font-size:.85rem}
    .mac{font-family:'Courier New',monospace;color:var(--muted);font-size:.78rem}
    .hostname{font-weight:500}
    .sub{font-size:.78rem;color:var(--muted);margin-top:2px}
    .geo-cell{line-height:1.6}
    .geo-country{font-size:.82rem}
    .geo-asn{font-size:.75rem;color:var(--muted)}
    .geo-device{font-size:.82rem;color:var(--green)}
    td.ports{white-space:normal;min-width:140px}
    td.nowrap{white-space:nowrap}

    /* online dot */
    .dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex-shrink:0;margin-right:6px}
    .dot-online{background:var(--green)}
    .dot-recent{background:var(--yellow)}
    .dot-offline{background:#484f58}

    /* label badge + btn */
    .label-badge{
      display:inline-flex;align-items:center;gap:4px;
      background:#1f2d3d;border:1px solid #2d4a6b;color:var(--accent);
      border-radius:12px;padding:2px 8px 2px 10px;font-size:.78rem;font-weight:500;
    }
    .label-edit-btn{
      background:none;border:none;cursor:pointer;color:var(--muted);
      font-size:.7rem;padding:0 2px;line-height:1;
    }
    .label-edit-btn:hover{color:var(--accent)}
    .tag-btn{
      background:none;border:1px dashed var(--border);color:var(--muted);
      border-radius:12px;padding:2px 8px;font-size:.75rem;cursor:pointer;
    }
    .tag-btn:hover{border-color:var(--accent);color:var(--accent)}

    /* modal */
    #label-modal{
      display:none;position:fixed;inset:0;z-index:100;
      align-items:center;justify-content:center;
    }
    .modal-backdrop{position:absolute;inset:0;background:rgba(0,0,0,.65)}
    .modal-box{
      position:relative;background:var(--surface);border:1px solid var(--border);
      border-radius:12px;padding:24px;width:380px;max-width:90vw;
      display:flex;flex-direction:column;gap:16px;z-index:1;
    }
    .modal-box h3{font-size:1rem;font-weight:600}
    .modal-context{
      background:#0d1117;border:1px solid var(--border);
      border-radius:6px;padding:10px 14px;
      display:flex;flex-direction:column;gap:4px;font-size:.82rem;
    }
    .modal-hint{font-size:.75rem;color:var(--muted)}
    .modal-input{
      background:#0d1117;border:1px solid var(--border);color:var(--text);
      border-radius:6px;padding:8px 12px;font-size:.9rem;width:100%;
      outline:none;
    }
    .modal-input:focus{border-color:var(--accent)}
    .modal-actions{display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap}
    .btn{padding:7px 16px;border-radius:6px;border:none;cursor:pointer;font-size:.85rem;font-weight:500}
    .btn-primary{background:var(--accent);color:#0d1117}
    .btn-primary:hover{opacity:.85}
    .btn-danger{background:var(--red);color:#fff}
    .btn-danger:hover{opacity:.85}
    .btn-ghost{background:var(--border);color:var(--text)}
    .btn-ghost:hover{background:#3d444d}
  </style>
</head>
<body>

<!-- Label Modal -->
<div id="label-modal">
  <div class="modal-backdrop" onclick="closeModal()"></div>
  <div class="modal-box">
    <h3>Tag Device</h3>
    <div class="modal-context">
      <div><span style="color:var(--muted);font-size:.75rem">IP &nbsp;</span><span class="ip" id="m-ip"></span></div>
      <div><span style="color:var(--muted);font-size:.75rem">MAC </span><span class="mac" id="m-mac"></span></div>
    </div>
    <div>
      <input class="modal-input" id="m-name" type="text" placeholder="e.g. My iPhone"
             onkeydown="if(event.key==='Enter')saveLabel()"/>
      <div class="modal-hint" style="margin-top:6px">
        Type an existing label to group this IP/MAC with it — useful after reconnecting with a new address.
      </div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-danger" id="m-del-btn" onclick="deleteLabel()">Remove label</button>
      <button class="btn btn-ghost"  onclick="closeModal()">Cancel</button>
      <button class="btn btn-primary" onclick="saveLabel()">Save</button>
    </div>
  </div>
</div>

<header>
  <div class="pulse" id="pulse"></div>
  <h1>Device Monitor</h1>
  <div class="status-bar">Auto-refresh 5s &nbsp;|&nbsp; <span id="last-update">—</span></div>
</header>
<main>
  <div class="stats">
    <div class="stat-card devices"><div class="label">Devices</div><div class="value" id="stat-devices">0</div></div>
    <div class="stat-card flows"><div class="label">Active Flows</div><div class="value" id="stat-flows">0</div></div>
    <div class="stat-card alerts"><div class="label">Alerts</div><div class="value" id="stat-alerts">0</div></div>
  </div>

  <div class="section">
    <div class="section-header">Discovered Devices <span class="badge" id="badge-devices">0</span></div>
    <div id="devices-container"><div class="empty">Scanning LAN…</div></div>
  </div>

  <div class="section">
    <div class="section-header">Alerts <span class="badge" id="badge-alerts">0</span></div>
    <div id="alerts-container"><div class="empty">No alerts</div></div>
  </div>

  <div class="section">
    <div class="section-header">Active Flows (top 50 by bytes) <span class="badge" id="badge-flows">0</span></div>
    <div id="flows-container"><div class="empty">Waiting for traffic…</div></div>
  </div>
</main>

<script>
  // ── modal state ────────────────────────────────────────────────────────────
  let modal = {};

  function openModal(ip, mac, labelName, labelId) {
    modal = { ip, mac, labelName, labelId };
    document.getElementById('m-ip').textContent   = ip;
    document.getElementById('m-mac').textContent  = mac || '—';
    document.getElementById('m-name').value       = labelName || '';
    document.getElementById('m-del-btn').style.display = labelId ? '' : 'none';
    document.getElementById('label-modal').style.display = 'flex';
    setTimeout(() => document.getElementById('m-name').focus(), 50);
  }
  function closeModal() { document.getElementById('label-modal').style.display = 'none'; }

  async function saveLabel() {
    const name = document.getElementById('m-name').value.trim();
    if (!name) return;
    await fetch('/labels', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, ip: modal.ip, mac: modal.mac }),
    });
    closeModal();
    refresh();
  }

  async function deleteLabel() {
    if (!modal.labelId) return;
    await fetch(`/labels/${modal.labelId}`, { method: 'DELETE' });
    closeModal();
    refresh();
  }

  // ── helpers ────────────────────────────────────────────────────────────────
  function fmt(n) {
    return n >= 1e9 ? (n/1e9).toFixed(1)+'G'
         : n >= 1e6 ? (n/1e6).toFixed(1)+'M'
         : n >= 1e3 ? (n/1e3).toFixed(1)+'K'
         : String(n);
  }
  function ts(iso) { return new Date(iso).toLocaleTimeString(); }
  function flag(iso) {
    if (!iso || iso.length !== 2) return '';
    return String.fromCodePoint(...[...iso.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
  }

  function renderLabel(ip, mac, labelName, labelId) {
    if (labelName) {
      return `<span class="label-badge">
        ${labelName}
        <button class="label-edit-btn" title="Edit" onclick="openModal('${ip}','${esc(mac)}','${esc(labelName)}','${esc(labelId)}')">✎</button>
      </span>`;
    }
    return `<button class="tag-btn" onclick="openModal('${ip}','${esc(mac)}','','')">+ Tag</button>`;
  }

  function renderGeo(geo, ip, port) {
    if (!geo) return `<span class="ip">${ip}:${port}</span>`;
    const portStr = `<span class="ip">${ip}:${port}</span>`;
    if (geo.is_private) {
      const name = geo.device_name || ip;
      return `<div class="geo-cell">${portStr}<div class="geo-device">🏠 ${name}</div></div>`;
    }
    const f = flag(geo.country_code);
    const country = geo.country_name || geo.country_code || '';
    const asn = geo.asn_org ? `AS${geo.asn_number||''} ${geo.asn_org}` : '';
    return `<div class="geo-cell">${portStr}
      ${country ? `<div class="geo-country"><span>${f}</span> ${country}</div>` : ''}
      ${asn     ? `<div class="geo-asn">${asn}</div>` : ''}
    </div>`;
  }

  function esc(s) { return (s||'').replace(/'/g,"\\'"); }

  // ── scan interval (fetched once) ──────────────────────────────────────────
  let scanInterval = 30;
  fetch('/health').then(r => r.json()).then(h => { scanInterval = h.scan_interval || 30; });

  function onlineDot(lastSeenIso) {
    const ageMs = Date.now() - new Date(lastSeenIso).getTime();
    const ageSec = ageMs / 1000;
    if (ageSec < scanInterval * 2.5) return `<span class="dot dot-online" title="Online"></span>`;
    if (ageSec < 300)               return `<span class="dot dot-recent" title="Recently seen"></span>`;
    return `<span class="dot dot-offline" title="Offline / sleeping"></span>`;
  }

  // ── main refresh ───────────────────────────────────────────────────────────
  async function refresh() {
    try {
      const [d, f, a] = await Promise.all([
        fetch('/devices').then(r => r.json()),
        fetch('/flows').then(r => r.json()),
        fetch('/alerts').then(r => r.json()),
      ]);

      document.getElementById('stat-devices').textContent  = d.count;
      document.getElementById('stat-flows').textContent    = f.count;
      document.getElementById('stat-alerts').textContent   = a.count;
      document.getElementById('badge-devices').textContent = d.count;
      document.getElementById('badge-flows').textContent   = f.count;
      document.getElementById('badge-alerts').textContent  = a.count;
      document.getElementById('last-update').textContent   = new Date().toLocaleTimeString();

      // ── Devices ──
      const dc = document.getElementById('devices-container');
      if (!d.devices?.length) {
        dc.innerHTML = '<div class="empty">No devices found yet.</div>';
      } else {
        dc.innerHTML = `<div class="table-wrap"><table>
          <thead><tr><th></th><th>Label / Tag</th><th>Host / IP</th><th>MAC</th><th>Vendor</th><th>Open Ports</th><th>First Seen</th><th>Last Seen</th></tr></thead>
          <tbody>${d.devices.map(dev => {
            const ports = (dev.open_ports||[]).map(p=>`<span class="tag tag-port">${p.port}/${p.service}</span>`).join(' ')
              || '<span style="color:var(--muted)">—</span>';
            return `<tr>
              <td style="padding:10px 8px 10px 16px">${onlineDot(dev.last_seen)}</td>
              <td class="nowrap">${renderLabel(dev.ip, dev.mac, dev.label_name, dev.label_id)}</td>
              <td>
                <div class="hostname">${dev.hostname||'<span style="color:var(--muted)">—</span>'}</div>
                <div class="sub"><span class="ip">${dev.ip}</span></div>
              </td>
              <td class="nowrap"><span class="mac">${dev.mac}</span></td>
              <td class="nowrap">${dev.vendor||'—'}</td>
              <td class="ports">${ports}</td>
              <td class="nowrap">${ts(dev.first_seen)}</td>
              <td class="nowrap">${ts(dev.last_seen)}</td>
            </tr>`;
          }).join('')}</tbody></table></div>`;
      }

      // ── Alerts ──
      const ac = document.getElementById('alerts-container');
      if (!a.alerts?.length) {
        ac.innerHTML = '<div class="empty">No alerts</div>';
      } else {
        const sorted = [...a.alerts].reverse().slice(0,50);
        ac.innerHTML = `<div class="table-wrap"><table>
          <thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Destination</th><th>Message</th></tr></thead>
          <tbody>${sorted.map(al=>`<tr>
            <td class="nowrap">${ts(al.timestamp)}</td>
            <td><span class="tag tag-alert">${al.alert_type}</span></td>
            <td><span class="ip">${al.src_ip}</span></td>
            <td><span class="ip">${al.dst_ip}</span></td>
            <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${al.message}</td>
          </tr>`).join('')}</tbody></table></div>`;
      }

      // ── Flows ──
      const fc = document.getElementById('flows-container');
      if (!f.flows?.length) {
        fc.innerHTML = '<div class="empty">No flows captured yet</div>';
      } else {
        const sorted = [...f.flows].sort((a,b)=>b.total_bytes-a.total_bytes).slice(0,50);
        fc.innerHTML = `<div class="table-wrap"><table>
          <thead><tr><th>Proto</th><th>Source</th><th>Destination</th><th>Bytes</th><th>Pkts</th><th>Last Seen</th></tr></thead>
          <tbody>${sorted.map(fl=>`<tr>
            <td><span class="tag tag-${fl.key.protocol.toLowerCase()}">${fl.key.protocol}</span></td>
            <td>${renderGeo(fl.src_geo, fl.key.src_ip, fl.key.src_port)}</td>
            <td>${renderGeo(fl.dst_geo, fl.key.dst_ip, fl.key.dst_port)}</td>
            <td class="nowrap">${fmt(fl.total_bytes)}</td>
            <td class="nowrap">${fmt(fl.packet_count)}</td>
            <td class="nowrap">${ts(fl.last_seen)}</td>
          </tr>`).join('')}</tbody></table></div>`;
      }

      document.getElementById('pulse').style.background = 'var(--green)';
    } catch(e) {
      document.getElementById('pulse').style.background = 'var(--red)';
      console.error('Refresh failed:', e);
    }
  }

  refresh();
  setInterval(refresh, 5000);
</script>
</body>
</html>
"#;
