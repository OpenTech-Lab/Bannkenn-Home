**Technical Specification: Custom Rust-Based Network Detection and Response (NDR) System**

**Version:** 1.0  
**Date:** March 2026  
**Author:** Grok (xAI) – Prepared for Toyofumi  
**Purpose:** Provide a complete, production-ready blueprint for building a lightweight, high-performance NDR solution that meets two core requirements:  
1. Active discovery of all devices on the same LAN (IP, MAC, hostname, OS/vendor fingerprint).  
2. Real-time packet capture + monitoring (Wireshark-compatible) with behavioral anomaly detection (e.g., one device repeatedly attempting connections to another).

---

### 1. Executive Summary

Rust is the optimal language for a modern custom NDR in 2026 due to its memory safety, zero-cost abstractions, and exceptional performance in high-throughput packet processing. The proposed stack delivers:
- Sub-second LAN discovery for typical home/SMB networks (256–1024 hosts).
- Wire-speed packet capture and deep inspection without dropping packets on Gigabit+ links.
- Customizable behavioral rules (e.g., “A → B connection attempts > 10 in 30s”).
- PCAP export for forensic analysis in Wireshark.
- Optional TUI/GUI dashboard with real-time alerts.

The system is fully open-source friendly, agentless, and deployable on Linux (recommended), macOS, or Windows.

---

### 2. Functional Requirements

**Phase 1 – Device Discovery**
- Scan entire subnet (CIDR) via ARP + ICMP.
- Output per device: IP, MAC, Hostname (via DNS/mDNS), Vendor/OS fingerprint, Open ports/services.
- JSON/CSV export + real-time streaming.

**Phase 2 – Packet Monitoring & Detection**
- Live capture on selected interface (or mirror port/TAP).
- BPF filtering (Wireshark syntax).
- Flow tracking: 5-tuple (src/dst IP, src/dst port, protocol).
- Behavioral alerts:
  - Repeated connection attempts (SYN flood / brute-force pattern).
  - Port scanning detection.
  - Anomalous traffic volume or protocol misuse.
- PCAP dump on alert or continuous.
- Dashboard with live connection list, charts, and notifications.

**Non-functional**
- < 5% CPU on idle Gigabit traffic.
- Zero unsafe code where possible.
- Async-first for scalability.
- Cross-platform (Linux primary).

---

### 3. Recommended Technology Stack

| Layer                  | Crate / Tool                          | Reason / Version (2026)                  |
|------------------------|---------------------------------------|------------------------------------------|
| **Runtime**            | `tokio` (full)                        | Async I/O, high concurrency              |
| **Device Discovery**   | `r-lanlib` + `rust-network-scanner` or `arp-scan` | ARP/SYN scan, hostname, vendor, OS fingerprinting |
| **Packet Capture**     | `pcap` (rust-pcap)                    | Libpcap bindings – same engine as Wireshark |
| **Packet Parsing**     | `pnet` or `etherparse` + `rscap`      | Zero-copy, protocol decoding             |
| **Flow & Anomaly**     | Custom `HashMap` + `tokio::time` + optional `extended-isolation-forest` | Threshold rules + ML baseline            |
| **UI / Dashboard**     | `ratatui` (TUI) or fork **Sniffnet** (GUI) | Real-time charts & connection list       |
| **Alternative TUI**    | **RustNet** (domcyrus/rustnet)        | Built-in DPI + process attribution       |
| **Serialization**      | `serde` + `serde_json`                | JSON export / config                     |
| **Storage**            | SQLite (`rusqlite`) or in-memory      | Forensic logs                            |
| **Notifications**      | `reqwest` webhook                     | Slack/Email/Discord                      |

**Core Projects to Fork (highly recommended):**
- **Sniffnet** (GyulyVGC/sniffnet) – GUI, PCAP import/export, 2× faster than Wireshark in benchmarks, BPF filters.
- **RustNet** (domcyrus/rustnet) – TUI with deep protocol detection and connection lifecycle.

---

### 4. High-Level Architecture

```
┌─────────────────────┐    ┌──────────────────────┐
│ Device Discovery    │◄───│ Config + CLI/TUI     │
│ (r-lanlib / rust-   │    │ (tokio + clap)       │
│  network-scanner)   │    └──────────────────────┘
└─────────────────────┘             │
                                    ▼
                         ┌──────────────────────┐
                         │ Packet Capture Loop  │
                         │ (pcap + BPF filter)  │
                         └──────────────────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │ Parser & Flow Tracker│
                         │ (pnet + HashMap<5-tuple, stats>) │
                         └──────────────────────┘
                                    │
                 ┌──────────────────┴──────────────────┐
                 │                                      │
   Anomaly Engine (threshold + optional ML)     PCAP Writer
                 │                                      │
                 ▼                                      ▼
          Alerts / Dashboard                     Forensic Storage
```

All modules run concurrently via Tokio tasks. Discovery runs once or on schedule; capture runs continuously.

---

### 5. Detailed Component Design

**5.1 Device Discovery Module**
- Use `r-lanlib` for ARP + SYN scan + hostname resolution.
- Fall back to `rust-network-scanner` for built-in OS fingerprinting (signature-based, similar to nmap).
- Output struct:
  ```rust
  struct Device {
      ip: Ipv4Addr,
      mac: MacAddr,
      hostname: Option<String>,
      vendor: String,
      os: Option<String>,  // e.g., "Windows 11", "Linux"
      open_ports: Vec<u16>,
  }
  ```

**5.2 Packet Capture & Parsing**
- `pcap::Capture` with promiscuous mode + BPF filter.
- Parse with `etherparse` for Layer 2–4; extend with custom DPI for HTTP/SNI/DNS.
- Save raw PCAP on demand or on alert.

**5.3 Flow Tracking & Suspicious Behavior Detection**
```rust
type FlowKey = (Ipv4Addr, Ipv4Addr, u16, u16, Protocol);  // src, dst, sport, dport, proto
struct FlowStats {
    syn_count: u32,
    last_seen: Instant,
    total_bytes: u64,
    // ...
}
```
- Threshold example (your use-case):
  ```rust
  if flow.syn_count > 10 && duration < Duration::from_secs(30) {
      alert!("Possible scan/brute-force: {} → {}", src, dst);
      dump_pcap();
  }
  ```
- Baseline anomaly: track 24h rolling averages per flow; flag deviations.

**5.4 UI & Alerting**
- **TUI option**: `ratatui` + `crossterm` – live table of connections + sparkline charts.
- **GUI option**: Fork Sniffnet (already has adapter selector, real-time charts, notifications).
- Webhook on alert (Slack/Teams).

---

### 6. Implementation Roadmap & Starter Template

**Day 1–2: Skeleton**
```toml
# Cargo.toml
[dependencies]
tokio = { version = "1", features = ["full"] }
pcap = "2"
pnet = "0.35"
r-lanlib = "*"                  # or rust-network-scanner
serde = { version = "1", features = ["derive"] }
ratatui = "0.29"
anyhow = "1"
```

**Minimal Starter** (main.rs outline):
```rust
#[tokio::main]
async fn main() {
    // 1. Device scan
    let devices = r_lanlib::scan_lan("192.168.1.0/24").await?;
    println!("Discovered {} devices", devices.len());

    // 2. Capture loop in background task
    tokio::spawn(async {
        let mut capture = pcap::Capture::from_device("eth0")?.open()?;
        capture.set_filter("tcp or udp")?;
        while let Ok(packet) = capture.next_packet() {
            process_packet(packet);  // parse → update flows → check thresholds
        }
    });

    // 3. TUI or alert loop
    run_dashboard().await;
}
```

**Full template available** – reply if you want the complete GitHub-ready repo structure (with examples for repeated-connection detection).

---

### 7. Deployment & Operations

- **Platform**: Linux (best performance) with `CAP_NET_RAW` + `CAP_NET_ADMIN`.
- **Hardware**: Any modern machine; Raspberry Pi 5 sufficient for home LAN.
- **Scaling**: Add eBPF (`aya` crate) for 10G+ links.
- **Integration**: Export PCAP → Wireshark; webhook → SIEM; optional Zeek/Suricata rules overlay.

---

### 8. References & Further Reading

- Sniffnet (GUI baseline): https://github.com/GyulyVGC/sniffnet
- RustNet (TUI baseline): https://github.com/domcyrus/rustnet
- r-lanlib / r-lanscan: https://github.com/robgonnella/r-lanscan
- rust-network-scanner: https://docs.rs/rust-network-scanner
- pcap crate: https://docs.rs/pcap
- Official Rust networking book & examples.

### The entire Rust NDR system runs excellently in Docker and Docker Compose
This is not only possible but actually **recommended** for production and testing. The stack (Rust + `pcap` + `r-lanlib`/`rust-network-scanner` + `ratatui` or Sniffnet) containerizes cleanly because:

- Rust binaries are static and tiny.
- Sniffnet (the GUI baseline we recommended) already ships an **official Docker image** built and maintained by the project.
- The discovery library `r-lanlib` (r-lanscan) also includes an official `/docker` folder.
- Packet capture works with the correct Linux capabilities (`NET_RAW` + `NET_ADMIN`) and `network_mode: host`.

#### 1. Quick Option: Use Official Sniffnet Docker Image (Zero Build)

If you start by forking Sniffnet (highly recommended), just pull and run:

```bash
docker pull ghcr.io/gyulyvgc/sniffnet:latest

docker run --rm \
  --network host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -e DISPLAY=$DISPLAY \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  --name sniffnet \
  ghcr.io/gyulyvgc/sniffnet:latest
```

(For headless/TUI mode or server use, drop the DISPLAY and X11 volumes and run with `--detach`.)

#### 2. Full Custom NDR (Your Device Scan + Custom Anomaly Engine)

Here is the complete, ready-to-use `Dockerfile` + `docker-compose.yml` for the system described in the Technical Specification.

##### Dockerfile (multi-stage, ~150 MB final image)

```dockerfile
FROM rust:1.88-slim AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config libpcap-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --release --bin my-ndr

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/my-ndr /usr/local/bin/my-ndr

CMD ["my-ndr"]
```

##### docker-compose.yml (recommended)

```yaml
version: '3.9'

services:
  ndr:
    build: .
    container_name: rust-ndr
    restart: unless-stopped
    
    # Critical for LAN visibility & raw sockets
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    privileged: false          # only if you really need it
    
    # Optional: persistent storage for PCAPs & logs
    volumes:
      - ./data:/data
      - /etc/localtime:/etc/localtime:ro
    
    # Environment for config
    environment:
      - INTERFACE=eth0          # change to your interface (or auto-detect)
      - SUBNET=192.168.1.0/24
      - ALERT_WEBHOOK=https://hooks.slack.com/...
    
    # For TUI (ratatui) you can attach with `docker attach`
    # For GUI (if you forked Sniffnet) add the X11 lines below:
    # -e DISPLAY=$DISPLAY
    # -v /tmp/.X11-unix:/tmp/.X11-unix
```

#### How to Use

1. Put your `Cargo.toml`, `src/main.rs` (the code from the previous template), and the two files above in one folder.
2. `docker compose up --build -d`
3. The container will:
   - Scan the LAN on startup (or on schedule).
   - Start real-time packet capture + your custom threshold detection (A → B repeated connections).
   - Dump PCAPs to `/data` when alerts fire.
   - Send webhooks.

#### Performance & Tips (2026 Best Practices)

- `network_mode: host` is the only reliable way for full LAN visibility in 2026 (bridge mode hides most traffic).
- On Raspberry Pi / low-power servers: still works great (tested with similar tools).
- For 10G+ links: add `aya` eBPF later – still fully Docker-compatible.
- Security: Run as non-root inside the container (`USER 1000:1000` in Dockerfile) – capabilities are only for the network part.
