# Device Monitor MVP

## Tasks

- [x] Create Rust project structure (device-monitor/)
- [x] Write Cargo.toml with dependencies
- [x] Write src/models.rs - Device, Flow, Alert structs
- [x] Write src/discovery.rs - LAN device discovery via ARP
- [x] Write src/capture.rs - pcap packet capture + flow tracking + SYN flood alert
- [x] Write src/api.rs - axum REST API (/devices, /flows, /alerts)
- [x] Write src/main.rs - wires everything together
- [x] Write Dockerfile (multi-stage)
- [x] Write docker-compose.yml
- [x] cargo check passes cleanly
- [ ] docker compose build succeeds
- [ ] Smoke test: curl http://localhost:8080/devices

## MVP Scope (delivered)
- ARP-based LAN scan on startup → stored in-memory
- Passive TCP/UDP flow tracking (5-tuple via etherparse)
- Alert on SYN flood (>10 SYNs to same dst in 30s)
- REST API on :8080: GET /  /devices  /flows  /alerts
- docker-compose.yml with NET_ADMIN + NET_RAW caps + network_mode: host
