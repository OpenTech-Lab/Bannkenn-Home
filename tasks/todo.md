# Device Monitor MVP

## Current Task: Synology Raw Socket Fix

- [x] Confirm the deployment mismatch causing `Operation not permitted` on Synology NAS
- [x] Update Docker runtime config so ARP scan and pcap run with Synology-safe privileges
- [x] Align Dockerfile and README with the Synology runtime model
- [x] Run verification checks and record the result

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
- [x] docker compose build succeeds
- [ ] Smoke test: curl http://localhost:8080/devices

## MVP Scope (delivered)
- ARP-based LAN scan on startup → stored in-memory
- Passive TCP/UDP flow tracking (5-tuple via etherparse)
- Alert on SYN flood (>10 SYNs to same dst in 30s)
- REST API on :8080: GET /  /devices  /flows  /alerts
- docker-compose.yml with host networking and Synology-safe privileged root runtime

## Review

- `cargo check --manifest-path device-monitor/Cargo.toml` passed
- `docker compose config` and `docker compose -f docker-compose-build.yml config` resolve to `network_mode: host`, `privileged: true`, `user: "0:0"`
- `docker compose -f docker-compose-build.yml build device-monitor` passed
- API smoke test was not run locally because the container was not started in this session
