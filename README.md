# Bannkenn Home — Device Monitor

A lightweight LAN device monitor built in Rust. Discovers all devices on your network via ARP, tracks live TCP/UDP flows, enriches IPs with GeoLite2 country + ASN data, and lets you tag devices with custom names that survive IP/MAC changes.

## Features

- **ARP-based LAN scan** — runs on startup and repeats every 30 s (configurable)
- **Passive packet capture** — tracks live TCP/UDP flows with 5-tuple stats
- **SYN flood detection** — alerts when >10 SYNs hit the same destination within 30 s
- **Geo enrichment** — country flag + ASN org for public IPs via MaxMind GeoLite2
- **Custom device labels** — tag a device by name; labels persist across IP/MAC changes
- **Online status dots** — green / yellow / gray based on last ARP reply
- **Web dashboard** — auto-refreshes every 5 s at `http://localhost:8080`

---

## Requirements

- Docker + Docker Compose v2
- Linux host (required for `network_mode: host` and raw packet capture)
- MaxMind GeoLite2 database files (free, see below)
- Device users should run the container as `root` with `privileged: true`

---

## Quick Start

### 1. Clone the repo

```bash
git clone <repo-url>
cd Bannkenn-Home
```

### 2. Get GeoLite2 databases

Register for a free account at [maxmind.com](https://www.maxmind.com/en/geolite2/signup) and download:

- `GeoLite2-Country.mmdb`
- `GeoLite2-ASN.mmdb`

Place them in `device-monitor/data/`:

```
device-monitor/data/
├── GeoLite2-Country.mmdb
└── GeoLite2-ASN.mmdb
```

Make the files readable:

```bash
chmod o+r device-monitor/data/*.mmdb
chmod o+rx device-monitor/data/
```

### 3. Configure your network interface

Find your network interface name:

```bash
ip link
# look for your active interface, e.g. eth0, enp3s0, wlp2s0
```

Find your LAN subnet:

```bash
ip route
# e.g. 192.168.1.0/24 dev eth0
```

Copy and edit the env file:

```bash
cp .env.example .env
```

Edit `.env`:

```env
INTERFACE=eth0          # your interface name
SUBNET=192.168.1.0/24   # your LAN subnet in CIDR notation
```

### 4. Start

```bash
docker compose up --build -d
```

Open the dashboard: **http://localhost:8080**

To follow logs:

```bash
docker logs -f device-monitor
```

---

## Configuration

All options are set via environment variables (in `.env` or directly in `docker-compose.yml`):

| Variable        | Default             | Description                                      |
|-----------------|---------------------|--------------------------------------------------|
| `INTERFACE`     | `eth0`              | Network interface to capture on                  |
| `SUBNET`        | `192.168.1.0/24`    | LAN subnet to scan (CIDR notation)               |
| `SCAN_INTERVAL` | `30`                | Seconds between ARP scans                        |
| `PORT`          | `8080`              | HTTP port for the dashboard                      |
| `GEO_DATA_DIR`  | `/data`             | Path to MMDB files inside the container          |
| `LABELS_FILE`   | `/data/labels.json` | Where custom device labels are persisted         |
| `RUST_LOG`      | `device_monitor=info,warn` | Log level                               |

---

## Device Labels

Devices can be tagged with a custom name from the dashboard. Labels are matched by **IP or MAC address**, so a name survives:

- DHCP IP changes (new IP matched by MAC)
- MAC randomization (new MAC matched by IP, then user can re-associate)

To tag a device: click **+ Tag** next to any device row, type a name, and save.
To re-tag a device with a new IP/MAC: type the same name again — the new address is added to the existing label automatically.

Labels are saved to `device-monitor/data/labels.json` and persist across container restarts.

---

## API Endpoints

| Method   | Path           | Description                    |
|----------|----------------|--------------------------------|
| `GET`    | `/`            | Dashboard (HTML)               |
| `GET`    | `/health`      | Health check + scan interval   |
| `GET`    | `/devices`     | Discovered devices (JSON)      |
| `GET`    | `/flows`       | Active flows with geo info     |
| `GET`    | `/alerts`      | SYN flood / anomaly alerts     |
| `GET`    | `/labels`      | All custom device labels       |
| `POST`   | `/labels`      | Create or update a label       |
| `DELETE` | `/labels/:id`  | Delete a label                 |

---

## Project Structure

```
Bannkenn-Home/
├── docker-compose.yml
├── .env.example
├── device-monitor/
│   ├── Dockerfile
│   ├── Cargo.toml
│   ├── data/                   # MMDB files + labels.json (mount point)
│   │   ├── GeoLite2-Country.mmdb
│   │   ├── GeoLite2-ASN.mmdb
│   │   └── labels.json         # auto-created on first label save
│   └── src/
│       ├── main.rs             # startup + wiring
│       ├── models.rs           # Device, Flow, Alert structs
│       ├── discovery.rs        # ARP scan loop + enrichment
│       ├── capture.rs          # pcap packet capture + flow tracking
│       ├── geo.rs              # MaxMind MMDB lookup
│       ├── labels.rs           # custom device label store
│       └── api.rs              # axum HTTP handlers + dashboard HTML
└── docs/
    └── 01_Custom Rust-Based Network Detection and Response (NDR) System.md
```

---

## Notes

- `network_mode: host` is required — bridge mode hides most LAN traffic from the container.
- On Synology, raw packet sockets are not reliable with only `NET_ADMIN` / `NET_RAW`. Run the container as `root` with `privileged: true`.
- The provided compose files use `user: "0:0"` so ARP scanning and libpcap can open `AF_PACKET` sockets consistently.
- The host machine running the monitor is automatically included in the device list.
- Devices that stop responding to ARP show a gray dot but remain in the list indefinitely.
