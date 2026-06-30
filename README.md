# Network Scanner

A lightweight CLI tool for local-network host discovery and TCP port scanning — built with Python 3, Scapy, and the standard library.

Useful as a CCNA / CEH portfolio piece demonstrating knowledge of ARP, TCP three-way handshake, subnetting, and service identification.

---

## Features

| Feature | Details |
|---|---|
| ARP host discovery | Broadcasts ARP requests across a CIDR subnet to identify live hosts and their MAC addresses |
| TCP port scanning | Multi-threaded `connect()` scan; configurable thread count and timeout |
| Service detection | Resolves service name per open port via `socket.getservbyport` |
| Flexible port input | Range (`1-1024`), list (`22,80,443`), or mixed (`22,8000-8100`) |
| Export | Results to `.csv` or `.json` |
| Verbose mode | Optionally show closed ports alongside open ones |

---

## Requirements

- Python 3.10+
- `scapy` (ARP scanning only)
- Root / administrator privileges for ARP scanning

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
# Discover all live hosts on a subnet (requires sudo)
sudo python main.py --target 192.168.1.0/24

# Scan the 1-1024 port range on a single host
python main.py --target 192.168.1.1 --ports 1-1024

# Scan specific ports
python main.py --target 192.168.1.1 --ports 22,80,443,8080

# Export results to JSON
python main.py --target 192.168.1.1 --export results.json

# Export subnet discovery to CSV
sudo python main.py --target 192.168.1.0/24 --export hosts.csv

# Show closed ports as well (verbose)
python main.py --target 192.168.1.1 --verbose

# Tune performance
python main.py --target 192.168.1.1 --ports 1-65535 --threads 200 --timeout 0.5
```

### All options

```
--target TARGET    IP, hostname, or CIDR subnet  (required)
--ports PORTS      Port range or list (default: built-in common-ports list)
--threads N        Worker threads for port scanning (default: 100)
--timeout SECS     Per-port socket timeout (default: 1.0)
--export FILE      Save output to .csv or .json
--verbose / -v     Also display closed ports
```

---

## Project Structure

```
network-scanner/
├── main.py          # CLI entry point (argparse, orchestration)
├── scanner.py       # TCP port scanning (socket + ThreadPoolExecutor)
├── discovery.py     # ARP host discovery (Scapy)
├── export.py        # CSV / JSON output
├── requirements.txt
└── README.md
```

---

## How It Works

### ARP Discovery (`discovery.py`)
Crafts an `Ether / ARP` broadcast packet targeting every address in the supplied CIDR range using Scapy's `srp()` (send/receive at layer 2). Hosts that reply are live; their source IP and MAC are extracted from the response.

### Port Scanning (`scanner.py`)
Uses `socket.connect_ex()` — a non-exception-raising connect attempt — inside a `ThreadPoolExecutor`. A return value of `0` means the port accepted the connection (open); anything else means closed or filtered. Results are collected via `as_completed()` and sorted by port number.

### Service Detection
`socket.getservbyport()` maps well-known port numbers to IANA service names (`ssh`, `http`, `https`, …). Falls back to `"unknown"` for unregistered ports.

### Export (`export.py`)
- **JSON** — structured array of host objects, each with a `ports` sub-array.
- **CSV** — flattened rows: `host, mac, port, state, service`.

---

## Limitations & Notes

- ARP scanning only works on the **local Layer 2 segment** — it will not cross routers.
- TCP `connect()` scans may be logged by host firewalls and IDS systems.
- Only run this tool against networks and hosts **you own or have explicit written permission to test**.

---

## Legal Disclaimer

This tool is intended for authorized network administration, security education, and CTF/lab environments only. Unauthorized port scanning or network probing may violate local laws and terms of service. The author accepts no liability for misuse.
