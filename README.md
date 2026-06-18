# Automated Red Team Reconnaissance Framework

A highly modular, low-level network reconnaissance and security audit framework engineered in Python. This tool moves away from standard, high-level application-layer socket constraints to craft raw transport and network-layer packet structures, facilitating stealth discovery, operational evasion, and passive target OS identification.

---

## 🛠️ Core Architecture & Pipeline

The framework utilizes a dual-tier discovery pipeline designed to gather maximum network intelligence while minimizing the target forensic footprint:
1. **Raw Packet Crafting Engine (Layer 3/4):** Bypasses the operating system's standard TCP/IP stack implementation using `Scapy`. This allows manual bit-flipping of TCP flags (`SYN`, `FIN`, `Xmas`, `ACK`) to test protocol compliance and firewalls.
2. **Passive OS Fingerprinting Engine:** Inspects raw layer-3 IPv4 header parameters—specifically **TTL (Time to Live)** and **TCP Window Size**—from returning packets to infer the remote operating system kernel without executing intrusive exploits.
3. **Application Banner Enumeration:** If a port is verified open via a half-open state, the execution lifecycle passes the file descriptor handle to a standard `SOCK_STREAM` socket to extract high-level service banner strings (e.g., HTTP headers, OpenSSH versions).
4. **Operational Evasion Layer:** Avoids simple threshold-based Intrusion Detection Systems (IDS) and security logs by injecting pseudo-random timing jitter between sequential packet dispatches.

---

## 🔬 Multi-Protocol Scan Mechanics

The framework supports a suite of scanning methodologies, each altering the TCP header flag architecture:

| Scan Type | Flags Configured | Expected Response (Open) | Expected Response (Closed) | Stealth Profile |
| :--- | :--- | :--- | :--- | :--- |
| **SYN (Half-Open)** | `S` (Synchronize) | `SYN-ACK` (Then script drops `RST`) | `RST-ACK` | **High** (Connection never logs) |
| **FIN Scan** | `F` (Finish) | No Response (Silent Drop) | `RST-ACK` | **Very High** (Passes through basic filters) |
| **Xmas Scan** | `F`, `P`, `U` (Fin/Psh/Urg) | No Response (Silent Drop) | `RST-ACK` | **Very High** (Lights up like a tree) |
| **ACK Scan** | `A` (Acknowledge) | `RST` (Used to map firewall rules) | `RST` | **Medium** (Filters analysis only) |

---

## 💻 Sandboxed Environment & Verification

### 1. Prerequisites & Target Setup
This tool must be run inside an isolated virtual sandbox. Ensure your target instance (e.g., Kali Linux) is bound to a dedicated **Host-Only Network Adapter**.

Inside your target instance, spawn standard service daemons to listen for inbound traffic connections:
```bash
# Target Step A: Spawn a temporary application layer web server
python3 -m http.server 8000

# Target Step B: Activate the system Secure Shell daemon
sudo systemctl start ssh

TARGET_IP = "192.168.56.101"
PORTS_TO_SCAN = [22, 80, 443, 8000, 9999]
SCAN_TYPE = "SYN"  # Toggle options: "SYN", "FIN", "Xmas", "ACK"
python recon_core_final.py
