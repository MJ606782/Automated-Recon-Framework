# Automated Red Team Recon Framework

A Python-based modular reconnaissance and offensive security framework designed to map network targets, analyze protocol flag states, and infer target operating system parameters using low-level TCP/IP stack signatures.

## Core Architecture & Workflow

The framework implements a dual-tiered reconnaissance pipeline that transitions from low-level transport layer discovery to high-level application inspection:

1. **Active Port Discovery (Stealth SYN Scanning):** Bypasses the standard OS networking API using `Scapy` to build custom raw IP/TCP layers. Differentiates port states by parsing raw header responses.
2. **OS Fingerprinting Module:** Automatically reads the `TTL` (Time to Live) and Window Size values from intercepted network headers to determine target host environments based on kernel RFC baselines.
3. **Application Verification (Banner Grabbing):** Hands off active ports to standard socket handles (`SOCK_STREAM`) to negotiate full connections and extract application-layer header strings like HTTP and SSH version strings.
4. **Evasion Extension (Timing Randomization):** Mitigates threshold-based IDS/IPS logging by introducing random jitter delays between sequential packet transmissions.

---

## Sandbox Setup & Verification

### Prerequisites
- Python 3.x
- VirtualBox containing an isolated target instance (e.g., Kali Linux) configured with a Host-Only Network Adapter.
- Wireshark (for raw traffic inspection).

### Operational Deployment
1. Establish a target listener inside the isolated VM environment:
   ```bash
   python3 -m http.server 8000