<p align="center">
  <img src="lineman.png" width="520">
</p>

# Lineman v2.0 — Ghost-Protocol HIPS
A Host Intrusion Prevention System (HIPS) elevated for the 2026/2027 macOS security landscape.

```
┌──────────────────────────────────────────┐
│  lineman-gui (unprivileged user process) │
│  Tkinter control surface + Ed25519 Verify│
└────────────────┬─────────────────────────┘
                 │  Unix socket  /var/run/lineman.sock
                 │  JSON command API + Public Key fetch
┌────────────────▼─────────────────────────┐
│  lineman-daemon (root)                   │
│  ┌──────────────┐  ┌───────────────────┐ │
│  │ bsm_monitor.py│  │ dns_correlator.py │ │
│  │ Real-time BSM │  │ DNS <-> IP Match  │ │
│  │ (exec events) │  │ (ECH Bypass)      │ │
│  └──────────────┘  └───────────────────┘ │
│  ┌────────────────────────────────────┐  │
│  │ egress_forensics.py                │  │
│  │ Ed25519 Immutable Signing          │  │
│  │ Tamper-evident JSON reports        │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
```

---

## v2.0 Elevation Features (The Python Maximalist)

Lineman v2.0 transitions from reactive polling to **event-driven, cryptographically-rooted defense**.

### 1. Real-Time Process Events (OpenBSM)
Replaced 2-second polling with real-time `/dev/auditpipe` monitoring.
- **Zero-Delay Detection:** Child processes and XPC helpers are identified and blocked the microsecond they execute.
- **Bypass Resistance:** Malicious helpers can no longer "slip through" between polling intervals.

### 2. DNS-Based Egress Correlation (ECH Bypass)
Solved the "SNI Blindspot" caused by TLS 1.3 Encrypted Client Hello (ECH).
- **Correlation Engine:** Intercepts local DNS activity to map hostnames to resolved IPs.
- **Forensic Visibility:** When a connection to an IP is dropped, Lineman looks up the recent DNS query to identify the true target domain, bypassing encryption.

### 3. Cryptographically Signed Immutable Reports
Replaced simple hashing with **Asymmetric Integrity Signing**.
- **Hardware-Comparable Security:** Every report is signed by the daemon using a root-protected Ed25519 private key.
- **Visual Verification:** The GUI fetches the public key and visually confirms report integrity. Any tampering triggers a critical SOC alert.

---

## Security Scenarios (Ghost-Protocol)

- **s1: Trojan-Egress** — exfiltration via spoofed headers.
- **s2: Side-Channel-Leak** — data leakage via timing/size modulation.
- **s3: Buffer-Overflow-Sim** — validation against crafted payloads.

---

## Installation & Usage

```bash
# 1. Install dependencies
pip3 install cryptography psutil

# 2. Start Daemon (Root required for BSM/Audit)
sudo python3 lineman-daemon/daemon.py

# 3. Start GUI
python3 lineman-gui/app.py
```

---

## ⚠ Legal Notice
Authorized security research and system administration use only. v2.0 elevation utilizes native macOS auditing subsystems. Do not deploy on systems you do not own.
