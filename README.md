# Lineman — macOS HIPS & Egress Forensics Prototype

<div align="center">
  <img src="lineman.png" width="256" height="256" alt="Lineman Icon" />
</div>

A Host Intrusion Prevention System (HIPS) prototype demonstrating macOS
security internals: **pf anchor management**, **XPC process lineage tracking**,
**privilege-separated daemon/GUI architecture**, and **egress forensic capture**
via `pflog0`.

```
┌──────────────────────────────────────────┐
│  lineman-gui (unprivileged user process) │
│  Tkinter control surface                 │
└────────────────┬─────────────────────────┘
                 │  Unix socket  /var/run/lineman.sock
                 │  JSON command API
┌────────────────▼─────────────────────────┐
│  lineman-daemon (root)                   │
│  ┌──────────────┐  ┌───────────────────┐ │
│  │ pf_anchor.py │  │ process_lineage.py│ │
│  │ pf anchor    │  │ XPC helper scan   │ │
│  │ table mgmt   │  │ PID lifecycle mon │ │
│  └──────────────┘  └───────────────────┘ │
│  ┌────────────────────────────────────┐  │
│  │ egress_forensics.py                │  │
│  │ tcpdump pflog0 → SNI + host parse  │  │
│  │ Tamper-evident JSON reports        │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
         │                  │
    socketfilterfw         pf anchor
    (ALF per-app block)    <lineman_blocked> table
```

---

## Architecture

### Why Two Processes?

Running a GUI as `sudo` is a macOS security anti-pattern. If the GUI is
compromised (by a malicious `.app` bundle being inspected, or a Tkinter
vulnerability), an attacker gains root. Lineman separates concerns:

- **`lineman-daemon`** — minimal root process, owns all privileged syscalls,
  exposes a narrow JSON socket API
- **`lineman-gui`** — unprivileged Tkinter app, never calls `pfctl` or `tcpdump`
  directly

### pf Anchor — Non-Destructive Firewall Integration

Lineman creates a dedicated pf anchor (`com.lineman.blocker`) and never touches
the system's main ruleset beyond two lines:

```
# Added to /etc/pf.conf:
anchor "com.lineman.blocker"
load anchor "com.lineman.blocker" from "/etc/pf.anchors/com.lineman.blocker"
```

The anchor file contains a persistent IP table and two rules:

```
table <lineman_blocked> persist {}
block drop out log quick proto tcp from any to <lineman_blocked>
block drop out log quick proto udp from any to <lineman_blocked>
```

IPs are added/removed dynamically without reloading pf:

```bash
pfctl -a com.lineman.blocker -t lineman_blocked -T add 35.186.224.25
pfctl -a com.lineman.blocker -t lineman_blocked -T flush
```

### Process Lineage Engine

`pgrep -f bundle_id` misses a large fraction of an app's network-capable
processes. The lineage engine uses three strategies in combination:

1. **Bundle-path scan** — any process whose `argv` contains the `.app` path
2. **XPC service enumeration** — reads `Contents/XPCServices/*.xpc/Info.plist`
   to find declared helper bundle IDs, matches them against running processes
3. **LaunchAgent correlation** — scans `~/Library/LaunchAgents/` for plists
   whose `Program` key references the app bundle (catches update daemons that
   survive parent termination)
4. **PPID tree expansion** — BFS from any matched PID to capture all descendants

### Egress Forensics

The `log` keyword in the pf rules routes dropped packets to the `pflog0`
interface. When a block is applied, `egress_forensics.py` starts a 30-second
`tcpdump -i pflog0` session and parses captured packets for:

- Destination IP and port
- **TLS SNI** — extracted by parsing the raw ClientHello (no MITM required)
- **HTTP Host header** — for plaintext connections
- Destination classification: `TELEMETRY` / `UPDATE_SERVER` / `CRASH_REPORTER`
  / `ADVERTISING` / `CDN` / `ENCRYPTED_UNKNOWN`

Reports are written to `forensics/<timestamp>_<app>.json` as tamper-evident
records (SHA-256 of the canonical body).

---

## Installation

```bash
# 1. Clone
git clone https://github.com/your-org/lineman
cd lineman

# 2. Install dependencies
pip3 install psutil

# 3. Install (sets up daemon, pf anchor, launchd service)
sudo bash install.sh
```

### Manual start (development)

```bash
# Terminal 1 — daemon (root)
sudo python3 lineman-daemon/daemon.py

# Terminal 2 — GUI (user)
python3 lineman-gui/app.py
```

---

## Usage

1. Start the GUI (`python3 lineman-gui/app.py`)
2. The status indicator shows **DAEMON ONLINE** when the root daemon is
   reachable
3. Click **+ Add App**, navigate to `/Applications/`, select any `.app`
4. The daemon will:
   - Block the app via the macOS Application Layer Firewall
   - Discover all XPC helpers and child processes
   - Resolve current outbound connections and add their IPs to the pf table
   - Start a 30-second egress forensic capture on `pflog0`
5. Open `forensics/*.json` to read the egress report

---

## Project Structure

```
lineman/
├── lineman-daemon/
│   ├── daemon.py              # Root daemon — IPC server + orchestration
│   ├── pf_anchor.py           # pf anchor lifecycle + table management
│   ├── process_lineage.py     # XPC discovery + PID lifecycle monitor
│   └── egress_forensics.py    # pflog0 capture + SNI parsing + JSON reports
├── lineman-gui/
│   └── app.py                 # Unprivileged Tkinter control surface
├── forensics/                 # Egress report output
├── docs/
│   └── THREAT_MODEL.md        # How XPC bypasses naive firewalls + mitigations
├── com.lineman.daemon.plist   # launchd service definition
├── install.sh                 # Guided installer
└── app_blocker.py             # Original prototype (preserved)
```

---

## Technical References

- Apple Developer: [XPC Services](https://developer.apple.com/documentation/xpc)
- Apple Developer: [Network Extensions](https://developer.apple.com/documentation/networkextension)
- FreeBSD Handbook: [Firewalls / PF](https://docs.freebsd.org/en/books/handbook/firewalls/#firewalls-pf)
- `man pfctl(8)`, `man pf.conf(5)`, `man pflog(4)`
- `man socketfilterfw(8)`
- Apple TN3135: [Inside code signing: Requirements](https://developer.apple.com/documentation/technotes/tn3135-inside-code-signing-requirements)

---

## ⚠ Legal Notice

Authorized security research and system administration use only. pf anchor
modifications require root. Do not deploy on systems you do not own or
administer.
