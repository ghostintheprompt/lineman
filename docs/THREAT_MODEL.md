# Threat Model: How macOS Applications Bypass Standard Firewalls

## 1. The Naive Blocking Problem

A simplistic macOS firewall (including many commercial "app firewalls") blocks
network access by matching the application bundle path against outbound
connections. This approach fails against modern macOS application architecture
for several structural reasons documented below.

---

## 2. XPC Services — The Primary Bypass Vector

### What XPC Is

XPC (Cross-Process Communication) is Apple's IPC framework for privilege
separation. Every application that handles untrusted content is *required* by
App Store guidelines to isolate risky operations in separate XPC helper
processes. In practice this means:

```
/Applications/Spotify.app/
└── Contents/
    ├── MacOS/
    │   └── Spotify           ← main process (what your firewall sees)
    └── XPCServices/
        ├── com.spotify.SpotifyHelper.xpc
        │   └── Contents/MacOS/SpotifyHelper   ← separate process, separate PID
        └── com.spotify.SpotifyNotificationService.xpc
            └── Contents/MacOS/SpotifyNotificationService
```

The XPC service processes are **spawned by launchd, not by the parent app**.
By the time they're running, they have a PPID of 1 (launchd). A firewall that
blocks by matching the parent app's PID or bundle path against running processes
sees these helpers as unrelated processes.

### Why This Matters for Blocking

When you block Spotify's main process, it continues to phone home through
`SpotifyHelper` because:
- `SpotifyHelper` is a different binary with a different process name
- Its PPID is 1 (launchd), not Spotify's PID
- The macOS Application Layer Firewall (ALF) identifies apps by executable path —
  `socketfilterfw --blockApp` applied to the main bundle blocks the main binary
  but often misses XPC helpers running from within the same bundle

### Lineman's Countermeasure

`process_lineage.py` `_enumerate_xpc_bundle_ids()` reads every
`Contents/XPCServices/*.xpc/Contents/Info.plist` in the target bundle and
extracts their `CFBundleIdentifier` values. These are then matched against
running processes by scanning `/proc` (via `ps -axo args`) for any process
whose argv contains the XPC bundle ID string. All matched PIDs are included in
the block scope.

---

## 3. LaunchAgents — Persistence Beyond Parent Death

### The Pattern

Many applications register a `LaunchAgent` plist in
`~/Library/LaunchAgents/` during first launch. These agents:
- Start at user login, independent of the main application
- Survive the main application quitting
- Perform background sync, updates, and telemetry
- Run as the same UID as the user but are children of launchd (PID 1)

Example: Dropbox registers `com.dropbox.DropboxMacUpdate.agent` as a
LaunchAgent. Blocking the Dropbox.app bundle does not stop this agent because
it is a separate launchd-managed process.

### Lineman's Countermeasure

`process_lineage.py` `_find_launch_agent_pids()` scans:
- `~/Library/LaunchAgents/`
- `/Library/LaunchAgents/`
- `/Library/LaunchDaemons/`

For each plist, it checks whether the `Program` or `ProgramArguments` keys
reference the blocked app's bundle path. Any running process matching a
registered agent label is added to the block scope.

---

## 4. PID Lifecycle — The Restart Problem

### The Pattern

PIDs are ephemeral. An application blocked by PID at 14:32:01 is running with
a completely different PID by 14:32:45 if it crashes and respawns. A static PID
blocker stops working the moment the application restarts.

This is particularly relevant for:
- Crash reporters that relaunch immediately on crash
- Update daemons with `KeepAlive = true` in their launchd plist
- App sandboxes that fork helper processes per-connection

### Lineman's Countermeasure

`process_lineage.PIDLifecycleMonitor` polls the process table every 2 seconds.
When it detects that a new PID has appeared for a tracked application (any
process whose argv references the blocked bundle), it immediately fires
`on_new_pids()`, which triggers the daemon to:
1. Re-resolve current outbound connections for the new PID
2. Add any new destination IPs to the pf blocked table
3. Apply `socketfilterfw --blockApp` again (idempotent on macOS)
4. Update the PID registry

---

## 5. The pf Anchor Architecture — Why Not Just iptables?

macOS uses its own `pf` (Packet Filter) inherited from BSD, not Linux netfilter.
The key design constraint is that pf operates on **network-layer IPs**, not on
process identities. This means:

### What pf Can Do
- Block all traffic to/from specific IP addresses (what Lineman uses)
- Block by user ID (`block out quick user <uid>`) — but this blocks ALL traffic
  for that user, not just one app
- Log dropped packets to `pflog0` for forensic analysis

### What pf Cannot Do (Without Kernel Extensions)
- Block by process ID
- Block by application bundle path
- Block by TCP connection socket

### Lineman's Hybrid Architecture

Because of this constraint, Lineman uses a two-layer approach:

```
Layer 1 — macOS ALF (socketfilterfw):
  Blocks the app's registered binaries at the socket layer.
  Reliable for the main binary. May miss some XPC services.

Layer 2 — pf Anchor (IP-level):
  Resolves current destination IPs from the app's active connections via lsof.
  Adds those IPs to the <lineman_blocked> pf table.
  Catches bypass attempts through XPC helpers that the ALF misses.
  Also catches future connections to already-known telemetry server IPs.
```

The pf anchor is isolated from the system ruleset:

```
/etc/pf.conf (system, unmodified except for two added lines):
  anchor "com.lineman.blocker"
  load anchor "com.lineman.blocker" from "/etc/pf.anchors/com.lineman.blocker"

/etc/pf.anchors/com.lineman.blocker (Lineman-owned):
  table <lineman_blocked> persist {}
  block drop out log quick proto tcp from any to <lineman_blocked>
  block drop out log quick proto udp from any to <lineman_blocked>
```

Dynamic IP table operations (`pfctl -t lineman_blocked -T add/delete/flush`)
do not require reloading pf or touching the system ruleset.

---

## 6. Egress Forensics — What Was the App Actually Doing?

When a packet is blocked by the pf `log` rule, it appears on the `pflog0`
pseudo-interface. Lineman's `egress_forensics.py` runs `tcpdump -i pflog0` to
capture these blocked packets for 30 seconds after a block is applied.

### What the Capture Reveals

| Data Point | Source | Significance |
|------------|--------|--------------|
| Destination IP | pf log | Maps to telemetry server, CDN, or update service |
| Destination port | pf log | 443 = likely TLS; 80 = plaintext |
| TLS SNI | TLS ClientHello payload | Identifies domain even when IP is shared (CDN) |
| HTTP Host header | First packet payload (plaintext only) | Identifies endpoint on shared IP |
| Payload classification | Pattern matching on SNI/rDNS | TELEMETRY / UPDATE / CRASH / ADVERTISING |

### Telemetry vs. Payload Download

The classification engine distinguishes between:
- **TELEMETRY**: Calls to `metrics.`, `analytics.`, `stats.`, `tracker.`
  — legitimate but privacy-relevant
- **UPDATE_SERVER**: Calls to `autoupdate.`, `software-update.`
  — expected behavior; blocks may break functionality
- **CRASH_REPORTER**: Calls to Sentry, BugSplat, Crashlytics
  — contains device identifiers and stack traces
- **ADVERTISING**: Calls to DoubleClick, Google Syndication
  — unexpected from non-browser apps; warrants investigation
- **ENCRYPTED_UNKNOWN**: TLS on port 443 with unrecognized SNI
  — warrants DNS investigation of the destination IP

---

## 7. Privilege Separation — The Daemon/Client Split

### The Anti-Pattern Being Avoided

Running a GUI process as root is a macOS security anti-pattern. The GUI:
- Renders untrusted content (application names, bundle IDs)
- Handles user input (file paths from dialogs)
- Links against large UI frameworks (AppKit, Tkinter) with broad attack surface

If the GUI process has root privileges and is exploited, the attacker gains
full system access.

### Lineman's Model

```
┌─────────────────────────────────────┐
│  lineman-daemon (root)              │
│  • pfctl anchor management          │  Unix socket
│  • socketfilterfw calls             │  /var/run/lineman.sock
│  • tcpdump on pflog0                │  (root:staff, 0660)
│  • Narrow JSON command API          │◄──────────────────────────────┐
└─────────────────────────────────────┘                               │
                                                                       │
┌─────────────────────────────────────┐                               │
│  lineman-gui (user)                 │                               │
│  • Tkinter UI                       │                               │
│  • File picker                      │──────────────────────────────►│
│  • Report viewer                    │   JSON commands + responses
│  • NO elevated privileges           │
└─────────────────────────────────────┘
```

The daemon validates all inputs and executes a minimal, well-defined command
set. The GUI cannot directly invoke any system commands — it can only send
named actions over the socket. If the GUI is compromised, the attacker gains
only user-level access and can only invoke the commands the daemon was designed
to handle.

---

## 8. Known Limitations

### TLS 1.3 / QUIC
Encrypted SNI (ESNI/ECH) hides the hostname at the TLS layer. Lineman's SNI
extraction works against TLS 1.2 and early TLS 1.3 handshakes; QUIC (HTTP/3)
traffic captures only the destination IP and port.

### Network Extensions
Apple's `NetworkExtension` framework (used by Little Snitch, NextDNS, etc.)
provides per-connection interception with application identity at the system
call level. This requires a System Extension entitlement from Apple and code
signing. Lineman's pf+ALF hybrid approach is a demonstration of the same
principles without requiring Apple entitlements.

### App Notarization / SIP
System Integrity Protection prevents modification of system binaries. Lineman
does not attempt to modify any SIP-protected path. The pf anchor file is
written to `/etc/pf.anchors/` which is not SIP-protected.

### IP Sharing (CDN)
When an application's traffic routes through a CDN (Akamai, CloudFront, etc.),
blocking the destination IP may block other unrelated services sharing that IP.
The forensic classification engine flags CDN destinations specifically so the
operator can make an informed decision.
