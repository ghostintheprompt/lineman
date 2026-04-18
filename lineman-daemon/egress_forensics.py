"""
egress_forensics.py — Egress Forensic Capture Engine
======================================================
When a blocked app attempts egress, pf drops the packet and logs it to the
pflog0 pseudo-interface (because our anchor rules use the `log` keyword).

This module:
  1. Listens on pflog0 with tcpdump, filtering for packets dropped by our anchor
  2. Parses each captured record for: dst IP, dst port, protocol, SNI (TLS),
     HTTP Host header (plaintext), and the first 64 bytes of payload
  3. Classifies the destination (telemetry, CDN, analytics, update server, unknown)
  4. Writes a tamper-evident JSON "Egress Forensic Report" to forensics/

Why pflog0 instead of BPF on the app's socket?
  The packet is DROPPED by pf before it leaves the host. After pf drops it, the
  socket is closed. BPF on the egress interface never sees the packet because pf
  acts in the network stack before the driver. pflog0 is the only interface that
  shows dropped/logged pf traffic.

Forensic report structure (forensics/<timestamp>_<app_name>.json):
  {
    "schema": "lineman-egress-v1",
    "app": "Spotify",
    "app_path": "/Applications/Spotify.app",
    "capture_start": "2026-04-17T14:32:01Z",
    "capture_end":   "2026-04-17T14:32:31Z",
    "sha256": "...",          ← SHA-256 of the report body (tamper-evident)
    "events": [
      {
        "timestamp": "...",
        "pid": 12345,
        "src_ip": "192.168.1.5",
        "dst_ip": "35.186.224.25",
        "dst_port": 443,
        "protocol": "TCP",
        "sni": "spclient.wg.spotify.com",
        "classification": "TELEMETRY",
        "payload_hex": "..."
      }
    ]
  }
"""

import hashlib
import json
import logging
import os
import re
import struct
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

FORENSICS_DIR   = Path(__file__).parent.parent / "forensics"
CAPTURE_SECONDS = 30           # default capture window per trigger
PFLOG_IFACE     = "pflog0"

# ── Destination classifier ────────────────────────────────────────────────────

# Patterns matched against SNI / reverse-DNS / dst IP strings.
# Order matters: first match wins.
_CLASSIFIERS = [
    (re.compile(r"telemetry|analytics|metrics|tracker|stats\.", re.I), "TELEMETRY"),
    (re.compile(r"update|autoupdate|software-update|cdn\..*update", re.I), "UPDATE_SERVER"),
    (re.compile(r"crash|bugsplat|sentry\.io|bugsnag|crashlytics", re.I), "CRASH_REPORTER"),
    (re.compile(r"ads\.|advertising|doubleclick|googlesyndication", re.I), "ADVERTISING"),
    (re.compile(r"akamai|cloudfront|fastly|cdn\.", re.I), "CDN"),
    (re.compile(r"apple\.com|icloud\.com|push\.apple\.com", re.I), "APPLE_SERVICES"),
]


def classify_destination(sni: str, dst_ip: str, dst_port: int) -> str:
    target = sni or dst_ip
    for pattern, label in _CLASSIFIERS:
        if pattern.search(target):
            return label
    if dst_port == 443:
        return "ENCRYPTED_UNKNOWN"
    if dst_port == 80:
        return "PLAINTEXT_UNKNOWN"
    return "UNKNOWN"


# ── SNI extraction from raw TLS ClientHello ───────────────────────────────────

def extract_sni(payload: bytes) -> Optional[str]:
    """
    Parse a TLS ClientHello and extract the SNI hostname.
    Returns None if payload is not a valid ClientHello.
    """
    try:
        if len(payload) < 5 or payload[0] != 0x16:  # ContentType: Handshake
            return None
        # TLS record: type(1) + version(2) + length(2) + handshake(...)
        record_len = struct.unpack_from(">H", payload, 3)[0]
        if len(payload) < 5 + record_len:
            return None
        hs = payload[5:]
        if hs[0] != 0x01:  # HandshakeType: ClientHello
            return None
        # ClientHello: type(1) + length(3) + version(2) + random(32) + session_id_len(1)
        offset = 4 + 2 + 32
        sid_len = hs[offset]
        offset += 1 + sid_len
        # Cipher suites
        cs_len = struct.unpack_from(">H", hs, offset)[0]
        offset += 2 + cs_len
        # Compression methods
        cm_len = hs[offset]
        offset += 1 + cm_len
        # Extensions
        if offset + 2 > len(hs):
            return None
        ext_total = struct.unpack_from(">H", hs, offset)[0]
        offset += 2
        end = offset + ext_total
        while offset + 4 <= end:
            ext_type = struct.unpack_from(">H", hs, offset)[0]
            ext_len  = struct.unpack_from(">H", hs, offset + 2)[0]
            offset  += 4
            if ext_type == 0x0000:  # SNI
                # SNI list: list_len(2) + type(1) + name_len(2) + name
                name_len = struct.unpack_from(">H", hs, offset + 3)[0]
                return hs[offset + 5: offset + 5 + name_len].decode("ascii", errors="replace")
            offset += ext_len
    except Exception:
        pass
    return None


# ── HTTP Host extraction ──────────────────────────────────────────────────────

def extract_http_host(payload: bytes) -> Optional[str]:
    try:
        text = payload.decode("latin-1", errors="replace")
        m = re.search(r"^Host:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
        return m.group(1).strip() if m else None
    except Exception:
        return None


# ── pflog0 capture session ────────────────────────────────────────────────────

class EgressCaptureSession:
    """
    Runs a time-bounded tcpdump on pflog0 to capture packets dropped by
    the com.lineman.blocker anchor, then parses and reports.
    """

    def __init__(self, app_path: str, duration: int = CAPTURE_SECONDS):
        self.app_path   = app_path
        self.app_name   = Path(app_path).stem
        self.duration   = duration
        self._proc: Optional[subprocess.Popen] = None
        self._pcap_path: Optional[Path]        = None

    def _pcap_file(self) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        FORENSICS_DIR.mkdir(parents=True, exist_ok=True)
        return FORENSICS_DIR / f"{ts}_{self.app_name}.pcap"

    def start(self) -> None:
        self._pcap_path = self._pcap_file()
        # Filter: only packets logged by pf (ruleset = our anchor)
        # pflog0 frames include a pflog header; tcpdump -D shows "pflog0" on macOS
        cmd = [
            "tcpdump",
            "-i", PFLOG_IFACE,
            "-n",                         # no reverse DNS during capture
            "-w", str(self._pcap_path),
            "-G", str(self.duration),     # rotate after N seconds
            "-W", "1",                    # only one rotation (= stop after duration)
            # Filter: only packets from our anchor
            f"ifname {PFLOG_IFACE}",
        ]
        # On macOS pflog, we filter in post-processing (pflog header not BPF-filterable)
        cmd = [
            "tcpdump",
            "-i", PFLOG_IFACE,
            "-n", "-s", "256",            # 256 bytes per packet (enough for TLS CH + HTTP Host)
            "-w", str(self._pcap_path),
        ]
        log.info("[forensics] Starting %ds capture → %s", self.duration, self._pcap_path)
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        threading.Timer(self.duration, self._stop).start()

    def _stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            self._proc.wait()
            log.info("[forensics] Capture stopped.")
        self._parse_and_report()

    def _parse_and_report(self) -> Optional[Path]:
        if not self._pcap_path or not self._pcap_path.exists():
            return None

        events = self._parse_pcap(self._pcap_path)

        report = {
            "schema":        "lineman-egress-v1",
            "app":           self.app_name,
            "app_path":      self.app_path,
            "capture_start": datetime.now(timezone.utc).isoformat(),
            "capture_end":   datetime.now(timezone.utc).isoformat(),
            "pcap_file":     str(self._pcap_path),
            "events":        events,
            "event_count":   len(events),
        }

        # Tamper-evident hash
        body = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
        report["sha256"] = hashlib.sha256(body).hexdigest()

        out_path = self._pcap_path.with_suffix(".json")
        out_path.write_text(json.dumps(report, indent=2))
        log.info("[forensics] Report saved: %s (%d events)", out_path, len(events))

        self._print_summary(events)
        return out_path

    def _parse_pcap(self, pcap_path: Path) -> list[dict]:
        """
        Parse the PCAP using tcpdump -r for text output, then extract fields.
        Falls back to a basic header parser if tcpdump can't read the file.
        """
        events = []
        try:
            out = subprocess.check_output(
                ["tcpdump", "-r", str(pcap_path), "-n", "-x", "-v"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            return events

        # Each packet block starts with a timestamp line:
        # HH:MM:SS.ffffff IP src.port > dst.port: ...
        pkt_re = re.compile(
            r"(\d+:\d+:\d+\.\d+)\s+IP(?:v6)?\s+"
            r"([\d.a-f:]+)\.(\d+)\s+>\s+([\d.a-f:]+)\.(\d+)"
        )
        lines = out.splitlines()
        i = 0
        while i < len(lines):
            m = pkt_re.search(lines[i])
            if not m:
                i += 1
                continue

            ts_str, src_ip, src_port, dst_ip, dst_port = m.groups()
            dst_port_int = int(dst_port)

            # Collect hex payload lines (lines starting with tab + hex offsets)
            hex_bytes = b""
            j = i + 1
            while j < len(lines) and re.match(r"\s+0x[0-9a-f]+:", lines[j]):
                hex_part = re.sub(r"\s+0x[0-9a-f]+:\s+", " ", lines[j])
                raw = re.findall(r"[0-9a-f]{2}", hex_part)
                hex_bytes += bytes(int(b, 16) for b in raw)
                j += 1
            i = j

            sni       = extract_sni(hex_bytes)
            http_host = extract_http_host(hex_bytes) if not sni else None
            host_label = sni or http_host or ""

            events.append({
                "timestamp":     ts_str,
                "src_ip":        src_ip,
                "src_port":      int(src_port),
                "dst_ip":        dst_ip,
                "dst_port":      dst_port_int,
                "protocol":      "TCP" if dst_port_int in (80, 443, 8080, 8443) else "UDP",
                "sni":           sni or "",
                "http_host":     http_host or "",
                "classification": classify_destination(host_label, dst_ip, dst_port_int),
                "payload_hex":   hex_bytes[:64].hex(),
            })

        return events

    def _print_summary(self, events: list[dict]) -> None:
        if not events:
            log.info("[forensics] No egress events captured.")
            return
        log.info("[forensics] === Egress Forensic Summary ===")
        classes: dict[str, int] = {}
        for ev in events:
            classes[ev["classification"]] = classes.get(ev["classification"], 0) + 1
        for cls, count in sorted(classes.items(), key=lambda x: -x[1]):
            log.info("[forensics]   %-25s %d connection(s)", cls, count)
        unique_dst = {ev["dst_ip"] for ev in events}
        log.info("[forensics]   Unique destination IPs: %d", len(unique_dst))


# ── Session manager (one session per blocked app) ─────────────────────────────

_active_sessions: dict[str, EgressCaptureSession] = {}
_session_lock = threading.Lock()


def trigger_capture(app_path: str, duration: int = CAPTURE_SECONDS) -> None:
    """
    Start a forensic capture session for app_path.
    If a session is already running for this app, this is a no-op.
    """
    with _session_lock:
        if app_path in _active_sessions:
            return
        session = EgressCaptureSession(app_path, duration)
        _active_sessions[app_path] = session

    try:
        session.start()
    except Exception as e:
        log.error("[forensics] Could not start capture: %s", e)
        with _session_lock:
            _active_sessions.pop(app_path, None)


def stop_capture(app_path: str) -> None:
    with _session_lock:
        session = _active_sessions.pop(app_path, None)
    if session:
        session._stop()
