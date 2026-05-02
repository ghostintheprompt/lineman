"""
egress_forensics.py — Egress Forensic Capture Engine (v2.0)
==========================================================
Elevation v2.0 (The Python Maximalist):
  In addition to raw TLS SNI extraction, this version integrates with the
  DNSCorrelator to resolve destination hostnames via recent DNS activity.
  This allows Lineman to bypass the "ECH blindspot" where SNI fields are
  encrypted in TLS 1.3.

  Integrity Upgrade: Every report is now cryptographically signed with an
  Ed25519 private key stored in a root-only directory.

Forensic report structure (forensics/<timestamp>_<app_name>.json):
  {
    "schema": "lineman-egress-v2",
    "app": "Spotify",
    "signature": "...",          ← NEW in Phase 3: Ed25519 asymmetric signature
    "events": [...]
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

try:
    from . import dns_correlator
    from . import integrity_signer
except ImportError:
    import dns_correlator
    import integrity_signer

log = logging.getLogger(__name__)

FORENSICS_DIR   = Path(__file__).parent.parent / "forensics"
CAPTURE_SECONDS = 30           # default capture window per trigger
PFLOG_IFACE     = "pflog0"

# ── Destination classifier ────────────────────────────────────────────────────

# SOC Alert ID mapping
_SOC_ALERTS = {
    "TELEMETRY":          "INC-EGRESS-01",
    "UPDATE_SERVER":      "INC-EGRESS-01",
    "CRASH_REPORTER":     "INC-EGRESS-01",
    "ADVERTISING":        "INC-EGRESS-01",
    "APPLE_SERVICES":     "INC-EGRESS-01",
    "ENCRYPTED_UNKNOWN":  "INC-EGRESS-01",
    "PLAINTEXT_UNKNOWN":  "INC-EGRESS-01",
    "UNKNOWN":            "INC-EGRESS-01",
}

# Patterns matched against SNI / DNS / dst IP strings.
_CLASSIFIERS = [
    (re.compile(r"apple\.com|icloud\.com|push\.apple\.com", re.I), "APPLE_SERVICES"),
    (re.compile(r"telemetry|analytics|metrics|tracker|stats\.", re.I), "TELEMETRY"),
    (re.compile(r"update|autoupdate|software-update|cdn\..*update", re.I), "UPDATE_SERVER"),
    (re.compile(r"crash|bugsplat|sentry\.io|bugsnag|crashlytics", re.I), "CRASH_REPORTER"),
    (re.compile(r"ads\.|advertising|doubleclick|googlesyndication", re.I), "ADVERTISING"),
    (re.compile(r"akamai|cloudfront|fastly|cdn\.", re.I), "CDN"),
]


def classify_destination(sni: str, dns_hint: str, dst_ip: str, dst_port: int) -> dict:
    """
    Classifies a connection and maps it to a SOC Alert ID.
    Returns: {"classification": str, "soc_alert_id": str}
    """
    # Order of precedence: SNI (payload), then DNS Hint (correlator), then IP
    target = sni or dns_hint or dst_ip
    classification = "UNKNOWN"
    
    for pattern, label in _CLASSIFIERS:
        if pattern.search(target):
            classification = label
            break
    
    if classification == "UNKNOWN":
        if dst_port == 443:
            classification = "ENCRYPTED_UNKNOWN"
        elif dst_port == 80:
            classification = "PLAINTEXT_UNKNOWN"
            
    return {
        "classification": classification,
        "soc_alert_id": _SOC_ALERTS.get(classification, "INC-EGRESS-01")
    }


# ── SNI extraction from raw TLS ClientHello ───────────────────────────────────

def extract_sni(payload: bytes) -> Optional[str]:
    """
    Parse a TLS ClientHello and extract the SNI hostname.
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
    Runs a time-bounded tcpdump on pflog0.
    """

    def __init__(self, app_path: str, duration: int = CAPTURE_SECONDS):
        self.app_path   = app_path
        self.app_name   = Path(app_path).stem
        self.duration   = duration
        self._proc: Optional[subprocess.Popen] = None
        self._pcap_path: Optional[Path]        = None
        self._dns      = dns_correlator.get_instance()
        self._signer   = integrity_signer.get_instance()

    def _pcap_file(self) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        FORENSICS_DIR.mkdir(parents=True, exist_ok=True)
        return FORENSICS_DIR / f"{ts}_{self.app_name}.pcap"

    def start(self) -> None:
        self._pcap_path = self._pcap_file()
        cmd = [
            "tcpdump",
            "-i", PFLOG_IFACE,
            "-n", "-s", "256",
            "-w", str(self._pcap_path),
        ]
        log.info("[forensics-v2] Starting %ds capture → %s", self.duration, self._pcap_path)
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
            log.info("[forensics-v2] Capture stopped.")
        self._parse_and_report()

    def _parse_and_report(self) -> Optional[Path]:
        if not self._pcap_path or not self._pcap_path.exists():
            return None

        events = self._parse_pcap(self._pcap_path)

        report = {
            "schema":        "lineman-egress-v2",
            "app":           self.app_name,
            "app_path":      self.app_path,
            "capture_start": datetime.now(timezone.utc).isoformat(),
            "capture_end":   datetime.now(timezone.utc).isoformat(),
            "pcap_file":     str(self._pcap_path),
            "events":        events,
            "event_count":   len(events),
        }

        # Sign the canonical body
        body = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
        report["signature"] = self._signer.sign_payload(body)
        
        # Legacy compat
        report["sha256"] = hashlib.sha256(body).hexdigest()

        out_path = self._pcap_path.with_suffix(".json")
        out_path.write_text(json.dumps(report, indent=2))
        log.info("[forensics-v2] Signed report saved: %s (%d events)", out_path, len(events))

        self._print_summary(events)
        return out_path

    def _parse_pcap(self, pcap_path: Path) -> list[dict]:
        events = []
        try:
            out = subprocess.check_output(
                ["tcpdump", "-r", str(pcap_path), "-n", "-x", "-v"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            return events

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
            dns_hint  = self._dns.get_hostname(dst_ip)
            
            # v2.0 Enrichment
            analysis = classify_destination(sni or http_host or "", dns_hint or "", dst_ip, dst_port_int)

            events.append({
                "timestamp":      ts_str,
                "src_ip":         src_ip,
                "src_port":       int(src_port),
                "dst_ip":         dst_ip,
                "dst_port":       dst_port_int,
                "protocol":       "TCP" if dst_port_int in (80, 443, 8080, 8443) else "UDP",
                "sni":            sni or "",
                "dns_hint":       dns_hint or "",
                "classification": analysis["classification"],
                "soc_alert_id":   analysis["soc_alert_id"],
                "payload_hex":    hex_bytes[:64].hex(),
            })

        return events

    def _print_summary(self, events: list[dict]) -> None:
        if not events:
            log.info("[forensics] No egress events captured.")
            return
        log.info("[forensics-v2] === Egress Forensic Summary ===")
        classes: dict[str, int] = {}
        for ev in events:
            classes[ev["classification"]] = classes.get(ev["classification"], 0) + 1
        for cls, count in sorted(classes.items(), key=lambda x: -x[1]):
            log.info("[forensics-v2]   %-25s %d connection(s)", cls, count)


# ── Session manager (one session per blocked app) ─────────────────────────────

_active_sessions: dict[str, EgressCaptureSession] = {}
_session_lock = threading.Lock()


def trigger_capture(app_path: str, duration: int = CAPTURE_SECONDS) -> None:
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
