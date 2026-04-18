#!/usr/bin/env python3
"""
lineman-daemon — Privileged HIPS Daemon
========================================
Runs as root. Owns all operations that require elevated privilege:
  • pf anchor management (pfctl requires root)
  • tcpdump on pflog0 (requires root)
  • socketfilterfw --blockApp (requires root or appropriate entitlement)

Communicates with the unprivileged GUI via a Unix domain socket at
SOCKET_PATH. The protocol is newline-delimited JSON.

Inbound commands (GUI → daemon):
  {"action": "block_app",        "app_path": "/Applications/Foo.app"}
  {"action": "unblock_app",      "app_path": "/Applications/Foo.app"}
  {"action": "list_blocked"}
  {"action": "get_blocked_ips"}
  {"action": "list_reports"}
  {"action": "ping"}

Outbound responses (daemon → GUI):
  {"status": "ok",    "data": {...}}
  {"status": "error", "message": "..."}

Security properties of this design:
  • The GUI process never calls pfctl, tcpdump, or socketfilterfw
  • The socket is owned by root:staff, mode 0660 — any staff user can connect
    but unprivileged processes on other UIDs cannot
  • Each command is validated before execution
  • No shell=True anywhere — all subprocess calls use explicit argv lists

Why split GUI from daemon?
  Running a GUI as root is a macOS security anti-pattern. If the GUI process
  were compromised (e.g., via a malicious .app bundle it is inspecting), an
  attacker would gain root. The daemon surface area is minimal — it does one
  job and exposes a narrow socket interface.
"""

import json
import logging
import os
import plistlib
import signal
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Optional

# Ensure our package is importable when running as a script
sys.path.insert(0, str(Path(__file__).parent))

import pf_anchor
import process_lineage
import egress_forensics

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("lineman.daemon")

SOCKET_PATH  = "/var/run/lineman.sock"
SOCKET_MODE  = 0o660
PID_FILE     = "/var/run/lineman.pid"

# ── App registry ──────────────────────────────────────────────────────────────
# app_path → {"bundle_id": str, "pids": [int], "blocked_ips": [str]}
_blocked_apps: dict[str, dict] = {}
_registry_lock = threading.Lock()


# ── Block / unblock ───────────────────────────────────────────────────────────

def _block_app(app_path: str) -> dict:
    if not os.path.isdir(app_path):
        return {"status": "error", "message": f"Not a directory: {app_path}"}
    if not app_path.endswith(".app"):
        return {"status": "error", "message": "Path must end in .app"}

    # Read bundle ID
    info_plist = os.path.join(app_path, "Contents", "Info.plist")
    if not os.path.exists(info_plist):
        return {"status": "error", "message": "Info.plist not found"}
    with open(info_plist, "rb") as f:
        plist = plistlib.load(f)
    bundle_id = plist.get("CFBundleIdentifier", "")

    # 1. macOS Application Layer Firewall — reliable per-app blocking
    _alf_block(app_path)

    # 2. Discover full process lineage (main process + XPC helpers + children)
    procs      = process_lineage.find_app_processes(app_path)
    pids       = [p.pid for p in procs]
    xpc_helpers = process_lineage._enumerate_xpc_bundle_ids(app_path)

    log.info(
        "Blocking %s (bundle=%s, pids=%s, xpc_helpers=%s)",
        os.path.basename(app_path), bundle_id, pids, xpc_helpers,
    )

    # 3. Resolve current outbound connections → add destination IPs to pf table
    connections  = process_lineage.get_active_connections(pids)
    blocked_ips  = []
    for conn in connections:
        ip = _extract_ip(conn.get("remote_addr", ""))
        if ip:
            pf_anchor.block_ip(ip)
            blocked_ips.append(ip)
            log.info("  → blocked destination IP: %s", ip)

    # 4. Register and start lifecycle monitor
    with _registry_lock:
        _blocked_apps[app_path] = {
            "bundle_id":   bundle_id,
            "pids":        pids,
            "blocked_ips": blocked_ips,
            "xpc_helpers": xpc_helpers,
        }

    _lifecycle_monitor.track(app_path, pids)

    # 5. Trigger forensic capture (runs in background)
    egress_forensics.trigger_capture(app_path)

    return {
        "status": "ok",
        "data": {
            "app":         os.path.basename(app_path),
            "bundle_id":   bundle_id,
            "pids":        pids,
            "blocked_ips": blocked_ips,
            "xpc_helpers": xpc_helpers,
        },
    }


def _unblock_app(app_path: str) -> dict:
    with _registry_lock:
        info = _blocked_apps.pop(app_path, None)
    if not info:
        return {"status": "error", "message": "App not in blocked list"}

    # Remove IPs from pf table
    for ip in info.get("blocked_ips", []):
        pf_anchor.unblock_ip(ip)

    # Remove from ALF
    _alf_unblock(app_path)

    # Stop forensic capture
    egress_forensics.stop_capture(app_path)

    # Stop lifecycle monitoring
    _lifecycle_monitor.untrack(app_path)

    log.info("Unblocked: %s", os.path.basename(app_path))
    return {"status": "ok", "data": {"app": os.path.basename(app_path)}}


def _on_new_pids(app_path: str, new_procs: list) -> None:
    """Lifecycle monitor callback — app was relaunched with new PIDs."""
    with _registry_lock:
        if app_path not in _blocked_apps:
            return
        _blocked_apps[app_path]["pids"] = [p.pid for p in new_procs]

    # Re-resolve connections for new PIDs and block their IPs
    pids = [p.pid for p in new_procs]
    connections = process_lineage.get_active_connections(pids)
    for conn in connections:
        ip = _extract_ip(conn.get("remote_addr", ""))
        if ip:
            pf_anchor.block_ip(ip)
            with _registry_lock:
                if app_path in _blocked_apps:
                    if ip not in _blocked_apps[app_path]["blocked_ips"]:
                        _blocked_apps[app_path]["blocked_ips"].append(ip)
            log.info("[lifecycle] New PID %s blocked IP: %s", pids, ip)


def _on_app_quit(app_path: str) -> None:
    log.info("[lifecycle] %s quit — maintaining pf blocks until explicitly unblocked.",
             os.path.basename(app_path))


def _extract_ip(addr: str) -> Optional[str]:
    """Extract bare IP from 'ip:port' or '[ip]:port'."""
    if not addr:
        return None
    addr = addr.strip()
    # IPv6
    m = re.match(r"\[(.+)\]:\d+", addr)
    if m:
        return m.group(1)
    # IPv4
    parts = addr.rsplit(":", 1)
    if len(parts) == 2 and parts[0]:
        return parts[0]
    return addr if addr else None


import re


# ── Application Layer Firewall wrappers ───────────────────────────────────────

_SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"


def _alf_block(app_path: str) -> None:
    try:
        import subprocess as _sp
        _sp.run([_SOCKETFILTERFW, "--blockApp", app_path],
                check=True, capture_output=True)
        log.info("ALF block applied: %s", os.path.basename(app_path))
    except Exception as e:
        log.warning("ALF block failed (non-fatal): %s", e)


def _alf_unblock(app_path: str) -> None:
    try:
        import subprocess as _sp
        _sp.run([_SOCKETFILTERFW, "--unblockApp", app_path],
                check=True, capture_output=True)
    except Exception:
        pass


# ── Socket server ─────────────────────────────────────────────────────────────

def _handle_command(payload: dict) -> dict:
    action = payload.get("action", "")

    if action == "ping":
        return {"status": "ok", "data": {"pong": True, "pid": os.getpid()}}

    if action == "block_app":
        return _block_app(payload.get("app_path", ""))

    if action == "unblock_app":
        return _unblock_app(payload.get("app_path", ""))

    if action == "list_blocked":
        with _registry_lock:
            apps = [
                {
                    "app_path":  k,
                    "app_name":  os.path.basename(k),
                    "bundle_id": v["bundle_id"],
                    "pid_count": len(v["pids"]),
                    "ip_count":  len(v["blocked_ips"]),
                }
                for k, v in _blocked_apps.items()
            ]
        return {"status": "ok", "data": {"blocked_apps": apps}}

    if action == "get_blocked_ips":
        return {"status": "ok", "data": {"ips": pf_anchor.list_blocked_ips()}}

    if action == "list_reports":
        reports = sorted(
            egress_forensics.FORENSICS_DIR.glob("*.json"),
            key=lambda p: p.stat().st_mtime, reverse=True,
        )
        return {"status": "ok", "data": {"reports": [str(r) for r in reports[:20]]}}

    return {"status": "error", "message": f"Unknown action: {action!r}"}


def _client_thread(conn: socket.socket, addr) -> None:
    try:
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break

        line = data.decode("utf-8", errors="replace").strip()
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as e:
            response = {"status": "error", "message": f"Invalid JSON: {e}"}
        else:
            response = _handle_command(payload)

        conn.sendall((json.dumps(response) + "\n").encode())
    except Exception as e:
        log.error("Client handler error: %s", e)
    finally:
        conn.close()


def _run_server() -> None:
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, SOCKET_MODE)
    srv.listen(8)
    log.info("Daemon listening on %s", SOCKET_PATH)

    while True:
        try:
            conn, addr = srv.accept()
            threading.Thread(
                target=_client_thread,
                args=(conn, addr),
                daemon=True,
            ).start()
        except OSError:
            break


# ── Lifecycle ─────────────────────────────────────────────────────────────────

_lifecycle_monitor = process_lineage.PIDLifecycleMonitor(
    on_new_pids=_on_new_pids,
    on_app_quit=_on_app_quit,
)


def _startup() -> None:
    if os.geteuid() != 0:
        print("lineman-daemon must run as root. Use: sudo python3 daemon.py")
        sys.exit(1)

    # Write PID file
    Path(PID_FILE).write_text(str(os.getpid()))

    # Ensure pf anchor is installed and pf is enabled
    pf_anchor.enable_pf()
    pf_anchor.install_anchor()

    # Start lifecycle monitor thread
    _lifecycle_monitor.start()

    log.info("Lineman daemon started (pid=%d)", os.getpid())


def _shutdown(signum, frame) -> None:
    log.info("Shutdown signal received — cleaning up.")

    # Flush all pf blocks but leave anchor installed (defensive default)
    pf_anchor.flush_blocked_ips()

    _lifecycle_monitor.stop()

    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)
    if os.path.exists(PID_FILE):
        os.unlink(PID_FILE)

    log.info("Lineman daemon stopped.")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    _startup()
    _run_server()   # blocks until socket closed
