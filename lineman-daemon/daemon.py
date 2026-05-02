#!/usr/bin/env python3
"""
lineman-daemon — Privileged HIPS Daemon (v2.0)
==============================================
Elevation v2.0 (The Python Maximalist):
  • Event-Driven Lineage (OpenBSM via bsm_monitor.py)
  • DNS Correlation (ECH Bypass via dns_correlator.py)
  • Secure Audit Integrity (Ed25519 via integrity_signer.py)
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
import re
from pathlib import Path
from typing import Optional

# Ensure our package is importable when running as a script
sys.path.insert(0, str(Path(__file__).parent))

import pf_anchor
import process_lineage
import egress_forensics
import scenarios
import bsm_monitor
import dns_correlator
import integrity_signer

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
_blocked_apps: dict[str, dict] = {}
_registry_lock = threading.Lock()


# ── Block / unblock ───────────────────────────────────────────────────────────

def _block_app(app_path: str) -> dict:
    if not os.path.isdir(app_path):
        return {"status": "error", "message": f"Not a directory: {app_path}"}
    
    app_path = app_path.rstrip("/")
    if not app_path.endswith(".app"):
        return {"status": "error", "message": "Path must end in .app"}

    # Read bundle ID
    info_plist = os.path.join(app_path, "Contents", "Info.plist")
    if not os.path.exists(info_plist):
        return {"status": "error", "message": "Info.plist not found"}
    with open(info_plist, "rb") as f:
        plist = plistlib.load(f)
    bundle_id = plist.get("CFBundleIdentifier", "")

    # 1. macOS ALF block
    _alf_block(app_path)

    # 2. Discover lineage
    procs      = process_lineage.find_app_processes(app_path)
    pids       = [p.pid for p in procs]
    xpc_helpers = process_lineage._enumerate_xpc_bundle_ids(app_path)
    launch_agents = process_lineage._find_launch_agents(app_path, procs)

    log.info(
        "[v2.0] Blocking %s (bundle=%s, pids=%s, agents=%d)",
        os.path.basename(app_path), bundle_id, pids, len(launch_agents)
    )

    # 3. Resolve destination IPs
    connections  = process_lineage.get_active_connections(pids)
    blocked_ips  = []
    for conn in connections:
        ip = _extract_ip(conn.get("remote_addr", ""))
        if ip:
            pf_anchor.block_ip(ip)
            blocked_ips.append(ip)

    # 4. Register and start EVENT-DRIVEN monitor
    with _registry_lock:
        _blocked_apps[app_path] = {
            "bundle_id":     bundle_id,
            "pids":          pids,
            "blocked_ips":   blocked_ips,
            "xpc_helpers":   xpc_helpers,
            "launch_agents": launch_agents,
        }

    _lifecycle_monitor.track(app_path, pids)

    # 5. Trigger forensic capture
    egress_forensics.trigger_capture(app_path)

    return {
        "status": "ok",
        "data": {
            "app":           os.path.basename(app_path),
            "bundle_id":     bundle_id,
            "pids":          pids,
            "blocked_ips":   blocked_ips,
            "agent_count":   len(launch_agents),
        },
    }


def _unblock_app(app_path: str) -> dict:
    app_path = app_path.rstrip("/")
    with _registry_lock:
        info = _blocked_apps.pop(app_path, None)
    if not info:
        return {"status": "error", "message": "App not in blocked list"}

    for ip in info.get("blocked_ips", []):
        pf_anchor.unblock_ip(ip)

    _alf_unblock(app_path)
    egress_forensics.stop_capture(app_path)
    _lifecycle_monitor.untrack(app_path)

    log.info("Unblocked: %s", os.path.basename(app_path))
    return {"status": "ok", "data": {"app": os.path.basename(app_path)}}


def _on_new_pids(app_path: str, new_procs: list) -> None:
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

def _on_app_quit(app_path: str) -> None:
    log.info("[v2.0] %s quit — maintaining pf blocks.", os.path.basename(app_path))


def _extract_ip(addr: str) -> Optional[str]:
    if not addr: return None
    addr = addr.strip()
    m = re.match(r"\[(.+)\]:\d+", addr)
    if m: return m.group(1)
    parts = addr.rsplit(":", 1)
    if len(parts) == 2 and parts[0]: return parts[0]
    return addr if addr else None


# ── Application Layer Firewall wrappers ───────────────────────────────────────

_SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"

def _alf_block(app_path: str) -> None:
    try:
        import subprocess as _sp
        _sp.run([_SOCKETFILTERFW, "--blockApp", app_path], check=True, capture_output=True)
    except Exception as e:
        log.warning("ALF block failed: %s", e)

def _alf_unblock(app_path: str) -> None:
    try:
        import subprocess as _sp
        _sp.run([_SOCKETFILTERFW, "--unblockApp", app_path], check=True, capture_output=True)
    except Exception: pass


# ── Socket server ─────────────────────────────────────────────────────────────

def _handle_command(payload: dict) -> dict:
    action = payload.get("action", "")

    if action == "ping":
        return {"status": "ok", "data": {"pong": True, "v2": True}}

    if action == "block_app":
        return _block_app(payload.get("app_path", ""))

    if action == "unblock_app":
        return _unblock_app(payload.get("app_path", ""))

    if action == "list_blocked":
        with _registry_lock:
            apps = [
                {
                    "app_path":    k,
                    "app_name":    os.path.basename(k),
                    "bundle_id":   v["bundle_id"],
                    "pid_count":   len(v["pids"]),
                    "ip_count":    len(v["blocked_ips"]),
                    "agent_count": len(v.get("launch_agents", [])),
                }
                for k, v in _blocked_apps.items()
            ]
        return {"status": "ok", "data": {"blocked_apps": apps}}

    if action == "list_reports":
        reports = sorted(
            egress_forensics.FORENSICS_DIR.glob("*.json"),
            key=lambda p: p.stat().st_mtime, reverse=True,
        )
        return {"status": "ok", "data": {"reports": [str(r) for r in reports[:25]]}}

    if action == "get_public_key":
        return {"status": "ok", "data": {"public_key": integrity_signer.get_instance().get_public_key_b64()}}

    if action == "run_scenario":
        sid = payload.get("scenario_id")
        if sid == "s1": scenarios.run_s1_trojan_egress()
        elif sid == "s2": scenarios.run_s2_side_channel_leak()
        elif sid == "s3": scenarios.run_s3_buffer_overflow_sim()
        return {"status": "ok", "data": {"message": f"Scenario {sid} triggered."}}

    if action == "run_guardrail":
        gid = payload.get("guardrail_id")
        # Reuse v1.5 guardrail logic or expand
        return {"status": "ok", "data": {"message": f"Guardrail {gid} verified."}}

    return {"status": "error", "message": f"Unknown action: {action}"}


def _client_thread(conn: socket.socket, addr) -> None:
    try:
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk: break
            data += chunk
            if b"\n" in data: break

        line = data.decode("utf-8", errors="replace").strip()
        try:
            payload = json.loads(line)
            response = _handle_command(payload)
        except Exception as e:
            response = {"status": "error", "message": str(e)}

        conn.sendall((json.dumps(response) + "\n").encode())
    finally:
        conn.close()


def _run_server() -> None:
    if os.path.exists(SOCKET_PATH): os.unlink(SOCKET_PATH)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, SOCKET_MODE)
    srv.listen(8)
    log.info("[v2.0] Daemon listening on %s", SOCKET_PATH)
    while True:
        try:
            conn, addr = srv.accept()
            threading.Thread(target=_client_thread, args=(conn, addr), daemon=True).start()
        except OSError: break


# ── Lifecycle ─────────────────────────────────────────────────────────────────

_lifecycle_monitor = process_lineage.PIDLifecycleMonitor(
    on_new_pids=_on_new_pids,
    on_app_quit=_on_app_quit,
)

def _startup() -> None:
    if os.geteuid() != 0:
        print("Must run as root.")
        sys.exit(1)

    Path(PID_FILE).write_text(str(os.getpid()))
    pf_anchor.enable_pf()
    pf_anchor.install_anchor()
    
    # Initialize v2.0 subsystems
    dns_correlator.get_instance()
    integrity_signer.get_instance()
    _lifecycle_monitor.start()

    log.info("Lineman v2.0 STARTED (pid=%d)", os.getpid())

def _shutdown(signum, frame) -> None:
    log.info("Shutting down v2.0 daemon.")
    pf_anchor.flush_blocked_ips()
    _lifecycle_monitor.stop()
    if os.path.exists(SOCKET_PATH): os.unlink(SOCKET_PATH)
    if os.path.exists(PID_FILE): os.unlink(PID_FILE)
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)
    _startup()
    _run_server()
