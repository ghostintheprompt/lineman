"""
process_lineage.py — XPC & Child Process Lineage Engine (v2.0)
==============================================================
On macOS, blocking a single PID is almost always insufficient.

Elevation v2.0 (The Python Maximalist):
  This version replaces polling with real-time OpenBSM event parsing via
  bsm_monitor.py. This allows the daemon to react INSTANTLY to new process
  starts, even if they terminate within milliseconds.

Detection strategy (layered):
  1. Real-time OpenBSM (BSM) — execve() events from /dev/auditpipe
  2. Bundle-path correlation  — argv starts with the app bundle path
  3. XPCServices helpers      — declared service bundle IDs found in running procs
  4. PPID tree expansion      — descendants of any PID matched by 1 or 2
  5. LaunchAgent correlation  — registered agents referencing the bundle
"""

import os
import re
import plistlib
import subprocess
import threading
import time
import logging
from pathlib import Path
from typing import Callable, Optional

try:
    from . import bsm_monitor
except ImportError:
    import bsm_monitor

log = logging.getLogger(__name__)

POLL_INTERVAL = 2.0  # seconds between PID sweeps (v1.5 fallback)


# ── Process table snapshot ────────────────────────────────────────────────────

class ProcessInfo:
    __slots__ = ("pid", "ppid", "uid", "comm", "args")

    def __init__(self, pid, ppid, uid, comm, args):
        self.pid  = int(pid)
        self.ppid = int(ppid)
        self.uid  = int(uid)
        self.comm = comm      # short name (ps comm column)
        self.args = args      # full argv[0...] string

    def __repr__(self):
        return f"<Proc pid={self.pid} comm={self.comm!r}>"


def snapshot_processes() -> list[ProcessInfo]:
    """
    Return all running processes as ProcessInfo objects.
    Uses BSD ps — no /proc on macOS.
    """
    try:
        out = subprocess.check_output(
            ["ps", "-axo", "pid=,ppid=,uid=,comm=,args="],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return []

    procs = []
    for line in out.splitlines():
        # Format: "  pid ppid uid comm  args..."
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        try:
            procs.append(ProcessInfo(*parts[:5]))
        except (ValueError, IndexError):
            continue
    return procs


def _build_child_map(procs: list[ProcessInfo]) -> dict[int, list[ProcessInfo]]:
    mapping: dict[int, list[ProcessInfo]] = {}
    for p in procs:
        mapping.setdefault(p.ppid, []).append(p)
    return mapping


# ── Lineage detection ─────────────────────────────────────────────────────────

def get_process_tree(root_pid: int, procs: list[ProcessInfo] = None) -> list[ProcessInfo]:
    """
    BFS from root_pid through the PPID tree.
    Returns the root process + all descendants.
    """
    if procs is None:
        procs = snapshot_processes()

    pid_map  = {p.pid: p for p in procs}
    child_map = _build_child_map(procs)

    result: list[ProcessInfo] = []
    queue   = [root_pid]
    visited = set()

    while queue:
        pid = queue.pop(0)
        if pid in visited:
            continue
        visited.add(pid)
        if pid in pid_map:
            result.append(pid_map[pid])
        for child in child_map.get(pid, []):
            queue.append(child.pid)

    return result


def find_app_processes(app_bundle_path: str) -> list[ProcessInfo]:
    """
    Return every running process that is part of the given .app bundle.
    """
    procs  = snapshot_processes()
    bundle = app_bundle_path.rstrip("/")

    matched_pids: set[int] = set()

    # ── Strategy 1: bundle path in argv ──────────────────────────────────────
    for p in procs:
        if bundle in p.args:
            matched_pids.add(p.pid)

    # ── Strategy 2: XPCServices declared in the bundle ───────────────────────
    xpc_bundle_ids = _enumerate_xpc_bundle_ids(bundle)
    for p in procs:
        for xpc_id in xpc_bundle_ids:
            if xpc_id in p.args:
                matched_pids.add(p.pid)
                break

    # ── Strategy 3: expand each seed PID into its PPID subtree ───────────────
    all_related: set[int] = set()
    for seed_pid in list(matched_pids):
        for p in get_process_tree(seed_pid, procs):
            all_related.add(p.pid)

    # ── Strategy 4: LaunchAgent correlation ──────────────────────────────────
    la_info = _find_launch_agents(bundle, procs)
    for info in la_info:
        all_related.update(info['pids'])

    pid_map = {p.pid: p for p in procs}
    return [pid_map[pid] for pid in all_related if pid in pid_map]


def _enumerate_xpc_bundle_ids(bundle_path: str) -> list[str]:
    """
    Read Contents/XPCServices/*.xpc/Contents/Info.plist files and return
    their CFBundleIdentifier values.
    """
    xpc_dir = Path(bundle_path) / "Contents" / "XPCServices"
    ids = []
    if not xpc_dir.is_dir():
        return ids
    for xpc_bundle in xpc_dir.iterdir():
        plist_path = xpc_bundle / "Contents" / "Info.plist"
        if plist_path.exists():
            try:
                with open(plist_path, "rb") as f:
                    data = plistlib.load(f)
                bid = data.get("CFBundleIdentifier")
                if bid:
                    ids.append(bid)
                    log.debug("XPCService: %s → %s", xpc_bundle.name, bid)
            except Exception:
                pass
    return ids


def _find_launch_agents(bundle_path: str, procs: list[ProcessInfo]) -> list[dict]:
    agents = []
    agent_dirs = [
        Path.home() / "Library" / "LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
    ]
    for d in agent_dirs:
        if not d.is_dir():
            continue
        for plist_file in d.glob("*.plist"):
            try:
                with open(plist_file, "rb") as f:
                    data = plistlib.load(f)
                program  = data.get("Program", "")
                prog_args = data.get("ProgramArguments", [])
                label     = data.get("Label", "")
                all_refs  = " ".join([program] + [str(a) for a in prog_args])
                if bundle_path in all_refs:
                    matched_pids = set()
                    # Match label against process args
                    for p in procs:
                        if label in p.args or (program and program in p.args):
                            matched_pids.add(p.pid)
                    
                    agents.append({
                        "plist_path": str(plist_file),
                        "label":      label,
                        "pids":       list(matched_pids),
                        "soc_alert":  "INC-PERSIST-01"
                    })
                    log.info("[persistence] Detected LaunchAgent: %s (%s)", label, plist_file.name)
            except Exception:
                pass
    return agents


# ── PID lifecycle monitor (The Python Maximalist v2.0) ─────────────────────────

class PIDLifecycleMonitor(threading.Thread):
    """
    v2.0 Orchestrator: Combines BSMMonitor (events) and Polling (fallback).
    
    When an app is blocked, we track its bundle path via OpenBSM.
    Any new process starting within that path triggers an immediate block.
    The legacy sweep still runs every POLL_INTERVAL as a safety mechanism.
    """

    def __init__(
        self,
        on_new_pids: Callable[[str, list[ProcessInfo]], None],
        on_app_quit: Optional[Callable[[str], None]] = None,
    ):
        super().__init__(daemon=True, name="PIDLifecycleMonitor")
        self._tracked: dict[str, set[int]] = {}  # app_path → set of known PIDs
        self._lock    = threading.Lock()
        self._running = True
        self.on_new_pids = on_new_pids
        self.on_app_quit = on_app_quit
        
        # v2.0: Event-driven monitor
        self._bsm = bsm_monitor.BSMMonitor(on_exec=self._on_bsm_exec)
        self._bsm.start()

    def _on_bsm_exec(self, pid: int, ppid: int, path: str):
        """Callback from BSMMonitor."""
        with self._lock:
            for app_path in self._tracked.keys():
                if path.startswith(app_path):
                    # Identified a new process for a blocked app!
                    # Fetch ProcessInfo (need args/comm)
                    try:
                        out = subprocess.check_output(
                            ["ps", "-p", str(pid), "-o", "pid=,ppid=,uid=,comm=,args="],
                            text=True, stderr=subprocess.DEVNULL
                        )
                        parts = out.split(None, 4)
                        if len(parts) >= 5:
                            new_proc = ProcessInfo(*parts[:5])
                            if pid not in self._tracked[app_path]:
                                log.info("[lifecycle-v2] Instant detection of %s (PID %d)", path, pid)
                                self._tracked[app_path].add(pid)
                                self.on_new_pids(app_path, [new_proc])
                    except Exception:
                        pass
                    break

    def track(self, app_path: str, initial_pids: list[int]) -> None:
        with self._lock:
            app_path = app_path.rstrip("/")
            self._tracked[app_path] = set(initial_pids)
            self._bsm.track_path(app_path)

    def untrack(self, app_path: str) -> None:
        with self._lock:
            app_path = app_path.rstrip("/")
            self._tracked.pop(app_path, None)
            self._bsm.untrack_path(app_path)

    def run(self) -> None:
        while self._running:
            time.sleep(POLL_INTERVAL)
            self._sweep()

    def stop(self) -> None:
        self._running = False
        self._bsm.stop()

    def _sweep(self) -> None:
        with self._lock:
            tracked = dict(self._tracked)

        for app_path, known_pids in tracked.items():
            current_procs = find_app_processes(app_path)
            current_pids  = {p.pid for p in current_procs}

            new_pids = current_pids - known_pids
            if new_pids:
                new_procs = [p for p in current_procs if p.pid in new_pids]
                log.info(
                    "[lifecycle-fallback] %s: %d new PID(s) detected",
                    os.path.basename(app_path), len(new_pids),
                )
                try:
                    self.on_new_pids(app_path, new_procs)
                except Exception as e:
                    log.error("on_new_pids callback error: %s", e)

                with self._lock:
                    if app_path in self._tracked:
                        self._tracked[app_path].update(current_pids)

            elif not current_pids and known_pids:
                log.info("[lifecycle] %s: all PIDs gone (app quit)", os.path.basename(app_path))
                if self.on_app_quit:
                    try:
                        self.on_app_quit(app_path)
                    except Exception as e:
                        log.error("on_app_quit callback error: %s", e)
                with self._lock:
                    if app_path in self._tracked:
                        self._tracked[app_path] = set()


# ── Convenience ───────────────────────────────────────────────────────────────

def get_active_connections(pids: list[int]) -> list[dict]:
    """
    Use lsof to list active INET connections for a set of PIDs.
    Returns list of dicts with pid, proto, local_addr, remote_addr, state.
    """
    if not pids:
        return []
    pid_args = [str(p) for p in pids]
    try:
        out = subprocess.check_output(
            ["lsof", "-nP", "-iTCP", "-iUDP", "-p", ",".join(pid_args)],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return []

    connections = []
    for line in out.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 9:
            continue
        # lsof format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        #   NAME for network: local->remote (STATE)
        name = parts[-1]
        state = ""
        if "(" in name:
            state = name[name.rfind("(") + 1 : name.rfind(")")]
            name  = name[: name.rfind("(")].strip()

        addrs = name.split("->")
        connections.append({
            "pid":         int(parts[1]),
            "proto":       parts[7],
            "local_addr":  addrs[0] if addrs else "",
            "remote_addr": addrs[1] if len(addrs) > 1 else "",
            "state":       state,
        })
    return connections
