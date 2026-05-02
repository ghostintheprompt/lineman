"""
bsm_monitor.py — Real-time Process Event Monitor (OpenBSM)
==========================================================
Uses /dev/auditpipe to receive real-time notifications of execve() syscalls.
This provides zero-delay detection of child processes and XPC helpers without
polling the process table.

Technical Details:
  - OpenBSM (Basic Security Module) is the native macOS auditing subsystem.
  - /dev/auditpipe is a cloning device that provides a stream of audit records.
  - We filter for 'ex' (execve) events to catch new process starts.
  - This requires root privileges to read /dev/auditpipe.

Note: This is a 2026/2027 elevation to replace polling-based monitors.
"""

import os
import struct
import threading
import logging
import subprocess
import time
from typing import Callable, Set

log = logging.getLogger(__name__)

AUDITPIPE = "/dev/auditpipe"

# ── BSM Token Constants ───────────────────────────────────────────────────────
# Reference: /usr/include/bsm/libbsm.h and audit_record(8)
AUT_HEADER32 = 0x14  # 32-bit header
AUT_HEADER64 = 0x71  # 64-bit header
AUT_PATH     = 0x2b  # Path token
AUT_ARG32    = 0x24  # 32-bit argument
AUT_ARG64    = 0x77  # 64-bit argument
AUT_SUBJECT32 = 0x26 # Subject token
AUT_SUBJECT64 = 0x7a # Subject token (64-bit)
AUT_RETURN32 = 0x27  # Return token
AUT_RETURN64 = 0x7b  # Return token (64-bit)

# Event IDs (from /etc/security/audit_event)
AUE_EXECVE   = 23    # execve(2)

class BSMMonitor(threading.Thread):
    """
    Background thread that streams records from /dev/auditpipe.
    When a new process matches a tracked bundle path, it triggers the callback.
    """

    def __init__(self, on_exec: Callable[[int, int, str], None]):
        super().__init__(daemon=True, name="BSMMonitor")
        self._on_exec = on_exec
        self._running = True
        self._tracked_paths: Set[str] = set()
        self._lock = threading.Lock()

    def track_path(self, path: str):
        with self._lock:
            self._tracked_paths.add(path.rstrip("/"))

    def untrack_path(self, path: str):
        with self._lock:
            self._tracked_paths.discard(path.rstrip("/"))

    def stop(self):
        self._running = False

    def run(self):
        log.info("[bsm] Starting OpenBSM monitor on %s", AUDITPIPE)
        
        # Configure auditpipe to only show execve events
        # This is done via ioctl, but for a Python implementation, 
        # we can also filter in-process or use 'praudit'.
        # To keep it "Python Maximalist" and robust, we'll use a subprocess
        # of 'praudit -l' which parses the binary BSM stream into line-delimited text.
        
        try:
            # praudit -l: raw line-delimited format
            # praudit -r: short (numeric) format
            # We filter for AUE_EXECVE (23) records
            cmd = ["praudit", "-l", AUDITPIPE]
            self._proc = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            while self._running and self._proc.poll() is None:
                line = self._proc.stdout.readline()
                if not line:
                    break
                
                # Format of praudit -l for execve:
                # header,149,11,execve(2),0,Mon Apr 20 20:15:01 2026, + 65 msec
                # path,/usr/bin/python3
                # attribute,100755,root,wheel,1,16777234,0
                # subject,root,root,wheel,root,wheel,43015,43015,0,0.0.0.0
                # return,success,0
                
                if "execve(2)" in line:
                    self._handle_record(line)
                    
        except Exception as e:
            log.error("[bsm] Monitor failure: %s", e)
        finally:
            log.info("[bsm] Monitor stopped.")

    def _handle_record(self, record: str):
        """
        Parses a single line-delimited BSM record from praudit.
        Example record segments: header,... path,... subject,... return,...
        """
        try:
            # Basic parsing of the praudit comma-separated record
            parts = record.split(",")
            
            # Find path and subject (PID)
            path = ""
            pid = -1
            ppid = -1 # Not always in subject token, might need ps lookup
            
            for i, part in enumerate(parts):
                if part == "path" and i + 1 < len(parts):
                    path = parts[i+1].strip()
                elif part == "subject" and i + 6 < len(parts):
                    # subject tokens vary by OS version, but usually:
                    # user, ruid, rgid, euid, egid, pid, session, terminal_id, machine_id
                    pid = int(parts[i+6])
            
            if pid != -1 and path:
                self._check_and_trigger(pid, path)
                
        except Exception as e:
            log.debug("[bsm] Parse error: %s", e)

    def _check_and_trigger(self, pid: int, path: str):
        with self._lock:
            for tracked in self._tracked_paths:
                if path.startswith(tracked):
                    log.info("[bsm] Event-Driven match: PID %d starting %s", pid, path)
                    # Use a thread to avoid blocking the monitor loop
                    threading.Thread(target=self._on_exec, args=(pid, -1, path), daemon=True).start()
                    break

# ── Manual Configuration ──────────────────────────────────────────────────────

def configure_audit():
    """
    Ensure the system is configured to capture exec events.
    Usually requires 'ex' in /etc/security/audit_control flags.
    """
    # On many macOS systems, audit is enabled by default.
    # We can check with 'audit -s'.
    try:
        subprocess.run(["audit", "-s"], capture_output=True, check=True)
    except Exception:
        log.warning("[bsm] Could not signal audit daemon. Events might be missing.")
