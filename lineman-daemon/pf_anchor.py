"""
pf_anchor.py — Isolated pf Anchor Management
=============================================
Creates and manages a dedicated pf anchor (com.lineman.blocker) so Lineman
never touches the system's main firewall ruleset.

Architecture:
  /etc/pf.conf           — system ruleset; we append ONE anchor reference
  /etc/pf.anchors/com.lineman.blocker
                         — our ruleset; contains a persistent table of blocked IPs
                           and two block rules (TCP + UDP outbound, with logging)
  pflog0                 — kernel logging interface; our dropped packets land here
                           for egress_forensics.py to consume

Why a dedicated anchor?
  • Non-destructive: `pfctl -a com.lineman.blocker -F all` wipes only our rules
  • Dynamic: IPs can be added/removed from the table without touching pf.conf
  • Auditable: `pfctl -a com.lineman.blocker -s rules` shows exactly what we own
"""

import os
import re
import subprocess
import logging

log = logging.getLogger(__name__)

ANCHOR_NAME   = "com.lineman.blocker"
TABLE_NAME    = "lineman_blocked"
ANCHOR_FILE   = f"/etc/pf.anchors/{ANCHOR_NAME}"
PF_CONF       = "/etc/pf.conf"

# The anchor ruleset loaded into /etc/pf.anchors/com.lineman.blocker
ANCHOR_RULES = f"""\
# Lineman HIPS — managed by lineman-daemon. DO NOT EDIT MANUALLY.
# Flush and reload via: pfctl -a {ANCHOR_NAME} -f {ANCHOR_FILE}

table <{TABLE_NAME}> persist {{}}

# Drop and log outbound TCP/UDP to any IP in the blocked table.
# Logged packets appear on pflog0 and are consumed by egress_forensics.py.
block drop out log quick proto tcp from any to <{TABLE_NAME}>
block drop out log quick proto udp from any to <{TABLE_NAME}>
"""

# Lines injected into /etc/pf.conf
ANCHOR_REF_LINES = [
    f'anchor "{ANCHOR_NAME}"',
    f'load anchor "{ANCHOR_NAME}" from "{ANCHOR_FILE}"',
]


# ── Low-level pfctl wrappers ──────────────────────────────────────────────────

def _pfctl(*args, input_text: str = None) -> str:
    """Run pfctl, return stdout. Raises on non-zero exit."""
    cmd = ["pfctl"] + list(args)
    result = subprocess.run(
        cmd,
        input=input_text,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"pfctl {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


# ── Anchor lifecycle ──────────────────────────────────────────────────────────

def install_anchor() -> None:
    """
    One-time setup: write the anchor file and inject the anchor reference into
    /etc/pf.conf if it isn't already there. Reloads pf to activate.
    """
    # Write anchor rules
    with open(ANCHOR_FILE, "w") as f:
        f.write(ANCHOR_RULES)
    log.info("Anchor file written: %s", ANCHOR_FILE)

    # Patch pf.conf — only if not already present
    with open(PF_CONF, "r") as f:
        conf = f.read()

    lines_to_add = [l for l in ANCHOR_REF_LINES if l not in conf]
    if lines_to_add:
        with open(PF_CONF, "a") as f:
            f.write("\n# --- Lineman HIPS anchor (managed) ---\n")
            for line in lines_to_add:
                f.write(line + "\n")
        log.info("Patched %s with anchor reference.", PF_CONF)

    reload_system_pf()


def uninstall_anchor() -> None:
    """Remove our lines from pf.conf, delete the anchor file, flush rules."""
    flush_anchor()

    if os.path.exists(ANCHOR_FILE):
        os.remove(ANCHOR_FILE)
        log.info("Removed anchor file: %s", ANCHOR_FILE)

    with open(PF_CONF, "r") as f:
        lines = f.readlines()

    cleaned = [
        l for l in lines
        if ANCHOR_NAME not in l and "Lineman HIPS anchor" not in l
    ]
    with open(PF_CONF, "w") as f:
        f.writelines(cleaned)

    reload_system_pf()
    log.info("Anchor uninstalled.")


def reload_anchor() -> None:
    """Flush and reload only our anchor — leaves every other pf rule untouched."""
    _pfctl("-a", ANCHOR_NAME, "-f", ANCHOR_FILE)
    log.debug("Anchor reloaded.")


def flush_anchor() -> None:
    """Remove all rules and table entries from our anchor."""
    try:
        _pfctl("-a", ANCHOR_NAME, "-F", "all")
        log.info("Anchor flushed.")
    except RuntimeError as e:
        log.warning("Flush anchor: %s", e)


def reload_system_pf() -> None:
    """Reload the full pf ruleset from pf.conf (required after patching it)."""
    _pfctl("-f", PF_CONF)
    log.info("System pf reloaded.")


def is_anchor_active() -> bool:
    """Return True if our anchor is currently loaded in pf."""
    try:
        out = _pfctl("-s", "Anchors")
        return ANCHOR_NAME in out
    except RuntimeError:
        return False


# ── Per-IP table management ───────────────────────────────────────────────────

def block_ip(ip: str) -> None:
    """Add a single IP to the blocked table. Instant — no pf reload required."""
    _pfctl("-a", ANCHOR_NAME, "-t", TABLE_NAME, "-T", "add", ip)
    log.info("Blocked IP: %s", ip)


def unblock_ip(ip: str) -> None:
    """Remove a single IP from the blocked table."""
    try:
        _pfctl("-a", ANCHOR_NAME, "-t", TABLE_NAME, "-T", "delete", ip)
        log.info("Unblocked IP: %s", ip)
    except RuntimeError:
        pass


def flush_blocked_ips() -> None:
    """Clear every IP from the blocked table (keeps rules intact)."""
    try:
        _pfctl("-a", ANCHOR_NAME, "-t", TABLE_NAME, "-T", "flush")
        log.info("Flushed all blocked IPs.")
    except RuntimeError:
        pass


def list_blocked_ips() -> list[str]:
    """Return all IPs currently in the blocked table."""
    try:
        out = _pfctl("-a", ANCHOR_NAME, "-t", TABLE_NAME, "-T", "show")
        return [line.strip() for line in out.splitlines() if line.strip()]
    except RuntimeError:
        return []


def enable_pf() -> None:
    """Enable pf if it isn't running."""
    result = subprocess.run(["pfctl", "-s", "info"], capture_output=True, text=True)
    if "Enabled" not in result.stdout:
        _pfctl("-e")
        log.info("pf enabled.")
