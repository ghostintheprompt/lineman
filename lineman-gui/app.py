"""
lineman-gui — Unprivileged GUI Client (Ghost-Protocol Tier v2.0)
==============================================================
Elevation v2.0 (The Python Maximalist):
  This version adds visual verification of cryptographic signatures for
  forensic reports. It fetches the daemon's public key on startup and
  validates that every report opened has not been tampered with.

Restored Ghost-Protocol Features:
  • Event-Driven Lineage (BSM/Audit)
  • DNS Correlation (ECH Bypass)
  • Ed25519 Immutable Signing
"""

import json
import os
import socket
import threading
import tkinter as tk
import base64
from tkinter import filedialog, font, messagebox, ttk
from pathlib import Path

# v2.0: Native verification
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

SOCKET_PATH = "/var/run/lineman.sock"
DAEMON_TIMEOUT = 5.0


# ── Daemon client ──────────────────────────────────────────────────────────────

class DaemonClient:
    """
    Thin IPC client.
    """

    def send(self, payload: dict) -> dict:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(DAEMON_TIMEOUT)
            sock.connect(SOCKET_PATH)
            sock.sendall((json.dumps(payload) + "\n").encode())

            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\n" in response:
                    break
            sock.close()
            return json.loads(response.decode().strip())
        except FileNotFoundError:
            return {"status": "error", "message": "Daemon not running."}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def block_app(self, app_path: str) -> dict:
        return self.send({"action": "block_app", "app_path": app_path})

    def unblock_app(self, app_path: str) -> dict:
        return self.send({"action": "unblock_app", "app_path": app_path})

    def list_blocked(self) -> list[dict]:
        r = self.send({"action": "list_blocked"})
        return r.get("data", {}).get("blocked_apps", [])

    def list_reports(self) -> list[str]:
        r = self.send({"action": "list_reports"})
        return r.get("data", {}).get("reports", [])

    def get_public_key(self) -> str:
        r = self.send({"action": "get_public_key"})
        return r.get("data", {}).get("public_key", "")

    def run_scenario(self, scenario_id: str) -> dict:
        return self.send({"action": "run_scenario", "scenario_id": scenario_id})

    def run_guardrail(self, guardrail_id: str) -> dict:
        return self.send({"action": "run_guardrail", "guardrail_id": guardrail_id})

    def ping(self) -> bool:
        r = self.send({"action": "ping"})
        return r.get("status") == "ok"


# ── GUI ───────────────────────────────────────────────────────────────────────

class LinemanApp:

    def __init__(self, root: tk.Tk):
        self.root   = root
        self.client = DaemonClient()
        self._pub_key_b64 = ""
        self._pub_key = None

        root.title("Lineman v2.0 · Ghost-Protocol HIPS")
        root.geometry("1000x750")
        root.configure(bg="#1a1a2e")

        self._build_ui()
        self._check_daemon_status()
        self._refresh_list()
        self._load_public_key()

        self._schedule_refresh()

    def _load_public_key(self):
        def _do():
            key = self.client.get_public_key()
            if key:
                self._pub_key_b64 = key
                try:
                    pk_bytes = base64.b64decode(key)
                    self._pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pk_bytes)
                    self.root.after(0, lambda: self._set_status("✓ Integrity key loaded. Secure audit active."))
                except Exception:
                    pass
        threading.Thread(target=_do, daemon=True).start()

    # ── Build UI ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        BG      = "#1a1a2e"
        PANEL   = "#16213e"
        ACCENT  = "#0f3460"
        RED     = "#e94560"
        GREEN   = "#00b4d8"
        TEXT    = "#e0e0e0"
        SUBTEXT = "#888"

        self.mono = font.Font(family="Menlo", size=11)
        self.head = font.Font(family="Helvetica Neue", size=13, weight="bold")
        self.tiny = font.Font(family="Menlo", size=9)

        # Header
        header = tk.Frame(self.root, bg=ACCENT, height=52)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(header, text="LINEMAN v2.0  ·  GHOST-PROTOCOL", bg=ACCENT, fg=TEXT, font=self.head).pack(side="left", padx=20)

        self._status_dot = tk.Label(header, text="●", bg=ACCENT, fg=RED, font=font.Font(size=18))
        self._status_dot.pack(side="right", padx=6)
        self._status_lbl = tk.Label(header, text="DAEMON OFFLINE", bg=ACCENT, fg=SUBTEXT, font=self.tiny)
        self._status_lbl.pack(side="right", padx=4)

        # Main frame
        main_frame = tk.Frame(self.root, bg=BG)
        main_frame.pack(fill="both", expand=True)

        # Sidebar
        sidebar = tk.Frame(main_frame, bg=PANEL, width=220)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="SCENARIOS (OFFENSIVE)", bg=PANEL, fg=SUBTEXT, font=self.tiny).pack(pady=(20, 5))
        for sid, label in [("s1", "Trojan-Egress"), ("s2", "Side-Channel"), ("s3", "Buffer-Overflow")]:
            tk.Button(sidebar, text=label, command=lambda s=sid: self._run_scenario(s), bg=ACCENT, fg=TEXT, relief="flat", font=self.tiny, padx=10, pady=4).pack(fill="x", padx=15, pady=2)

        tk.Label(sidebar, text="GUARDRAILS (POLICY)", bg=PANEL, fg=SUBTEXT, font=self.tiny).pack(pady=(20, 5))
        for gid, label in [("G1", "Zero-Sanitize"), ("G2", "Kernel-Integ")]:
            tk.Button(sidebar, text=label, command=lambda g=gid: self._run_guardrail(g), bg="#23395d", fg=TEXT, relief="flat", font=self.tiny, padx=10, pady=4).pack(fill="x", padx=15, pady=2)

        # Content
        dashboard = tk.Frame(main_frame, bg=BG)
        dashboard.pack(side="right", fill="both", expand=True)

        # Toolbar
        toolbar = tk.Frame(dashboard, bg=BG, pady=15)
        toolbar.pack(fill="x")
        tk.Button(toolbar, text="+ Add App", command=self._add_app, bg=RED, fg="white", relief="flat", font=self.head, padx=15, pady=5).pack(side="left", padx=20)
        tk.Button(toolbar, text="⊖ Unblock", command=self._unblock_selected, bg=ACCENT, fg=TEXT, relief="flat", font=self.head, padx=15, pady=5).pack(side="left", padx=5)
        tk.Button(toolbar, text="⟳ Refresh", command=self._refresh_list, bg=BG, fg=SUBTEXT, relief="flat", font=self.mono).pack(side="right", padx=20)

        # Blocked list
        self._tree = ttk.Treeview(dashboard, columns=("app", "bundle", "pids", "ips", "agents"), show="headings", height=12)
        for col, label, w in [("app", "Application", 180), ("bundle", "Bundle ID", 220), ("pids", "PIDs", 60), ("ips", "IPs", 60), ("agents", "Agents", 60)]:
            self._tree.heading(col, text=label)
            self._tree.column(col, width=w)
        self._tree.pack(fill="x", padx=20, pady=5)

        # Reports list
        tk.Label(dashboard, text="SECURE AUDIT LOG (SIGNED REPORTS)", bg=BG, fg=SUBTEXT, font=self.tiny, anchor="w").pack(fill="x", padx=20, pady=(20, 5))
        self._reports_list = tk.Listbox(dashboard, bg=PANEL, fg=GREEN, font=self.tiny, relief="flat", height=10)
        self._reports_list.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self._reports_list.bind("<Double-Button-1>", self._open_report)

        # Status bar
        self._statusbar = tk.Label(self.root, text="System Ready. Ghost-Protocol v2.0 Active.", bg="#0d0d1a", fg=SUBTEXT, font=self.tiny, anchor="w")
        self._statusbar.pack(fill="x", padx=14, pady=4)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _open_report(self, _event=None):
        sel = self._reports_list.curselection()
        if not sel: return
        path = self._reports_list.get(sel[0])
        
        # v2.0: Integrity Verification
        try:
            with open(path, "r") as f:
                data = json.load(f)
            
            sig_b64 = data.get("signature")
            if not sig_b64 or not self._pub_key:
                messagebox.showwarning("Insecure Report", "This report is missing a cryptographic signature or public key is unavailable.")
            else:
                # Reconstruct canonical body (remove signature field)
                report_copy = dict(data)
                del report_copy["signature"]
                body = json.dumps(report_copy, sort_keys=True, separators=(",", ":")).encode()
                
                try:
                    self._pub_key.verify(base64.b64decode(sig_b64), body)
                    messagebox.showinfo("Integrity Verified", "✓ Report signature is VALID.\nThis log originated from the trusted daemon and has not been altered.")
                except InvalidSignature:
                    messagebox.showerror("CRITICAL: Tamper Detected", "⚠ INVALID SIGNATURE!\nThis forensic report has been tampered with or did not originate from this daemon.")
                    return

            import subprocess
            subprocess.run(["open", path])
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _run_scenario(self, sid: str):
        r = self.client.run_scenario(sid)
        self._set_status(f"Scenario {sid} status: {r.get('status')}")

    def _run_guardrail(self, gid: str):
        r = self.client.run_guardrail(gid)
        messagebox.showinfo("Guardrail Result", r.get("data", {}).get("message", "Unknown"))

    def _add_app(self):
        app_path = filedialog.askdirectory(title="Select .app", initialdir="/Applications")
        if app_path and app_path.endswith(".app"):
            threading.Thread(target=lambda: self.client.block_app(app_path), daemon=True).start()

    def _unblock_selected(self):
        sel = self._tree.selection()
        if not sel: return
        app_name = self._tree.item(sel[0])["values"][0]
        for info in self._last_blocked:
            if info.get("app_name") == app_name:
                self.client.unblock_app(info["app_path"])
                return

    # ── System ────────────────────────────────────────────────────────────────

    _last_blocked: list = []

    def _refresh_list(self):
        def _do():
            blocked = self.client.list_blocked()
            reports = self.client.list_reports()
            self.root.after(0, lambda: self._update_ui(blocked, reports))
        threading.Thread(target=_do, daemon=True).start()

    def _update_ui(self, blocked: list, reports: list):
        self._last_blocked = blocked
        self._tree.delete(*self._tree.get_children())
        for info in blocked:
            self._tree.insert("", "end", values=(info.get("app_name"), info.get("bundle_id"), info.get("pid_count"), info.get("ip_count"), info.get("agent_count")))
        self._reports_list.delete(0, tk.END)
        for r in reports: self._reports_list.insert(tk.END, r)

    def _schedule_refresh(self):
        self._refresh_list()
        self.root.after(8000, self._schedule_refresh)

    def _check_daemon_status(self):
        def _do():
            alive = self.client.ping()
            self.root.after(0, lambda: self._set_daemon_status(alive))
            self.root.after(10000, self._check_daemon_status)
        threading.Thread(target=_do, daemon=True).start()

    def _set_daemon_status(self, alive: bool):
        self._status_dot.config(fg="#00e676" if alive else "#e94560")
        self._status_lbl.config(text="DAEMON ONLINE " if alive else "DAEMON OFFLINE")

    def _set_status(self, msg: str):
        self._statusbar.config(text=msg)

def main():
    root = tk.Tk()
    app  = LinemanApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
