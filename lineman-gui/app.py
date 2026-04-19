#!/usr/bin/env python3
"""
lineman-gui — Unprivileged GUI Client
======================================
Runs as the logged-in user (NOT root). Communicates with lineman-daemon
via the Unix socket at /var/run/lineman.sock.

Security properties:
  • This process has no elevated privileges
  • It never calls pfctl, tcpdump, or socketfilterfw directly
  • If this process were compromised, the attacker gains no root access
  • All privileged operations go through the narrow daemon socket API

The GUI is intentionally minimal — it is a control surface for the daemon,
not the security engine itself.
"""

import json
import os
import socket
import threading
import tkinter as tk
from tkinter import filedialog, font, messagebox, ttk
from pathlib import Path

SOCKET_PATH = "/var/run/lineman.sock"
DAEMON_TIMEOUT = 5.0


# ── Daemon client ──────────────────────────────────────────────────────────────

class DaemonClient:
    """
    Thin IPC client. Each call opens a fresh connection — the daemon handles
    concurrent connections via per-client threads.
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
            return {"status": "error",
                    "message": "Daemon not running.\n\nStart it with:\n  sudo python3 lineman-daemon/daemon.py"}
        except ConnectionRefusedError:
            return {"status": "error",
                    "message": "Daemon socket refused connection.\nTry restarting the daemon."}
        except socket.timeout:
            return {"status": "error", "message": "Daemon timed out."}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def block_app(self, app_path: str) -> dict:
        return self.send({"action": "block_app", "app_path": app_path})

    def unblock_app(self, app_path: str) -> dict:
        return self.send({"action": "unblock_app", "app_path": app_path})

    def list_blocked(self) -> list[dict]:
        r = self.send({"action": "list_blocked"})
        return r.get("data", {}).get("blocked_apps", [])

    def list_blocked_ips(self) -> list[str]:
        r = self.send({"action": "get_blocked_ips"})
        return r.get("data", {}).get("ips", [])

    def list_reports(self) -> list[str]:
        r = self.send({"action": "list_reports"})
        return r.get("data", {}).get("reports", [])

    def ping(self) -> bool:
        r = self.send({"action": "ping"})
        return r.get("status") == "ok"


# ── GUI ───────────────────────────────────────────────────────────────────────

class LinemanApp:

    def __init__(self, root: tk.Tk):
        self.root   = root
        self.client = DaemonClient()

        root.title("Lineman · macOS HIPS")
        root.geometry("740x560")
        root.resizable(True, True)
        root.configure(bg="#1a1a2e")

        self._build_ui()
        self._check_daemon_status()
        self._refresh_list()

        # Poll every 8 seconds
        self._schedule_refresh()

    # ── Build UI ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        BG      = "#1a1a2e"
        PANEL   = "#16213e"
        ACCENT  = "#0f3460"
        RED     = "#e94560"
        GREEN   = "#00b4d8"
        TEXT    = "#e0e0e0"
        SUBTEXT = "#888"

        mono = font.Font(family="Menlo", size=11)
        head = font.Font(family="Helvetica Neue", size=13, weight="bold")
        tiny = font.Font(family="Menlo", size=9)

        # ── Header ────────────────────────────────────────────────────────────
        header = tk.Frame(self.root, bg=ACCENT, height=52)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(
            header, text="LINEMAN  ·  macOS HIPS",
            bg=ACCENT, fg=TEXT,
            font=font.Font(family="Helvetica Neue", size=14, weight="bold"),
        ).pack(side="left", padx=18, pady=12)

        self._status_dot = tk.Label(header, text="●", bg=ACCENT, fg=RED,
                                    font=font.Font(size=18))
        self._status_dot.pack(side="right", padx=6)

        self._status_lbl = tk.Label(header, text="DAEMON OFFLINE",
                                     bg=ACCENT, fg=SUBTEXT, font=tiny)
        self._status_lbl.pack(side="right", padx=4)

        # ── Toolbar ───────────────────────────────────────────────────────────
        toolbar = tk.Frame(self.root, bg=PANEL, pady=8)
        toolbar.pack(fill="x")

        tk.Button(
            toolbar, text="+ Add App",
            command=self._add_app,
            bg=RED, fg="white", relief="flat",
            font=head, padx=12, pady=4,
            activebackground="#c73652", activeforeground="white",
            cursor="hand2",
        ).pack(side="left", padx=12)

        tk.Button(
            toolbar, text="⊖ Unblock",
            command=self._unblock_selected,
            bg=ACCENT, fg=TEXT, relief="flat",
            font=head, padx=12, pady=4,
            activebackground="#1a4a80", activeforeground="white",
            cursor="hand2",
        ).pack(side="left", padx=4)

        tk.Button(
            toolbar, text="⟳ Refresh",
            command=self._refresh_list,
            bg=PANEL, fg=SUBTEXT, relief="flat",
            font=mono, padx=10, pady=4,
            cursor="hand2",
        ).pack(side="right", padx=12)

        # ── Main panes ────────────────────────────────────────────────────────
        paned = tk.PanedWindow(self.root, orient="vertical",
                               bg=BG, sashrelief="flat", sashwidth=4)
        paned.pack(fill="both", expand=True, padx=0, pady=0)

        # Blocked apps pane
        apps_frame = tk.Frame(paned, bg=BG)
        paned.add(apps_frame, minsize=180)

        tk.Label(apps_frame, text="BLOCKED APPLICATIONS",
                 bg=BG, fg=SUBTEXT, font=tiny, anchor="w").pack(fill="x", padx=14, pady=(10, 2))

        cols = ("app", "bundle_id", "pids", "ips")
        self._tree = ttk.Treeview(apps_frame, columns=cols, show="headings", height=8)
        for col, label, w in [
            ("app",       "Application",   200),
            ("bundle_id", "Bundle ID",      250),
            ("pids",      "PIDs",           60),
            ("ips",       "Blocked IPs",    80),
        ]:
            self._tree.heading(col, text=label)
            self._tree.column(col, width=w, anchor="w")

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
                         background=PANEL, fieldbackground=PANEL,
                         foreground=TEXT, font=mono, rowheight=22)
        style.configure("Treeview.Heading",
                         background=ACCENT, foreground=TEXT,
                         font=font.Font(family="Menlo", size=10, weight="bold"))
        style.map("Treeview", background=[("selected", "#0f3460")])

        sb = ttk.Scrollbar(apps_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        self._tree.pack(side="left", fill="both", expand=True, padx=(14, 0), pady=4)
        sb.pack(side="right", fill="y", pady=4, padx=(0, 8))

        # Forensic reports pane
        reports_frame = tk.Frame(paned, bg=BG)
        paned.add(reports_frame, minsize=160)

        tk.Label(reports_frame, text="EGRESS FORENSIC REPORTS",
                 bg=BG, fg=SUBTEXT, font=tiny, anchor="w").pack(fill="x", padx=14, pady=(10, 2))

        self._reports_list = tk.Listbox(
            reports_frame, bg=PANEL, fg=GREEN,
            font=tiny, selectbackground=ACCENT,
            selectforeground=TEXT, relief="flat",
            activestyle="none", height=7,
        )
        self._reports_list.pack(fill="both", expand=True, padx=14, pady=(0, 4))
        self._reports_list.bind("<Double-Button-1>", self._open_report)

        tk.Label(reports_frame,
                 text="Double-click a report to view · Reports auto-generate on block",
                 bg=BG, fg=SUBTEXT, font=tiny).pack(anchor="w", padx=14, pady=(0, 6))

        # ── Status bar ────────────────────────────────────────────────────────
        self._statusbar = tk.Label(
            self.root, text="Ready.",
            bg="#0d0d1a", fg=SUBTEXT, font=tiny, anchor="w",
        )
        self._statusbar.pack(fill="x", padx=14, pady=4)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _add_app(self):
        app_path = filedialog.askdirectory(
            title="Select .app bundle to block",
            initialdir="/Applications",
        )
        if not app_path:
            return
        if not app_path.endswith(".app"):
            messagebox.showerror("Invalid selection", "Please select a .app bundle.")
            return

        self._set_status(f"Blocking {os.path.basename(app_path)}…")
        self.root.update_idletasks()

        def _do():
            r = self.client.block_app(app_path)
            self.root.after(0, lambda: self._on_block_result(r, app_path))

        threading.Thread(target=_do, daemon=True).start()

    def _on_block_result(self, r: dict, app_path: str):
        if r["status"] == "ok":
            d = r["data"]
            msg = (
                f"Blocked: {d['app']}\n"
                f"Bundle:  {d['bundle_id']}\n"
                f"PIDs:    {d['pids']}\n"
                f"XPC helpers: {d['xpc_helpers']}\n"
                f"IPs blocked: {d['blocked_ips']}"
            )
            self._set_status(f"✓ Blocked {d['app']} — forensic capture started.")
            messagebox.showinfo("App Blocked", msg)
        else:
            self._set_status(f"Error: {r['message']}")
            messagebox.showerror("Block Failed", r["message"])
        self._refresh_list()

    def _unblock_selected(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("Nothing selected", "Select an app from the list first.")
            return
        values = self._tree.item(sel[0])["values"]
        # We stored app_path in hidden column — look it up from our last refresh data
        app_name = values[0] if values else ""
        # Find the full path from the daemon
        for info in self._last_blocked:
            if info.get("app_name") == app_name:
                r = self.client.unblock_app(info["app_path"])
                if r["status"] == "ok":
                    self._set_status(f"Unblocked: {app_name}")
                else:
                    messagebox.showerror("Unblock Failed", r.get("message", ""))
                self._refresh_list()
                return

    def _open_report(self, _event=None):
        sel = self._reports_list.curselection()
        if not sel:
            return
        path = self._reports_list.get(sel[0])
        try:
            import subprocess
            subprocess.run(["open", path])
        except Exception:
            pass

    # ── Refresh ───────────────────────────────────────────────────────────────

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
            self._tree.insert("", "end", values=(
                info.get("app_name", ""),
                info.get("bundle_id", ""),
                info.get("pid_count", 0),
                info.get("ip_count", 0),
            ))

        self._reports_list.delete(0, tk.END)
        for r in reports:
            self._reports_list.insert(tk.END, r)

        if not blocked:
            self._set_status("No apps blocked. Click '+ Add App' to begin.")

    def _schedule_refresh(self):
        self._refresh_list()
        self.root.after(8000, self._schedule_refresh)

    # ── Daemon status ─────────────────────────────────────────────────────────

    def _check_daemon_status(self):
        def _do():
            alive = self.client.ping()
            self.root.after(0, lambda: self._set_daemon_status(alive))
            self.root.after(10000, self._check_daemon_status)

        threading.Thread(target=_do, daemon=True).start()

    def _set_daemon_status(self, alive: bool):
        if alive:
            self._status_dot.config(fg="#00e676")
            self._status_lbl.config(text="DAEMON ONLINE ")
        else:
            self._status_dot.config(fg="#e94560")
            self._status_lbl.config(text="DAEMON OFFLINE")

    def _set_status(self, msg: str):
        self._statusbar.config(text=msg)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    root = tk.Tk()
    _set_icon(root)
    app  = LinemanApp(root)
    root.mainloop()


def _set_icon(root: tk.Tk) -> None:
    icon_path = Path(__file__).parent.parent / "docs" / "icon.png"
    if icon_path.exists():
        try:
            img = tk.PhotoImage(file=str(icon_path))
            root.wm_iconphoto(True, img)
            root._icon_ref = img  # prevent GC
        except Exception:
            pass


if __name__ == "__main__":
    main()
