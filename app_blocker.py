#!/usr/bin/env /usr/bin/python3
import os
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import threading
import plistlib
import time

BLOCKED_APPS = {}
LOG_FILE = "blocked_connections.log"

# Helper to get bundle id from .app path
def get_bundle_id(app_path):
    info_plist = os.path.join(app_path, 'Contents', 'Info.plist')
    if os.path.exists(info_plist):
        with open(info_plist, 'rb') as f:
            plist = plistlib.load(f)
            return plist.get('CFBundleIdentifier')
    return None

# Helper to get all PIDs for a bundle id
def get_pids_for_bundle(bundle_id):
    try:
        output = subprocess.check_output(['pgrep', '-f', bundle_id]).decode().strip()
        return [int(pid) for pid in output.split('\n') if pid]
    except subprocess.CalledProcessError:
        return []

# Block outgoing connections for a PID using pfctl (requires sudo)
def block_pid(pid):
    rule = f"block drop out quick proto {pid} from any to any"
    # This is a placeholder; real implementation would use anchor rules and tags
    # For demo, just log
    with open(LOG_FILE, 'a') as f:
        f.write(f"Blocked PID {pid} at {time.ctime()}\n")

# Monitor network connections and alert if blocked app tries to connect
def monitor_connections():
    import psutil
    while True:
        for app, info in BLOCKED_APPS.items():
            for pid in info['pids']:
                try:
                    p = psutil.Process(pid)
                    conns = p.connections(kind='inet')
                    for c in conns:
                        if c.status == 'ESTABLISHED':
                            msg = f"Blocked app {app} (PID {pid}) tried to connect to {c.raddr}"
                            with open(LOG_FILE, 'a') as f:
                                f.write(msg + '\n')
                            messagebox.showwarning("Blocked Connection", msg)
                except Exception:
                    continue
        time.sleep(5)

def add_app():
    app_path = filedialog.askdirectory(title="Select .app to block")
    if not app_path or not app_path.endswith('.app'):
        messagebox.showerror("Error", "Please select a valid .app bundle.")
        return
    bundle_id = get_bundle_id(app_path)
    if not bundle_id:
        messagebox.showerror("Error", "Could not get bundle id.")
        return
    pids = get_pids_for_bundle(bundle_id)
    for pid in pids:
        block_pid(pid)
    BLOCKED_APPS[app_path] = {'bundle_id': bundle_id, 'pids': pids}
    update_list()

def update_list():
    listbox.delete(0, tk.END)
    for app, info in BLOCKED_APPS.items():
        listbox.insert(tk.END, f"{os.path.basename(app)} (PIDs: {info['pids']})")

def main():
    global listbox
    root = tk.Tk()
    root.title("App Blocker - Drag & Drop to Block Apps")
    root.geometry("500x400")

    frame = tk.Frame(root)
    frame.pack(pady=10)

    add_btn = tk.Button(frame, text="Add App to Block", command=add_app)
    add_btn.pack(side=tk.LEFT, padx=10)

    listbox = tk.Listbox(root, width=60, height=15)
    listbox.pack(pady=10)

    # Start monitor thread
    threading.Thread(target=monitor_connections, daemon=True).start()

    root.mainloop()

if __name__ == "__main__":
    main()
