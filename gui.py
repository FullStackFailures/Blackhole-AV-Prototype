from __future__ import annotations

import hashlib
import os
import platform
import queue
import subprocess
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

from detector import analyze
from sandbox import quarantine_file

# ================= ROOT =================
root = tk.Tk()
root.title("🐉 Blackhole AV — Prototype")
root.geometry("1350x780")
root.configure(bg="black")

queue_data: queue.Queue[tuple[str, str, str]] = queue.Queue()
scan_paths = [str(Path.home())]
selected: str | None = None
running = False

# ================= BACKGROUND =================
canvas = tk.Canvas(root, bg="black", highlightthickness=0)
canvas.place(relwidth=1, relheight=1)

try:
    bg = tk.PhotoImage(file=Path(__file__).with_name("dragon.png"))
    canvas.create_image(0, 0, image=bg, anchor="nw")
except tk.TclError:
    bg = None

# ================= SCANNER =================
def monitor() -> None:
    global running
    seen: set[str] = set()

    while running:
        for directory in list(scan_paths):
            if not os.path.isdir(directory):
                queue_data.put((directory, "ERROR", "Scan path does not exist"))
                continue

            for root_dir, _, files in os.walk(directory):
                for filename in files:
                    path = os.path.abspath(os.path.join(root_dir, filename))
                    if path in seen:
                        continue
                    seen.add(path)

                    try:
                        result = analyze(path)
                        if result.suspicious:
                            queue_data.put((path, "THREAT", "; ".join(result.reasons)))
                        else:
                            queue_data.put((path, "SAFE", "OK"))
                    except Exception as exc:
                        queue_data.put((path, "ERROR", str(exc)))

        time.sleep(1)


def get_process_tree() -> str:
    try:
        if os.name == "nt":
            output = subprocess.check_output(["tasklist"], text=True, errors="replace")
        else:
            output = subprocess.check_output(["ps", "aux"], text=True, errors="replace")
        return output
    except (OSError, subprocess.SubprocessError) as exc:
        return f"Error loading processes: {exc}"

# ================= MAIN FRAME =================
frame = tk.Frame(root, bg="#050505")
frame.pack(fill="both", expand=True)

left = tk.Frame(frame, bg="#050505", width=420)
left.pack(side="left", fill="y")
left.pack_propagate(False)

search_var = tk.StringVar()
all_safe: set[str] = set()
all_threat: set[str] = set()


def search() -> None:
    term = search_var.get().lower()
    safe_box.delete(0, tk.END)
    threat_box.delete(0, tk.END)
    for path in sorted(all_safe):
        if term in path.lower():
            safe_box.insert(tk.END, path)
    for path in sorted(all_threat):
        if term in path.lower():
            threat_box.insert(tk.END, path)


tk.Entry(left, textvariable=search_var, bg="black", fg="white").pack(fill="x", padx=5, pady=5)
tk.Button(left, text="Search", command=search).pack()
tk.Label(left, text="SAFE FILES", fg="#22c55e", bg="#050505").pack()
safe_box = tk.Listbox(left, bg="black", fg="#22c55e")
safe_box.pack(fill="both", expand=True, padx=5, pady=5)
tk.Label(left, text="THREATS", fg="#ef4444", bg="#050505").pack()
threat_box = tk.Listbox(left, bg="black", fg="#ef4444")
threat_box.pack(fill="both", expand=True, padx=5, pady=5)


def select_item() -> None:
    global selected
    if threat_box.curselection():
        selected = threat_box.get(threat_box.curselection())
    elif safe_box.curselection():
        selected = safe_box.get(safe_box.curselection())


tk.Button(left, text="Select File", command=select_item).pack(pady=5)

right = tk.Frame(frame, bg="#050505")
right.pack(side="right", fill="both", expand=True)
tabs = ttk.Notebook(right)
tabs.pack(fill="both", expand=True)

proc_tab = tk.Frame(tabs, bg="black")
tabs.add(proc_tab, text="Process Tree")
proc_text = tk.Text(proc_tab, bg="black", fg="#00ff9c")
proc_text.pack(fill="both", expand=True)


def load_process() -> None:
    proc_text.delete(1.0, tk.END)
    proc_text.insert(tk.END, get_process_tree())


tk.Button(proc_tab, text="Load Processes", command=load_process).pack()

inf_tab = tk.Frame(tabs, bg="black")
tabs.add(inf_tab, text="Infinity Viewer")
inf_text = tk.Text(inf_tab, bg="black", fg="#00ff9c")
inf_text.pack(fill="both", expand=True)


def infinity_view() -> None:
    if selected:
        info = analyze(selected)
        inf_text.insert(tk.END, f"Watching: {selected}\nVerdict: {'THREAT' if info.suspicious else 'NO MATCH'}\n")
        if info.reasons:
            inf_text.insert(tk.END, f"Reasons: {'; '.join(info.reasons)}\n")


tk.Button(inf_tab, text="Inspect Selected", command=infinity_view).pack()

log_tab = tk.Frame(tabs, bg="black")
tabs.add(log_tab, text="Logs")
log_text = tk.Text(log_tab, bg="black", fg="white")
log_text.pack(fill="both", expand=True)

control = tk.Frame(root, bg="black")
control.pack(fill="x")


def start() -> None:
    global running
    if running:
        return
    if not scan_paths:
        log_text.insert(tk.END, "⚠️ Choose a folder first\n")
        return
    running = True
    threading.Thread(target=monitor, daemon=True).start()
    log_text.insert(tk.END, f"🟢 Scan Started: {', '.join(scan_paths)}\n")


def stop() -> None:
    global running
    running = False
    log_text.insert(tk.END, "🔴 Scan Stopped\n")


def choose() -> None:
    folder = filedialog.askdirectory()
    if folder:
        scan_paths.clear()
        scan_paths.append(folder)
        log_text.insert(tk.END, f"📂 Scan path: {folder}\n")


def refresh() -> None:
    safe_box.delete(0, tk.END)
    threat_box.delete(0, tk.END)
    all_safe.clear()
    all_threat.clear()


def blackhole() -> None:
    if not selected:
        log_text.insert(tk.END, "⚠️ No file selected\n")
        return
    try:
        record = quarantine_file(selected)
        log_text.insert(tk.END, f"🕳️ Quarantined: {record['original_path']}\n")
        if selected in all_threat:
            all_threat.remove(selected)
            threat_box.delete(0, tk.END)
            for item in sorted(all_threat):
                threat_box.insert(tk.END, item)
    except PermissionError:
        log_text.insert(tk.END, "❌ Permission denied\n")
    except FileNotFoundError:
        log_text.insert(tk.END, "❌ File not found\n")
    except Exception as exc:
        log_text.insert(tk.END, f"❌ Error: {exc}\n")


tk.Button(control, text="📂 Folder", command=choose).pack(side="left")
tk.Button(control, text="▶ Start", command=start).pack(side="left")
tk.Button(control, text="■ Stop", command=stop).pack(side="left")
tk.Button(control, text="🔄 Refresh", command=refresh).pack(side="left")
tk.Button(control, text="🕳️ Quarantine", command=blackhole).pack(side="left")


def update() -> None:
    while not queue_data.empty():
        path, status, result = queue_data.get()
        if status == "SAFE":
            if path not in all_safe:
                all_safe.add(path)
                safe_box.insert(tk.END, path)
        elif status == "THREAT":
            if path not in all_threat:
                all_threat.add(path)
                threat_box.insert(tk.END, path)
        log_text.insert(tk.END, f"{status}: {path} :: {result}\n")
    root.after(300, update)


update()
root.mainloop()
