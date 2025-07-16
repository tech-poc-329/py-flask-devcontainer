// secret_guard.py — system‑tray helper v0.3
// Updated: adds per‑line logging of secrets found during folder scan

"""
Secret Guard
============
• Clipboard sanitiser that redacts secrets before they can be pasted.
• Tray‑menu action to scan a project folder, list files/lines containing
  secrets, append those files to .copilotignore **and** write a log
  detailing every finding.

Log file: <project‑root>/secret_guard_scan.log
Each run appends a block like:
    --- Scan 2025‑07‑15 15:42:10 ---
    src/config.py:17: password = "hunter2"
    README.md:1: AKIA****************

Tested: Windows 11 / Python 3.11
Dependencies: pyperclip, pystray, pillow, win10toast
"""

import os, re, sys, time, threading, tkinter as tk
from tkinter import filedialog, messagebox

import pyperclip                       # pip install pyperclip
from win10toast import ToastNotifier   # pip install win10toast
import pystray                         # pip install pystray pillow
from pystray import MenuItem as Item
from PIL import Image, ImageDraw

# ───────────────────────────────────────── 1. Secret‑detection heuristics
PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                      # AWS access keys
    re.compile(r"(?:password|passwd|pwd)[\s:=]+.*", re.I),
    re.compile(r"(?:ssh-rsa|ssh-ed25519)[A-Za-z0-9+/]{50,}"),
    re.compile(r"-----BEGIN (?:RSA|EC|DSA) PRIVATE KEY-----"),
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"),        # Slack tokens
    re.compile(r"\b[nz][a-z0-9]{6}\b", re.I),           # 7‑char IDs
]

MAX_SCAN_BYTES = 1_000_000   # skip files >1 MB when scanning


def contains_secret(text: str) -> bool:
    return any(p.search(text) for p in PATTERNS)


def redact(text: str) -> str:
    for p in PATTERNS:
        text = p.sub("<REDACTED>", text)
    return text

# ───────────────────────────────────────── 2. Clipboard watchdog thread

def clipboard_loop(toaster: ToastNotifier, stop_evt: threading.Event):
    last = None
    while not stop_evt.is_set():
        try:
            clip = pyperclip.paste()
            if clip and clip != last:
                last = clip
                if contains_secret(clip):
                    toaster.show_toast(
                        "Secret Guard",
                        "Sensitive data caught – clipboard sanitised.",
                        threaded=True,
                        duration=4
                    )
                    pyperclip.copy(redact(clip))
        except Exception as exc:
            print("[Clipboard] error:", exc, file=sys.stderr)
        time.sleep(0.6)

# ───────────────────────────────────────── 3. Folder scan + .copilotignore + log

def scan_project(folder: str):
    hits: list[str] = []          # files containing at least one secret
    log_lines: list[str] = []     # detailed <file>:<line>:<snippet>

    for root, _dnames, fnames in os.walk(folder):
        for fn in fnames:
            path = os.path.join(root, fn)
            try:
                if os.path.getsize(path) > MAX_SCAN_BYTES:
                    continue  # large/binary – skip
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for lineno, line in enumerate(f, 1):
                        if contains_secret(line):
                            rel = os.path.relpath(path, folder).replace("\\", "/")
                            snippet = line.strip()[:120]
                            log_lines.append(f"{rel}:{lineno}: {snippet}")
                            hits.append(rel)
                            break  # one hit is enough to flag file for ignore
            except OSError:
                continue

    if not hits:
        messagebox.showinfo("Secret Guard", "No secrets found 🎉")
        return

    # Update .copilotignore
    ignore_path = os.path.join(folder, ".copilotignore")
    existing: set[str] = set()
    if os.path.exists(ignore_path):
        with open(ignore_path, "r", encoding="utf-8") as fh:
            existing = {ln.strip() for ln in fh if ln.strip()}
    new_entries = [h for h in hits if h not in existing]
    if new_entries:
        with open(ignore_path, "a", encoding="utf-8") as fh:
            for entry in new_entries:
                fh.write(entry + "\n")

    # Write / append detailed log
    log_path = os.path.join(folder, "secret_guard_scan.log")
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(log_path, "a", encoding="utf-8") as logf:
        logf.write(f"--- Scan {timestamp} ---\n")
        for ln in log_lines:
            logf.write(ln + "\n")

    messagebox.showinfo(
        "Secret Guard",
        f"Scan complete.\nFound {len(log_lines)} secret line(s) in {len(hits)} file(s).\n"
        f"Added {len(new_entries)} path(s) to .copilotignore.\n"
        f"Details saved to {os.path.basename(log_path)}."
    )


def choose_folder_and_scan(_icon, _item):
    root = tk.Tk(); root.withdraw()
    folder = filedialog.askdirectory(title="Select project folder")
    root.destroy()
    if folder:
        scan_project(folder)

# ───────────────────────────────────────── 4. Tray icon helpers

def tray_icon_img():
    img = Image.new("RGB", (64,64), "white")
    d   = ImageDraw.Draw(img)
    d.ellipse((10,10,54,54), fill="red")
    d.text((24,20), "S", fill="white")
    return img


def quit_app(icon, _item, stop_evt):
    stop_evt.set()
    icon.stop()

# ───────────────────────────────────────── 5. Main entry‑point

def run():
    toaster    = ToastNotifier()
    stop_event = threading.Event()

    threading.Thread(
        target=clipboard_loop,
        args=(toaster, stop_event),
        daemon=True
    ).start()

    icon = pystray.Icon(
        "secret_guard",
        tray_icon_img(),
        "Secret Guard",
        menu=pystray.Menu(
            Item("Scan folder for secrets…", choose_folder_and_scan),
            Item("Quit", lambda i, it: quit_app(i, it, stop_event))
        )
    )
    icon.run()

if __name__ == "__main__":
    run()
