from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello from Flask in a devcontainer!"

import tkinter as tk
from tkinter import ttk, messagebox

def scan_project(folder: str):
    # 1) Build a simple progress window
    prog = tk.Tk()
    prog.title("Secret Guard Scan")
    prog.geometry("300x80")
    lbl = tk.Label(prog, text="Scanning project…")
    lbl.pack(pady=(10, 0))
    bar = ttk.Progressbar(prog, mode="indeterminate")
    bar.pack(fill="x", padx=20, pady=(5,10))
    bar.start(50)              # 50ms between moves
    prog.update()              # draw it

    # 2) Scan loop (with UI refresh)
    hits, log_lines = [], []
    for root, dirnames, filenames in os.walk(folder):
        # update the label for each directory
        rel = os.path.relpath(root, folder)
        lbl.config(text=f"Scanning {rel} …")
        prog.update_idletasks()
        
        # your existing pruning + file‑checking logic here…
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for fn in filenames:
            path = os.path.join(root, fn)
            # check file, record hits, etc.

    # 3) Tear down the progress UI
    bar.stop()
    prog.destroy()

    # 4) Show your summary dialog
    messagebox.showinfo(
      "Secret Guard",
      f"Scan complete.\nFound {len(log_lines)} hits in {len(hits)} files."
    )


if __name__ == '__main__':
    # It's often better to use a WSGI server in production, but for this POC, we'll use Flask's built-in server.
    app.run(host='0.0.0.0', port=5000, debug=True)
