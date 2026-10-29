"""Source-only network settings for the existing FindAll executable."""

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import ttk

from . import apex_network


def open_window(path: Path) -> int:
    root = tk.Tk()
    root.title("FindAll · Apex network")
    root.geometry("1050x650")
    frame = ttk.Frame(root, padding=16)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="Apex network", font=("Segoe UI", 18)).pack(anchor="w")
    ttk.Label(frame, text="1. Install Xray   2. Refresh subscriptions   3. Check nodes   4. Select a checked node and enable").pack(anchor="w", pady=8)
    settings = ttk.Frame(frame)
    settings.pack(fill="x", pady=8)
    group = tk.StringVar(value="bl")
    country = tk.StringVar()
    limit = tk.StringVar(value="300")
    checks = tk.StringVar(value="12")
    subscription = tk.StringVar()
    for label, value, width in (("Group", group, 12), ("Country", country, 5),
                                ("Node limit", limit, 7), ("Checks", checks, 7)):
        ttk.Label(settings, text=label).pack(side="left", padx=(0, 4))
        widget = (ttk.Combobox(settings, textvariable=value, values=list(apex_network.FEEDS),
                               state="readonly", width=width) if value is group
                  else ttk.Entry(settings, textvariable=value, width=width))
        widget.pack(side="left", padx=(0, 14))
    ttk.Label(frame, text="Custom public HTTPS subscription (optional)").pack(anchor="w")
    ttk.Entry(frame, textvariable=subscription).pack(fill="x", pady=(3, 12))
    toolbar = ttk.Frame(frame)
    toolbar.pack(fill="x", pady=8)
    message = tk.StringVar(value="Loading network state…")
    ttk.Label(frame, textvariable=message, wraplength=1000).pack(anchor="w", pady=8)
    columns = ("protocol", "host", "port", "name", "status", "latency")
    table = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
    for field, width in zip(columns, (90, 210, 70, 280, 95, 95)):
        table.heading(field, text=field.replace("latency", "Latency ms").title())
        table.column(field, width=width, minwidth=50)
    scroll = ttk.Scrollbar(frame, orient="vertical", command=table.yview)
    table.configure(yscrollcommand=scroll.set)
    scroll.pack(side="right", fill="y")
    table.pack(fill="both", expand=True)
    ttk.Label(frame, text="The saved route applies to the existing FindAll search backend. Xray runs only during commands.",
              wraplength=1000).pack(anchor="w", pady=8)
    coverage = tk.StringVar()
    ttk.Label(frame, textvariable=coverage, wraplength=1000).pack(anchor="w")
    replies = queue.Queue()
    buttons = []
    busy = False

    def start(action):
        nonlocal busy
        if busy:
            return
        try:
            count = int(limit.get())
            check_count = int(checks.get())
        except ValueError:
            message.set("Node limit and checks must be numbers")
            return
        selected = table.selection()
        node = selected[0] if selected else ""
        if action == "enable" and not node:
            message.set("Select a node with status ok")
            return
        values = (group.get(), country.get().strip(), subscription.get().strip())
        busy = True
        for button in buttons:
            button.configure(state="disabled")
        message.set(f"Apex: {action}…")

        def work():
            try:
                if action == "install":
                    apex_network.install_core()
                elif action == "refresh":
                    apex_network.refresh(path, values[0], values[1], [values[2]] if values[2] else None, count)
                elif action == "check":
                    apex_network.check(path, check_count)
                elif action == "check-selected":
                    apex_network.check(path, 1, node)
                elif action in ("enable", "disable"):
                    apex_network.configure(path, action == "enable", node)
                replies.put((apex_network.status(path), ""))
            except Exception as exc:
                replies.put((None, str(exc)))

        threading.Thread(target=work, daemon=True).start()

    for label, action in (("Install Xray", "install"), ("Refresh", "refresh"), ("Check nodes", "check"),
                           ("Check selected", "check-selected"), ("Enable selected", "enable"),
                           ("Disable Apex", "disable"), ("Reload", "status")):
        button = ttk.Button(toolbar, text=label, command=lambda action=action: start(action))
        button.pack(side="left", padx=(0, 6))
        buttons.append(button)

    def poll():
        nonlocal busy
        try:
            result, error = replies.get_nowait()
        except queue.Empty:
            root.after(100, poll)
            return
        busy = False
        for button in buttons:
            button.configure(state="normal")
        if error:
            message.set(error)
        else:
            table.delete(*table.get_children())
            for row in result["rows"]:
                table.insert("", "end", iid=row["id"], values=(row["protocol"], row["host"], row["port"],
                             row["name"], row["status"], row["latency_ms"] if row["latency_ms"] is not None else ""))
            if result["selected"] and table.exists(result["selected"]):
                table.selection_set(result["selected"])
            healthy = sum(row["status"] == "ok" for row in result["rows"])
            message.set(f"Route: {'Apex' if result['enabled'] else 'existing/direct'} · {healthy} checked nodes · "
                        f"Xray: {'installed' if result['core'] else 'missing'} · {path}")
            coverage.set(f"{result['coverage']}. Separate routes: {result['separate_routes']}.")
        root.after(100, poll)

    root.protocol("WM_DELETE_WINDOW", lambda: message.set("Wait for the current operation to finish") if busy else root.destroy())
    start("status")
    root.after(100, poll)
    root.mainloop()
    return 0
