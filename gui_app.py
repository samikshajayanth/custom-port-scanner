import tkinter as tk
from tkinter import ttk, messagebox
import asyncio
import threading
from scanner_core import scan_multiple_hosts
from banner_grabber import grab_banner
from service_map import get_service_name


def run_scan():
    ip_input  = ip_entry.get().strip()
    scan_type = scan_type_var.get()

    try:
        start = int(start_entry.get())
        end   = int(end_entry.get())
    except ValueError:
        messagebox.showerror("Error", "Ports must be numbers")
        return

    if not ip_input:
        messagebox.showerror("Error", "Enter an IP or range")
        return

    result_box.delete(*result_box.get_children())
    scan_btn.config(state="disabled", text="Scanning...")
    status_var.set("Scanning...")

    def do_scan():
        try:
            results = asyncio.run(
                scan_multiple_hosts(ip_input, start, end, scan_type)
            )
            root.after(0, lambda: display_results(results))
        except Exception as e:
            root.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            root.after(0, lambda: scan_btn.config(state="normal", text="Start Scan"))

    threading.Thread(target=do_scan, daemon=True).start()


def display_results(results: dict):
    """
    results = { "192.168.1.1": [22, 80, 443], "192.168.1.2": [] }
    grab_banner returns a dict: { port, service, banner, version }
    """
    total = 0
    for host, ports in results.items():
        if not ports:
            result_box.insert("", "end", values=(host, "—", "No open ports", "—", "CLOSED"))
            continue
        for port in ports:
            info    = grab_banner(host, port)          # ← returns dict
            service = info["service"]                  # e.g. "SSH"
            version = info["version"]                  # e.g. "OpenSSH 8.9"
            result_box.insert("", "end", values=(
                host,
                port,
                service,
                version,
                "OPEN"
            ), tags=("open",))
            total += 1

    status_var.set(f"Done — {total} open port(s) found across {len(results)} host(s)")


# ─── WINDOW ───────────────────────────────────────────────────────────────────

root = tk.Tk()
root.title("Custom Port Scanner")
root.geometry("860x500")
root.resizable(True, True)

# ─── INPUT FRAME ──────────────────────────────────────────────────────────────

frame = tk.LabelFrame(root, text="Scan Settings", padx=10, pady=8)
frame.pack(fill="x", padx=10, pady=8)

tk.Label(frame, text="IP / Range:").grid(row=0, column=0, sticky="e")
ip_entry = tk.Entry(frame, width=28)
ip_entry.insert(0, "192.168.1.1")
ip_entry.grid(row=0, column=1, padx=5)
tk.Label(frame, text="e.g.  192.168.1.1   or   192.168.1.1-192.168.1.5   or   192.168.1.0/24",
         fg="grey").grid(row=0, column=2, sticky="w")

tk.Label(frame, text="Start Port:").grid(row=1, column=0, sticky="e")
start_entry = tk.Entry(frame, width=10)
start_entry.insert(0, "1")
start_entry.grid(row=1, column=1, sticky="w", padx=5)

tk.Label(frame, text="End Port:").grid(row=2, column=0, sticky="e")
end_entry = tk.Entry(frame, width=10)
end_entry.insert(0, "1024")
end_entry.grid(row=2, column=1, sticky="w", padx=5)

tk.Label(frame, text="Scan Type:").grid(row=3, column=0, sticky="e")
scan_type_var = tk.StringVar(value="tcp")
ttk.Combobox(frame, textvariable=scan_type_var,
             values=["tcp", "udp", "syn"],
             state="readonly", width=10).grid(row=3, column=1, sticky="w", padx=5)
tk.Label(frame, text="SYN requires sudo on Linux",
         fg="grey").grid(row=3, column=2, sticky="w")

scan_btn = tk.Button(frame, text="Start Scan", command=run_scan,
                     bg="#2ecc71", fg="white", width=14,
                     font=("Arial", 10, "bold"))
scan_btn.grid(row=4, column=0, columnspan=2, pady=10)

# ─── RESULTS TABLE ────────────────────────────────────────────────────────────

columns = ("Host", "Port", "Service", "Version", "Status")
result_box = ttk.Treeview(root, columns=columns, show="headings")

col_widths = {"Host": 140, "Port": 70, "Service": 120, "Version": 320, "Status": 80}
for col in columns:
    result_box.heading(col, text=col)
    result_box.column(col, width=col_widths[col])

result_box.tag_configure("open", foreground="#27ae60")
result_box.pack(fill="both", expand=True, padx=10, pady=(0, 5))

# scrollbar
scrollbar = ttk.Scrollbar(root, orient="vertical", command=result_box.yview)
result_box.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side="right", fill="y")

# ─── STATUS BAR ───────────────────────────────────────────────────────────────

status_var = tk.StringVar(value="Ready")
tk.Label(root, textvariable=status_var, anchor="w", fg="grey").pack(
    fill="x", padx=10, pady=(0, 5))

root.mainloop()