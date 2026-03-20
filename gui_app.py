import tkinter as tk
from tkinter import ttk, messagebox
import socket
import json

# CHANGE THIS to your child laptop IP
CHILD_IP = "172.20.10.2"
CHILD_PORT = 9999


def send_scan_command(target_ip, start_port, end_port):
    command = {"target": target_ip, "start": start_port, "end": end_port}
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((CHILD_IP, CHILD_PORT))
        s.sendall(json.dumps(command).encode())
        s.shutdown(socket.SHUT_WR)

        chunks = []
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)

    return json.loads(b"".join(chunks).decode())


def start_scan():
    target = ip_entry.get().strip()
    try:
        start = int(start_entry.get())
        end = int(end_entry.get())
    except ValueError:
        messagebox.showerror("Error", "Ports must be numbers")
        return

    result_box.delete(*result_box.get_children())

    try:
        results = send_scan_command(target, start, end)

        if not results:
            messagebox.showinfo("Result", "No open ports found")
            return

        for r in results:
            result_box.insert("", "end", values=(
                r['port'],
                r['service'],
                r['version'],
                r['status']
            ))

    except Exception as e:
        messagebox.showerror("Error", f"Connection failed:\n{e}")


# GUI WINDOW
root = tk.Tk()
root.title("Port Scanner GUI")
root.geometry("700x400")

# INPUT FRAME
frame = tk.Frame(root)
frame.pack(pady=10)
# Scan Type Dropdown
scan_type = tk.StringVar(value="TCP")

tk.Label(frame, text="Scan Type:").grid(row=3, column=0)
scan_menu = ttk.Combobox(frame, textvariable=scan_type, state="readonly")
scan_menu['values'] = ("TCP", "BANNER", "UDP")
scan_menu.grid(row=3, column=1)

tk.Label(frame, text="Target IP:").grid(row=0, column=0)
ip_entry = tk.Entry(frame, width=20)
ip_entry.grid(row=0, column=1)

tk.Label(frame, text="Start Port:").grid(row=1, column=0)
start_entry = tk.Entry(frame, width=10)
start_entry.grid(row=1, column=1)

tk.Label(frame, text="End Port:").grid(row=2, column=0)
end_entry = tk.Entry(frame, width=10)
end_entry.grid(row=2, column=1)

scan_btn = tk.Button(frame, text="Start Scan", command=start_scan, bg="green", fg="white")
scan_btn.grid(row=3, column=0, columnspan=2, pady=10)

# RESULT TABLE
columns = ("Port", "Service", "Version", "Status")
result_box = ttk.Treeview(root, columns=columns, show="headings")

for col in columns:
    result_box.heading(col, text=col)
    result_box.column(col, width=150)

result_box.pack(fill="both", expand=True)

root.mainloop()