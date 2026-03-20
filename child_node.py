import socket
import json
import asyncio
from scanner_core import scan_range
from banner_grabber import grab_banner

HOST = "0.0.0.0"
PORT = 9999

def run_full_scan(ip, start, end):
    open_ports = asyncio.run(scan_range(ip, start, end))
    results = []
    for port in open_ports:
        info = grab_banner(ip, port)
        results.append({
            "port":    port,
            "service": info["service"],
            "version": info["version"],
            "status":  "OPEN"
        })
    return results

def start_child_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # fixes port stuck bug
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"[Child] Waiting for Parent on port {PORT}...")

    while True:
        conn, addr = server.accept()
        print(f"[Child] Connected from {addr}")
        with conn:
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            command = json.loads(data.decode())
            print(f"[Child] Scanning {command['target']} ports {command['start']}-{command['end']}")
            results = run_full_scan(command["target"], command["start"], command["end"])
            conn.sendall(json.dumps(results).encode())
            print(f"[Child] Done. Sent {len(results)} results.")

if __name__ == "__main__":
    start_child_server()