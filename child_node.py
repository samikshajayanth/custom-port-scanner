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
            "port": port,
            "service": info[1],
            "version": info[2],
            "status": "OPEN"
        })
    return results

def start_child_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)

    print(f"[Child] Waiting for Parent on port {PORT}...")

    while True:
        conn, addr = server.accept()
        print(f"[Child] Connected from {addr}")

        data = conn.recv(4096)
        command = json.loads(data.decode())

        results = run_full_scan(
            command["target"],
            command["start"],
            command["end"]
        )

        conn.sendall(json.dumps(results).encode())
        conn.close()

if __name__ == "__main__":
    start_child_server()