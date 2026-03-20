import socket
import re
from service_map import SERVICE_MAP, PORT_PROBES

def grab_banner(ip: str, port: int, timeout: float = 2.0) -> dict:
    result = {
        "port":    port,
        "service": SERVICE_MAP.get(port, "Unknown"),
        "banner":  "",
        "version": "Unknown"
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            probe = PORT_PROBES.get(port, b"")
            if probe:
                s.sendall(probe)
            banner_bytes = s.recv(1024)
            result["banner"] = banner_bytes.decode("utf-8", errors="ignore").strip()
    except (socket.timeout, ConnectionRefusedError, OSError):
        result["banner"] = "No banner received"
        return result

    result["version"] = detect_version(result["banner"])
    return result


def detect_version(banner: str) -> str:
    patterns = [
        r"SSH-[\d.]+-[\w._]+",
        r"Apache[/ ]([\d.]+)",
        r"nginx[/ ]([\d.]+)",
        r"Microsoft-IIS[/ ]([\d.]+)",
        r"vsftpd ([\d.]+)",
        r"FileZilla Server ([\d.]+)",
        r"MySQL ([\d.]+)",
        r"PostgreSQL ([\d.]+)",
        r"220[- ]([^\r\n]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(0)
    if banner and banner != "No banner received":
        return banner.split("\n")[0][:60]
    return "Unknown"

if __name__ == "__main__":
    for port in [22, 80, 8080, 3306]:
        info = grab_banner("127.0.0.1", port)
        print(f"Port {info['port']:5} | {info['service']:15} | {info['version']}")