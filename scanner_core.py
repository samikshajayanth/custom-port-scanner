import asyncio
import time
import socket
import struct
import random
import ipaddress


# ─── IP RANGE EXPANDER ────────────────────────────────────────────────────────

def expand_ip_range(ip_input: str):
    """
    Accepts:
      - Single IP:   "192.168.1.5"
      - CIDR:        "192.168.1.0/24"
      - Dash range:  "192.168.1.1-192.168.1.10"
    Returns list of IP strings.
    """
    ip_input = ip_input.strip()
    if '-' in ip_input:
        start_str, end_str = ip_input.split('-')
        start = ipaddress.IPv4Address(start_str.strip())
        end   = ipaddress.IPv4Address(end_str.strip())
        return [str(ipaddress.IPv4Address(i)) for i in range(int(start), int(end) + 1)]
    elif '/' in ip_input:
        return [str(ip) for ip in ipaddress.IPv4Network(ip_input, strict=False).hosts()]
    else:
        return [ip_input]


# ─── TCP CONNECT SCAN ─────────────────────────────────────────────────────────

async def scan_port(ip: str, port: int, timeout: float = 1.0, retries: int = 2):
    for attempt in range(retries):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return (port, True)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            if attempt == retries - 1:
                return (port, False)
            await asyncio.sleep(0.1)
    return (port, False)


async def scan_range(ip: str, start_port: int, end_port: int,
                     concurrency: int = 200, timeout: float = 1.0):
    semaphore = asyncio.Semaphore(concurrency)
    open_ports = []
    start_time = time.time()

    async def bounded_scan(port):
        async with semaphore:
            result = await scan_port(ip, port, timeout)
            if result[1]:
                open_ports.append(result[0])

    tasks = [bounded_scan(p) for p in range(start_port, end_port + 1)]
    await asyncio.gather(*tasks)

    elapsed = time.time() - start_time
    print(f"[TCP] {ip} — {end_port - start_port + 1} ports in {elapsed:.2f}s | Open: {sorted(open_ports)}")
    return sorted(open_ports)


# ─── UDP SCAN ─────────────────────────────────────────────────────────────────

def udp_scan_port(ip: str, port: int, timeout: float = 1.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x00", (ip, port))
        sock.recvfrom(1024)
        return (port, True)
    except socket.timeout:
        # No ICMP error = likely open|filtered
        return (port, True)
    except Exception:
        return (port, False)
    finally:
        sock.close()


def udp_scan_range(ip: str, start_port: int, end_port: int, timeout: float = 1.0):
    open_ports = []
    start_time = time.time()
    for port in range(start_port, end_port + 1):
        result = udp_scan_port(ip, port, timeout)
        if result[1]:
            open_ports.append(port)
    elapsed = time.time() - start_time
    print(f"[UDP] {ip} — {end_port - start_port + 1} ports in {elapsed:.2f}s | Open: {open_ports}")
    return open_ports


# ─── SYN SCAN (requires sudo on Linux) ───────────────────────────────────────

def _checksum(data: bytes) -> int:
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += (data[i] << 8) + data[i + 1]
    if len(data) % 2:
        s += data[-1] << 8
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return ~s & 0xFFFF


def syn_scan_port(target_ip: str, port: int, timeout: float = 1.5) -> bool:
    try:
        src_ip = socket.gethostbyname(socket.gethostname())
        src_port = random.randint(1024, 65535)

        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.settimeout(timeout)

        # IP header
        ip_hdr = struct.pack('!BBHHHBBH4s4s',
            0x45, 0, 40,
            random.randint(1, 65535), 0,
            64, socket.IPPROTO_TCP, 0,
            socket.inet_aton(src_ip),
            socket.inet_aton(target_ip)
        )

        # TCP SYN header (checksum=0 first)
        tcp_hdr = struct.pack('!HHLLBBHHH',
            src_port, port, 0, 0, 0x50, 0x02, 1024, 0, 0)

        # Pseudo header for checksum
        pseudo = struct.pack('!4s4sBBH',
            socket.inet_aton(src_ip),
            socket.inet_aton(target_ip),
            0, socket.IPPROTO_TCP, len(tcp_hdr)
        )
        tcp_chk = _checksum(pseudo + tcp_hdr)
        tcp_hdr = struct.pack('!HHLLBBHHH',
            src_port, port, 0, 0, 0x50, 0x02, 1024, tcp_chk, 0)

        s.sendto(ip_hdr + tcp_hdr, (target_ip, 0))

        while True:
            raw = s.recv(1024)
            ip_len = (raw[0] & 0x0F) * 4
            tcp = raw[ip_len:]
            if len(tcp) < 14:
                continue
            r_port = struct.unpack('!H', tcp[0:2])[0]
            flags  = tcp[13]
            if r_port == port:
                s.close()
                return bool(flags & 0x12 == 0x12)   # SYN-ACK = open
    except PermissionError:
        print("[SYN] Permission denied — run as sudo/root")
        return False
    except Exception:
        return False


def syn_scan_range(ip: str, start_port: int, end_port: int) -> list:
    open_ports = []
    start_time = time.time()
    for port in range(start_port, end_port + 1):
        if syn_scan_port(ip, port):
            open_ports.append(port)
            print(f"  [SYN] {ip}:{port} OPEN")
    elapsed = time.time() - start_time
    print(f"[SYN] {ip} — {end_port - start_port + 1} ports in {elapsed:.2f}s | Open: {open_ports}")
    return open_ports


# ─── MULTI-HOST ENTRY POINT ───────────────────────────────────────────────────

async def scan_multiple_hosts(ip_input: str, start_port: int, end_port: int,
                               scan_type: str = "tcp",
                               concurrency: int = 100,
                               timeout: float = 1.0) -> dict:
    """
    Returns: { "192.168.1.1": [22, 80], "192.168.1.2": [22, 443], ... }
    scan_type: "tcp" | "udp" | "syn"
    """
    hosts = expand_ip_range(ip_input)
    all_results = {}

    for host in hosts:
        print(f"\n[*] Scanning {host} — type={scan_type.upper()}")
        if scan_type == "tcp":
            ports = await scan_range(host, start_port, end_port, concurrency, timeout)
        elif scan_type == "udp":
            ports = udp_scan_range(host, start_port, end_port, timeout)
        elif scan_type == "syn":
            ports = syn_scan_range(host, start_port, end_port)
        else:
            ports = []
        all_results[host] = ports

    return all_results


# ─── QUICK TEST ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    results = asyncio.run(
        scan_multiple_hosts("127.0.0.1", 1, 1024, scan_type="tcp")
    )
    for host, ports in results.items():
        print(f"{host}: {ports}")