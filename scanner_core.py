import asyncio
import time

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
    print(f"[Scanner] Scanned {end_port - start_port + 1} ports in {elapsed:.2f}s")
    print(f"[Scanner] Open ports: {sorted(open_ports)}")
    return sorted(open_ports)

if __name__ == "__main__":
    asyncio.run(scan_range("127.0.0.1", 1, 1024))