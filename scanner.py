from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 27017,
]


def _service_name(port: int) -> str:
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def _scan_port(host: str, port: int, timeout: float) -> dict:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            open_ = sock.connect_ex((host, port)) == 0
    except OSError:
        open_ = False

    return {
        "port": port,
        "state": "open" if open_ else "closed",
        "service": _service_name(port) if open_ else "unknown",
    }


def scan_ports(
    host: str,
    ports: list[int] = None,
    threads: int = 100,
    timeout: float = 1.0,
    verbose: bool = False,
) -> list[dict]:
    """Scan ports on host; returns results sorted by port number."""
    target_ports = ports if ports is not None else COMMON_PORTS

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_scan_port, host, p, timeout): p for p in target_ports}
        for future in as_completed(futures):
            result = future.result()
            if result["state"] == "open" or verbose:
                results.append(result)

    results.sort(key=lambda r: r["port"])
    return results
