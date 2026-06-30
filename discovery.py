from __future__ import annotations

import ipaddress
from scapy.all import ARP, Ether, srp


def arp_scan(subnet: str, timeout: int = 2) -> list[dict]:
    """Return live hosts on subnet as list of {ip, mac} dicts."""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid subnet '{subnet}': {exc}") from exc

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    answered, _ = srp(packet, timeout=timeout, verbose=0)

    return [
        {"ip": received.psrc, "mac": received.hwsrc}
        for _, received in answered
    ]
