#!/usr/bin/env python3
"""Network Scanner — ARP host discovery and TCP port scanning."""
from __future__ import annotations

import argparse
import os
import sys

from discovery import arp_scan
from export import export_results
from scanner import COMMON_PORTS, scan_ports


def _parse_ports(spec: str) -> list[int]:
    """Accept '1-1024', '80,443', or mixed '22,80,8000-8100'."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network-scanner",
        description="ARP host discovery and TCP port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  sudo python main.py --target 192.168.1.0/24
  python main.py --target 192.168.1.1 --ports 1-1024
  python main.py --target 192.168.1.1 --ports 22,80,443,8080
  python main.py --target 192.168.1.1 --export results.json
  sudo python main.py --target 192.168.1.0/24 --export hosts.csv
        """,
    )
    parser.add_argument("--target", required=True,
                        help="IP address, hostname, or CIDR subnet (e.g. 192.168.1.0/24)")
    parser.add_argument("--ports",
                        help="Port range or list (e.g. 1-1024 or 22,80,443). "
                             "Defaults to built-in common-ports list.")
    parser.add_argument("--threads", type=int, default=100,
                        help="Worker threads for port scanning (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Per-port socket timeout in seconds (default: 1.0)")
    parser.add_argument("--export", metavar="FILE",
                        help="Write results to FILE (.csv or .json)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Also show closed ports")
    return parser


def _run_arp_scan(args: argparse.Namespace) -> list[dict]:
    if os.geteuid() != 0:
        sys.exit("[-] ARP scanning requires root privileges — run with sudo.")

    print(f"[*] ARP scan → {args.target}")
    try:
        hosts = arp_scan(args.target)
    except Exception as exc:
        sys.exit(f"[-] ARP scan failed: {exc}")

    if not hosts:
        print("[-] No live hosts found.")
        return []

    print(f"[+] {len(hosts)} host(s) discovered:\n")
    for h in hosts:
        print(f"    {h['ip']:<18} {h['mac']}")
    print()

    return [{"host": h["ip"], "mac": h["mac"], "ports": []} for h in hosts]


def _run_port_scan(args: argparse.Namespace) -> list[dict]:
    ports = _parse_ports(args.ports) if args.ports else COMMON_PORTS
    print(f"[*] Port scan → {args.target}  ({len(ports)} ports, {args.threads} threads)")

    results = scan_ports(
        args.target,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose,
    )

    open_ports = [p for p in results if p["state"] == "open"]
    print(f"[+] {len(open_ports)} open port(s) on {args.target}:\n")

    for p in results:
        state_label = "open  " if p["state"] == "open" else "closed"
        if p["state"] == "open" or args.verbose:
            print(f"    {p['port']:<7} {state_label}  {p['service']}")
    print()

    return [{"host": args.target, "mac": "", "ports": results}]


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    is_subnet = "/" in args.target
    data = _run_arp_scan(args) if is_subnet else _run_port_scan(args)

    if args.export and data:
        try:
            export_results(data, args.export)
        except ValueError as exc:
            sys.exit(f"[-] Export error: {exc}")


if __name__ == "__main__":
    main()
