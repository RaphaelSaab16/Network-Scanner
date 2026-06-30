from __future__ import annotations

import csv
import json
import os


def export_results(data: list[dict], filepath: str) -> None:
    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".csv":
        _export_csv(data, filepath)
    elif ext == ".json":
        _export_json(data, filepath)
    else:
        raise ValueError(f"Unsupported format '{ext}'. Use .csv or .json")


def _export_csv(data: list[dict], filepath: str) -> None:
    rows = []
    for entry in data:
        host = entry.get("host", "")
        mac = entry.get("mac", "")
        ports = entry.get("ports", [])
        if ports:
            for p in ports:
                rows.append({
                    "host": host,
                    "mac": mac,
                    "port": p["port"],
                    "state": p["state"],
                    "service": p["service"],
                })
        else:
            rows.append({"host": host, "mac": mac, "port": "", "state": "", "service": ""})

    fieldnames = ["host", "mac", "port", "state", "service"]
    with open(filepath, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Saved to {filepath}")


def _export_json(data: list[dict], filepath: str) -> None:
    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2)
    print(f"[+] Saved to {filepath}")
