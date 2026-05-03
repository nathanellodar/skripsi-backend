# alert_writer.py
import os
from datetime import datetime

ALERT_DIR = "alerts"

ALERT_FILE_MAP = {
    "[BRUTE-FORCE]": "brute-force.txt",
    "[PORT-SCAN]":   "port-scan.txt",
    "[DDOS]":        "ddos.txt",
}

# key: (filename, src_ip, "YYYY-MM-DD HH") → sudah ditulis di jam itu
_written: set[tuple] = set()


def _get_filename(alert: str) -> str | None:
    for keyword, filename in ALERT_FILE_MAP.items():
        if keyword in alert:
            return filename
    return None


def write_alert(alert: str, log: dict) -> None:
    filename = _get_filename(alert)
    if not filename:
        return

    src_ip    = log["src_ip"]
    ts        = log["timestamp"]
    hour_key  = ts.strftime("%Y-%m-%d %H")        # per jam
    dedup_key = (filename, src_ip, hour_key)

    if dedup_key in _written:
        return  # IP ini sudah dicatat di jam yang sama, skip

    # Tulis ke file
    os.makedirs(ALERT_DIR, exist_ok=True)
    ts_str   = ts.strftime("%Y-%m-%d %H:%M:%S")
    filepath = os.path.join(ALERT_DIR, filename)

    with open(filepath, "a") as f:
        f.write(f"[{ts_str}] {alert}\n")

    _written.add(dedup_key)