# alert_writer.py
import os
from datetime import datetime

ALERT_DIR = "alerts"

# Map keyword di alert string → nama file output
ALERT_FILE_MAP = {
    "[BRUTE-FORCE]": "brute-force.txt",
    "[PORT-SCAN]":   "port-scan.txt",
    "[DDOS]":        "ddos.txt",
}

def _get_filepath(alert: str) -> str | None:
    for keyword, filename in ALERT_FILE_MAP.items():
        if keyword in alert:
            return os.path.join(ALERT_DIR, filename)
    return None

def write_alert(alert: str, log: dict) -> None:
    """Tulis satu alert ke file yang sesuai."""
    filepath = _get_filepath(alert)
    if not filepath:
        return

    os.makedirs(ALERT_DIR, exist_ok=True)
    ts = log["timestamp"].strftime("%Y-%m-%d %H:%M:%S")

    with open(filepath, "a") as f:
        f.write(f"[{ts}] {alert}\n")