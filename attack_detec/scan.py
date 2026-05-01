# attack_detec/scan.py
from collections import defaultdict, deque
from datetime import timedelta

from attack_detec.base import BaseDetector
from config import PORTSCAN_THRESHOLD, PORTSCAN_WINDOW


class PortScanDetector(BaseDetector):
    name = "PortScan"

    def __init__(self):
        # { ip: { port: deque of timestamps } }
        self.ip_ports: dict[str, dict[int, deque]] = defaultdict(lambda: defaultdict(deque))

    def process(self, log: dict) -> str | None:
        # Port scan biasanya TCP SYN atau UDP ke banyak port
        if log["proto"] not in ("TCP", "UDP"):
            return None

        ip   = log["src_ip"]
        port = log["dst_port"]
        now  = log["timestamp"]

        self.ip_ports[ip][port].append(now)

        # Hitung port aktif dalam window
        cutoff      = now - timedelta(seconds=PORTSCAN_WINDOW)
        active_ports = []

        for p, times in self.ip_ports[ip].items():
            while times and times[0] < cutoff:
                times.popleft()
            if times:
                active_ports.append(p)

        if len(active_ports) >= PORTSCAN_THRESHOLD:
            ports_str = ",".join(str(p) for p in sorted(active_ports))
            return (
                f"[PORT-SCAN] src={ip} "
                f"ports={len(active_ports)} ({ports_str}) "
                f"in {PORTSCAN_WINDOW}s"
            )

        return None