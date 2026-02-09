# detectors/portscan.py
from collections import defaultdict, deque
from datetime import timedelta
from config import PORTSCAN_THRESHOLD, PORTSCAN_WINDOW

# debug
import json

class PortScanDetector:
    def __init__(self):
        self.ports = defaultdict(lambda: defaultdict(deque))

    def process(self, log):
        if not log:
            return None

        ip = log["src_ip"]
        port = log["dst_port"]
        now = log["timestamp"]

        self.ports[ip][port].append(now)

        active_ports = []
        for p, times in self.ports[ip].items():
            while times and now - times[0] > timedelta(seconds=PORTSCAN_WINDOW):
                times.popleft()
            if times:
                active_ports.append(p)

        if len(active_ports) >= PORTSCAN_THRESHOLD:
            return f"[ALERT] Port Scanning from {ip} ({len(active_ports)} ports)"
        # debug
        print(json.dumps(self.ports, default=str, indent=2))
        return None
