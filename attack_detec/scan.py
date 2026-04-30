# detectors/portscan.py
from collections import defaultdict, deque
from datetime import timedelta
from config import PORTSCAN_THRESHOLD, PORTSCAN_WINDOW

class PortScanDetector:
    def __init__(self):
        # Changed structure: ip -> deque of ports (with timestamps)
        self.ip_ports = defaultdict(lambda: defaultdict(deque))

    def process(self, log):
        if not log:
            return None

        ip = log["src_ip"]
        port = log["dst_port"]
        now = log["timestamp"]

        # Add port with timestamp
        self.ip_ports[ip][port].append(now)

        # Clean old entries and count active ports for this IP
        active_ports = []
        for p, times in self.ip_ports[ip].items():
            # Remove old entries
            while times and now - times[0] > timedelta(seconds=PORTSCAN_WINDOW):
                times.popleft()
            # If there are recent entries, count this port as active
            if times:
                active_ports.append(p)

        if len(active_ports) >= PORTSCAN_THRESHOLD:
            return f"[ALERT] Port Scanning from {ip} ({len(active_ports)} ports)"
        
        return None
