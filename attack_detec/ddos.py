# detectors/ddos.py
from collections import defaultdict, deque
from datetime import timedelta
from config import DDOS_THRESHOLD, DDOS_WINDOW

class DDoSDetector:
    def __init__(self):
        self.hits = defaultdict(deque)

    def process(self, log):
        if not log:
            return None

        ip = log["src_ip"]
        now = log["timestamp"]

        q = self.hits[ip]
        q.append(now)

        while q and now - q[0] > timedelta(seconds=DDOS_WINDOW):
            q.popleft()

        if len(q) >= DDOS_THRESHOLD:
            return f"[ALERT] DDoS/Flood from {ip}"

        return None
