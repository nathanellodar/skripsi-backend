# detectors/brute.py
from collections import defaultdict, deque
from datetime import timedelta
from config import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW

class BruteForceDetector:
    def __init__(self):
        self.hits = defaultdict(deque)

    def process(self, log):
        if not log:
            return None

        if log["dst_port"] != 22 or log["action"] != "drop":
            return None

        ip = log["src_ip"]
        now = log["timestamp"]

        q = self.hits[ip]
        q.append(now)

        while q and now - q[0] > timedelta(seconds=BRUTE_FORCE_WINDOW):
            q.popleft()

        if len(q) >= BRUTE_FORCE_THRESHOLD:
            return f"[ALERT] SSH Brute Force from {ip}"

        return None
