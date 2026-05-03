# attack_detec/brute.py
from collections import defaultdict, deque
from datetime import timedelta

from attack_detec.base import BaseDetector
from config import BRUTE_FORCE_PORTS, BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW

PORT_LABEL = {
    22:   "SSH",
    23:   "Telnet",
    3389: "RDP",
    8291: "Winbox",
}

class BruteForceDetector(BaseDetector):
    name = "BruteForce"

    def __init__(self):
        # { ip: deque of timestamps }
        self.hits: dict[str, deque] = defaultdict(deque)
    
    def process(self, log: dict) -> str | None:
        if log.get("prefix") != "[FW]":
            return None
        
        if log["dst_port"] not in BRUTE_FORCE_PORTS:
            return None

        ip  = log["src_ip"]
        now = log["timestamp"]
        q   = self.hits[ip]

        q.append(now)

        # Buang entri di luar window
        cutoff = now - timedelta(seconds=BRUTE_FORCE_WINDOW)
        while q and q[0] < cutoff:
            q.popleft()

        if len(q) >= BRUTE_FORCE_THRESHOLD:
            label = PORT_LABEL.get(log["dst_port"], f"port {log['dst_port']}")
            return (
                f"[BRUTE-FORCE] src={ip} "
                f"port={log['dst_port']} "
                f"target={label} "
                f"hits={len(q)} in {BRUTE_FORCE_WINDOW}s"
            )

        return None