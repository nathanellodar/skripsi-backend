# attack_detec/ddos.py
from collections import defaultdict, deque
from datetime import timedelta

from attack_detec.base import BaseDetector
from config import DDOS_THRESHOLD, DDOS_WINDOW


class DDoSDetector(BaseDetector):
    name = "DDoS"

    def __init__(self):
        # { ip: deque of timestamps }
        self.hits: dict[str, deque] = defaultdict(deque)

    def process(self, log: dict) -> str | None:
        ip  = log["src_ip"]
        now = log["timestamp"]
        q   = self.hits[ip]

        q.append(now)

        cutoff = now - timedelta(seconds=DDOS_WINDOW)
        while q and q[0] < cutoff:
            q.popleft()

        if len(q) >= DDOS_THRESHOLD:
            return (
                f"[DDOS] src={ip} "
                f"packets={len(q)} in {DDOS_WINDOW}s"
            )

        return None