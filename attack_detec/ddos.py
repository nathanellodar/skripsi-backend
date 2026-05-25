# attack_detec/ddos.py
from collections import defaultdict, deque
from datetime import timedelta

from attack_detec.base import BaseDetector
from config import DDOS_THRESHOLD, DDOS_WINDOW


class DDoSDetector(BaseDetector):
    name = "DDoS"

    def __init__(self):
        # { dst_port: deque of timestamps } — hitung per port yang diserang
        self.hits: dict[int, deque] = defaultdict(deque)

    def process(self, log: dict) -> str | None:
        if log.get("prefix") != "[FW]":
            return None

        dst_port = log["dst_port"]
        now      = log["timestamp"]
        q        = self.hits[dst_port]

        q.append(now)

        cutoff = now - timedelta(seconds=DDOS_WINDOW)
        while q and q[0] < cutoff:
            q.popleft()

        if len(q) >= DDOS_THRESHOLD:
            return (
                f"[DDOS] dst_port={dst_port} "
                f"packets={len(q)} in {DDOS_WINDOW}s"
            )

        return None