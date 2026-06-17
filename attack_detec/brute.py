# attack_detec/brute.py
from collections import defaultdict, deque
from datetime import timedelta

from attack_detec.base import BaseDetector
from config import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW


class BruteForceDetector(BaseDetector):
    name = "BruteForce"

    def __init__(self):
        # { ip: deque of timestamps }
        self.hits: dict[str, deque] = defaultdict(deque)
        self._load_ports()

    def _load_ports(self):
        """Load daftar port dan label dari database (sinkron dengan router)."""
        from service_sync import get_brute_force_ports, get_port_labels
        self.watched_ports = set(get_brute_force_ports())
        self.port_labels   = get_port_labels()
        print(f"[BRUTE] Loaded ports: {self.watched_ports}")
        print(f"[BRUTE] Port labels: {self.port_labels}")

    def reload_ports(self):
        """Reload port saat ada perubahan dari router. Dipanggil setelah sync."""
        self._load_ports()
        print(f"[BRUTE] ✅ Port list diperbarui: {self.watched_ports}")

    def process(self, log: dict) -> str | None:
        if log.get("prefix") != "[FW]":
            return None

        if log["dst_port"] not in self.watched_ports:
            return None

        ip  = log["src_ip"]
        now = log["timestamp"]
        q   = self.hits[ip]

        q.append(now)

        cutoff = now - timedelta(seconds=BRUTE_FORCE_WINDOW)
        while q and q[0] < cutoff:
            q.popleft()

        # sementara tambah ini
        print(f"[DEBUG BRUTE] ip={ip} port={log['dst_port']} service={self.port_labels.get(log['dst_port'], 'unknown')} hits={len(q)} threshold={BRUTE_FORCE_THRESHOLD}")

        if len(q) >= BRUTE_FORCE_THRESHOLD:
            label = self.port_labels.get(log["dst_port"], f"port {log['dst_port']}")
            return (
                f"[BRUTE-FORCE] src={ip} "
                f"port={log['dst_port']} "
                f"target={label} "
                f"hits={len(q)} in {BRUTE_FORCE_WINDOW}s"
            )

        return None