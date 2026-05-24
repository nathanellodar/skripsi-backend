# mitigation/mitigator.py
from datetime import datetime
from librouteros.exceptions import TrapError, ConnectionClosed
from mikrotik_api import get_connection


class Mitigator:
    """
    Mitigasi otomatis serangan dengan menutup port di MikroTik.
    - DDOS        → tutup dst_port yang dibanjiri paket
    - BRUTE-FORCE → tutup dst_port yang di-bruteforce
    """

    def __init__(self):
        self._closed_ports: set[int] = set()

    def handle(self, alert: str, log: dict) -> None:
        attack_type = self._detect_type(alert)
        if not attack_type:
            return

        dst_port = log["dst_port"]
        if dst_port == 0:
            print(f"[MITIGASI] ⚠️  Port tidak diketahui, skip")
            return

        if dst_port in self._closed_ports:
            return

        print(f"[MITIGASI] {attack_type} di port {dst_port} — menutup port...")

        try:
            self._close_port(dst_port, attack_type)
            self._closed_ports.add(dst_port)
            print(f"[MITIGASI] ✅ Port {dst_port} berhasil ditutup ({attack_type})")
        except ConnectionError as e:
            print(f"[MITIGASI] ❌ Gagal konek ke MikroTik: {e}")
        except (TrapError, ConnectionClosed) as e:
            print(f"[MITIGASI] ❌ RouterOS error: {e}")
        except Exception as e:
            print(f"[MITIGASI] ❌ Error tidak terduga: {e}")

    def _detect_type(self, alert: str) -> str | None:
        if "[DDOS]" in alert:
            return "DDOS"
        elif "[BRUTE-FORCE]" in alert:
            return "BRUTE-FORCE"
        return None

    def _close_port(self, dst_port: int, attack_type: str) -> None:
        """Tutup port dengan tambah rule DROP via RouterOS API."""
        comment = (
            f"auto-close port {dst_port} - SkripsiThanel"
            f"[{attack_type}] "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        api = get_connection()
        try:
            fw_filter = api.path("ip", "firewall", "filter")
            fw_filter.add(**{
                "chain":        "input",
                "protocol":     "tcp",
                "dst-port":     str(dst_port),
                "action":       "drop",
                "comment":      comment,
                "place-before": "0",
            })
        finally:
            api.close()

    def open_port(self, dst_port: int) -> None:
        """Buka kembali port yang sebelumnya ditutup otomatis."""
        api = get_connection()
        try:
            fw_filter = api.path("ip", "firewall", "filter")
            for rule in fw_filter:
                comment = rule.get("comment", "")
                if f"auto-close port {dst_port}" in comment:
                    fw_filter.remove(rule[".id"])
                    self._closed_ports.discard(dst_port)
                    print(f"[MITIGASI] ✅ Port {dst_port} berhasil dibuka kembali")
                    return
            print(f"[MITIGASI] Rule untuk port {dst_port} tidak ditemukan")
        finally:
            api.close()