# mitigation/mitigator.py
from dotenv import load_dotenv
load_dotenv(override=True)

from datetime import datetime
from librouteros.exceptions import TrapError, ConnectionClosed
from mitigation.mikrotik_api import get_connection

BLACKLIST_NAME      = "skripsi-thanel-blacklist"  # DDOS & BRUTE-FORCE
SCAN_BLACKLIST_NAME = "skripsi-thanel-scan"        # PORT-SCAN
DROP_RULE_COMMENT   = "SkripsiThanel - drop blacklist"

ADDRESS_LIST = {
    "DDOS":        BLACKLIST_NAME,
    "BRUTE-FORCE": BLACKLIST_NAME,
    "PORT-SCAN":   SCAN_BLACKLIST_NAME,  # address-list terpisah
}

# Jenis serangan yang blok semua port (bukan per port)
BLOCK_ALL_PORT_TYPES = {"PORT-SCAN"}

DROP_ALL_KEY = "all/any"


class Mitigator:
    """
    Mitigasi otomatis serangan di MikroTik.

    Address-list:
    - skripsi-thanel-blacklist → DDOS & BRUTE-FORCE
    - skripsi-thanel-scan      → PORT-SCAN (blok semua port)

    Auto (dipanggil engine):
    - DDOS & BRUTE-FORCE : drop rule filter address-list + dst-port spesifik
    - PORT-SCAN          : satu drop rule tanpa filter port (blok IP total)

    Manual (untuk UI nanti):
    - Tutup/buka port
    - Hapus IP dari blacklist
    """

    def __init__(self):
        self._listed: set[str] = set()
        self._drop_rules_created: set[str] = set()
        self._closed_ports: set[int] = set()

    # ------------------------------------------------------------------
    # AUTO MITIGASI
    # ------------------------------------------------------------------

    def handle(self, alert: str, log: dict) -> None:
        attack_type = self._detect_type(alert)
        if not attack_type:
            return

        src_ip   = log["src_ip"]
        dst_port = log.get("dst_port", 0)
        proto    = log.get("proto", "TCP")

        ip_key   = f"{attack_type}:{src_ip}"
        port_key = DROP_ALL_KEY if attack_type in BLOCK_ALL_PORT_TYPES else f"{dst_port}/{proto.lower()}"

        if ip_key in self._listed and port_key in self._drop_rules_created:
            return

        try:
            if attack_type in BLOCK_ALL_PORT_TYPES:
                self._ensure_drop_rule_all(attack_type)
            else:
                self._ensure_drop_rule_port(dst_port, proto)

            if ip_key not in self._listed:
                address_list = ADDRESS_LIST[attack_type]
                print(f"[MITIGASI] {attack_type} dari {src_ip} — menambah ke {address_list}...")
                self._add_to_blacklist(src_ip, attack_type, log)
                self._listed.add(ip_key)
                print(f"[MITIGASI] ✅ {src_ip} ditambahkan ke {address_list}")

        except ConnectionError as e:
            print(f"[MITIGASI] ❌ Gagal konek ke MikroTik: {e}")
        except (TrapError, ConnectionClosed) as e:
            print(f"[MITIGASI] ❌ RouterOS error: {e}")
        except Exception as e:
            print(f"[MITIGASI] ❌ Error tidak terduga: {e}")

    def _ensure_drop_rule_all(self, attack_type: str) -> None:
        """
        Buat satu drop rule yang blok SEMUA port dari skripsi-thanel-scan.
        Untuk PORT-SCAN — IP yang scanning langsung diblok total.
        Hanya dibuat sekali.
        """
        if DROP_ALL_KEY in self._drop_rules_created:
            return

        address_list = ADDRESS_LIST[attack_type]  # skripsi-thanel-scan
        comment      = f"{DROP_RULE_COMMENT} [{attack_type}] all-port"

        api = get_connection()
        try:
            fw    = api.path("ip", "firewall", "filter")
            rules = list(fw)

            for rule in rules:
                if rule.get("comment", "") == comment:
                    self._drop_rules_created.add(DROP_ALL_KEY)
                    return

            rule_params = {
                "chain":            "input",
                "src-address-list": address_list,
                "action":           "drop",
                "comment":          comment,
            }
            if rules:
                first_id = rules[0].get(".id")
                if first_id:
                    rule_params["place-before"] = first_id

            fw.add(**rule_params)
            self._drop_rules_created.add(DROP_ALL_KEY)
            print(f"[MITIGASI] ✅ Drop rule {address_list} ALL PORT dibuat di posisi paling atas")
        finally:
            api.close()

    def _ensure_drop_rule_port(self, dst_port: int, proto: str) -> None:
        """
        Buat drop rule filter skripsi-thanel-blacklist + dst-port spesifik.
        Untuk DDOS dan BRUTE-FORCE.
        """
        rule_key = f"{dst_port}/{proto.lower()}"
        if rule_key in self._drop_rules_created:
            return

        comment = f"{DROP_RULE_COMMENT} port={dst_port}/{proto.upper()}"

        api = get_connection()
        try:
            fw    = api.path("ip", "firewall", "filter")
            rules = list(fw)

            for rule in rules:
                if rule.get("comment", "") == comment:
                    self._drop_rules_created.add(rule_key)
                    return

            rule_params = {
                "chain":            "input",
                "src-address-list": BLACKLIST_NAME,
                "protocol":         proto.lower(),
                "dst-port":         str(dst_port),
                "action":           "drop",
                "comment":          comment,
            }
            if rules:
                first_id = rules[0].get(".id")
                if first_id:
                    rule_params["place-before"] = first_id

            fw.add(**rule_params)
            self._drop_rules_created.add(rule_key)
            print(f"[MITIGASI] ✅ Drop rule {BLACKLIST_NAME} port {dst_port}/{proto.upper()} dibuat")
        finally:
            api.close()

    def _add_to_blacklist(self, src_ip: str, attack_type: str, log: dict) -> None:
        """
        Tambah src IP ke address-list sesuai jenis serangan.
        Format comment: [jenis serangan]-[waktu]-[port]-[protocol]
        """
        address_list = ADDRESS_LIST[attack_type]
        dst_port     = log.get("dst_port", 0)
        proto        = log.get("proto", "TCP")
        ts           = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        comment      = f"{attack_type}-{ts}-{dst_port}-{proto}"

        api = get_connection()
        try:
            existing = list(api.path("ip", "firewall", "address-list"))
            for entry in existing:
                if entry.get("list") == address_list and entry.get("address") == src_ip:
                    api.path("ip", "firewall", "address-list").update(
                        **{".id": entry[".id"], "comment": comment}
                    )
                    return

            api.path("ip", "firewall", "address-list").add(**{
                "list":    address_list,
                "address": src_ip,
                "comment": comment,
            })
        finally:
            api.close()

    # ------------------------------------------------------------------
    # MANUAL MITIGASI — untuk UI
    # ------------------------------------------------------------------

    def close_port(self, dst_port: int, proto: str = "tcp") -> bool:
        """Tutup port dengan DROP rule di posisi paling atas. Untuk UI."""
        if dst_port in self._closed_ports:
            print(f"[MITIGASI] Port {dst_port} sudah ditutup sebelumnya")
            return False

        ts      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        comment = f"manual-close port {dst_port} [{proto.upper()}] {ts}"

        try:
            api = get_connection()
            try:
                fw    = api.path("ip", "firewall", "filter")
                rules = list(fw)
                rule_params = {
                    "chain":    "input",
                    "protocol": proto.lower(),
                    "dst-port": str(dst_port),
                    "action":   "drop",
                    "comment":  comment,
                }
                if rules:
                    first_id = rules[0].get(".id")
                    if first_id:
                        rule_params["place-before"] = first_id
                fw.add(**rule_params)
            finally:
                api.close()

            self._closed_ports.add(dst_port)
            print(f"[MITIGASI] ✅ Port {dst_port} ditutup di posisi paling atas")
            return True

        except ConnectionError as e:
            print(f"[MITIGASI] ❌ Gagal konek: {e}")
            return False
        except (TrapError, ConnectionClosed) as e:
            print(f"[MITIGASI] ❌ RouterOS error: {e}")
            return False

    def open_port(self, dst_port: int) -> bool:
        """Buka kembali port yang ditutup manual. Untuk UI."""
        try:
            api = get_connection()
            try:
                fw    = api.path("ip", "firewall", "filter")
                rules = list(fw)
                found = False
                for rule in rules:
                    if f"manual-close port {dst_port}" in rule.get("comment", ""):
                        fw.remove(rule[".id"])
                        self._closed_ports.discard(dst_port)
                        found = True
                        break
            finally:
                api.close()

            if found:
                print(f"[MITIGASI] ✅ Port {dst_port} berhasil dibuka")
                return True
            else:
                print(f"[MITIGASI] Rule untuk port {dst_port} tidak ditemukan")
                return False

        except ConnectionError as e:
            print(f"[MITIGASI] ❌ Gagal konek: {e}")
            return False
        except (TrapError, ConnectionClosed) as e:
            print(f"[MITIGASI] ❌ RouterOS error: {e}")
            return False

    def remove_from_blacklist(self, src_ip: str, attack_type: str) -> bool:
        """Hapus IP dari address-list (unban). Untuk UI."""
        address_list = ADDRESS_LIST.get(attack_type)
        if not address_list:
            print(f"[MITIGASI] Jenis serangan tidak dikenal: {attack_type}")
            return False

        try:
            api = get_connection()
            try:
                entries = list(api.path("ip", "firewall", "address-list"))
                found   = False
                for entry in entries:
                    if entry.get("list") == address_list and entry.get("address") == src_ip:
                        api.path("ip", "firewall", "address-list").remove(entry[".id"])
                        self._listed.discard(f"{attack_type}:{src_ip}")
                        found = True
                        break
            finally:
                api.close()

            if found:
                print(f"[MITIGASI] ✅ {src_ip} dihapus dari {address_list}")
                return True
            else:
                print(f"[MITIGASI] {src_ip} tidak ditemukan di {address_list}")
                return False

        except ConnectionError as e:
            print(f"[MITIGASI] ❌ Gagal konek: {e}")
            return False
        except (TrapError, ConnectionClosed) as e:
            print(f"[MITIGASI] ❌ RouterOS error: {e}")
            return False

    # ------------------------------------------------------------------
    # HELPER
    # ------------------------------------------------------------------

    def _detect_type(self, alert: str) -> str | None:
        if "[DDOS]" in alert:
            return "DDOS"
        elif "[BRUTE-FORCE]" in alert:
            return "BRUTE-FORCE"
        elif "[PORT-SCAN]" in alert:
            return "PORT-SCAN"
        return None