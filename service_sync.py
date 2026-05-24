# service_sync.py
"""
Sinkronisasi service/port dari MikroTik router (ip/service) ke database.

Fitur:
- Fetch semua service dari router via API
- Simpan/update ke tabel router_services
- Deteksi perubahan port → catat di port_change_log
- Sediakan fungsi untuk load port brute force dari DB
"""

from config import BRUTE_FORCE_SERVICES
from mitigation.mikrotik_api import get_connection as mt_conn
from db import get_connection as db_conn


# Mapping nama service MikroTik ke label yang lebih readable
SERVICE_LABEL_MAP = {
    "ssh":     "SSH",
    "telnet":  "Telnet",
    "winbox":  "Winbox",
    "ftp":     "FTP",
    "api":     "RouterOS API",
    "api-ssl": "RouterOS API-SSL",
    "www":     "HTTP",
    "www-ssl": "HTTPS",
}


def sync_services_from_router() -> list[dict]:
    """
    Fetch ip/service dari MikroTik, compare dengan DB, dan update.

    Hanya service STATIC yang disimpan (dynamic di-skip karena duplikat
    dan auto-generated oleh router).

    Return list perubahan yang terdeteksi:
    [{"service": "ssh", "old_port": 22, "new_port": 1177}, ...]
    """
    print("[SYNC] Mengambil daftar service dari router...")

    changes = []

    try:
        api = mt_conn()
        services = list(api.path("ip", "service"))
        api.close()
    except Exception as e:
        print(f"[SYNC] ❌ Gagal ambil service dari router: {e}")
        return changes

    conn = db_conn()
    try:
        cur = conn.cursor()

        # Ambil data existing dari DB
        cur.execute("SELECT service_name, port, disabled FROM router_services")
        existing = {row[0]: {"port": row[1], "disabled": row[2]} for row in cur.fetchall()}

        # Track service yang sudah diproses untuk skip duplikat
        seen = set()

        for svc in services:
            name     = svc.get("name", "").strip().lower()
            port     = int(svc.get("port", 0))
            disabled_raw = svc.get("disabled", False)
            disabled = 1 if (disabled_raw is True or disabled_raw == "true") else 0

            if not name or port == 0:
                continue

            # Skip service dynamic (flag D di MikroTik)
            # Dynamic entries adalah service auto-generated oleh router
            dynamic_raw = svc.get("dynamic", False)
            is_dynamic  = dynamic_raw is True or dynamic_raw == "true"
            if is_dynamic:
                continue

            # Skip jika sudah diproses (nama yang sama)
            if name in seen:
                continue
            seen.add(name)

            if name in existing:
                old_port     = existing[name]["port"]
                old_disabled = existing[name]["disabled"]

                # Cek apakah port berubah
                if old_port != port:
                    print(f"[SYNC] ⚠️  Port berubah: {name} {old_port} → {port}")
                    changes.append({
                        "service": name,
                        "old_port": old_port,
                        "new_port": port,
                    })

                    # Catat di port_change_log
                    cur.execute(
                        "INSERT INTO port_change_log (service_name, old_port, new_port) VALUES (?, ?, ?)",
                        (name, old_port, port),
                    )

                # Update jika port atau disabled berubah
                if old_port != port or old_disabled != disabled:
                    cur.execute(
                        "UPDATE router_services SET port=?, disabled=?, synced_at=NOW() WHERE service_name=?",
                        (port, disabled, name),
                    )
            else:
                # Service baru — insert
                print(f"[SYNC] ➕ Service baru: {name} port={port}")
                cur.execute(
                    "INSERT INTO router_services (service_name, port, protocol, disabled) VALUES (?, ?, 'tcp', ?)",
                    (name, port, disabled),
                )

        conn.commit()

        print(f"[SYNC] ✅ {len(seen)} service static disinkronkan, {len(changes)} perubahan port terdeteksi")

    except Exception as e:
        conn.rollback()
        print(f"[SYNC] ❌ Gagal sync ke database: {e}")
    finally:
        conn.close()

    return changes


def get_brute_force_ports() -> list[int]:
    """
    Ambil daftar port aktif dari DB yang relevan untuk deteksi brute force.
    Hanya service yang ada di BRUTE_FORCE_SERVICES dan tidak disabled.

    Fallback ke default ports jika DB kosong/error.
    """
    fallback = [22, 23, 8291, 21, 8728, 8729]

    try:
        conn = db_conn()
        try:
            cur = conn.cursor()
            # Build placeholders untuk IN clause
            placeholders = ", ".join("?" for _ in BRUTE_FORCE_SERVICES)
            cur.execute(
                f"SELECT port FROM router_services WHERE service_name IN ({placeholders}) AND disabled = 0",
                tuple(BRUTE_FORCE_SERVICES),
            )
            ports = [row[0] for row in cur.fetchall()]
            return ports if ports else fallback
        finally:
            conn.close()
    except Exception as e:
        print(f"[SYNC] ⚠️  Gagal load port dari DB, pakai fallback: {e}")
        return fallback


def get_port_labels() -> dict[int, str]:
    """
    Ambil mapping {port: label} dari DB untuk semua service.
    Digunakan oleh BruteForceDetector untuk menampilkan label di alert.
    """
    fallback = {22: "SSH", 23: "Telnet", 3389: "RDP", 8291: "Winbox", 21: "FTP"}

    try:
        conn = db_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT service_name, port FROM router_services WHERE disabled = 0")
            labels = {}
            for row in cur.fetchall():
                service_name = row[0]
                port         = row[1]
                label        = SERVICE_LABEL_MAP.get(service_name, service_name.upper())
                labels[port] = label
            return labels if labels else fallback
        finally:
            conn.close()
    except Exception as e:
        print(f"[SYNC] ⚠️  Gagal load label dari DB, pakai fallback: {e}")
        return fallback


def get_all_services() -> list[dict]:
    """
    Ambil semua service dari DB.
    Dipakai oleh API endpoint GET /services/ports.
    """
    conn = db_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, service_name, port, protocol, disabled, synced_at FROM router_services ORDER BY port"
        )
        return [
            {
                "id": row[0],
                "service_name": row[1],
                "port": row[2],
                "protocol": row[3],
                "disabled": bool(row[4]),
                "synced_at": row[5],
            }
            for row in cur.fetchall()
        ]
    finally:
        conn.close()


def get_port_changes(limit: int = 50) -> list[dict]:
    """
    Ambil history perubahan port dari port_change_log.
    Dipakai oleh API endpoint GET /services/changes.
    """
    conn = db_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, service_name, old_port, new_port, changed_at "
            "FROM port_change_log ORDER BY changed_at DESC LIMIT ?",
            (limit,),
        )
        return [
            {
                "id": row[0],
                "service_name": row[1],
                "old_port": row[2],
                "new_port": row[3],
                "changed_at": row[4],
            }
            for row in cur.fetchall()
        ]
    finally:
        conn.close()
