# run.py
import threading
import asyncio
import uvicorn

from api.terminal import terminal_broadcaster
from db import init_db
from get_log import follow
from parser import parse_log
from engine import DetectionEngine
from alert_writer import write_alert
from mitigation import mitigator
from api.app import app
from api.routes.ports import set_mitigator
from api.routes.services import set_engine
from service_sync import sync_services_from_router


def sync_device_info() -> None:
    """
    Fetch informasi router dari MikroTik saat startup dan simpan ke DB.
    Mengambil: brand (hardcode MikroTik), model, identity, public IP.
    """
    from mitigation.mikrotik_api import get_connection as mt_conn
    from db import get_connection as db_conn

    print("[DEVICE] Mengambil informasi router dari MikroTik...")

    try:
        api = mt_conn()

        # Ambil identity router
        identity_data = list(api.path("system", "identity"))
        identity = identity_data[0].get("name", "unknown") if identity_data else "unknown"

        # Ambil model dari resource
        resource_data = list(api.path("system", "resource"))
        resource = resource_data[0] if resource_data else {}
        board_name = resource.get("board-name", "unknown")

        # Ambil IP publik dari interface WAN (ether1)
        ip_data = list(api.path("ip", "address"))
        public_ip = "unknown"
        for entry in ip_data:
            iface = entry.get("interface", "")
            if "ether1" in iface or "WAN" in iface.upper() or "TELKOM" in iface.upper():
                public_ip = entry.get("address", "unknown").split("/")[0]
                break

        api.close()

        # Simpan ke DB
        conn = db_conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT id FROM device_info LIMIT 1")
            existing = cur.fetchone()

            if existing:
                cur.execute(
                    "UPDATE device_info SET brand=?, model=?, identity=?, public_ip=? WHERE id=?",
                    ("MikroTik", board_name, identity, public_ip, existing[0])
                )
            else:
                cur.execute(
                    "INSERT INTO device_info (brand, model, identity, public_ip) VALUES (?, ?, ?, ?)",
                    ("MikroTik", board_name, identity, public_ip)
                )
            conn.commit()
            print(f"[DEVICE] ✅ Info router disimpan — {board_name} | {identity} | {public_ip}")
        finally:
            conn.close()

    except Exception as e:
        print(f"[DEVICE] ⚠️  Gagal ambil info router: {e}")


def run_engine():
    engine    = DetectionEngine()
    Mitigator = mitigator.Mitigator()
    set_mitigator(Mitigator)
    set_engine(engine)  # CHANGED: expose engine ke services route untuk reload detector

    print("[engine] Detection engine started.\n")

    for line in follow():
        log = parse_log(line)
        if not log:
            continue

        print(f"[LOG] {log['src_ip']}:{log['src_port']} -> {log['dst_ip']}:{log['dst_port']} ({log['proto']})")

        alerts = engine.process(log)
        for alert in alerts:
            print(f"  !! {alert}")
            write_alert(alert, log)
            Mitigator.handle(alert, log)


if __name__ == "__main__":
    terminal_broadcaster.install()

    init_db()
    sync_device_info()   # fetch info router dan simpan ke DB
    sync_services_from_router()  # CHANGED: sync port service dari router ke DB

    engine_thread = threading.Thread(target=run_engine, daemon=True)
    engine_thread.start()

    print("[API] Starting API server on http://0.0.0.0:8000")

    config = uvicorn.Config(app, host="0.0.0.0", port=8000)
    server = uvicorn.Server(config)

    async def serve():
        terminal_broadcaster.set_loop(asyncio.get_running_loop())
        await server.serve()

    asyncio.run(serve())