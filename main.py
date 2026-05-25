# main.py
# CHANGED: tambah init_db() saat startup
# CHANGED: hapus import notif — notifikasi sekarang dihandle di alert_writer.py
from get_log import follow
from parser import parse_log
from engine import DetectionEngine
from alert_writer import write_alert
from mitigation import mitigator
from db import init_db


def main():
    # CHANGED: inisiasi database sebelum mulai proses log
    init_db()

    engine    = DetectionEngine()
    Mitigator = mitigator.Mitigator()

    print("[main] System started. Waiting for logs...\n")

    for line in follow():
        log = parse_log(line)
        if not log:
            continue

        print(f"[LOG] {log['src_ip']}:{log['src_port']} -> {log['dst_ip']}:{log['dst_port']} ({log['proto']})")

        alerts = engine.process(log)
        for alert in alerts:
            # Console — semua alert tampil
            print(f"  !! {alert}")

            # CHANGED: write_alert sekarang simpan ke DB + kirim notif ke n8n
            write_alert(alert, log)

            # Mitigasi — blok IP di MikroTik
            Mitigator.handle(alert, log)


if __name__ == "__main__":
    main()