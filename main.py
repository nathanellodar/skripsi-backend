# main.py
from get_log import follow
from parser import parse_log
from engine import DetectionEngine
from alert_writer import write_alert
from mitigation import mitigator


def main():
    engine    = DetectionEngine()
    mitigators = mitigator.Mitigator()

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

            # File — deduplikasi per IP per jam
            write_alert(alert, log)

            # Mitigasi — blok IP di MikroTik
            mitigators.handle(alert, log)


if __name__ == "__main__":
    main()