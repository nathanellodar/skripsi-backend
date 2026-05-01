# main.py
from get_log import follow
from parser import parse_log
from engine import DetectionEngine
from alert_writer import write_alert


def main():
    engine = DetectionEngine()
    print("[main] System started. Waiting for logs...\n")

    for line in follow():
        log = parse_log(line)
        if not log:
            continue

        print(f"[LOG] {log['src_ip']}:{log['src_port']} -> {log['dst_ip']}:{log['dst_port']} ({log['proto']})")

        alerts = engine.process(log)
        for alert in alerts:
            print(f"  !! {alert}")
            write_alert(alert, log)


if __name__ == "__main__":
    main()