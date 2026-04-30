# main.py
from get_log import follow
from parser import parse_log
from engine import DetectionEngine

LOG_FILE = "log-example.txt"

def main():
    engine = DetectionEngine()

    with open(LOG_FILE, "r") as f:
        # Read all existing lines instead of following
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            if line:  # Skip empty lines
                log = parse_log(line)
                # Print parsed log for debugging
                print(f"Parsed: {log['src_ip']}:{log['src_port']} -> {log['dst_ip']}:{log['dst_port']} ({log['proto']})")
                alerts = engine.process(log)
                # print("LOG:", log)

                for alert in alerts:
                    print(alert)
                    print("   Raw:", log["raw"])

if __name__ == "__main__":
    main()
