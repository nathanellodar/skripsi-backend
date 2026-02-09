# main.py
from get_log import follow
from parser import parse_log
from engine import DetectionEngine

LOG_FILE = "/var/log/mikrotik1.log"

def main():
    engine = DetectionEngine()

    with open(LOG_FILE, "r") as f:
        for line in follow(f):
            log = parse_log(line)
            alerts = engine.process(log)

            for alert in alerts:
                print(alert)
                print("   Raw:", log["raw"])

if __name__ == "__main__":
    main()
