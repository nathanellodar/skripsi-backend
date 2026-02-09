# engine.py
from attack_detec.brute import BruteForceDetector
from attack_detec.scan import PortScanDetector
from attack_detec.ddos import DDoSDetector

class DetectionEngine:
    def __init__(self):
        self.detectors = [
            BruteForceDetector(),
            PortScanDetector(),
            DDoSDetector()
        ]

    def process(self, log):
        alerts = []
        for detector in self.detectors:
            result = detector.process(log)
            if result:
                alerts.append(result)
        return alerts
