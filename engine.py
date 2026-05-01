# engine.py
from attack_detec import BruteForceDetector, PortScanDetector, DDoSDetector
from attack_detec.base import BaseDetector


class DetectionEngine:
    def __init__(self):
        self.detectors: list[BaseDetector] = [
            BruteForceDetector(),
            PortScanDetector(),
            DDoSDetector(),
        ]

    def process(self, log: dict) -> list[str]:
        """Jalankan semua detector, kembalikan list alert (bisa kosong)."""
        alerts = []
        for detector in self.detectors:
            result = detector.process(log)
            if result:
                alerts.append(result)
        return alerts