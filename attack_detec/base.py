# attack_detec/base.py

class BaseDetector:
    """Interface dasar untuk semua detector."""

    name: str = "BaseDetector"

    def process(self, log: dict) -> str | None:
        """
        Proses satu log entry.
        Return alert string jika terdeteksi, None jika tidak.
        """
        raise NotImplementedError