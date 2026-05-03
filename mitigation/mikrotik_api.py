# mitigation/mikrotik_api.py
from librouteros import connect
from librouteros.exceptions import TrapError, ConnectionClosed
import os


def get_connection():
    """
    Buat koneksi ke MikroTik RouterOS API.
    Credential diambil dari environment variable / .env
    """
    host     = os.getenv("MIKROTIK_HOST", "192.168.12.1")
    port     = int(os.getenv("MIKROTIK_API_PORT", "11500"))
    username = os.getenv("MIKROTIK_USER", "admin")
    password = os.getenv("MIKROTIK_PASS", "")

    try:
        conn = connect(
            host=host,
            port=port,
            username=username,
            password=password,
        )
        return conn
    except (TrapError, ConnectionClosed, OSError) as e:
        raise ConnectionError(f"[MikroTik API] Gagal konek ke {host}:{port} — {e}")