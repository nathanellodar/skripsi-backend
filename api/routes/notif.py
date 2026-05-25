# api/routes/notif.py
from fastapi import APIRouter, Depends, Query
from typing import Annotated
from api.auth import verify_token
from db import get_connection

router = APIRouter(prefix="/notif", tags=["Notifications"])


@router.get("/history")
def notif_history(
    _: Annotated[dict, Depends(verify_token)],
    limit: int = Query(20, ge=1, le=100),
):
    """
    GET /notif/history
    Riwayat notifikasi dengan payload berbeda per jenis serangan.

    Response DDOS:
    {
      "src_ip": "1.2.3.4",
      "attack_type": "DDOS",
      "port": 80,
      "protocol": "TCP",
      "timestamp": "2026-05-18 10:00:00",
      "alert": "[DDOS] dst_port=80 packets=150 in 5s",
      "packets": 150,
      "window_seconds": 5,
      "rate_per_sec": 30.0,
      "insight": "⚠️ DDoS Flood Terdeteksi\\n• Sumber: 1.2.3.4\\n• Target port: 80/TCP\\n..."
    }

    Response BRUTE-FORCE:
    {
      "src_ip": "1.2.3.4",
      "attack_type": "BRUTE-FORCE",
      "port": 22,
      "protocol": "TCP",
      "timestamp": "2026-05-18 10:00:00",
      "alert": "[BRUTE-FORCE] src=1.2.3.4 target=SSH port=22 hits=7 in 30s",
      "service": "SSH",
      "hits": 7,
      "window_seconds": 30,
      "insight": "🔐 Brute Force Terdeteksi\\n• Sumber: 1.2.3.4\\n• Target: SSH (port 22)\\n..."
    }

    Response PORT-SCAN:
    {
      "src_ip": "1.2.3.4",
      "attack_type": "PORT-SCAN",
      "port": 0,
      "protocol": "TCP",
      "timestamp": "2026-05-18 10:00:00",
      "alert": "[PORT-SCAN] src=1.2.3.4 ports=45 (21,22,23,...) in 10s",
      "total_ports_scanned": 45,
      "window_seconds": 10,
      "sample_ports": "21,22,23,80,443...",
      "insight": "🔍 Port Scanning Terdeteksi\\n• Sumber: 1.2.3.4\\n• Port di-scan: 45 port\\n..."
    }
    """
    from alert_writer import _build_payload

    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT src_ip, attack_type, dst_port, protocol, detected_at, alert_msg
            FROM alerts
            ORDER BY detected_at DESC
            LIMIT ?
            """,
            (limit,)
        )
        rows = cur.fetchall()

        result = []
        for r in rows:
            src_ip, attack_type, dst_port, protocol, detected_at, alert_msg = r
            ts_str  = detected_at.strftime("%Y-%m-%d %H:%M:%S")
            payload = _build_payload(attack_type, src_ip, dst_port, protocol, alert_msg, ts_str)
            result.append(payload)

        return result
    finally:
        conn.close()