# api/routes/stats.py
from fastapi import APIRouter, Depends, Query
from typing import Annotated, Optional
from api.auth import verify_token
from api.schemas import PortStatOut
from db import get_connection

router = APIRouter(prefix="/stats", tags=["Statistics"])


@router.get("/per-port", response_model=list[PortStatOut])
def stats_per_port(
    _: Annotated[dict, Depends(verify_token)],
    attack_type: Optional[str] = Query(None),
):
    """
    GET /stats/per-port
    Jumlah serangan per port per jenis serangan.

    Response:
    [
      { "dst_port": 22, "attack_type": "BRUTE-FORCE", "total": 47, "last_seen": "..." }
    ]
    """
    conn = get_connection()
    try:
        cur   = conn.cursor()
        query = """
            SELECT dst_port, attack_type, COUNT(*) AS total, MAX(detected_at) AS last_seen
            FROM alerts WHERE 1=1
        """
        params = []
        if attack_type:
            query += " AND attack_type = ?"
            params.append(attack_type)

        query += " GROUP BY dst_port, attack_type ORDER BY total DESC"
        cur.execute(query, params)
        rows = cur.fetchall()
        return [
            PortStatOut(dst_port=r[0], attack_type=r[1], total=r[2], last_seen=r[3])
            for r in rows
        ]
    finally:
        conn.close()


@router.get("/summary")
def stats_summary(_: Annotated[dict, Depends(verify_token)]):
    """
    GET /stats/summary
    CHANGED: ringkasan total serangan + breakdown per port yang terbuka.

    Response:
    {
      "total": 120,
      "by_type": { "DDOS": 50, "BRUTE-FORCE": 45, "PORT-SCAN": 25 },
      "top_attacker": "1.2.3.4",
      "most_attacked_port": 22,
      "per_port": [
        {
          "port": 22,
          "total": 47,
          "by_type": { "BRUTE-FORCE": 47 },
          "last_seen": "2026-05-18T10:23:00"
        },
        {
          "port": 80,
          "total": 50,
          "by_type": { "DDOS": 50 },
          "last_seen": "2026-05-18T09:10:00"
        }
      ]
    }
    """
    conn = get_connection()
    try:
        cur = conn.cursor()

        # Total keseluruhan
        cur.execute("SELECT COUNT(*) FROM alerts")
        total = cur.fetchone()[0]

        # Per jenis serangan
        cur.execute("SELECT attack_type, COUNT(*) FROM alerts GROUP BY attack_type")
        by_type = {row[0]: row[1] for row in cur.fetchall()}

        # Top attacker
        cur.execute(
            "SELECT src_ip, COUNT(*) as c FROM alerts GROUP BY src_ip ORDER BY c DESC LIMIT 1"
        )
        row = cur.fetchone()
        top_attacker = row[0] if row else None

        # Most attacked port
        cur.execute(
            "SELECT dst_port, COUNT(*) as c FROM alerts GROUP BY dst_port ORDER BY c DESC LIMIT 1"
        )
        row = cur.fetchone()
        most_attacked_port = row[0] if row else None

        # CHANGED: per_port — breakdown tiap port beserta by_type dan last_seen
        cur.execute("""
            SELECT
                dst_port,
                attack_type,
                COUNT(*)         AS total,
                MAX(detected_at) AS last_seen
            FROM alerts
            GROUP BY dst_port, attack_type
            ORDER BY dst_port, total DESC
        """)
        rows = cur.fetchall()

        # Susun per_port: { port: { total, by_type, last_seen } }
        port_map: dict = {}
        for dst_port, atk_type, cnt, last_seen in rows:
            if dst_port not in port_map:
                port_map[dst_port] = {
                    "port":      dst_port,
                    "total":     0,
                    "by_type":   {},
                    "last_seen": None,
                }
            port_map[dst_port]["total"]            += cnt
            port_map[dst_port]["by_type"][atk_type] = cnt
            # Ambil last_seen terbaru
            if port_map[dst_port]["last_seen"] is None or (last_seen and last_seen > port_map[dst_port]["last_seen"]):
                port_map[dst_port]["last_seen"] = last_seen

        # Konversi last_seen ke string ISO
        per_port = []
        for p in sorted(port_map.values(), key=lambda x: x["total"], reverse=True):
            per_port.append({
                "port":      p["port"],
                "total":     p["total"],
                "by_type":   p["by_type"],
                "last_seen": p["last_seen"].isoformat() if p["last_seen"] else None,
            })

        return {
            "total":              total,
            "by_type":            by_type,
            "top_attacker":       top_attacker,
            "most_attacked_port": most_attacked_port,
            "per_port":           per_port,
        }
    finally:
        conn.close()