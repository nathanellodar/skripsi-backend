# api/routes/logs.py
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
from typing import Annotated, Optional
from datetime import date
from api.auth import verify_token
from api.schemas import AlertOut
from db import get_connection
import asyncio

router = APIRouter(prefix="/logs", tags=["Logs"])


class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)

manager = ConnectionManager()


async def broadcast_alert(alert_data: dict):
    await manager.broadcast(alert_data)


@router.websocket("/ws")
async def websocket_logs(ws: WebSocket, token: str = Query(...)):
    """
    WebSocket realtime log.
    Connect: ws://host/logs/ws?token=<JWT>
    Push otomatis setiap ada alert baru.
    """
    from api.auth import verify_token as _verify
    from fastapi.security import HTTPAuthorizationCredentials
    try:
        _verify(HTTPAuthorizationCredentials(scheme="Bearer", credentials=token))
    except Exception:
        await ws.close(code=1008)
        return

    await manager.connect(ws)
    try:
        while True:
            await asyncio.sleep(30)
            await ws.send_json({"type": "ping"})
    except WebSocketDisconnect:
        manager.disconnect(ws)


@router.get("", response_model=list[AlertOut])
def get_logs(
    _: Annotated[dict, Depends(verify_token)],
    limit:       int           = Query(50,   ge=1, le=500),
    attack_type: Optional[str] = Query(None, description="DDOS | BRUTE-FORCE | PORT-SCAN"),
    src_ip:      Optional[str] = Query(None, description="Filter IP sumber"),
    # CHANGED: tambah filter tanggal
    date_from:   Optional[date] = Query(None, description="Tanggal mulai (YYYY-MM-DD)"),
    date_to:     Optional[date] = Query(None, description="Tanggal akhir (YYYY-MM-DD)"),
):
    """
    GET /logs
    Ambil riwayat alert dengan filter opsional.

    Query params:
    - limit       : jumlah data (default 50, max 500)
    - attack_type : DDOS | BRUTE-FORCE | PORT-SCAN
    - src_ip      : filter IP penyerang
    - date_from   : tanggal mulai range (YYYY-MM-DD)
    - date_to     : tanggal akhir range (YYYY-MM-DD)

    Contoh:
    GET /logs?date_from=2026-05-01&date_to=2026-05-18
    GET /logs?attack_type=DDOS&date_from=2026-05-18

    Response:
    [
      {
        "id": 1,
        "attack_type": "DDOS",
        "src_ip": "1.2.3.4",
        "dst_port": 80,
        "protocol": "TCP",
        "alert_msg": "[DDOS] dst_port=80 packets=150 in 5s",
        "detected_at": "2026-05-18T10:00:00"
      }
    ]
    """
    conn = get_connection()
    try:
        cur    = conn.cursor()
        query  = """
            SELECT id, attack_type, src_ip, dst_port, protocol, alert_msg, detected_at
            FROM alerts
            WHERE 1=1
        """
        params = []

        if attack_type:
            query += " AND attack_type = ?"
            params.append(attack_type)

        if src_ip:
            query += " AND src_ip = ?"
            params.append(src_ip)

        # CHANGED: filter range tanggal
        if date_from:
            query += " AND DATE(detected_at) >= ?"
            params.append(str(date_from))

        if date_to:
            query += " AND DATE(detected_at) <= ?"
            params.append(str(date_to))

        query += " ORDER BY detected_at DESC LIMIT ?"
        params.append(limit)

        cur.execute(query, params)
        rows = cur.fetchall()
        return [
            AlertOut(
                id=r[0], attack_type=r[1], src_ip=r[2],
                dst_port=r[3], protocol=r[4], alert_msg=r[5],
                detected_at=r[6]
            ) for r in rows
        ]
    finally:
        conn.close()


# ── Terminal WebSocket ────────────────────────────────────────────────────────

@router.websocket("/terminal/ws")
async def websocket_terminal(ws: WebSocket, token: str = Query(...)):
    """
    WebSocket realtime terminal output.
    Connect: ws://host/logs/terminal/ws?token=<JWT>

    Semua output terminal backend (print, [LOG], [DB], [MITIGASI], dll)
    akan di-push ke client secara realtime.

    Format data yang diterima:
    {
      "type": "terminal",
      "message": "[LOG] 1.2.3.4:1234 -> 222.124.22.44:80 (TCP)",
      "timestamp": "10:23:45"
    }

    Keep-alive ping (setiap 30 detik):
    { "type": "ping" }
    """
    from api.auth import verify_token as _verify
    from fastapi.security import HTTPAuthorizationCredentials
    from api.terminal import terminal_broadcaster

    try:
        _verify(HTTPAuthorizationCredentials(scheme="Bearer", credentials=token))
    except Exception:
        await ws.close(code=1008)
        return

    await terminal_broadcaster.connect(ws)
    try:
        while True:
            await asyncio.sleep(30)
            await ws.send_json({"type": "ping"})
    except WebSocketDisconnect:
        terminal_broadcaster.disconnect(ws)