# api/routes/services.py
"""
Endpoint untuk sinkronisasi service/port dari MikroTik router.

- GET  /services/ports   → Lihat daftar port service yang tersimpan di DB
- POST /services/sync    → Trigger rescan port dari router (frontend hit ini)
- GET  /services/changes → Lihat history perubahan port
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Annotated

from api.auth import verify_token
from api.schemas import (
    RouterServiceOut,
    PortChangeOut,
    PortChangeItem,
    SyncResultOut,
)
from service_sync import (
    sync_services_from_router,
    get_all_services,
    get_port_changes,
)

router = APIRouter(prefix="/services", tags=["Services"])

# Reference ke DetectionEngine, di-set dari run.py
_engine = None


def set_engine(engine):
    global _engine
    _engine = engine


# ── List semua service/port dari DB ──────────────────────────────────────────

@router.get("/ports", response_model=list[RouterServiceOut])
def list_service_ports(_: Annotated[dict, Depends(verify_token)]):
    """
    GET /services/ports
    Lihat daftar semua service beserta port yang tersimpan di database
    (hasil sinkronisasi dari router MikroTik ip/service).

    Response:
    [
      { "id": 1, "service_name": "ssh", "port": 1177, "protocol": "tcp", "disabled": false, "synced_at": "..." },
      { "id": 2, "service_name": "winbox", "port": 8291, "protocol": "tcp", "disabled": false, "synced_at": "..." }
    ]
    """
    try:
        services = get_all_services()
        return [RouterServiceOut(**svc) for svc in services]
    except Exception as e:
        raise HTTPException(500, f"Gagal ambil data service: {e}")


# ── Trigger sync dari router ─────────────────────────────────────────────────

@router.post("/sync", response_model=SyncResultOut)
def sync_services(_: Annotated[dict, Depends(verify_token)]):
    """
    POST /services/sync
    Trigger sinkronisasi ulang port service dari router MikroTik.
    Frontend memanggil endpoint ini untuk memperbarui daftar port.

    Proses:
    1. Fetch ip/service dari router
    2. Bandingkan dengan data di DB
    3. Jika ada port berubah → catat di port_change_log + update DB
    4. Reload BruteForceDetector agar pakai port terbaru

    Response (ada perubahan):
    {
      "message": "Sync berhasil. 1 perubahan port terdeteksi.",
      "changes": [
        { "service": "ssh", "old_port": 1177, "new_port": 1919 }
      ]
    }

    Response (tidak ada perubahan):
    {
      "message": "Sync berhasil. Tidak ada perubahan port.",
      "changes": []
    }
    """
    try:
        changes = sync_services_from_router()

        # Reload BruteForceDetector jika ada perubahan
        if changes and _engine:
            brute_detector = _engine.get_detector("BruteForce")
            if brute_detector:
                brute_detector.reload_ports()

        change_items = [
            PortChangeItem(
                service=c["service"],
                old_port=c["old_port"],
                new_port=c["new_port"],
            )
            for c in changes
        ]

        if changes:
            msg = f"Sync berhasil. {len(changes)} perubahan port terdeteksi."
        else:
            msg = "Sync berhasil. Tidak ada perubahan port."

        return SyncResultOut(message=msg, changes=change_items)

    except Exception as e:
        raise HTTPException(500, f"Gagal sync service dari router: {e}")


# ── History perubahan port ───────────────────────────────────────────────────

@router.get("/changes", response_model=list[PortChangeOut])
def list_port_changes(
    _: Annotated[dict, Depends(verify_token)],
    limit: int = Query(50, ge=1, le=200, description="Jumlah data maksimal"),
):
    """
    GET /services/changes?limit=50
    Lihat history perubahan port yang pernah terjadi.

    Response:
    [
      {
        "id": 1,
        "service_name": "ssh",
        "old_port": 22,
        "new_port": 1177,
        "changed_at": "2026-05-18T10:00:00"
      },
      {
        "id": 2,
        "service_name": "ssh",
        "old_port": 1177,
        "new_port": 1919,
        "changed_at": "2026-05-20T14:30:00"
      }
    ]
    """
    try:
        changes = get_port_changes(limit)
        return [PortChangeOut(**c) for c in changes]
    except Exception as e:
        raise HTTPException(500, f"Gagal ambil history perubahan: {e}")
