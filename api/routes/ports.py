# api/routes/ports.py
from fastapi import APIRouter, Depends, HTTPException
from typing import Annotated
from api.auth import verify_token
from api.schemas import PortActionRequest, OpenPortOut
from mitigation import mitigator

router  = APIRouter(prefix="/ports", tags=["Ports"])

_mitigator: mitigator.Mitigator = None

def set_mitigator(m: mitigator.Mitigator):
    global _mitigator
    _mitigator = m

def get_mitigator() -> mitigator.Mitigator:
    return _mitigator


SERVICE_MAP = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8291: "Winbox",
    8443: "HTTPS-Alt",
    8728: "RouterOS API",
    8729: "RouterOS API-SSL",
}


def _get_api():
    from mitigation.mikrotik_api import get_connection as mt_conn
    return mt_conn()


def _find_service(api, port: int):
    """Cari service di MikroTik berdasarkan port number. Return entry atau None."""
    services = list(api.path("ip", "service"))
    for svc in services:
        if int(svc.get("port", 0)) == port:
            return svc
    return None


# ── List semua service/port ───────────────────────────────────────────────────

@router.get("/open-ports", response_model=list[OpenPortOut])
def list_open_ports(_: Annotated[dict, Depends(verify_token)]):
    """
    GET /ports/open-ports
    Lihat semua service di MikroTik beserta status enable/disable-nya.
    Langsung baca dari /ip/service — mencerminkan kondisi real router.

    Response:
    [
      { "port": 22,   "protocol": "tcp", "state": "open",     "service": "SSH" },
      { "port": 80,   "protocol": "tcp", "state": "filtered", "service": "HTTP" },
      { "port": 8291, "protocol": "tcp", "state": "open",     "service": "Winbox" }
    ]

    state:
    - "open"     → service aktif (enabled)
    - "filtered" → service dinonaktifkan (disabled)
    """
    try:
        api      = _get_api()
        services = list(api.path("ip", "service"))
        api.close()
    except Exception as e:
        raise HTTPException(500, f"Gagal ambil data dari MikroTik: {e}")

    result = []
    for svc in services:
        port     = int(svc.get("port", 0))
        disabled = svc.get("disabled", False)
        is_disabled = disabled is True or disabled == "true"

        result.append(OpenPortOut(
            port=port,
            protocol="tcp",
            state="filtered" if is_disabled else "open",
            service=SERVICE_MAP.get(port, svc.get("name", "unknown")),
        ))

    return sorted(result, key=lambda x: x.port)


# ── Enable / Disable service ──────────────────────────────────────────────────

@router.post("/enable")
def enable_port(
    body: PortActionRequest,
    _: Annotated[dict, Depends(verify_token)],
):
    """
    POST /ports/enable
    Enable service di MikroTik berdasarkan port.
    Langsung set disabled=false pada service yang sesuai.

    Body:
    { "port": 80, "protocol": "tcp" }

    Response:
    { "message": "Service port 80 (HTTP) berhasil diaktifkan" }

    Error (service tidak ditemukan):
    { "detail": "Service dengan port 80 tidak ditemukan di MikroTik" }
    """
    try:
        api = _get_api()
        try:
            svc = _find_service(api, body.port)
            if not svc:
                raise HTTPException(404, f"Service dengan port {body.port} tidak ditemukan di MikroTik")

            api.path("ip", "service").update(**{
                ".id":      svc[".id"],
                "disabled": False,
            })
        finally:
            api.close()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Gagal enable service: {e}")

    service_name = SERVICE_MAP.get(body.port, f"port {body.port}")
    return {"message": f"Service port {body.port} ({service_name}) berhasil diaktifkan"}


@router.post("/disable")
def disable_port(
    body: PortActionRequest,
    _: Annotated[dict, Depends(verify_token)],
):
    """
    POST /ports/disable
    Disable service di MikroTik berdasarkan port.
    Langsung set disabled=true pada service yang sesuai.

    Body:
    { "port": 80, "protocol": "tcp" }

    Response:
    { "message": "Service port 80 (HTTP) berhasil dinonaktifkan" }

    Error (service tidak ditemukan):
    { "detail": "Service dengan port 80 tidak ditemukan di MikroTik" }
    """
    try:
        api = _get_api()
        try:
            svc = _find_service(api, body.port)
            if not svc:
                raise HTTPException(404, f"Service dengan port {body.port} tidak ditemukan di MikroTik")

            api.path("ip", "service").update(**{
                ".id":      svc[".id"],
                "disabled": True,
            })
        finally:
            api.close()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Gagal disable service: {e}")

    service_name = SERVICE_MAP.get(body.port, f"port {body.port}")
    return {"message": f"Service port {body.port} ({service_name}) berhasil dinonaktifkan"}