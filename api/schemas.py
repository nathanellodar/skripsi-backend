# api/schemas.py
from pydantic import BaseModel
from datetime import datetime
from typing import Optional


# ── Auth ──────────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ── Alert / Log ───────────────────────────────────────────────────────────────
class AlertOut(BaseModel):
    id:          int
    attack_type: str
    src_ip:      str
    dst_port:    int
    protocol:    str
    alert_msg:   str
    detected_at: datetime


# ── Port Management ───────────────────────────────────────────────────────────
class PortActionRequest(BaseModel):
    port:     int
    protocol: str = "tcp"

class OpenPortOut(BaseModel):
    port:     int
    protocol: str
    state:    str   # "open" | "filtered"
    service:  Optional[str] = None


# ── Stats ─────────────────────────────────────────────────────────────────────
class PortStatOut(BaseModel):
    dst_port:    int
    attack_type: str
    total:       int
    last_seen:   Optional[datetime]


# ── Notif ─────────────────────────────────────────────────────────────────────
class NotifPayload(BaseModel):
    src_ip:      str
    attack_type: str
    port:        int
    protocol:    str
    timestamp:   str
    alert:       str
    insight:     str   # pesan insight per jenis serangan


# ── Router Services ──────────────────────────────────────────────────────────
class RouterServiceOut(BaseModel):
    id:           int
    service_name: str
    port:         int
    protocol:     str
    disabled:     bool
    synced_at:    datetime

class PortChangeOut(BaseModel):
    id:           int
    service_name: str
    old_port:     int
    new_port:     int
    changed_at:   datetime

class PortChangeItem(BaseModel):
    service:  str
    old_port: int
    new_port: int

class SyncResultOut(BaseModel):
    message: str
    changes: list[PortChangeItem]