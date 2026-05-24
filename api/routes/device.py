# api/routes/device.py
# CHANGED: route baru — informasi alat dan manajemen user
from fastapi import APIRouter, Depends, HTTPException
from typing import Annotated, Optional
from pydantic import BaseModel
from datetime import datetime
import hashlib
from api.auth import verify_token
from db import get_connection

router = APIRouter(tags=["Device & Users"])


# ── Schemas lokal ─────────────────────────────────────────────────────────────
class DeviceInfoOut(BaseModel):
    id:        int
    brand:     str
    model:     str
    identity:  str
    public_ip: str
    updated_at: datetime

class DeviceInfoIn(BaseModel):
    brand:     str
    model:     str
    identity:  str
    public_ip: str

class UserOut(BaseModel):
    id:               int
    username:         str
    password_changed: Optional[datetime]
    last_login:       Optional[datetime]
    last_logout:      Optional[datetime]
    created_at:       datetime

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# ── Device Info ───────────────────────────────────────────────────────────────

@router.get("/device", response_model=Optional[DeviceInfoOut], tags=["Device & Users"])
def get_device_info(_: Annotated[dict, Depends(verify_token)]):
    """
    GET /device
    Lihat informasi alat/router yang terdaftar.

    Response:
    {
      "id": 1,
      "brand": "MikroTik",
      "model": "CCR2004",
      "identity": "Router Gateway Lab",
      "public_ip": "222.124.22.44",
      "updated_at": "2026-05-18T10:00:00"
    }
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, brand, model, identity, public_ip, updated_at FROM device_info LIMIT 1")
        row = cur.fetchone()
        if not row:
            return None
        return DeviceInfoOut(
            id=row[0], brand=row[1], model=row[2],
            identity=row[3], public_ip=row[4], updated_at=row[5]
        )
    finally:
        conn.close()


@router.post("/device", response_model=DeviceInfoOut, tags=["Device & Users"])
def upsert_device_info(
    body: DeviceInfoIn,
    _: Annotated[dict, Depends(verify_token)],
):
    """
    POST /device
    Tambah atau update informasi alat. Jika sudah ada, update data yang ada.

    Body:
    {
      "brand": "MikroTik",
      "model": "CCR2004",
      "identity": "Router Gateway Lab",
      "public_ip": "222.124.22.44"
    }
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM device_info LIMIT 1")
        existing = cur.fetchone()

        if existing:
            cur.execute(
                "UPDATE device_info SET brand=?, model=?, identity=?, public_ip=? WHERE id=?",
                (body.brand, body.model, body.identity, body.public_ip, existing[0])
            )
            device_id = existing[0]
        else:
            cur.execute(
                "INSERT INTO device_info (brand, model, identity, public_ip) VALUES (?, ?, ?, ?)",
                (body.brand, body.model, body.identity, body.public_ip)
            )
            device_id = cur.lastrowid

        conn.commit()

        cur.execute(
            "SELECT id, brand, model, identity, public_ip, updated_at FROM device_info WHERE id=?",
            (device_id,)
        )
        row = cur.fetchone()
        return DeviceInfoOut(
            id=row[0], brand=row[1], model=row[2],
            identity=row[3], public_ip=row[4], updated_at=row[5]
        )
    finally:
        conn.close()


# ── Users ─────────────────────────────────────────────────────────────────────

@router.get("/users/me", response_model=UserOut, tags=["Device & Users"])
def get_current_user(token: Annotated[dict, Depends(verify_token)]):
    """
    GET /users/me
    Lihat informasi user yang sedang login.

    Response:
    {
      "id": 1,
      "username": "admin",
      "password_changed": "2026-05-18T10:00:00",
      "last_login": "2026-05-18T09:00:00",
      "last_logout": "2026-05-17T18:00:00",
      "created_at": "2026-05-01T00:00:00"
    }
    """
    username = token.get("sub")
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, password_changed, last_login, last_logout, created_at FROM users WHERE username=?",
            (username,)
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "User tidak ditemukan")
        return UserOut(
            id=row[0], username=row[1], password_changed=row[2],
            last_login=row[3], last_logout=row[4], created_at=row[5]
        )
    finally:
        conn.close()


@router.post("/users/change-password", tags=["Device & Users"])
def change_password(
    body: ChangePasswordRequest,
    token: Annotated[dict, Depends(verify_token)],
):
    """
    POST /users/change-password
    Ubah password user yang sedang login.

    Body:
    { "old_password": "lama", "new_password": "baru" }

    Response:
    { "message": "Password berhasil diubah" }
    """
    username = token.get("sub")
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "User tidak ditemukan")

        if row[0] != _hash(body.old_password):
            raise HTTPException(400, "Password lama tidak sesuai")

        cur.execute(
            "UPDATE users SET password_hash=?, password_changed=NOW() WHERE username=?",
            (_hash(body.new_password), username)
        )
        conn.commit()
        return {"message": "Password berhasil diubah"}
    finally:
        conn.close()


# ── First-time Setup ──────────────────────────────────────────────────────────

class SetupRequest(BaseModel):
    username: str
    password: str


@router.get("/users/check-setup", tags=["Device & Users"])
def check_setup():
    """
    GET /users/check-setup
    Cek apakah sistem perlu setup pertama kali (belum ada user).
    PUBLIC — tidak butuh token.

    Frontend memanggil ini saat pertama kali dimuat untuk menentukan
    apakah redirect ke halaman Setup atau langsung ke Login.

    Response (belum ada user):
    { "need_setup": true }

    Response (sudah ada user):
    { "need_setup": false }
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        count = cur.fetchone()[0]
        return {"need_setup": count == 0}
    finally:
        conn.close()


@router.post("/users/setup", tags=["Device & Users"])
def setup_first_user(body: SetupRequest):
    """
    POST /users/setup
    Daftarkan user pertama kali saat sistem baru berjalan.
    PUBLIC — tidak butuh token.

    Hanya bisa dipakai jika belum ada user di database.
    Jika sudah ada user, mengembalikan 403 Forbidden.

    Body:
    { "username": "admin", "password": "password_kamu" }

    Response:
    { "message": "Setup berhasil. Silakan login." }

    Error (sudah ada user):
    { "detail": "Setup sudah pernah dilakukan. Gunakan login." }
    """
    conn = get_connection()
    try:
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM users")
        count = cur.fetchone()[0]
        if count > 0:
            raise HTTPException(
                status_code=403,
                detail="Setup sudah pernah dilakukan. Gunakan login."
            )

        if len(body.username.strip()) < 3:
            raise HTTPException(400, "Username minimal 3 karakter")
        if len(body.password) < 6:
            raise HTTPException(400, "Password minimal 6 karakter")

        import hashlib as _hl
        hashed = _hl.sha256(body.password.encode()).hexdigest()

        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (body.username.strip(), hashed)
        )
        conn.commit()
        return {"message": "Setup berhasil. Silakan login."}
    finally:
        conn.close()