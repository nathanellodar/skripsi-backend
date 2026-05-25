# api/auth.py
from dotenv import load_dotenv
load_dotenv(override=True)

import os
import hashlib
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt

SECRET_KEY  = os.getenv("JWT_SECRET", "ganti-dengan-secret-yang-kuat")
ALGORITHM   = "HS256"
EXPIRE_MINS = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

bearer_scheme = HTTPBearer()


def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def create_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=EXPIRE_MINS)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)]
) -> dict:
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token tidak valid atau sudah expired",
            headers={"WWW-Authenticate": "Bearer"},
        )


def authenticate(username: str, password: str) -> bool:
    """Cek kredensial dari DB, update last_login jika berhasil."""
    from db import get_connection
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row or row[0] != _hash(password):
            return False

        # CHANGED: update last_login
        cur.execute("UPDATE users SET last_login=NOW() WHERE username=?", (username,))
        conn.commit()
        return True
    finally:
        conn.close()


def record_logout(username: str) -> None:
    """Update last_logout saat user logout."""
    from db import get_connection
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET last_logout=NOW() WHERE username=?", (username,))
        conn.commit()
    finally:
        conn.close()