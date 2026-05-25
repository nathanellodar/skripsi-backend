# api/app.py
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from typing import Annotated

from api.auth import authenticate, create_token, record_logout, verify_token
from api.schemas import LoginRequest, TokenResponse
from api.routes import logs, ports, stats, notif
from api.routes.device import router as device_router
from api.routes.services import router as services_router

app = FastAPI(
    title="Skripsi IDS API",
    description="API sistem deteksi dan mitigasi serangan jaringan berbasis MikroTik",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(logs.router)
app.include_router(ports.router)
app.include_router(stats.router)
app.include_router(notif.router)
app.include_router(device_router)   # CHANGED: register route device & users
app.include_router(services_router)  # CHANGED: register route service sync


@app.post("/auth/login", response_model=TokenResponse, tags=["Auth"])
def login(body: LoginRequest):
    """
    POST /auth/login
    Login dan dapatkan JWT token. Otomatis update last_login di DB.

    Body: { "username": "admin", "password": "password" }
    Response: { "access_token": "eyJ...", "token_type": "bearer" }
    """
    if not authenticate(body.username, body.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Username atau password salah")
    token = create_token({"sub": body.username})
    return TokenResponse(access_token=token)


@app.post("/auth/logout", tags=["Auth"])
def logout(token: Annotated[dict, Depends(verify_token)]):
    """
    POST /auth/logout
    CHANGED: logout dan update last_logout di DB.

    Response: { "message": "Logout berhasil" }
    """
    username = token.get("sub")
    record_logout(username)
    return {"message": "Logout berhasil"}


@app.get("/", tags=["Health"])
def health():
    return {"status": "ok", "service": "Skripsi IDS API"}