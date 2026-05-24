# API Documentation — Skripsi IDS

Base URL: `http://localhost:8000`

Semua endpoint kecuali yang ditandai **PUBLIC** membutuhkan header:
```
Authorization: Bearer <token>
```

---

## Auth

### POST /auth/login
Login dan dapatkan JWT token. Otomatis update `last_login` di database.

**Body:**
```json
{ "username": "admin", "password": "password" }
```

**Response:**
```json
{ "access_token": "eyJ...", "token_type": "bearer" }
```

---

### POST /auth/logout
Logout dan update `last_logout` di database.

**Headers:** `Authorization: Bearer <token>`

**Response:**
```json
{ "message": "Logout berhasil" }
```

---

## Logs

### GET /logs
Ambil riwayat alert dengan filter opsional termasuk range tanggal.

**Query params:**
| Param | Type | Default | Keterangan |
|-------|------|---------|------------|
| limit | int | 50 | Jumlah data (max 500) |
| attack_type | string | - | Filter: DDOS / BRUTE-FORCE / PORT-SCAN |
| src_ip | string | - | Filter berdasarkan IP penyerang |
| date_from | string | - | Tanggal mulai range (YYYY-MM-DD) |
| date_to | string | - | Tanggal akhir range (YYYY-MM-DD) |

**Contoh penggunaan:**
```
GET /logs?date_from=2026-05-01&date_to=2026-05-18
GET /logs?attack_type=DDOS&date_from=2026-05-18
GET /logs?src_ip=1.2.3.4&limit=100
```

**Response:**
```json
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
```

---

### WebSocket ws://host/logs/ws?token=\<JWT\>
Realtime log tanpa refresh. Server push otomatis setiap ada alert baru.

**Connect:**
```javascript
const ws = new WebSocket('ws://localhost:8000/logs/ws?token=eyJ...')
ws.onmessage = (e) => {
  const data = JSON.parse(e.data)
  if (data.type === 'ping') return  // abaikan keep-alive
  console.log(data)
}
```

**Data yang diterima saat ada alert:**
```json
{
  "src_ip": "1.2.3.4",
  "attack_type": "DDOS",
  "port": 80,
  "protocol": "TCP",
  "timestamp": "2026-05-18 10:00:00",
  "alert": "[DDOS] dst_port=80 packets=150 in 5s",
  "insight": "⚠️ DDoS Flood Terdeteksi\nIP 1.2.3.4 membanjiri port 80/TCP..."
}
```

**Keep-alive ping (setiap 30 detik):**
```json
{ "type": "ping" }
```

---

## Ports

### GET /ports/open-ports
Lihat semua service di MikroTik beserta status enable/disable-nya.
Langsung baca dari `/ip/service` — mencerminkan kondisi real router.

**Response:**
```json
[
  { "port": 22,   "protocol": "tcp", "state": "open",     "service": "SSH" },
  { "port": 80,   "protocol": "tcp", "state": "filtered", "service": "HTTP" },
  { "port": 8291, "protocol": "tcp", "state": "open",     "service": "Winbox" }
]
```

| State | Keterangan |
|-------|------------|
| `open` | Service aktif (enabled) |
| `filtered` | Service dinonaktifkan (disabled) |

---

### POST /ports/enable
Enable (aktifkan) service di MikroTik berdasarkan port.
Langsung set `disabled=false` pada service yang sesuai di `/ip/service`.

**Body:**
```json
{ "port": 80, "protocol": "tcp" }
```

**Response:**
```json
{ "message": "Service port 80 (HTTP) berhasil diaktifkan" }
```

**Error (service tidak ditemukan):**
```json
{ "detail": "Service dengan port 80 tidak ditemukan di MikroTik" }
```

---

### POST /ports/disable
Disable (nonaktifkan) service di MikroTik berdasarkan port.
Langsung set `disabled=true` pada service yang sesuai di `/ip/service`.

**Body:**
```json
{ "port": 80, "protocol": "tcp" }
```

**Response:**
```json
{ "message": "Service port 80 (HTTP) berhasil dinonaktifkan" }
```

**Error (service tidak ditemukan):**
```json
{ "detail": "Service dengan port 80 tidak ditemukan di MikroTik" }
```

---

## Services (Sinkronisasi Port)

Fitur sinkronisasi port service dari MikroTik router (`ip/service`) ke database.
Digunakan agar deteksi brute force tetap akurat meski port di router berubah.

**Alur kerja:**
1. Saat startup, sistem otomatis fetch `ip/service` dari router dan simpan ke DB
2. `BruteForceDetector` membaca daftar port dari DB (bukan hardcode)
3. Frontend bisa trigger rescan kapan saja via `POST /services/sync`
4. Jika port berubah (misal SSH 22 → 1177), perubahan tercatat di history dan detector otomatis reload

### GET /services/ports
Lihat daftar semua service beserta port yang tersimpan di database (hasil sinkronisasi dari router).

**Response:**
```json
[
  {
    "id": 1,
    "service_name": "ssh",
    "port": 1177,
    "protocol": "tcp",
    "disabled": false,
    "synced_at": "2026-05-18T10:00:00"
  },
  {
    "id": 2,
    "service_name": "winbox",
    "port": 8291,
    "protocol": "tcp",
    "disabled": false,
    "synced_at": "2026-05-18T10:00:00"
  }
]
```

> Hanya service **static** yang disimpan. Service dynamic (auto-generated oleh router) di-skip untuk menghindari duplikasi.

---

### POST /services/sync
Trigger sinkronisasi ulang port service dari router MikroTik.
Frontend memanggil endpoint ini untuk memperbarui daftar port.

**Proses internal:**
1. Fetch `ip/service` dari router (hanya static, skip dynamic)
2. Bandingkan dengan data di DB
3. Jika ada port berubah → catat di `port_change_log` + update DB
4. Reload `BruteForceDetector` agar pakai port terbaru

**Response (ada perubahan):**
```json
{
  "message": "Sync berhasil. 1 perubahan port terdeteksi.",
  "changes": [
    { "service": "ssh", "old_port": 1177, "new_port": 1919 }
  ]
}
```

**Response (tidak ada perubahan):**
```json
{
  "message": "Sync berhasil. Tidak ada perubahan port.",
  "changes": []
}
```

---

### GET /services/changes
Lihat history perubahan port yang pernah terjadi.

**Query params:**
| Param | Type | Default | Keterangan |
|-------|------|---------|------------|
| limit | int | 50 | Jumlah data maksimal (1–200) |

**Response:**
```json
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
```

---

## Statistics

### GET /stats/per-port
Jumlah serangan per port per jenis serangan.

**Query params:**
| Param | Type | Keterangan |
|-------|------|------------|
| attack_type | string | Filter opsional (DDOS / BRUTE-FORCE / PORT-SCAN) |

**Response:**
```json
[
  {
    "dst_port": 22,
    "attack_type": "BRUTE-FORCE",
    "total": 47,
    "last_seen": "2026-05-18T10:23:00"
  }
]
```

---

### GET /stats/summary
Ringkasan keseluruhan statistik serangan beserta breakdown per port.

**Response:**
```json
{
  "total": 120,
  "by_type": {
    "DDOS": 50,
    "BRUTE-FORCE": 45,
    "PORT-SCAN": 25
  },
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
```

---

## Notifications

### GET /notif/history
Riwayat notifikasi lengkap dengan insight berbeda per jenis serangan.

**Query params:**
| Param | Type | Default | Keterangan |
|-------|------|---------|------------|
| limit | int | 20 | Jumlah notifikasi (max 100) |

**Response:**
```json
[
  {
    "src_ip": "1.2.3.4",
    "attack_type": "BRUTE-FORCE",
    "port": 22,
    "protocol": "TCP",
    "timestamp": "2026-05-18 10:00:00",
    "alert": "[BRUTE-FORCE] src=1.2.3.4 target=SSH hits=5 in 30s",
    "insight": "🔐 Brute Force Terdeteksi\nIP 1.2.3.4 mencoba login berulang ke SSH (port 22)..."
  }
]
```

---

## Device & Users

### GET /device
Lihat informasi alat/router yang terdaftar di sistem.

**Response:**
```json
{
  "id": 1,
  "brand": "MikroTik",
  "model": "CCR2004",
  "identity": "Router Gateway Lab",
  "public_ip": "222.124.22.44",
  "updated_at": "2026-05-18T10:00:00"
}
```

> Mengembalikan `null` jika belum ada data device yang didaftarkan.

---

### POST /device
Tambah atau update informasi alat. Jika sudah ada data sebelumnya, data lama akan diupdate.

**Body:**
```json
{
  "brand": "MikroTik",
  "model": "CCR2004",
  "identity": "Router Gateway Lab",
  "public_ip": "222.124.22.44"
}
```

**Response:**
```json
{
  "id": 1,
  "brand": "MikroTik",
  "model": "CCR2004",
  "identity": "Router Gateway Lab",
  "public_ip": "222.124.22.44",
  "updated_at": "2026-05-18T10:00:00"
}
```

---

### GET /users/check-setup — PUBLIC
Cek apakah sistem perlu setup pertama kali (belum ada user).
Frontend memanggil ini saat pertama kali dimuat untuk menentukan apakah redirect ke halaman Setup atau langsung ke Login.

**Response (belum ada user):**
```json
{ "need_setup": true }
```

**Response (sudah ada user):**
```json
{ "need_setup": false }
```

---

### POST /users/setup — PUBLIC
Daftarkan user pertama kali saat sistem baru berjalan.
Hanya bisa dipakai jika belum ada user di database.

**Body:**
```json
{ "username": "admin", "password": "password_kamu" }
```

**Response:**
```json
{ "message": "Setup berhasil. Silakan login." }
```

**Error (sudah ada user):**
```json
{ "detail": "Setup sudah pernah dilakukan. Gunakan login." }
```

**Validasi:**
- Username minimal 3 karakter
- Password minimal 6 karakter

---

### GET /users/me
Lihat informasi user yang sedang login beserta riwayat aktivitas.

**Response:**
```json
{
  "id": 1,
  "username": "admin",
  "password_changed": "2026-05-10T08:00:00",
  "last_login": "2026-05-18T09:00:00",
  "last_logout": "2026-05-17T18:00:00",
  "created_at": "2026-05-01T00:00:00"
}
```

> `password_changed`, `last_login`, `last_logout` bisa `null` jika belum pernah terjadi.

---

### POST /users/change-password
Ubah password user yang sedang login.

**Body:**
```json
{
  "old_password": "password_lama",
  "new_password": "password_baru"
}
```

**Response:**
```json
{ "message": "Password berhasil diubah" }
```

**Error (password lama salah):**
```json
{ "detail": "Password lama tidak sesuai" }
```

---

## Insight per Jenis Serangan

Setiap jenis serangan menghasilkan pesan insight yang berbeda di endpoint `/notif/history` dan WebSocket:

| Jenis | Insight |
|-------|---------| 
| DDOS | Menjelaskan flood ke port tertentu, total paket, rata-rata paket/detik, tindakan blok otomatis |
| BRUTE-FORCE | Menjelaskan target service (SSH/Telnet/Winbox/FTP/RouterOS API), pola tebak password, tindakan blok |
| PORT-SCAN | Menjelaskan fase reconnaissance, jumlah port di-scan, contoh port, blok total semua port dari IP tersebut |

---

## Database Tables

| Tabel | Deskripsi |
|-------|-----------|
| `alerts` | Riwayat alert serangan yang terdeteksi |
| `users` | Data user sistem (login, password, audit) |
| `device_info` | Informasi router/alat yang terhubung |
| `router_services` | Daftar service/port dari router (hasil sync `ip/service`) |
| `port_change_log` | History perubahan port service di router |

---

## Cara Jalankan

```bash
# Install dependencies
pip install -r requirements.txt

# Salin dan isi konfigurasi
cp .env.example .env

# Jalankan (detection engine + API server sekaligus)
python run.py
```

**Urutan startup:**
1. `init_db()` — buat database dan tabel jika belum ada
2. `sync_device_info()` — ambil info router (model, identity, IP)
3. `sync_services_from_router()` — sync port service dari router ke DB
4. Start detection engine + API server

Swagger UI: `http://localhost:8000/docs`
ReDoc: `http://localhost:8000/redoc`

---

## Konfigurasi .env

```env
# Log source
LOG_MODE=dev
LOG_HOST=192.168.100.51
LOG_PORT=9000
# LOG_FILE=/var/log/mikrotik/gateway.log   # aktifkan saat deploy

# Database MariaDB
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASS=password_db
DB_NAME=skripsi_ids

# MikroTik RouterOS API
MIKROTIK_HOST=192.168.88.1
MIKROTIK_API_PORT=8728
MIKROTIK_USER=admin
MIKROTIK_PASS=password_mikrotik

# n8n Webhook → Telegram
N8N_WEBHOOK_URL=https://n8n.domain.com/webhook/xxx

# API Credentials
API_USER=admin
API_PASS=password_api
JWT_SECRET=isi-dengan-string-panjang-dan-random
JWT_EXPIRE_MINUTES=60
```
