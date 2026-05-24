# alert_writer.py
from dotenv import load_dotenv
load_dotenv(override=True)

import re
import os
import asyncio
import requests
from datetime import datetime
import mariadb
from db import get_connection

N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL", "")

ALERT_TYPE_MAP = {
    "[BRUTE-FORCE]": "BRUTE-FORCE",
    "[PORT-SCAN]":   "PORT-SCAN",
    "[DDOS]":        "DDOS",
}

_written: set[tuple] = set()


def _detect_attack_type(alert: str) -> str | None:
    for keyword, attack_type in ALERT_TYPE_MAP.items():
        if keyword in alert:
            return attack_type
    return None


def _parse_alert_detail(alert_msg: str) -> dict:
    """Ekstrak detail numerik dari string alert."""
    detail = {}

    for match in re.finditer(r'(\w+)=(\S+)', alert_msg):
        key, val = match.group(1), match.group(2)
        try:
            detail[key] = int(val)
        except ValueError:
            detail[key] = val

    # Daftar port dari format (21,22,23,...)
    port_list = re.search(r'\(([\d,]+)\)', alert_msg)
    if port_list:
        detail["port_list"] = port_list.group(1).split(",")

    # Window waktu "in Xs"
    window = re.search(r'in (\d+)s', alert_msg)
    if window:
        detail["window_seconds"] = int(window.group(1))

    return detail


def _build_payload(attack_type: str, src_ip: str, dst_port: int,
                   protocol: str, alert_msg: str, ts_str: str) -> dict:
    """
    Bangun payload berbeda per jenis serangan dengan detail yang kaya.
    Dipakai untuk n8n webhook, WebSocket broadcast, dan endpoint /notif/history.
    """
    SERVICE_MAP = {
        22: "SSH", 23: "Telnet", 3389: "RDP", 8291: "Winbox",
        21: "FTP", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
    }

    detail = _parse_alert_detail(alert_msg)
    base = {
        "src_ip":      src_ip,
        "attack_type": attack_type,
        "port":        dst_port,
        "protocol":    protocol,
        "timestamp":   ts_str,
        "alert":       alert_msg,
    }

    if attack_type == "DDOS":
        packets     = detail.get("packets", "?")
        window_secs = detail.get("window_seconds", "?")
        try:
            rate = round(int(packets) / int(window_secs), 1)
        except (TypeError, ValueError, ZeroDivisionError):
            rate = "?"

        base.update({
            "packets":        packets,
            "window_seconds": window_secs,
            "rate_per_sec":   rate,
            "insight": (
                f"⚠️ *DDoS Flood Terdeteksi*\n"
                f"• Sumber: `{src_ip}`\n"
                f"• Target port: `{dst_port}/{protocol}`\n"
                f"• Total paket: `{packets}` dalam `{window_secs}` detik\n"
                f"• Rata-rata: `{rate}` paket/detik\n"
                f"• Status: IP diblok otomatis di firewall"
            ),
        })

    elif attack_type == "BRUTE-FORCE":
        service     = SERVICE_MAP.get(dst_port, f"port {dst_port}")
        hits        = detail.get("hits", "?")
        window_secs = detail.get("window_seconds", "?")

        base.update({
            "service":        service,
            "hits":           hits,
            "window_seconds": window_secs,
            "insight": (
                f"🔐 *Brute Force Terdeteksi*\n"
                f"• Sumber: `{src_ip}`\n"
                f"• Target: `{service}` (port {dst_port})\n"
                f"• Percobaan login: `{hits}` kali dalam `{window_secs}` detik\n"
                f"• Indikasi: tebak password otomatis\n"
                f"• Status: IP diblok, akses ke {service} dihentikan"
            ),
        })

    elif attack_type == "PORT-SCAN":
        total_ports = detail.get("ports", "?")
        window_secs = detail.get("window_seconds", "?")
        port_list   = detail.get("port_list", [])
        sample      = ", ".join(port_list[:5]) + ("..." if len(port_list) > 5 else "") if port_list else "?"

        base.update({
            "total_ports_scanned": total_ports,
            "window_seconds":      window_secs,
            "sample_ports":        sample,
            "insight": (
                f"🔍 *Port Scanning Terdeteksi*\n"
                f"• Sumber: `{src_ip}`\n"
                f"• Port di-scan: `{total_ports}` port dalam `{window_secs}` detik\n"
                f"• Contoh port: `{sample}`\n"
                f"• Indikasi: fase reconnaissance sebelum serangan\n"
                f"• Status: IP diblok total semua port"
            ),
        })

    else:
        base["insight"] = f"⚡ Serangan `{attack_type}` dari `{src_ip}` ke port `{dst_port}`."

    return base


def _send_to_n8n(payload: dict) -> None:
    """Kirim payload ke n8n webhook → Telegram."""
    if not N8N_WEBHOOK_URL:
        return
    try:
        response = requests.post(N8N_WEBHOOK_URL, json=payload, timeout=5)
        if response.status_code == 200:
            print(f"[NOTIF] ✅ Notifikasi terkirim — {payload['attack_type']} dari {payload['src_ip']}")
        else:
            print(f"[NOTIF] ⚠️  n8n response: {response.status_code}")
    except requests.exceptions.Timeout:
        print("[NOTIF] ❌ Timeout kirim ke n8n")
    except requests.exceptions.ConnectionError:
        print("[NOTIF] ❌ Gagal konek ke n8n")
    except Exception as e:
        print(f"[NOTIF] ❌ Error: {e}")


def write_alert(alert: str, log: dict) -> None:
    """
    Catat alert ke MariaDB.
    Setelah berhasil: kirim ke n8n dan broadcast ke WebSocket.
    """
    attack_type = _detect_attack_type(alert)
    if not attack_type:
        return

    src_ip   = log["src_ip"]
    ts       = log["timestamp"]
    hour_key = ts.strftime("%Y-%m-%d %H")
    dedup    = (attack_type, src_ip, hour_key)

    if dedup in _written:
        return

    dst_port = log.get("dst_port", 0)
    proto    = log.get("proto", "-")
    ts_str   = ts.strftime("%Y-%m-%d %H:%M:%S")

    # ── Simpan ke MariaDB ────────────────────────────────────────────────────
    try:
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO alerts (attack_type, src_ip, dst_port, protocol, alert_msg, detected_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (attack_type, src_ip, dst_port, proto, alert, ts_str)
            )
            conn.commit()
            print(f"[DB] ✅ Alert disimpan — {attack_type} dari {src_ip}")
        finally:
            conn.close()

        _written.add(dedup)

    except (mariadb.Error, ConnectionError) as e:
        print(f"[DB] ❌ Gagal simpan alert: {e}")
        return

    # ── Bangun payload kaya per jenis serangan ────────────────────────────────
    payload = _build_payload(attack_type, src_ip, dst_port, proto, alert, ts_str)

    # ── Kirim ke n8n → Telegram ──────────────────────────────────────────────
    _send_to_n8n(payload)

    # ── Broadcast ke WebSocket client ────────────────────────────────────────
    try:
        from api.routes.logs import broadcast_alert
        asyncio.get_event_loop().run_until_complete(broadcast_alert(payload))
    except RuntimeError:
        import threading
        threading.Thread(
            target=lambda: asyncio.run(broadcast_alert(payload)),
            daemon=True
        ).start()
    except Exception as e:
        print(f"[WS] ❌ Gagal broadcast: {e}")