# db/connection.py
from dotenv import load_dotenv
load_dotenv(override=True)

import os
import mariadb

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "")
DB_NAME = os.getenv("DB_NAME", "skripsi_ids")

# CHANGED: tambah users dan device_info ke required tables
REQUIRED_TABLES = {"alerts", "users", "device_info", "router_services", "port_change_log"}

CREATE_ALERTS_TABLE = """
CREATE TABLE alerts (
    id          INT UNSIGNED      NOT NULL AUTO_INCREMENT,
    attack_type VARCHAR(20)       NOT NULL COMMENT 'DDOS | BRUTE-FORCE | PORT-SCAN',
    src_ip      VARCHAR(45)       NOT NULL,
    dst_port    SMALLINT UNSIGNED NOT NULL,
    protocol    VARCHAR(10)       NOT NULL,
    alert_msg   TEXT              NOT NULL,
    detected_at DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_attack_type (attack_type),
    INDEX idx_src_ip      (src_ip),
    INDEX idx_detected_at (detected_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

# CHANGED: tabel users dengan kolom audit lengkap
CREATE_USERS_TABLE = """
CREATE TABLE users (
    id                INT UNSIGNED NOT NULL AUTO_INCREMENT,
    username          VARCHAR(64)  NOT NULL UNIQUE,
    password_hash     VARCHAR(255) NOT NULL,
    password_changed  DATETIME     NULL     COMMENT 'Terakhir ubah password',
    last_login        DATETIME     NULL     COMMENT 'Login terakhir',
    last_logout       DATETIME     NULL     COMMENT 'Logout terakhir',
    created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

# CHANGED: tabel device_info untuk informasi alat/router
CREATE_DEVICE_INFO_TABLE = """
CREATE TABLE device_info (
    id         INT UNSIGNED NOT NULL AUTO_INCREMENT,
    brand      VARCHAR(64)  NOT NULL COMMENT 'Merk perangkat, contoh: MikroTik',
    model      VARCHAR(64)  NOT NULL COMMENT 'Model perangkat, contoh: CCR2004',
    identity   VARCHAR(128) NOT NULL COMMENT 'Nama identitas router',
    public_ip  VARCHAR(45)  NOT NULL COMMENT 'IP publik router',
    updated_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

# CHANGED: tabel router_services untuk menyimpan port service dari router
CREATE_ROUTER_SERVICES_TABLE = """
CREATE TABLE router_services (
    id           INT UNSIGNED       NOT NULL AUTO_INCREMENT,
    service_name VARCHAR(64)        NOT NULL COMMENT 'Nama service: ssh, telnet, winbox, dll',
    port         SMALLINT UNSIGNED  NOT NULL COMMENT 'Port number dari router',
    protocol     VARCHAR(10)        NOT NULL DEFAULT 'tcp',
    disabled     TINYINT(1)         NOT NULL DEFAULT 0 COMMENT '0=aktif, 1=disabled',
    synced_at    DATETIME           NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_service_name (service_name),
    INDEX idx_port (port)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

# CHANGED: tabel port_change_log untuk mencatat history perubahan port
CREATE_PORT_CHANGE_LOG_TABLE = """
CREATE TABLE port_change_log (
    id            INT UNSIGNED       NOT NULL AUTO_INCREMENT,
    service_name  VARCHAR(64)        NOT NULL,
    old_port      SMALLINT UNSIGNED  NOT NULL,
    new_port      SMALLINT UNSIGNED  NOT NULL,
    changed_at    DATETIME           NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_changed_at (changed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""


def get_connection(database: str = DB_NAME) -> mariadb.Connection:
    kwargs = dict(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS)
    if database:
        kwargs["database"] = database
    try:
        conn = mariadb.connect(**kwargs)
        conn.autocommit = False
        return conn
    except mariadb.Error as e:
        raise ConnectionError(f"[DB] Gagal konek ke {DB_HOST}:{DB_PORT} — {e}")


def init_db() -> None:
    """
    Inisiasi database saat program pertama kali jalan.
    Alur:
    1. Cek/buat database
    2. Cek kelengkapan tabel → drop semua & recreate jika ada yang kurang
    3. Seed default admin user jika tabel users kosong
    """
    print(f"[DB] Inisiasi database '{DB_NAME}'...")

    # Step 1: pastikan database ada
    conn = get_connection(database=None)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?",
            (DB_NAME,)
        )
        if not cur.fetchone():
            cur.execute(f"CREATE DATABASE `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
            conn.commit()
            print(f"[DB] ✅ Database '{DB_NAME}' dibuat")
        else:
            print(f"[DB] Database '{DB_NAME}' sudah ada")
    finally:
        conn.close()

    # Step 2: validasi dan buat tabel
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT TABLE_NAME FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE'",
            (DB_NAME,)
        )
        existing_tables = {row[0] for row in cur.fetchall()}
        missing_tables  = REQUIRED_TABLES - existing_tables

        if missing_tables:
            print(f"[DB] Tabel tidak lengkap, missing: {missing_tables} — recreate semua...")
            cur.execute("SET FOREIGN_KEY_CHECKS = 0")
            for table in existing_tables:
                cur.execute(f"DROP TABLE IF EXISTS `{table}`")
            cur.execute("SET FOREIGN_KEY_CHECKS = 1")

            cur.execute(CREATE_ALERTS_TABLE)
            cur.execute(CREATE_USERS_TABLE)
            cur.execute(CREATE_DEVICE_INFO_TABLE)
            cur.execute(CREATE_ROUTER_SERVICES_TABLE)
            cur.execute(CREATE_PORT_CHANGE_LOG_TABLE)
            conn.commit()
            print(f"[DB] ✅ Semua tabel berhasil dibuat")
        else:
            print(f"[DB] ✅ Semua tabel sudah lengkap")

    finally:
        conn.close()