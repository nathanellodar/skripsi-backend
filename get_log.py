# get_log.py
from dotenv import load_dotenv
load_dotenv()

import os
import io
import time
import socket
from typing import Generator

MODE         = os.getenv("LOG_MODE",  "dev")
LOG_FILE     = os.getenv("LOG_FILE",  "/var/log/mikrotik/gateway.log")
TCP_HOST     = os.getenv("LOG_HOST",  "192.168.100.51")
TCP_PORT     = int(os.getenv("LOG_PORT", "9000"))


def _follow_file(filepath: str) -> Generator[str, None, None]:
    """Tail file secara realtime (deploy mode)."""
    with open(filepath, "r") as f:
        f.seek(0, io.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line.strip()


def _follow_tcp(host: str, port: int) -> Generator[str, None, None]:
    """Terima log stream dari server via TCP (dev mode)."""
    while True:
        try:
            print(f"[get_log] Connecting to {host}:{port} ...")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, port))
                print("[get_log] Connected.")
                buffer = ""
                while True:
                    data = s.recv(4096).decode("utf-8", errors="replace")
                    if not data:
                        print("[get_log] Connection closed, reconnecting...")
                        break
                    buffer += data
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()
                        if line:
                            yield line
        except (ConnectionRefusedError, OSError) as e:
            print(f"[get_log] {e} — retry in 5s...")
            time.sleep(5)


def follow() -> Generator[str, None, None]:
    if MODE == "dev":
        print(f"[get_log] Mode: DEV  — TCP stream {TCP_HOST}:{TCP_PORT}")
        yield from _follow_tcp(TCP_HOST, TCP_PORT)
    elif MODE == "deploy":
        print(f"[get_log] Mode: DEPLOY — file {LOG_FILE}")
        yield from _follow_file(LOG_FILE)
    else:
        raise ValueError(f"[get_log] LOG_MODE tidak dikenal: '{MODE}' (gunakan 'dev' atau 'deploy')")