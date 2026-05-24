# api/terminal.py
# Intercept semua output terminal (print/stdout) dan broadcast ke WebSocket client
import sys
import asyncio
import threading
from datetime import datetime


class TerminalBroadcaster:
    """
    Intercept sys.stdout sehingga setiap print() yang dipanggil di mana saja
    di program akan otomatis di-broadcast ke semua WebSocket client yang
    terhubung ke /terminal/ws.

    Cara kerja:
    - Saat init, ganti sys.stdout dengan instance ini
    - Setiap write() ke stdout akan tetap tampil di terminal asli (tee)
      dan sekaligus di-queue untuk di-broadcast ke WebSocket
    """

    def __init__(self):
        self._original_stdout = sys.stdout
        self._active_ws: list  = []
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop = None

    def install(self):
        """Pasang interceptor — panggil sekali saat startup."""
        sys.stdout = self
        print("[TERMINAL] Broadcaster aktif")

    def write(self, text: str):
        # Tetap tampil di terminal asli
        self._original_stdout.write(text)
        self._original_stdout.flush()

        # Broadcast ke WebSocket jika ada teks bermakna
        stripped = text.strip()
        if stripped and self._loop and self._active_ws:
            payload = {
                "type":      "terminal",
                "message":   stripped,
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            }
            # Jadwalkan broadcast di event loop asyncio
            asyncio.run_coroutine_threadsafe(
                self._broadcast(payload),
                self._loop
            )

    def flush(self):
        self._original_stdout.flush()

    def isatty(self) -> bool:
        """Dibutuhkan uvicorn/logging — delegate ke stdout asli."""
        return self._original_stdout.isatty()

    def fileno(self):
        """Dibutuhkan beberapa library — delegate ke stdout asli."""
        return self._original_stdout.fileno()

    def readable(self) -> bool:
        return False

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        """Set event loop asyncio — dipanggil dari run.py setelah loop siap."""
        self._loop = loop

    async def connect(self, ws):
        await ws.accept()
        with self._lock:
            self._active_ws.append(ws)

    def disconnect(self, ws):
        with self._lock:
            if ws in self._active_ws:
                self._active_ws.remove(ws)

    async def _broadcast(self, payload: dict):
        dead = []
        with self._lock:
            targets = list(self._active_ws)
        for ws in targets:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


# Singleton — satu instance dipakai di seluruh program
terminal_broadcaster = TerminalBroadcaster()