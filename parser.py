# parser.py
import re
from datetime import datetime

LOG_REGEX = re.compile(
    r'(?P<ts>[\d\-T\:\.\+]+)'
    r'.*?'
    r'(?P<prefix>\[FW[^\]]*\])'          # ekstrak [FW] atau [FW-FLOOD]
    r'.*?'
    r'proto (?P<proto>\w+)'
    r'(?:\s*\([^)]+\))?'
    r'.*?'
    r'(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'(?::(?P<src_port>\d+))?'
    r'\s*->\s*'
    r'(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'(?::(?P<dst_port>\d+))?'
)

def parse_log(line: str) -> dict | None:
    m = LOG_REGEX.search(line)
    if not m:
        return None

    try:
        timestamp = datetime.fromisoformat(m.group("ts"))
    except ValueError:
        timestamp = datetime.now()

    return {
        "timestamp": timestamp,
        "prefix":    m.group("prefix"),   # [FW] atau [FW-FLOOD]
        "proto":     m.group("proto").upper(),
        "src_ip":    m.group("src_ip"),
        "src_port":  int(m.group("src_port")) if m.group("src_port") else 0,
        "dst_ip":    m.group("dst_ip"),
        "dst_port":  int(m.group("dst_port")) if m.group("dst_port") else 0,
        "raw":       line,
    }