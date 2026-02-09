# parser.py
import re
from datetime import datetime

LOG_REGEX = re.compile(
    r'(?P<ts>[\d\-T\:\.\+\:]+).*?'
    r'(drop|accept)? .*?'
    r'proto (?P<proto>\w+).*?,.*?'
    r'(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)->'
    r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)'
)

def parse_log(line):
    m = LOG_REGEX.search(line)
    if not m:
        print("PARSE FAIL:", line)
        return None

    return {
        "timestamp": datetime.now(),
        "action": m.group(2),   # bisa None
        "proto": m.group("proto"),
        "src_ip": m.group("src_ip"),
        "src_port": int(m.group("src_port")),
        "dst_ip": m.group("dst_ip"),
        "dst_port": int(m.group("dst_port")),
        "raw": line
    }
