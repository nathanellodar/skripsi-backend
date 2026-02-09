# log_watcher.py
import time
import io

def follow(thefile):
    thefile.seek(0, io.SEEK_END)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line.strip()
