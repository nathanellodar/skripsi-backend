# config.py

# --- Brute Force ---
BRUTE_FORCE_PORTS   = [22, 23, 3389, 8291]  # SSH, Telnet, RDP, Winbox
BRUTE_FORCE_THRESHOLD = 5                    # hits dalam window
BRUTE_FORCE_WINDOW    = 30                   # detik

# --- Port Scan ---
PORTSCAN_THRESHOLD = 5   # jumlah port unik dalam window
PORTSCAN_WINDOW    = 10  # detik

# --- DDoS ---
DDOS_THRESHOLD = 100  # total paket dari 1 IP dalam window
DDOS_WINDOW    = 5    # detik