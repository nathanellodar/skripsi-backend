# config.py

# --- Brute Force ---
# Service MikroTik yang dianggap target brute force (nama dari ip/service)
BRUTE_FORCE_SERVICES  = {"ssh", "telnet", "winbox", "ftp", "api", "api-ssl"}
BRUTE_FORCE_THRESHOLD = 3                    # hits dalam window
BRUTE_FORCE_WINDOW    = 0.5                  # detik

# --- Port Scan ---
PORTSCAN_THRESHOLD = 30   # jumlah port unik dalam window
PORTSCAN_WINDOW    = 5  # detik
    
# --- DDoS ---
DDOS_THRESHOLD = 20  # total paket dari 1 IP dalam window
DDOS_WINDOW    = 1.5    # detik