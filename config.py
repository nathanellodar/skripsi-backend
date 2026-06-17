# config.py

# --- Brute Force ---
# Service MikroTik yang dianggap target brute force (nama dari ip/service)
BRUTE_FORCE_SERVICES  = {"ssh", "telnet", "winbox", "ftp", "api", "api-ssl"}
BRUTE_FORCE_THRESHOLD = 10
BRUTE_FORCE_WINDOW    = 3                  # detik

# --- Port Scan ---
PORTSCAN_THRESHOLD = 50   # jumlah port unik dalam window
PORTSCAN_WINDOW    = 1  # detik
    
# --- DDoS ---
DDOS_THRESHOLD = 100  # total paket dari 1 IP dalam window
DDOS_WINDOW    = 1    # detik