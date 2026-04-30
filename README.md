# Mikrotik Log Analyzer - Attack Detection System

This system analyzes Mikrotik router firewall logs in real-time to detect various types of network attacks including DDoS, port scanning, and brute force attempts.

## Features

- Real-time log processing (simulated with file reading)
- Modular architecture with separate detectors for each attack type
- Configurable thresholds and time windows
- Detailed alert output with raw log information

## Detection Capabilities

1. **DDoS/Flood Detection**: Identifies IPs sending excessive requests within a time window
2. **Port Scanning Detection**: Identifies IPs accessing multiple different ports within a time window
3. **SSH Brute Force Detection**: Identifies IPs making multiple failed SSH connection attempts (port 22)

## File Structure

```
.
├── config.py          # Configuration parameters (thresholds, time windows)
├── engine.py          # Main detection engine coordinating all detectors
├── get_log.py         # Log file follower (tail -f equivalent)
├── main.py            # Entry point of the application
├── parser.py          # Log line parser converting text to structured data
├── log-example.txt    # Sample Mikrotik firewall logs
├── attack_detec/
│   ├── brute.py       # SSH Brute Force detector
│   ├── ddos.py        # DDoS/Flood detector
│   └── scan.py        # Port scanning detector
└── README.md          # This file
```

## How It Works

1. **Log Parsing**: `parser.py` extracts timestamp, source/destination IPs and ports, protocol, and action from Mikrotik firewall log lines
2. **Detection Engine**: `engine.py` runs all detectors in parallel and collects alerts
3. **Detectors**: Each detector in `attack_detec/` maintains state and checks if thresholds are exceeded:
   - Tracks events per IP with timestamps
   - Removes old events outside the time window
   - Triggers alerts when event count exceeds threshold
4. **Main Loop**: `main.py` reads logs (can be modified to follow live files) and processes each line

## Configuration

Adjust detection sensitivity in `config.py`:

```python
# DDoS Detection
DDOS_THRESHOLD = 3            # Minimum requests to trigger alert
DDOS_WINDOW = 5               # Time window in seconds

# Port Scanning Detection
PORTSCAN_THRESHOLD = 2        # Minimum different ports to trigger alert
PORTSCAN_WINDOW = 10          # Time window in seconds

# Brute Force Detection
BRUTE_FORCE_THRESHOLD = 3     # Minimum failed attempts to trigger alert
BRUTE_FORCE_WINDOW = 10       # Time window in seconds
```

## Running the System

```bash
python main.py
```

## Sample Output

```
Parsed: 109.252.190.230:3208 -> 222.124.22.44:22535 (TCP)
[ALERT] DDoS/Flood from 109.252.190.230
   Raw: 2026-04-29T09:31:06.283024+00:00 _gateway firewall,info [FW] input: in:ether1 - TELKOM out:(unknown 0), connection-state:new src-mac DC:EF:80:83:F6:48, proto TCP (SYN), 109.252.190.230:3208->222.124.22.44:22535, len 52
```

## Extending the System

To add new detection types:
1. Create a new detector class in `attack_detec/` following the pattern
2. Import and instantiate it in `engine.py`
3. The detector should implement a `process(log)` method that returns an alert string or None

## Requirements

- Python 3.7+
- No external dependencies (uses only standard library)

## Notes

- The system currently reads from a static file for demonstration. To monitor live logs, modify `main.py` to use the `follow()` function from `get_log.py` and point to your actual Mikrotik log file.
- Timestamp parsing handles ISO format with timezone information from Mikrotik logs.
- All detectors are designed to be efficient with O(1) average time complexity per log entry.