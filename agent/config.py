import os

SERVER_URL = "http://127.0.0.1:5001"
POLL_INTERVAL = 5
HEARTBEAT_INTERVAL = 30

# Directories to monitor
MONITOR_DIRS = [
    os.path.expandvars(r"%USERPROFILE%\Downloads"),
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
    os.path.expandvars(r"%TEMP%"),
]

# Suspicious extensions
SUSPICIOUS_EXTS = {".exe", ".dll", ".ps1", ".bat", ".vbs", ".js"}
