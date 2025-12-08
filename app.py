import threading
import time
from datetime import datetime
from collections import Counter, deque
import os
import hashlib
import psutil
from flask import Flask, jsonify, render_template

try:
    import winreg
    HAVE_WINREG = True
except ImportError:
    HAVE_WINREG = False

try:
    import win32evtlog
    import win32evtlogutil
    HAVE_EVENTLOGS = True
except ImportError:
    HAVE_EVENTLOGS = False

app = Flask(__name__)

# ---------------- CONFIG ----------------

CONFIG = {
    "blacklisted_ips": {"1.2.3.4", "5.6.7.8"},  
    "suspicious_ports": {4444, 1337, 6666, 9001},

    "suspicious_parents": {
        ("winword.exe", "powershell.exe"),
        ("winword.exe", "cmd.exe"),
        ("excel.exe", "powershell.exe"),
        ("excel.exe", "cmd.exe"),
        ("powerpnt.exe", "powershell.exe"),
    },

    "risky_dirs": [
        "\\appdata\\",
        "\\temp\\",
        "\\users\\public\\",
    ],

    "startup_dirs": [
        os.path.expandvars(r"%APPDATA%\\Microsoft\Windows\Start Menu\\Programs\Startup"),
        r"C:\\ProgramData\\Microsoft\Windows\Start Menu\\Programs\Startup",
    ],

    "long_cmdline_len": 200,
    "max_conns_per_proc": 50,

    "malware_like_names": {
        "mimikatz.exe",
        "nc.exe",
        "netcat.exe",
        "ngrok.exe",
        "keylogger.exe",
        "rat.exe",
        "svhost.exe",
        "svch0st.exe",
        "mshta.exe",
        "msbuild.exe",
        "powershell_ise.exe",
    },

    "file_monitor_dirs": [
        os.path.expandvars(r"%USERPROFILE%\Downloads"),
        os.path.expandvars(r"%USERPROFILE%\Desktop"),
        os.path.expandvars(r"%APPDATA%"),
        r"C:\\Users\\Public",
    ],

    "suspicious_exts": {
        ".exe", ".dll", ".scr", ".ps1", ".bat",
        ".cmd", ".js", ".jse", ".vbs", ".vbe"
    },

    "process_scan_interval": 5,
    "network_scan_interval": 7,
    "registry_scan_interval": 15,
    "filesystem_scan_interval": 30,
    "anomaly_interval": 20,
    "stats_interval": 2,
    "eventlog_interval": 30,

    "baseline_learn_seconds": 60,

    # Advanced: Suspicious event IDs for alerting (Security log examples)
    "suspicious_event_ids": {
        4625: "Failed logon attempt",  # Account logon failure
        4771: "Kerberos pre-authentication failure",
        1102: "Security log cleared",
        4616: "System time changed",
    },

    # Advanced: Network summary thresholds
    "top_ips_threshold": 5,  # Show top N IPs in summary
}

# Update CONFIG with hash settings
CONFIG.update({
    "known_bad_hashes": {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    },
    "hash_max_read_bytes": 10 * 1024 * 1024, 
})

running = True

PROCESS_DATA = {}      
NETWORK_DATA = []    
NETWORK_SUMMARY = {}   
ALERTS = deque(maxlen=500)   
LOG_LINES = deque(maxlen=1000)
EVENT_LOGS = deque(maxlen=500)  

FS_STATE = {}          

CPU_HISTORY = deque(maxlen=100)
MEM_HISTORY = deque(maxlen=100)
ALERT_COUNTER = Counter()

BASELINE = {
    "start_time": None,
    "proc_counts": [],
    "conn_counts": [],
    "baseline_ready": False,
    "avg_procs": 0.0,
    "avg_conns": 0.0,
}

# Locks
lock_proc = threading.Lock()
lock_net = threading.Lock()
lock_fs = threading.Lock()
lock_baseline = threading.Lock()
lock_eventlogs = threading.Lock()
lock_net_summary = threading.Lock()  

# Hash cache: path -> sha256 hex
HASH_CACHE = {}
lock_hash = threading.Lock()


try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent, FileMovedEvent
    HAVE_WATCHDOG = True
except Exception:
    HAVE_WATCHDOG = False

# ------------- helper utils -------------

def now_str():
    return datetime.now().strftime("%H:%M:%S")

def log_line(msg: str):
    line = f"[{now_str()}] {msg}"
    LOG_LINES.append(line)

ALERT_CATEGORY_COUNTER = Counter()
ALERT_SEVERITY_COUNTER = Counter()

def add_alert(category: str, source: str, message: str,
              severity: str = "medium", extra=None):
    data = {
        "time": now_str(),
        "category": category,
        "source": source,
        "message": message,
        "severity": (severity or "medium").lower(),
        "extra": extra or {},
    }
    ALERTS.appendleft(data)
    ALERT_CATEGORY_COUNTER[category] += 1
    ALERT_SEVERITY_COUNTER[data["severity"]] += 1
    log_line(f"[{source}/{category}/{data['severity'].upper()}] {message}")

def safe_exe(p: psutil.Process):
    try:
        return p.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return ""

def safe_cmdline(p: psutil.Process):
    try:
        return p.cmdline()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return []

def safe_user(p: psutil.Process):
    try:
        return p.username()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "N/A"

def safe_parent(p: psutil.Process):
    try:
        return p.parent()
    except (psutil.NoSuchProcess, psutil.Error):
        return None

def compute_sha256(path: str) -> str | None:
    if not path:
        return None

    p = os.path.expandvars(path)
    cache_key = os.path.normcase(os.path.abspath(p))

    with lock_hash:
        if cache_key in HASH_CACHE:
            return HASH_CACHE[cache_key]

    try:
        if not os.path.isfile(p):
            return None
        st = os.stat(p)
        max_bytes = CONFIG.get("hash_max_read_bytes", 10 * 1024 * 1024)
        if st.st_size > max_bytes:
            return None

        h = hashlib.sha256()
        with open(p, "rb") as f:
            # read in chunks
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        digest = h.hexdigest().lower()
    except Exception:
        return None

    with lock_hash:
        HASH_CACHE[cache_key] = digest
    return digest

def is_known_bad_hash(digest: str) -> bool:
    if not digest:
        return False
    return digest.lower() in {h.lower() for h in CONFIG.get("known_bad_hashes", set())}

# ------------- severity helpers -------------

def severity_from_process(score: int, flags, hash_hit: bool = False) -> str:
    """
    Map process score/flags/hash info -> severity string: low/medium/high/critical
    """
    flags = [f.lower() for f in (flags or [])]


    if hash_hit:
        return "critical"

  
    if score >= 8 or any("malware-like" in f for f in flags):
        return "critical"
    if score >= 6 or any("suspicious powershell" in f for f in flags):
        return "high"

    if score >= 3 or any(
        s in " ".join(flags)
        for s in [
            "office spawning script",
            "script execution via wscript",
            "frequent restarts",
            "executable in risky directory",
        ]
    ):
        return "medium"

    return "low"

def severity_from_network(flags) -> str:
    """
    Map network flags -> severity string.
    """
    flags = [f.lower() for f in (flags or [])]

    if any("blacklisted ip" in f for f in flags):
        return "critical"
    if any("suspicious port" in f for f in flags):
        return "high"
    if any("many connections" in f or "non-browser with many connections" in f for f in flags):
        return "medium"

    return "low"

# ------------- detection: process -------------

def evaluate_process(info: dict):
    """Return score, flags list."""
    score = 0
    flags = []

    name = (info.get("name") or "").lower()
    exe = (info.get("exe") or "").lower()
    cmd = " ".join(info.get("cmdline") or []).lower()
    parent_name = (info.get("parent_name") or "").lower()
    cpu = info.get("cpu", 0.0) or 0.0
    mem = info.get("mem", 0.0) or 0.0

    # risky dir
    for d in CONFIG["risky_dirs"]:
        if exe and d in exe:
            flags.append("Executable in risky directory")
            score += 2
            break

    # long cmd
    if len(cmd) > CONFIG["long_cmdline_len"]:
        flags.append("Very long command line")
        score += 1

    # suspicious powershell
    if "powershell.exe" in name or "powershell" in exe:
        if any(k in cmd for k in ["-enc", "downloadstring", "invoke-webrequest", "iex", "frombase64string"]):
            flags.append("Suspicious PowerShell usage")
            score += 3

    # parent-child
    for parent, child in CONFIG["suspicious_parents"]:
        if parent_name == parent and name == child:
            flags.append(f"Suspicious parent-child: {parent}->{child}")
            score += 3

    # masquerading
    for pat in ["svch0st", "cr0me", "expl0rer", "1sass", "1ssas"]:
        if pat in name:
            flags.append("Masquerading system process name")
            score += 3
            break

    # script hosts
    if name in ("wscript.exe", "cscript.exe"):
        if any(ext in cmd for ext in [".js", ".vbs", ".jse", ".vbe"]):
            flags.append("Script execution via WScript/CScript")
            score += 2

    
    if parent_name in ("winword.exe", "excel.exe", "powerpnt.exe"):
        if name in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"):
            flags.append("Office spawning script/CLI process")
            score += 3

 
    if cpu > 70:
        flags.append(f"High CPU: {cpu:.1f}%")
        score += 1
    if mem > 70:
        flags.append(f"High RAM: {mem:.1f}%")
        score += 1

    if name in CONFIG["malware_like_names"]:
        flags.append("Malware-like process name")
        score += 4

    return score, flags

def process_monitor():
    history = {}  
    while running:
        ts = time.time()
        new_data = {}

        for p in psutil.process_iter(attrs=["pid", "name"]):
            try:
                info = p.as_dict(attrs=["pid", "name"])
                info["exe"] = safe_exe(p)
                info["cmdline"] = safe_cmdline(p)
                info["user"] = safe_user(p)
            
                info["cpu"] = p.cpu_percent(interval=0.0)
                info["mem"] = p.memory_percent()
                parent = safe_parent(p)
                info["parent_name"] = parent.name() if parent else ""

                score, flags = evaluate_process(info)

                hash_hit = False
                exe_path = (info.get("exe") or "").strip()
                if exe_path:
                    try:
                        digest = compute_sha256(exe_path)
                    except Exception:
                        digest = None
                    if digest:
                        info["sha256"] = digest
                        if is_known_bad_hash(digest):
                            flags.append("Known-malicious file hash")
                            score += 8
                            hash_hit = True

                
                exe_key = (info.get("exe") or "").lower()
                if exe_key:
                    history.setdefault(exe_key, [])
                    history[exe_key].append((info["pid"], ts))
                    # keep last 60s
                    history[exe_key] = [(pid, t) for pid, t in history[exe_key] if ts - t <= 60]
                    unique_pids = {pid for pid, _ in history[exe_key]}
                    if len(unique_pids) > 5:
                        flags.append("Frequent restarts (behavioral)")
                        score += 2

                info["score"] = score
                info["flags"] = flags
                new_data[info["pid"]] = info

                if score > 0 and flags:
                    sev = severity_from_process(score, flags, hash_hit)
                    add_alert(
                        "Process",
                        "ProcessMonitor",
                        f"PID={info['pid']} NAME={info.get('name')} SCORE={score} FLAGS={'; '.join(flags)}",
                        severity=sev,
                        extra={
                            "pid": info["pid"],
                            "name": info.get("name"),
                            "flags": flags,
                            "sha256": info.get("sha256"),
                        },
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                log_line(f"process_monitor unexpected error: {e}")
                continue

        with lock_proc:
            PROCESS_DATA.clear()
            PROCESS_DATA.update(new_data)

        # feed baseline
        with lock_baseline:
            if BASELINE["start_time"] is None:
                BASELINE["start_time"] = ts
            BASELINE["proc_counts"].append(len(new_data))
            if not BASELINE["baseline_ready"] and ts - BASELINE["start_time"] >= CONFIG["baseline_learn_seconds"]:
                if BASELINE["proc_counts"]:
                    BASELINE["avg_procs"] = sum(BASELINE["proc_counts"]) / len(BASELINE["proc_counts"])
                BASELINE["baseline_ready"] = True

        time.sleep(CONFIG["process_scan_interval"])


# ------------- detection: network -------------

def evaluate_connection(conn, conns_per_pid):
    score = 0
    flags = []

    raddr = conn.get("raddr") or ""
    pid = conn.get("pid")
    proc_name = (conn.get("proc_name") or "").lower()

    if ":" in raddr:
        ip, port_s = raddr.split(":", 1)
    else:
        ip, port_s = raddr, ""
    try:
        port = int(port_s) if port_s else 0
    except ValueError:
        port = 0

    if ip in CONFIG["blacklisted_ips"]:
        flags.append(f"Blacklisted IP {ip}")
        score += 4

    if port in CONFIG["suspicious_ports"]:
        flags.append(f"Suspicious port {port}")
        score += 3

    if pid is not None:
        n = conns_per_pid.get(pid, 0)
        if n > CONFIG["max_conns_per_proc"]:
            flags.append(f"Many connections from PID ({n})")
            score += 2

        browser_like = any(b in proc_name for b in ["chrome", "edge", "firefox", "brave", "opera"])
        if not browser_like and n > 20:
            flags.append("Non-browser with many connections")
            score += 2

    return score, flags


def network_monitor():
    while running:
        conns_raw = psutil.net_connections(kind="inet")
        conns_per_pid = {}
        new_data = []
        ip_counter = Counter()

        for c in conns_raw:
            pid = c.pid or 0
            conns_per_pid[pid] = conns_per_pid.get(pid, 0) + 1
            if c.raddr:
                ip_counter[c.raddr.ip] += 1

        for c in conns_raw:
            if not c.raddr:
                continue
            try:
                pid = c.pid
                proc_name = ""
                if pid:
                    try:
                        proc_name = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        proc_name = ""

                info = {
                    "pid": pid,
                    "proc_name": proc_name,
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}",
                    "status": c.status,
                }

                score, flags = evaluate_connection(info, conns_per_pid)
                info["score"] = score
                info["flags"] = flags
                new_data.append(info)

                if score > 0 and flags:
                    sev = severity_from_network(flags)
                    add_alert(
                        "Network",
                        "NetworkMonitor",
                        f"PID={pid} NAME={proc_name} RADDR={info['raddr']} FLAGS={'; '.join(flags)}",
                        severity=sev,
                        extra=info,
                    )

            except Exception:
                continue

        with lock_net:
            NETWORK_DATA.clear()
            NETWORK_DATA.extend(new_data)

        top_ips = ip_counter.most_common(CONFIG["top_ips_threshold"])
        with lock_net_summary:
            NETWORK_SUMMARY = dict(top_ips)

        # baseline
        ts = time.time()
        with lock_baseline:
            BASELINE["conn_counts"].append(len(new_data))
            if BASELINE["start_time"] is None:
                BASELINE["start_time"] = ts
            if not BASELINE["baseline_ready"] and ts - BASELINE["start_time"] >= CONFIG["baseline_learn_seconds"]:
                if BASELINE["conn_counts"]:
                    BASELINE["avg_conns"] = sum(BASELINE["conn_counts"]) / len(BASELINE["conn_counts"])
                if BASELINE["avg_procs"] == 0 and BASELINE["proc_counts"]:
                    BASELINE["avg_procs"] = sum(BASELINE["proc_counts"]) / len(BASELINE["proc_counts"])
                BASELINE["baseline_ready"] = True

        time.sleep(CONFIG["network_scan_interval"])


# ------------- detection: registry (persistence / security) -------------

def snapshot_run_keys():
    if not HAVE_WINREG:
        return {}
    root_map = {
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
    }
    key_paths = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    snap = {}
    for path in key_paths:
        try:
            root_name, subkey = path.split("\\", 1)
            root = root_map[root_name]
            key = winreg.OpenKey(root, subkey, 0, winreg.KEY_READ)
        except Exception:
            continue
        values = {}
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                values[name] = value
                i += 1
            except OSError:
                break
        snap[path] = values
    return snap


def registry_monitor():
    if not HAVE_WINREG:
        log_line("winreg not available – registry monitoring disabled.")
        return

    prev = snapshot_run_keys()
    while running:
        time.sleep(CONFIG["registry_scan_interval"])
        current = snapshot_run_keys()

        for k, vals in current.items():
            old_vals = prev.get(k, {})
            for name, val in vals.items():
                if name not in old_vals:
                    add_alert(
                        "Registry",
                        "RegistryMonitor",
                        f"New Run entry: {k}\\{name} = {val}",
                    )
                else:
                    if old_vals[name] != val:
                        add_alert(
                            "Registry",
                            "RegistryMonitor",
                            f"Modified Run entry: {k}\\{name} = {val}",
                        )

        try:
            root = winreg.HKEY_LOCAL_MACHINE
            key = winreg.OpenKey(root, r"SYSTEM\CurrentControlSet\Control\Terminal Server")
            value, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
            if value == 0:
                add_alert(
                    "Registry",
                    "RegistryMonitor",
                    "RDP enabled via registry (fDenyTSConnections=0)",
                )
        except Exception:
            pass

        prev = current


# ------------- detection: filesystem (persistence + malware drops) -------------

def filesystem_monitor():
    global FS_STATE
    with lock_fs:
        FS_STATE = {}

    while running:
        new_state = {}
        watch_dirs = CONFIG["file_monitor_dirs"] + CONFIG["startup_dirs"]
        for base in watch_dirs:
            base = os.path.expandvars(base)
            if not os.path.isdir(base):
                continue
            for root, dirs, files in os.walk(base):
                for f in files:
                    path = os.path.join(root, f)
                    try:
                        st = os.stat(path)
                    except OSError:
                        continue
                    new_state[path] = (st.st_size, st.st_mtime)

        with lock_fs:
            old_state = FS_STATE
            FS_STATE = new_state

        for path, meta in new_state.items():
            try:
                lower = path.lower()
                _, ext = os.path.splitext(lower)

                if ext not in CONFIG["suspicious_exts"]:
                    continue

                in_startup = any(os.path.expandvars(sd).lower() in lower for sd in CONFIG["startup_dirs"])
                reason_base = "New executable/script file" if path not in old_state else "Suspicious file modified"
                if in_startup:
                    reason_base += " in Startup folder (persistence)"

                digest = None
                try:
                    digest = compute_sha256(path)
                except Exception:
                    digest = None

                if digest and is_known_bad_hash(digest):
                    add_alert(
                        "File-System",
                        "FSMonitor",
                        f"{reason_base} (known-bad hash): {path}",
                        severity="critical",
                        extra={"path": path, "sha256": digest},
                    )
                else:
                    add_alert(
                        "File-System",
                        "FSMonitor",
                        f"{reason_base}: {path}",
                        extra={"path": path, "sha256": digest},
                    )

            except Exception as e:
                # keep monitor alive; log unexpected errors for troubleshooting
                log_line(f"filesystem_monitor unexpected error for {path}: {e}")
                continue

        time.sleep(CONFIG["filesystem_scan_interval"])


# ------------- watchdog integration (optional, preferred) -------------

FS_OBSERVER = None
FS_EVENT_DEBOUNCE = {} 
FS_DEBOUNCE_SECONDS = 1.0
DEFAULT_IGNORE_PATTERNS = [
    "*.tmp", "~$*", "*.crdownload", "*.part", "*.swp", ".~lock.*",
]

import fnmatch


def _is_ignored_path(path: str) -> bool:
    p = path.lower()
    for pat in DEFAULT_IGNORE_PATTERNS:
        if fnmatch.fnmatch(os.path.basename(p), pat):
            return True
    try:
        st = os.stat(path)
        max_bytes = CONFIG.get("hash_max_read_bytes", 10 * 1024 * 1024)
        if st.st_size > max_bytes:
            return True
    except Exception:
        pass
    return False


if HAVE_WATCHDOG:
    class EDRFileHandler(FileSystemEventHandler):
        def __init__(self):
            super().__init__()

        def _should_process(self, path: str) -> bool:
            if not path:
                return False
            _, ext = os.path.splitext(path.lower())
            if ext not in CONFIG["suspicious_exts"]:
                return False
            if _is_ignored_path(path):
                return False
            now_ts = time.time()
            last = FS_EVENT_DEBOUNCE.get(path)
            if last and (now_ts - last) < FS_DEBOUNCE_SECONDS:
                return False
            FS_EVENT_DEBOUNCE[path] = now_ts
            return True

        def _handle_path(self, path: str, event_type: str, dest_path: str | None = None):
            try:
                if not self._should_process(path):
                    return

                lower = path.lower()
                in_startup = any(os.path.expandvars(sd).lower() in lower for sd in CONFIG["startup_dirs"])
                reason_base = f"{event_type}"
                if in_startup:
                    reason_base += " in Startup folder (persistence)"

                digest = None
                try:
                    digest = compute_sha256(path)
                except Exception:
                    digest = None

                if digest and is_known_bad_hash(digest):
                    add_alert(
                        "File-System",
                        "FSWatch",
                        f"{reason_base} (known-bad hash): {path}" + (f" -> {dest_path}" if dest_path else ""),
                        severity="critical",
                        extra={"path": path, "sha256": digest, "event": event_type, "dest": dest_path},
                    )
                else:
                    add_alert(
                        "File-System",
                        "FSWatch",
                        f"{reason_base}: {path}" + (f" -> {dest_path}" if dest_path else ""),
                        extra={"path": path, "sha256": digest, "event": event_type, "dest": dest_path},
                    )

            except Exception as e:
                log_line(f"EDRFileHandler unexpected error for {path}: {e}")

        def on_created(self, event):
            if isinstance(event, FileCreatedEvent) and not event.is_directory:
                self._handle_path(event.src_path, "New executable/script file")

        def on_modified(self, event):
            if isinstance(event, FileModifiedEvent) and not event.is_directory:
                self._handle_path(event.src_path, "Suspicious file modified")

        def on_moved(self, event):
            if isinstance(event, FileMovedEvent) and not event.is_directory:
                self._handle_path(event.dest_path, "File moved/renamed (created)", dest_path=event.src_path)

        def on_deleted(self, event):
            pass


# ------------- Windows Event Log monitoring -------------

def eventlog_monitor():
    if not HAVE_EVENTLOGS:
        log_line("pywin32 not available – event log monitoring disabled.")
        return

    while running:
        for log_type in ['System', 'Application', 'Security']:
            try:
                hand = win32evtlog.OpenEventLog(None, log_type)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                total = win32evtlog.GetNumberOfEventLogRecords(hand)
                events = win32evtlog.ReadEventLog(hand, flags, 0, 0, 50)  

                for e in events[:5]:  
                    try:
                        desc = win32evtlogutil.SafeFormatMessage(e, log_type)
                        event_data = {
                            "time": str(e.TimeGenerated),
                            "log": log_type,
                            "event_id": e.EventID,
                            "source": e.SourceName,
                            "category": e.EventCategory,
                            "message": desc[:200] + '...' if len(desc) > 200 else desc,
                        }
                        with lock_eventlogs:
                            EVENT_LOGS.appendleft(event_data)

                       
                        if e.EventID in CONFIG["suspicious_event_ids"]:
                            sev = "high" if e.EventID == 4625 else "critical"
                            alert_msg = f"{CONFIG['suspicious_event_ids'][e.EventID]} (Event ID {e.EventID}): {e.SourceName}"
                            add_alert(
                                "EventLog",
                                f"{log_type}Monitor",
                                alert_msg,
                                severity=sev,
                                extra=event_data,
                            )
                    except Exception as e_inner:
                        log_line(f"Error processing event {e.EventID}: {e_inner}")
                        continue

                win32evtlog.CloseEventLog(hand)
            except Exception as ex:
                log_line(f"Event log read error for {log_type}: {ex}")

        time.sleep(CONFIG["eventlog_interval"])


# ------------- anomaly & system stats -------------

def anomaly_monitor():
    while running:
        time.sleep(CONFIG["anomaly_interval"])
        with lock_proc:
            proc_count = len(PROCESS_DATA)
        with lock_net:
            conn_count = len(NETWORK_DATA)
        with lock_baseline:
            if not BASELINE["baseline_ready"]:
                continue
            avg_p = BASELINE["avg_procs"] or 1
            avg_c = BASELINE["avg_conns"] or 1

        if proc_count > 2 * avg_p:
            add_alert(
                "Anomaly",
                "AnomalyMonitor",
                f"Process count anomaly: current={proc_count}, baseline≈{avg_p:.1f}",
            )
        if conn_count > 2 * avg_c:
            add_alert(
                "Anomaly",
                "AnomalyMonitor",
                f"Connection count anomaly: current={conn_count}, baseline≈{avg_c:.1f}",
            )


def stats_monitor():
    while running:
        cpu = psutil.cpu_percent(interval=0.0)
        mem = psutil.virtual_memory().percent
        CPU_HISTORY.append(cpu)
        MEM_HISTORY.append(mem)
        time.sleep(CONFIG["stats_interval"])


# ------------- Flask routes (API + pages) -------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/summary")
def api_summary():
    with lock_proc:
        proc_count = len(PROCESS_DATA)
    with lock_net:
        conn_count = len(NETWORK_DATA)

    cpu = CPU_HISTORY[-1] if CPU_HISTORY else 0
    mem = MEM_HISTORY[-1] if MEM_HISTORY else 0

   
    total_alerts = len(ALERTS)

    return jsonify({
        "cpu": cpu,
        "mem": mem,
        "proc_count": proc_count,
        "conn_count": conn_count,
        "alert_total": total_alerts,          
        "alert_count": total_alerts,            
        "category_counts": dict(ALERT_CATEGORY_COUNTER),
        "severity_counts": dict(ALERT_SEVERITY_COUNTER),
    })


@app.route("/api/processes")
def api_processes():
    with lock_proc:
        procs = list(PROCESS_DATA.values())
    # make JSON-safe
    for p in procs:
        p["flags"] = p.get("flags", [])
    return jsonify(procs)


@app.route("/api/network")
def api_network():
    with lock_net:
        conns = list(NETWORK_DATA)
    for c in conns:
        c["flags"] = c.get("flags", [])
    with lock_net_summary:
        summary = NETWORK_SUMMARY
    return jsonify({
        "connections": conns,
        "summary": summary,
    })


@app.route("/api/alerts")
def api_alerts():
    return jsonify(list(ALERTS))


@app.route("/api/logs")
def api_logs():
    return jsonify(list(LOG_LINES))


@app.route("/api/eventlogs")  
def api_eventlogs():
    with lock_eventlogs:
        logs = list(EVENT_LOGS)
    return jsonify(logs)


@app.route("/api/stats")
def api_stats():
    return jsonify({
        "cpu_history": list(CPU_HISTORY),
        "mem_history": list(MEM_HISTORY),
        "category_counts": dict(ALERT_CATEGORY_COUNTER), 
    })


# ------------- startup -------------

def start_background_threads():
    global FS_OBSERVER
    threads = [
        threading.Thread(target=process_monitor, daemon=True),
        threading.Thread(target=network_monitor, daemon=True),
        threading.Thread(target=registry_monitor, daemon=True),
        # keep filesystem_monitor as fallback if watchdog not available
        threading.Thread(target=filesystem_monitor, daemon=True) if not HAVE_WATCHDOG else None,
        threading.Thread(target=anomaly_monitor, daemon=True),
        threading.Thread(target=stats_monitor, daemon=True),
        # Event log monitor if available
        threading.Thread(target=eventlog_monitor, daemon=True) if HAVE_EVENTLOGS else None,
    ]

    for t in threads:
        if t is None:
            continue
        t.start()

    if HAVE_WATCHDOG:
        try:
            event_handler = EDRFileHandler()
            observer = Observer()
            FS_OBSERVER = observer
            watch_dirs = list(dict.fromkeys([os.path.expandvars(d) for d in (CONFIG["file_monitor_dirs"] + CONFIG["startup_dirs"]) ]))
            for d in watch_dirs:
                if os.path.isdir(d):
                    observer.schedule(event_handler, path=d, recursive=True)
            observer.daemon = True
            observer.start()
            log_line("Watchdog filesystem observer started.")
        except Exception as e:
            log_line(f"Failed to start watchdog observer: {e}")

    log_line("Background monitoring threads started.")


if __name__ == "__main__":
    start_background_threads()
    try:
        app.run(host="127.0.0.1", port=5000, debug=False)
    finally:
        try:
            if FS_OBSERVER:
                FS_OBSERVER.stop()
                FS_OBSERVER.join(timeout=2)
        except Exception:
            pass