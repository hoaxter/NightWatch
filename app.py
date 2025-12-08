import threading
import time
from datetime import datetime
from collections import Counter, deque
import os

import psutil
from flask import Flask, jsonify, render_template

# Try Windows registry
try:
    import winreg
    HAVE_WINREG = True
except ImportError:
    HAVE_WINREG = False

app = Flask(__name__)


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
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
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
        r"C:\Users\Public",
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

    "baseline_learn_seconds": 60,
}

running = True

# Shared state
PROCESS_DATA = {}      # pid -> dict
NETWORK_DATA = []      # list[dict]
ALERTS = deque(maxlen=500)   # list of alerts
LOG_LINES = deque(maxlen=1000)

FS_STATE = {}          # path -> (size, mtime)

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


def severity_from_process(score: int, flags: list, hash_hit: bool) -> str:
    if hash_hit:
        return "high"
    if score >= 7:
        return "high"
    elif score >= 4:
        return "medium"
    else:
        return "low"
def severity_from_network(flags: list) -> str:
    if any("Blacklisted IP" in f for f in flags):
        return "high"
    if any("Suspicious port" in f for f in flags):
        return "medium"
    return "low"

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
        "severity": (severity or "medium").lower(),   # <-- important
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

    # office -> script/cli
    if parent_name in ("winword.exe", "excel.exe", "powerpnt.exe"):
        if name in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"):
            flags.append("Office spawning script/CLI process")
            score += 3

    # high cpu / mem
    if cpu > 70:
        flags.append(f"High CPU: {cpu:.1f}%")
        score += 1
    if mem > 70:
        flags.append(f"High RAM: {mem:.1f}%")
        score += 1

    # malware-like
    if name in CONFIG["malware_like_names"]:
        flags.append("Malware-like process name")
        score += 4

    return score, flags


def process_monitor():
    history = {}  # exe -> list[(pid, ts)]
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

                exe_key = (info["exe"] or "").lower()
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
                        f"PID={info['pid']} NAME={info['name']} SCORE={score} FLAGS={'; '.join(flags)}",
                        severity=sev,
                        extra={"pid": info["pid"], "name": info["name"], "flags": flags},
                )

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
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

        for c in conns_raw:
            pid = c.pid or 0
            conns_per_pid[pid] = conns_per_pid.get(pid, 0) + 1

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

        # RDP enabled example
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

        # detect new/changed
        for path, meta in new_state.items():
            lower = path.lower()
            _, ext = os.path.splitext(lower)
            if path not in old_state:
                if ext in CONFIG["suspicious_exts"]:
                    in_startup = any(os.path.expandvars(sd).lower() in lower for sd in CONFIG["startup_dirs"])
                    reason = "New executable/script file"
                    if in_startup:
                        reason += " in Startup folder (persistence)"
                    add_alert("File-System", "FSMonitor", f"{reason}: {path}")
            else:
                if old_state[path] != meta and ext in CONFIG["suspicious_exts"]:
                    add_alert("File-System", "FSMonitor", f"Suspicious file modified: {path}")

        time.sleep(CONFIG["filesystem_scan_interval"])


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

    # total alerts – we expose both names for compatibility
    total_alerts = len(ALERTS)

    return jsonify({
        "cpu": cpu,
        "mem": mem,
        "proc_count": proc_count,
        "conn_count": conn_count,
        "alert_total": total_alerts,            # <-- what the UI uses now
        "alert_count": total_alerts,            # <-- legacy name, just in case
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
    return jsonify(conns)


@app.route("/api/alerts")
def api_alerts():
    return jsonify(list(ALERTS))


@app.route("/api/logs")
def api_logs():
    return jsonify(list(LOG_LINES))


@app.route("/api/stats")
def api_stats():
    return jsonify({
        "cpu_history": list(CPU_HISTORY),
        "mem_history": list(MEM_HISTORY),
        "alert_categories": dict(ALERT_COUNTER),
    })


# ------------- startup -------------

def start_background_threads():
    threads = [
        threading.Thread(target=process_monitor, daemon=True),
        threading.Thread(target=network_monitor, daemon=True),
        threading.Thread(target=registry_monitor, daemon=True),
        threading.Thread(target=filesystem_monitor, daemon=True),
        threading.Thread(target=anomaly_monitor, daemon=True),
        threading.Thread(target=stats_monitor, daemon=True),
    ]
    for t in threads:
        t.start()
    log_line("Background monitoring threads started.")


if __name__ == "__main__":
    start_background_threads()
    # debug can be False in production
    app.run(host="127.0.0.1", port=5000, debug=False)
