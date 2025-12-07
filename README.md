# NightWatch – An Intelligent EDR Framework

NightWatch is a Python-based **Endpoint Detection and Response (EDR)** mini-framework that runs on a Windows endpoint and monitors:

- Running processes  
- Network connections  
- File system activity  
- (Optionally) Windows registry and event logs  

It uses **multi-threaded background monitoring** and a **Flask-based web dashboard** to show real-time alerts, system statistics and suspicious activity.

---

## ✨ Features

- **Process Monitoring**
  - Tracks running processes, their paths, CPU/RAM usage and command lines.
  - Detects:
    - Execution from risky directories (e.g. Temp, Downloads, AppData).
    - Suspicious parent–child chains (e.g. `winword.exe → powershell.exe`).
    - Masquerading process names (e.g. `svch0st.exe`).
    - Encoded or very long PowerShell commands.

- **Network Monitoring**
  - Monitors active TCP/UDP connections.
  - Flags:
    - Blacklisted IPs.
    - Suspicious ports (e.g. 4444, 1337).
    - Excessive connections from a single process.

- **File System Monitoring**
  - Watches common malware drop locations (Downloads, Desktop, AppData, Startup, etc.).
  - Detects new or modified executable and script files (`.exe`, `.dll`, `.bat`, `.js`, `.ps1`, etc.).
  - Optionally computes **SHA-256 hashes** and compares against a known-bad list.

- **Anomaly / Baseline Checks**
  - Learns average process and connection counts for a short baseline window.
  - Raises alerts if there is a sudden spike in processes or connections.

- **Web Dashboard (Flask)**
  - Live system summary (CPU, RAM, process & connection counts).
  - Alerts table with severity.
  - Process and network views.
  - Basic stats and logs.

---

## 🧱 Project Structure (example)

Your project may look like this (adjust names if different):

```text
NightWatch/
├─ app.py        # Main EDR script (agent + Flask dashboard)
├─ templates/
│  └─ index.html            # Dashboard HTML
├─ static/
│  ├─ style.css             # Optional CSS
│  └─ main.js               # Optional JS for frontend
├─ requirements.txt         # Python dependencies
└─ README.md
```
Installation Steps
```
- git clone <your-repo-url> NightWatch
- cd NightWatch

- python -m venv venv
- venv\Scripts\activate

- pip install -r requirements.txt

- python app.py
```
