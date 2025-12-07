import os
import sys
import time
import socket
import subprocess
from pathlib import Path

def get_downloads_dir() -> Path:
    user = os.path.expandvars(r"%USERPROFILE%")
    return Path(user) / "Downloads"

def write_suspicious_files():
    downloads = get_downloads_dir()
    downloads.mkdir(parents=True, exist_ok=True)
    
    exe_path = downloads / "edr_demo_malware.exe"
    
    print(f"[*] Creating suspicious file: {exe_path}")
    try:
        exe_path.write_bytes(os.urandom(2048))
        time.sleep(1)
        print("    File created.")
    except Exception as e:
        print(f"[!] Error: {e}")

def spike_network_activity():
    print("[*] Generating suspicious network traffic (Port 4444)...")
    # Try to connect to a "C2" server
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 4444))
        s.close()
    except:
        pass # Expected to fail, but the attempt is what matters
    print("    Traffic generated.")

def spawn_suspicious_process():
    print("[*] Spawning suspicious process chain (cmd -> powershell -enc)...")
    try:
        # This mimics a common attack chain
        cmd = "powershell.exe -enc AAAA" 
        subprocess.Popen(cmd, shell=True)
        print("    Process spawned.")
    except Exception as e:
        print(f"[!] Error: {e}")

def main():
    print("=== NightWatch EDR Attack Simulator ===")
    print("Generating noise to trigger alerts...")
    
    write_suspicious_files()
    time.sleep(2)
    spike_network_activity()
    time.sleep(2)
    spawn_suspicious_process()
    
    print("\n[+] Simulation complete. Check the Dashboard!")

if __name__ == "__main__":
    main()
