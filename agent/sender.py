import requests
import time
from agent.config import SERVER_URL

class Sender:
    def __init__(self):
        self.agent_id = None
        self.queue = []

    def register(self, hostname, ip, os_info):
        try:
            resp = requests.post(f"{SERVER_URL}/api/register", json={
                "hostname": hostname,
                "ip": ip,
                "os": os_info
            })
            if resp.status_code == 200:
                self.agent_id = resp.json().get("id")
                print(f"[+] Registered with server. Agent ID: {self.agent_id}")
                return True
        except Exception as e:
            print(f"[-] Registration failed: {e}")
        return False

    def send_telemetry(self, events):
        if not self.agent_id:
            return
        
        payload = {
            "agent_id": self.agent_id,
            "events": events
        }
        
        try:
            requests.post(f"{SERVER_URL}/api/telemetry", json=payload, timeout=2)
        except Exception as e:
            print(f"[-] Failed to send telemetry: {e}")
            # Simple retry logic: re-queue could be added here
