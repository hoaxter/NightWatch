import time
import socket
import platform
import sys
from agent.config import POLL_INTERVAL
from agent.sender import Sender
from agent.sensors.process import ProcessSensor
from agent.sensors.network import NetworkSensor
from agent.sensors.file import FileSensor

def main():
    print("[*] Starting NightWatch Agent...")
    
    # Init Sender
    sender = Sender()
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    os_info = f"{platform.system()} {platform.release()}"
    
    # Register loop
    while not sender.register(hostname, ip, os_info):
        print("[-] Retrying registration in 5s...")
        time.sleep(5)

    # Init Sensors
    proc_sensor = ProcessSensor()
    net_sensor = NetworkSensor()
    file_sensor = FileSensor()
    file_sensor.start()
    
    # Log Sensor (Windows only)
    log_sensor = None
    if platform.system() == "Windows":
        try:
            from agent.sensors.logs import LogSensor
            log_sensor = LogSensor()
        except ImportError:
            pass

    print("[+] Monitoring started.")

    try:
        while True:
            events = []
            
            # Collect from sensors
            events.extend(proc_sensor.scan())
            events.extend(net_sensor.scan())
            events.extend(file_sensor.get_events())
            
            if log_sensor:
                events.extend(log_sensor.scan())
            
            if events:
                print(f"[*] Sending {len(events)} events...")
                sender.send_telemetry(events)
            
            time.sleep(POLL_INTERVAL)
            
    except KeyboardInterrupt:
        print("[*] Stopping agent...")
        file_sensor.stop()

if __name__ == "__main__":
    main()
