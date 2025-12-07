import psutil
import time

from agent.utils import get_file_hash

class ProcessSensor:
    def __init__(self):
        self.seen_pids = set()

    def scan(self):
        events = []
        current_pids = set()
        
        for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'ppid', 'cpu_percent', 'memory_percent']):
            try:
                pid = p.info['pid']
                current_pids.add(pid)
                
                if pid not in self.seen_pids:
                    # New process event
                    parent = None
                    try:
                        parent = psutil.Process(p.info['ppid']).name()
                    except:
                        pass
                    
                    exe_path = p.info['exe']
                    file_hash = get_file_hash(exe_path) if exe_path else None

                    event_data = {
                        "pid": pid,
                        "name": p.info['name'],
                        "exe": exe_path,
                        "cmdline": " ".join(p.info['cmdline'] or []),
                        "user": p.info['username'],
                        "parent_pid": p.info['ppid'],
                        "parent_name": parent,
                        "cpu": p.info['cpu_percent'],
                        "memory": p.info['memory_percent'],
                        "hash": file_hash
                    }
                    
                    events.append({
                        "type": "process",
                        "data": event_data
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        self.seen_pids = current_pids
        return events
