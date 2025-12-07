import psutil

class NetworkSensor:
    def __init__(self):
        self.seen_conns = set()

    def scan(self):
        events = []
        current_conns = set()
        
        try:
            connections = psutil.net_connections(kind='inet')
            for c in connections:
                if c.status == 'ESTABLISHED' and c.raddr:
                    conn_id = f"{c.laddr.ip}:{c.laddr.port}-{c.raddr.ip}:{c.raddr.port}"
                    current_conns.add(conn_id)
                    
                    if conn_id not in self.seen_conns:
                        # New connection
                        proc_name = ""
                        try:
                            if c.pid:
                                proc_name = psutil.Process(c.pid).name()
                        except:
                            pass

                        event_data = {
                            "pid": c.pid,
                            "proc_name": proc_name,
                            "laddr": f"{c.laddr.ip}:{c.laddr.port}",
                            "raddr": f"{c.raddr.ip}:{c.raddr.port}",
                            "status": c.status
                        }
                        
                        events.append({
                            "type": "network",
                            "data": event_data
                        })
            
            self.seen_conns = current_conns
        except Exception as e:
            pass
            
        return events
