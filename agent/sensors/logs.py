import win32evtlog
import win32evtlogutil
import win32con
import time

class LogSensor:
    def __init__(self):
        self.server = 'localhost'
        self.log_type = 'Security'
        self.last_read_index = 0

    def scan(self):
        events = []
        try:
            hand = win32evtlog.OpenEventLog(self.server, self.log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total = win32evtlog.GetNumberOfEventLogRecords(hand)
            
            # Simple logic: read last 10 events and check if we haven't seen them
            # In a real app, we'd track RecordNumber properly
            
            events_list = win32evtlog.ReadEventLog(hand, flags, 0)
            for event in events_list:
                event_id = event.EventID & 0xFFFF
                if event_id in [4624, 4625, 4688]: # Logon Success, Failure, Process Create
                    data = {
                        "event_id": event_id,
                        "source": event.SourceName,
                        "time": event.TimeGenerated.isoformat(),
                        "message": win32evtlogutil.SafeFormatMessage(event, self.log_type)
                    }
                    events.append({
                        "type": "log",
                        "data": data
                    })
            
            win32evtlog.CloseEventLog(hand)
        except Exception as e:
            pass # Fail silently if no admin rights or other issue
            
        return events
