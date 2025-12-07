import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from agent.config import MONITOR_DIRS, SUSPICIOUS_EXTS

from agent.utils import get_file_hash

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, event_queue):
        self.event_queue = event_queue

    def on_created(self, event):
        if not event.is_directory:
            self._process(event, "created")

    def on_modified(self, event):
        if not event.is_directory:
            self._process(event, "modified")

    def _process(self, event, action):
        path = event.src_path
        if any(path.endswith(ext) for ext in SUSPICIOUS_EXTS):
            file_hash = get_file_hash(path)
            self.event_queue.append({
                "type": "file",
                "data": {
                    "action": action,
                    "path": path,
                    "name": path.split("\\")[-1],
                    "hash": file_hash
                }
            })

class FileSensor:
    def __init__(self):
        self.observer = Observer()
        self.events = []
        self.handler = FileEventHandler(self.events)

    def start(self):
        for d in MONITOR_DIRS:
            try:
                self.observer.schedule(self.handler, d, recursive=False)
            except OSError:
                pass
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()

    def get_events(self):
        # Return and clear events
        res = list(self.events)
        self.events.clear()
        return res
