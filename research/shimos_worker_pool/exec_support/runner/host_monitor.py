"""Host-only one-second resource observation; never mixed with guest clocks."""
import json, os, threading, time
from pathlib import Path

def snapshot():
    def read(path):
        try: return Path(path).read_text()
        except OSError as exc: return {'unavailable':str(exc)}
    return {'host_monotonic_ns':time.monotonic_ns(), 'host_realtime_ns':time.time_ns(),
            'loadavg':read('/proc/loadavg'), 'meminfo':read('/proc/meminfo'),
            'pressure':{key:read('/proc/pressure/'+key) for key in ('cpu','memory','io')},
            'affinity':sorted(os.sched_getaffinity(0))}

class HostMonitor:
    def __init__(self, directory):
        self.directory=Path(directory); self.event=threading.Event()
        self.thread=threading.Thread(target=self.run,daemon=True)
    def start(self): self.thread.start()
    def run(self):
        with (self.directory/'host-pressure.jsonl').open('x') as stream:
            while True:
                stream.write(json.dumps(snapshot())+'\n');stream.flush()
                if self.event.wait(1):break
    def stop(self): self.event.set();self.thread.join()
