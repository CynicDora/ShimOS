"""Read-only observations inside the private test VM, no cleanup or signals."""
import os,time
from pathlib import Path

def snapshot(cg,workroot):
    def read(p):
        try:return p.read_text()
        except OSError as e:return {'error':repr(e)}
    groups={}
    if cg.exists():
        for p in [cg,*sorted(x for x in cg.rglob('*') if x.is_dir())]:
            groups[str(p)]={n:read(p/n) for n in ['cgroup.events','cgroup.procs','cgroup.threads','pids.current','pids.max','pids.events','memory.current','memory.max','memory.events']}
    procs={}
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():continue
        try:
            status=(p/'status').read_text()
            fields=dict(line.split(':',1) for line in status.splitlines() if ':' in line)
            if int(fields['Uid'].split()[0])!=65534:continue
            fs={}
            try:
                for f in (p/'fd').iterdir():
                    try:fs[f.name]=os.readlink(f)
                    except OSError as e:fs[f.name]={'error':repr(e)}
            except OSError as e:fs={'error':repr(e)}
            ns={}
            for name in ['user','mnt','pid','net','ipc','uts']:
                try:ns[name]=os.readlink(p/'ns'/name)
                except OSError as e:ns[name]={'error':repr(e)}
            procs[p.name]={'status':status,'stat':read(p/'stat'),'cgroup':read(p/'cgroup'),'fds':fs,'ns':ns}
        except (OSError,KeyError,ValueError):continue
    work={}
    for p in workroot.glob('work-*'):
        work[str(p)]={'files':[str(f.relative_to(p)) for f in p.rglob('*')],'result':read(p/'result') if (p/'result').exists() else None}
    return {'monotonic_ns':time.monotonic_ns(),'cgroups':groups,'uid65534_processes':procs,'workspaces':work,'sampling_not_atomic':True}
