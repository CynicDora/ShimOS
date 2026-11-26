"""Read-only, root-fixture resource observer; never part of product cleanup.

Start after the H fork in the fixture's parent branch, stop after actual wait H.
It opens no descriptor inside H/R/Z/S/W and never signals or modifies them.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def proc_stat(pid):
    text=Path('/proc',str(pid),'stat').read_text()
    right=text.rfind(')');left=text.find('(');fields=text[right+2:].split()
    return dict(pid=int(text[:left].strip()),comm=text[left+1:right],state=fields[0],ppid=int(fields[1]),
                start_ticks=int(fields[19]),user_ticks=int(fields[11]),system_ticks=int(fields[12]),
                threads=int(fields[17]),vsize_bytes=int(fields[20]),rss_pages=int(fields[21]))


def read_group(path):
    start=time.monotonic_ns();data={'path':str(path),'start_ns':start}
    for name in ('cgroup.procs','cgroup.events','cpu.stat','memory.current','memory.peak','memory.events','pids.current','pids.peak'):
        try:data[name]=(path/name).read_text().strip()
        except OSError as e:data[name]={'error':repr(e)}
    data['end_ns']=time.monotonic_ns()
    return data


def role_of(pid,root_pid,cgroup):
    if pid==root_pid:return 'H'
    leaf=cgroup.rstrip('/').split('/')[-1]
    return {'client':'R','template':'Z','transition':'S','business':'W','control':'DOMAIN_CONTROL'}.get(leaf,'UNKNOWN')


def sample(root_pid,cgroup_root):
    start=time.monotonic_ns();groups=[];pid_groups={};errors=[]
    paths=[cgroup_root]
    try:
        # This experiment owns a fixed layout. Never stat every cgroup pseudo
        # file or repeatedly read final leaf statistics already kept by R.
        with os.scandir(cgroup_root) as entries:
            for entry in entries:
                if entry.name in ('client','template') or entry.name.startswith('d-'):
                    if not entry.is_dir(follow_symlinks=False):continue
                    path=Path(entry.path);paths.append(path)
                    if entry.name.startswith('d-'):
                        for name in ('control','template','transition','business'):
                            leaf=path/name
                            if leaf.is_dir():paths.append(leaf)
    except OSError as e:errors.append({'operation':'enumerate_cgroups','error':repr(e)})
    for path in paths:
        if path==cgroup_root:group=read_group(path)
        else:
            group={'path':str(path),'start_ns':time.monotonic_ns(),'scope':'membership only; leaf accounting is recorded by final R ledger'}
            try:group['cgroup.procs']=(path/'cgroup.procs').read_text().strip()
            except OSError as e:group['cgroup.procs']={'error':repr(e)}
            group['end_ns']=time.monotonic_ns()
        groups.append(group)
        procs=group.get('cgroup.procs')
        if isinstance(procs,str):
            for value in procs.split():pid_groups[int(value)]=str(path)
    # H may have just exited; never substitute a recycled numeric PID.
    records=[]
    for pid,group in sorted(pid_groups.items()):
        begin=time.monotonic_ns()
        row={'pid':pid,'role':role_of(pid,root_pid,group),'cgroup_observed':group,'start_ns':begin}
        try:
            before=proc_stat(pid);row['identity_before']=before
            membership=Path('/proc',str(pid),'cgroup').read_text().strip();row['membership_before']=membership
            memory=Path('/proc',str(pid),'smaps_rollup').read_text()
            row['memory_KiB']={key:int(value.split()[0]) for line in memory.splitlines() if ':' in line
                               for key,value in [line.split(':',1)] if value.strip().endswith('kB')}
            row['fd_count']=len(list(Path('/proc',str(pid),'fd').iterdir()))
            after=proc_stat(pid);row['identity_after']=after
            row['membership_after']=Path('/proc',str(pid),'cgroup').read_text().strip()
            row['identity_stable']=before['pid']==after['pid'] and before['start_ticks']==after['start_ticks']
            row['membership_stable']=row['membership_before']==row['membership_after']
            expected='0::'+group.removeprefix('/sys/fs/cgroup')
            row['membership_matches_enumeration']=expected in row['membership_before'].splitlines()
            row['observed']=row['identity_stable'] and row['membership_stable'] and row['membership_matches_enumeration']
        except (OSError,ValueError,IndexError) as e:
            row['observed']=False;row['error']=repr(e)
        row['end_ns']=time.monotonic_ns();records.append(row)
    end_members=set()
    try:
        for path in paths:
            try:end_members.update(int(p) for p in (path/'cgroup.procs').read_text().split())
            except OSError:pass
    except OSError as e:errors.append({'operation':'final_membership_census','error':repr(e)})
    try:root_pids_end=int((cgroup_root/'pids.current').read_text())
    except (OSError,ValueError):root_pids_end=None
    observed_threads=sum(row.get('identity_after',{}).get('threads',0) for row in records)
    return dict(start_ns=start,end_ns=time.monotonic_ns(),processes=records,cgroups=groups,errors=errors,
                enumerated_pids=sorted(pid_groups),end_census_pids=sorted(end_members),
                root_pids_current_end=root_pids_end,observed_threads=observed_threads,
                population_count_compatible=root_pids_end==observed_threads,
                membership_census_stable=set(pid_groups)==end_members and root_pids_end==observed_threads,
                layout_scope='owned root/client/template/d-*/{control,template,transition,business}; template includes local Z or persistent Worker; no arbitrary nested cgroups',
                scope='serial read-only batch, not atomic; role by owned leaf cgroup, DOMAIN_CONTROL includes bwrap/monitor/PID1')


def run(args):
    if os.geteuid()!=0:raise PermissionError('resource observer requires private-VM root')
    if Path('/run/native-benchmark-lab').read_text().strip()!='private-stock-linux-benchmark-vm':
        raise PermissionError('private VM marker absent or incorrect')
    target=Path(args.cgroup_root).resolve()
    if not str(target).startswith('/sys/fs/cgroup/') or target==Path('/sys/fs/cgroup'):
        raise ValueError('observer requires an explicit delegated child cgroup')
    membership=Path('/proc/self/cgroup').read_text().strip()
    member=[line.split('::',1)[1] for line in membership.splitlines() if line.startswith('0::')]
    target_member=str(target).removeprefix('/sys/fs/cgroup')
    inside=any(p==target_member or p.startswith(target_member+'/') for p in member)
    if inside:raise RuntimeError('observer must stay outside product accounting cgroup')
    stop=False
    def stop_signal(signum,frame):
        nonlocal stop
        stop=True
    signal.signal(signal.SIGTERM,stop_signal);signal.signal(signal.SIGINT,stop_signal)
    start=time.monotonic_ns();cpu=time.process_time_ns();count=0;missed=0;total_sample_ns=0
    interval=args.interval_ms*1_000_000
    if interval<10_000_000:raise ValueError('interval must be at least 10 ms')
    with Path(args.output).open('x') as output:
        def emit(event,**fields):
            output.write(json.dumps(dict(event=event,clock='CLOCK_MONOTONIC',session=args.session,
                observer_pid=os.getpid(),monotonic_ns=time.monotonic_ns(),**fields),separators=(',',':'))+'\n');output.flush()
        emit('RESOURCE_OBSERVER_START',root_pid=args.root_pid,root_start_ticks=args.root_start_ticks,
             cgroup_root=str(target),interval_ns=interval,clock_ticks_per_second=os.sysconf('SC_CLK_TCK'),
             page_size=os.sysconf('SC_PAGE_SIZE'),observer_in_product_cgroup=inside,observer_cgroup=membership,
             cleanup_authority='NONE; read-only proc/cgroup, never sends product signals')
        next_time=start
        try:
            while not stop:
                batch=sample(args.root_pid,target);count+=1;total_sample_ns+=batch['end_ns']-batch['start_ns']
                emit('RESOURCE_BATCH',sequence=count,**batch)
                if Path(args.stop_file).exists():break
                try:
                    identity=proc_stat(args.root_pid)
                    if identity['start_ticks']!=args.root_start_ticks or identity['state']=='Z':break
                except (OSError,ValueError,IndexError):break
                next_time+=interval;now=time.monotonic_ns()
                if now>next_time:
                    skipped=(now-next_time)//interval+1;missed+=skipped;next_time+=skipped*interval
                time.sleep(max(0,(next_time-time.monotonic_ns())/1e9))
        finally:
            emit('RESOURCE_OBSERVER_STOP',samples=count,skipped_intervals=missed,
                 observer_wall_ns=time.monotonic_ns()-start,observer_self_cpu_ns=time.process_time_ns()-cpu,
                 total_sampling_wall_ns=total_sample_ns,
                 scope='observer CPU is diagnostic and excluded from product cgroup; read cost may still perturb product latency/cache')


def start(root_pid,cgroup_root,output_dir,session,interval_ms=100):
    """Fixture-parent only. Call after fork(H), before its explicit waitpid.

    Importing this module after the H fork avoids expanding H/R's inherited
    Python module state. Missing observations do not authorize product success.
    """
    out=Path(output_dir);identity=proc_stat(root_pid)
    stop=out/'resource-observer.stop';log=out/'resource-observer.jsonl';stderr=out/'resource-observer.stderr'
    command=[sys.executable,str(Path(__file__).resolve()),'--root-pid',str(root_pid),
             '--root-start-ticks',str(identity['start_ticks']),'--cgroup-root',str(cgroup_root),
             '--output',str(log),'--stop-file',str(stop),'--session',str(session),'--interval-ms',str(interval_ms)]
    with stderr.open('xb') as err:
        process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=err,close_fds=True)
    return {'process':process,'stop_file':stop,'output':log,'command':command,'root_identity':identity,
            'started_ns':time.monotonic_ns()}


def stop(handle):
    """Join only our observer; never clean up or signal product processes."""
    handle['stop_file'].write_text('fixture has waited H\n')
    process=handle['process'];used_signal=False
    try:rc=process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        used_signal=True;process.terminate()  # its handler stops sampling only
        rc=process.wait(timeout=5)
    return dict(observer_pid=process.pid,returncode=rc,stop_signal_to_observer=used_signal,
                command=handle['command'],root_identity=handle['root_identity'],started_ns=handle['started_ns'],
                waited_ns=time.monotonic_ns(),output=str(handle['output']),product_cleanup_used=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root-pid',type=int,required=True);p.add_argument('--root-start-ticks',type=int,required=True)
    p.add_argument('--cgroup-root',required=True);p.add_argument('--output',required=True);p.add_argument('--stop-file',required=True)
    p.add_argument('--session',required=True);p.add_argument('--interval-ms',type=int,default=100)
    run(p.parse_args())
