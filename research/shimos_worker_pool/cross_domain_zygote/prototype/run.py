#!/usr/bin/env python3
"""Private VM mechanism qualification, not a benchmark or scheduler.
Controller below IS the lifecycle implementation; outer root only collects trace.
"""
import os,sys,time,json,socket,ctypes,select,signal,fcntl,hashlib,shutil,subprocess,traceback,array,stat
from pathlib import Path
from common import send,recv,bridge,identity
assert Path('/run/native-benchmark-lab').read_text().strip()=='private-stock-linux-benchmark-vm'
R=Path('/state/cross-domain');P=R/'prototype';O=Path('/evidence');CG=Path('/sys/fs/cgroup/cdz')
def dump(name,data):(O/name).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
def event(obj):
    obj={'monotonic_ns':time.monotonic_ns(),**obj}
    with (O/'events.jsonl').open('a') as f:f.write(json.dumps(obj)+'\n')
def delegate(p):
    os.chown(p,65534,65534)
    for n in ['cgroup.procs','cgroup.threads','cgroup.subtree_control']:os.chown(p/n,65534,65534)
def empty(p):return 'populated 0' in (p/'cgroup.events').read_text()
def stats(p):
    return {n:(p/n).read_text() for n in ['cgroup.events','cpu.stat','memory.current','memory.peak','memory.events','pids.current','pids.events']}
def killcg(p):
    (p/'cgroup.kill').write_text('1');event({'event':'PRODUCT_CGROUP_KILL','cgroup':str(p)})
def writecg(p):
    p.mkdir();(p/'pids.max').write_text('128');(p/'memory.max').write_text(str(256*1024**2));(p/'cpu.max').write_text('200000 100000');return p
def fdcount():return len(os.listdir('/proc/self/fd'))

class Controller:
    def __init__(self):
        self.lib=bridge(str(P/'bridge.so'));assert self.lib.subreaper()==0 and self.lib.set_base_safety()==0
        self.native=ctypes.CDLL(str(P/'native.so'),use_errno=True)
        self.native.bg_spawn.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.POINTER(ctypes.c_char_p),ctypes.POINTER(ctypes.c_int),ctypes.c_int,ctypes.c_int]
        self.z=None;self.known={};self.waited={};self.rows=[];self.seq=0
    def spawn(self,argv,cg,log,fd):
        cf=os.open(cg,os.O_DIRECTORY|os.O_RDONLY);pf=ctypes.c_int(-1)
        av=(ctypes.c_char_p*(len(argv)+1))(*[str(x).encode() for x in argv],None)
        p=self.native.bg_spawn(cf,log,av,ctypes.byref(pf),0,fd);os.close(cf)
        if p<0:raise OSError(ctypes.get_errno(),'spawn')
        return p,pf.value
    def reap(self):
        while True:
            try:p,s=os.waitpid(-1,os.WNOHANG)
            except ChildProcessError:return
            if not p:return
            self.waited[p]=s;event({'event':'CONTROLLER_REAP','pid':p,'wait_status':s})
    def start_z(self):
        cg=writecg(CG/'template');a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        log=(O/f'zygote-{self.seq}.log').open('wb');p,pf=self.spawn(['/usr/bin/python3','-B',str(P/'zygote.py'),str(P/'bridge.so')],cg,log.fileno(),b.fileno());b.close()
        a.settimeout(10);msg,fds,_=recv(a);assert not fds and msg['event']=='ZYGOTE_READY';assert msg['threads']==1
        event(msg);self.z={'sock':a,'pid':p,'pidfd':pf,'cg':cg,'log':log,'ready':msg,'alive':True};self.seq+=1
    def stop_z(self):
        z=self.z
        if z['alive']:
            send(z['sock'],{'op':'STOP'})
            deadline=time.monotonic()+5
            while True:
                m,f,_=recv(z['sock']);event(m);assert not f
                if m['event']=='ZYGOTE_STOP':assert m['state_unchanged'];break
                assert time.monotonic()<deadline
        end=time.monotonic()+5
        while z['pid'] not in self.waited:
            self.reap();assert time.monotonic()<end;time.sleep(.005)
        if z['alive']:assert self.waited[z['pid']]==0
        assert empty(z['cg'])
        dump(f'zygote-{self.seq}-final.json',{'wait':self.waited[z['pid']],'stats':stats(z['cg']),'alive_stop':z['alive']})
        z['sock'].close();os.close(z['pidfd']);z['log'].close();z['cg'].rmdir();self.z=None
    def bwrap(self,work,nonce):
        return ['/assets/bwrap/lib/ld-linux-x86-64.so.2','--library-path','/assets/bwrap/lib','/assets/bwrap/bwrap',
          '--unshare-user','--disable-userns','--unshare-pid','--unshare-net','--unshare-ipc','--unshare-uts',
          '--cap-drop','ALL','--as-pid-1','--die-with-parent','--new-session',
          '--ro-bind','/runtime','/','--proc','/proc','--dev','/dev','--tmpfs','/tmp',
          '--ro-bind',str(P),'/probe','--ro-bind','/assets','/tools','--ro-bind',str(R/'src'),'/src',
          '--bind',str(work),'/work','--chdir','/work','--clearenv','--setenv','PATH','/usr/bin:/bin',
          '/probe/domain_init',nonce]
    def domain(self,mode):
        number=len(self.rows);nonce=os.urandom(16).hex();cg=CG/('d'+str(number));cg.mkdir();(cg/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        (cg/'memory.max').write_text(str(512*1024**2));(cg/'pids.max').write_text('256');(cg/'cpu.max').write_text('400000 100000')
        control=writecg(cg/'control');trans=writecg(cg/'transition');business=writecg(cg/'business')
        work=R/('work-'+nonce);work.mkdir()
        ds,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);ds.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);ds.settimeout(10)
        log=(O/f'{number}-{mode}-bwrap.log').open('wb');argv=self.bwrap(work,nonce)
        mon,monfd=self.spawn(argv,control,log.fileno(),child.fileno());child.close()
        ready,export,creds=recv(ds);event(ready);assert ready['event']=='DOMAIN_READY' and ready['nonce']==nonce and len(export)==7
        assert creds and creds[1:]==(65534,65534);initpid=creds[0]
        assert str(initpid) in (control/'cgroup.procs').read_text().split()
        initfd=os.pidfd_open(initpid)
        if os.environ.get('CDZ_BAD_EXPORT')=='1':
            export[0],export[1]=export[1],export[0]
            event({'event':'FAULT_INJECT','mode':'swap_user_mount_fds','before_worker_spawn':True})
        base=fcntl.ioctl(export[1],0xb701)
        baseino=os.fstat(base).st_ino
        types=[0x10000000,0x20000,0x20000000,0x40000000,0x08000000,0x04000000]
        for fd,typ in zip(export,types):assert fcntl.ioctl(fd,0xb703)==typ
        parent=fcntl.ioctl(export[0],0xb702);assert os.fstat(parent).st_ino==baseino;os.close(parent)
        owner=array.array('I',[0]);fcntl.ioctl(base,0xb704,owner,True);assert owner[0]==os.getuid()
        assert stat.S_ISDIR(os.fstat(export[6]).st_mode)
        for f in export[1:6]:
            q=fcntl.ioctl(f,0xb701);assert os.fstat(q).st_ino==baseino;os.close(q)
        ns={n:f'{n}:[{os.fstat(f).st_ino}]' for n,f in zip(['user','mnt','pid','net','ipc','uts'],export[:6])}
        st,sc=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        rd,wr=os.pipe2(os.O_CLOEXEC);os.set_blocking(rd,False)
        tc=os.open(trans,os.O_RDONLY|os.O_DIRECTORY);bc=os.open(business,os.O_RDONLY|os.O_DIRECTORY)
        fds=[base,*export[:6],export[6],tc,bc,sc.fileno(),wr,initfd]
        assert len(fds)==13
        req={'op':'SPAWN','mode':mode,'nonce':nonce,'target_ns':ns,'root_identity':[os.fstat(export[6]).st_dev,os.fstat(export[6]).st_ino],'business_cgroup':str(business).removeprefix('/sys/fs/cgroup')}
        row={'mode':mode,'nonce':nonce,'argv':argv,'domain_ready':ready,'export_credentials':creds,'target_ns':ns,
             'base_userns_inode':baseino,'fd_metadata_validated':True,'init_host_pid':initpid,'monitor_host_pid':mon,'zygote_host_pid':self.z['pid'],
             'limits':{k:{n:(v/n).read_text() for n in ['cpu.max','memory.max','pids.max']} for k,v in [('task',cg),('transition',trans),('business',business)]},
             'expected_state':self.z['ready']['state'],'events':[],'worker':None,'worker_wait':None,'transition_reaped':False,'output_eof':False,'failure':None,'qualification':'PENDING'}
        send(self.z['sock'],req,fds)
        for f in [base,*export,tc,bc,wr]:os.close(f)
        sc.close()
        workerfd=None;transitionfd=None;spid=None;wpid=None;out=b'';outall=b'';status_open=True;domain_open=True;faulted=False;stopped=False;monitor_reaped=False
        start=time.monotonic();deadline=start+12;fault_at=None;ds.setblocking(False);st.setblocking(False);self.z['sock'].setblocking(False)
        row['start_ns']=time.monotonic_ns()
        try:
            while True:
                self.reap();monitor_reaped=mon in self.waited
                if self.z['alive'] and self.z['pid'] in self.waited:
                    self.z['alive']=False;row['failure']=row['failure'] or 'TEMPLATE_DIED';killcg(cg)
                if monitor_reaped and (not stopped or self.waited[mon]!=0) and not row['failure']:
                    row['failure']='DOMAIN_DIED';killcg(cg)
                if time.monotonic()>deadline:
                    row['failure']=row['failure'] or 'HARNESS_DEADLINE';killcg(cg);raise TimeoutError(row['failure'])
                sockets=[]
                if status_open:sockets.append(st)
                if domain_open:sockets.append(ds)
                if self.z['alive']:sockets.append(self.z['sock'])
                if not row['output_eof']:sockets.append(rd)
                readable,_,_=select.select(sockets,[],[],.01)
                for item in readable:
                    if item==rd:
                        data=os.read(rd,65536)
                        if not data:row['output_eof']=True;event({'event':'OUTPUT_EOF','nonce':nonce});continue
                        out+=data;outall+=data
                        while b'\n' in out:
                            line,out=out.split(b'\n',1)
                            try:m=json.loads(line)
                            except ValueError:row['events'].append({'event':'STDERR_TEXT','text':line.decode(errors='replace')});continue
                            row['events'].append(m);event(m)
                            if m['event']=='WORKER_READY':
                                row['worker']=m;fault_at=time.monotonic()+(.08 if mode=='timeout' else .01)
                                if not all(m['checks'].values()):row['failure']='WORKER_CHECK_FAILED';killcg(cg)
                        continue
                    try:m,received,cred=recv(item)
                    except EOFError:
                        if item==st:
                            status_open=False
                            if not row['worker_wait'] and not row['failure']:
                                row['failure']='TRANSITION_CHANNEL_CLOSED';killcg(cg)
                        elif item==ds:
                            domain_open=False
                            if not stopped and not row['failure']:row['failure']='DOMAIN_CHANNEL_CLOSED';killcg(cg)
                        else:self.z['alive']=False;row['failure']=row['failure'] or 'TEMPLATE_CHANNEL_CLOSED';killcg(cg)
                        continue
                    event(m);row['events'].append(m)
                    typ=m['event']
                    if typ=='TRANSITION_CREATED':spid=m['pid'];transitionfd=received.pop();row['transition_host_pid']=spid
                    elif typ=='WORKER_CREATED':wpid=m['worker_host_pid'];workerfd=received.pop();row['worker_host_pid']=wpid
                    elif typ=='WORKER_WAITED':row['worker_wait']=m
                    elif typ=='TRANSITION_REAPED':
                        assert m['nonce']==nonce;row['transition_reaped']=True;row['transition_status']=m['wait_status']
                        if m['wait_status']!=0 and not row['failure']:row['failure']='TRANSITION_FAILED';killcg(cg)
                    elif typ=='TRANSITION_PAUSED':
                        signal.pidfd_send_signal(initfd,signal.SIGKILL)
                        assert select.select([initfd],[],[],2)[0]
                        faulted=True;row['failure']='TARGET_DIED_DURING_ENTRY';send(st,{'op':'GO'})
                    elif typ in ('SPAWN_ERROR','TRANSITION_ERROR'):
                        row['failure']=typ;killcg(cg)
                    for f in received:os.close(f)
                if fault_at and not faulted and time.monotonic()>=fault_at and mode not in ('normal','nonzero','waiter_failure'):
                    faulted=True;row['fault_injected_ns']=time.monotonic_ns();event({'event':'FAULT_INJECT','mode':mode,'nonce':nonce})
                    if mode in ('cancel','timeout'):
                        row['failure']='CANCELLED' if mode=='cancel' else 'TIMED_OUT';killcg(cg)
                    elif mode=='zygote_death':signal.pidfd_send_signal(self.z['pidfd'],signal.SIGKILL)
                    elif mode=='pid1_death':signal.pidfd_send_signal(initfd,signal.SIGKILL)
                    elif mode=='control_eof':ds.close();domain_open=False;row['failure']='CONTROL_CLOSED'
                # If Z died, controller becomes the real reaper for adopted S/W.
                if not self.z['alive'] and spid in self.waited:row['transition_reaped']=True;row['transition_status']=self.waited[spid]
                # Normal completion: wait business emptiness and real S/W wait before stopping PID1.
                if not stopped and not row['failure'] and row['worker_wait'] and row['transition_reaped'] and empty(business) and row['output_eof']:
                    ds.send(b'STOP');stopped=True
                if row['failure'] and mode=='control_eof' and monitor_reaped:
                    # PID1 channel EOF terminated target; controller kills any surviving transition.
                    if not empty(cg):killcg(cg)
                if monitor_reaped and empty(cg) and row['transition_reaped'] and row['output_eof']:break
            self.reap();row['monitor_status']=self.waited[mon]
            row['controller_worker_wait']=self.waited.get(wpid)
            row['stats']={k:stats(v) for k,v in [('task',cg),('control',control),('transition',trans),('business',business)]}
            row['all_processes_empty']=empty(cg);row['drained']=any(m.get('event')=='DRAINED' and m.get('echild') for m in row['events'])
            # Conservative status: lost status never becomes success.
            row['task_state']=row['failure'] or ('SUCCEEDED' if row['worker_wait']['exit_code']==0 else 'NONZERO')
        finally:
            for f in [rd,initfd,monfd,workerfd,transitionfd]:
                if f is not None:
                    try:os.close(f)
                    except OSError:pass
            for s in [st,ds]:s.close()
            log.close()
            if self.z['alive']:self.z['sock'].settimeout(10)
            (O/f'{number}-{mode}-output.log').write_bytes(outall)
            dump(f'{number}-{mode}.json',row)
        assert empty(cg)
        for c in [business,trans,control]:c.rmdir()
        cg.rmdir();shutil.rmtree(work)
        row['resources_removed']=not cg.exists() and not work.exists()
        row['completed_ns']=time.monotonic_ns();dump(f'{number}-{mode}.json',row);self.rows.append(row)
        if mode=='target_during_entry':assert row['worker'] is None and row['failure'],row
        else:assert row['worker'] and all(row['worker']['checks'].values()),row
        assert row['resources_removed'] and row['output_eof'] and row['transition_reaped']
        if mode in ('normal','nonzero'):
            assert row['drained'] and row['worker_wait']['exit_code']==(0 if mode=='normal' else 7) and not row['failure'] and row['transition_status']==0 and row['monitor_status']==0,row
        elif mode=='waiter_failure':assert row['failure']=='TRANSITION_FAILED' and row['transition_status']==17*256,row
        else:assert row['failure'] and faulted,row
        row['qualification']='PASSED';dump(f'{number}-{mode}.json',row)
        return row
    def run(self):
        self.start_z();initial_fd=fdcount();initial_state=self.z['ready']['state']
        modes=['normal','normal','nonzero','cancel','timeout','pid1_death','control_eof','target_during_entry','waiter_failure','zygote_death']
        if os.environ.get('CDZ_NORMAL_STOP')=='1':modes=['normal','normal','nonzero']
        for mode in modes:
            row=self.domain(mode)
            if self.z['alive']:
                send(self.z['sock'],{'op':'PING'});m,fs,_=recv(self.z['sock']);assert m['event']=='PONG' and m['state_unchanged'] and not fs
                assert fdcount()==initial_fd,('controller FD growth',fdcount(),initial_fd)
                row['controller_fd_after']=fdcount();row['controller_fd_baseline']=initial_fd;row['zygote_post_request']=m
                dump(f'{len(self.rows)-1}-{mode}.json',row)
        self.stop_z();self.reap()
        try:os.waitpid(-1,os.WNOHANG);nochildren=False
        except ChildProcessError:nochildren=True
        assert nochildren
        dump('summary.json',{'all_passed':True,'cases':[{k:r.get(k) for k in ['mode','task_state','worker_host_pid','transition_host_pid','resources_removed','drained']} for r in self.rows],
          'same_template_served_second_domain':self.rows[0]['zygote_host_pid']==self.rows[1]['zygote_host_pid'],
          'initial_state':initial_state,'controller_echild':nochildren,'cpu_memory_benchmark':False})
    def abort(self):
        # Product fail-stop for setup/protocol errors. Never called by observer.
        errors=[]
        for p in CG.iterdir():
            if p.is_dir() and p.name!='client':
                try:killcg(p)
                except OSError as e:errors.append(repr(e))
        deadline=time.monotonic()+5;nochildren=False
        while time.monotonic()<deadline:
            self.reap()
            try:os.waitpid(-1,os.WNOHANG)
            except ChildProcessError:nochildren=True;break
            time.sleep(.005)
        self.lib.close_from(3)
        for p in sorted([p for p in CG.rglob('*') if p.is_dir() and p.name!='client'],key=lambda p:len(p.parts),reverse=True):
            try:p.rmdir()
            except OSError as e:errors.append(repr(e))
        for p in R.glob('work-*'):shutil.rmtree(p)
        dump('product-abort.json',{'controller_echild':nochildren,'errors':errors,'task_state':'FAILED','not_qualification_success':True})

def main():
    # Root fixture preparation ONLY inside the frozen VM.
    R.mkdir(exist_ok=True);(R/'src').mkdir(exist_ok=True);(R/'src/input').write_text('readonly-input\n')
    for n in ['probe','src','work','tools']:(Path('/runtime')/n).mkdir(exist_ok=True)
    for src,out,flags in [('bridge.c','bridge.so',['-shared','-fPIC','-ldl']),('domain_init.c','domain_init',['-static']),('native.c','native.so',['-shared','-fPIC'])]:
        subprocess.run(['gcc','-Wall','-Wextra','-O2',str(P/src),'-o',str(P/out),*flags],check=True)
        shutil.copy2(P/out,O/out)
    dump('build.json',{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in P.iterdir() if p.is_file()})
    CG.mkdir();(CG/'cgroup.subtree_control').write_text('+cpu +memory +pids');delegate(CG)
    client=CG/'client';client.mkdir();delegate(client)
    os.chown(R,65534,65534);os.chown(O,65534,65534)
    trace=Path('/sys/kernel/tracing');tracing=False
    try:
        trace.mkdir(exist_ok=True);subprocess.run(['mount','-t','tracefs','tracefs',str(trace)],check=True)
        (trace/'trace').write_text('');(trace/'buffer_size_kb').write_text('4096')
        for name in ['sched_process_fork','sched_process_exec','sched_process_exit']:(trace/'events/sched'/name/'enable').write_text('1')
        (trace/'tracing_on').write_text('1');tracing=True
    except BaseException as e:dump('trace-unavailable.json',{'error':repr(e)})
    p=os.fork()
    if p==0:
        (client/'cgroup.procs').write_text(str(os.getpid()));os.setgroups([]);os.setgid(65534);os.setuid(65534)
        c=Controller()
        try:c.run();os._exit(0)
        except BaseException:
            dump('failure.json',{'traceback':traceback.format_exc()});traceback.print_exc();c.abort();os._exit(1)
    q,status=os.waitpid(p,0)
    if tracing:
        (trace/'tracing_on').write_text('0');(O/'process-trace.txt').write_text((trace/'trace').read_text())
        dump('trace-stats.json',{str(f.relative_to(trace)):f.read_text() for f in (trace/'per_cpu').glob('cpu*/stats')})
    remaining=[str(x) for x in CG.iterdir() if x.is_dir()]
    released=False
    if remaining==[str(client)] and empty(client):client.rmdir();CG.rmdir();released=True
    dump('external-final-release.json',{'controller_wait_status':status,'remaining_before_release':remaining,'delegation_removed':released,'observer_killed_processes':False})
    return 0 if status==0 and released else 1
if __name__=='__main__':raise SystemExit(main())
