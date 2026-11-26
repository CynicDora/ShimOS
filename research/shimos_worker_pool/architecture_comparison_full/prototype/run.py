#!/usr/bin/env python3
"""Private VM mechanism qualification, not a benchmark or scheduler.
Controller below IS the lifecycle implementation; outer root only collects trace.
"""
import os,sys,time,json,socket,ctypes,select,signal,fcntl,hashlib,shutil,subprocess,traceback,array,stat
from pathlib import Path
from observation import snapshot
from common import send,recv,bridge,identity
import runtime_support as runtime
import cost
import numpy_workload as NW
assert Path('/run/native-benchmark-lab').read_text().strip()=='private-stock-linux-benchmark-vm'
R=Path('/state/cross-domain');P=R/'prototype';O=Path('/evidence');CG=Path('/sys/fs/cgroup/cdz')
def dump(name,data):
    started=cost.mark()
    p=O/name;t=p.with_suffix(p.suffix+'.tmp-'+str(os.getpid()));t.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n');os.replace(t,p)
    cost.finish('evidence_json_write',started,file=str(name),fsync=False)
def event(obj):
    started=cost.mark()
    obj={'monotonic_ns':time.monotonic_ns(),**obj}
    with (O/'events.jsonl').open('a') as f:f.write(json.dumps(obj)+'\n')
    cost.finish('controller_event_write',started,event_name=obj.get('event'))
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
def signal_stable(fd,sig):
    try:signal.pidfd_send_signal(fd,sig)
    except ProcessLookupError:pass
def fdcount():return len(os.listdir('/proc/self/fd'))


class Controller:
    def spawn(self,argv,cg,log,fd):
        started=cost.mark()
        cf=os.open(cg,os.O_DIRECTORY|os.O_RDONLY);pf=ctypes.c_int(-1)
        av=(ctypes.c_char_p*(len(argv)+1))(*[str(x).encode() for x in argv],None)
        p=self.native.bg_spawn(cf,log,av,ctypes.byref(pf),0,fd);os.close(cf)
        if p<0:raise OSError(ctypes.get_errno(),'spawn')
        cost.finish('native_launcher_spawn',started,child_pid=p,argv0=str(argv[0]))
        return p,pf.value
    def bwrap(self,work,nonce):
        argv = ['/assets/bwrap/lib/ld-linux-x86-64.so.2','--library-path','/assets/bwrap/lib','/assets/bwrap/bwrap',
          '--unshare-user','--disable-userns','--unshare-pid','--unshare-net','--unshare-ipc','--unshare-uts',
          '--cap-drop','ALL','--as-pid-1','--die-with-parent','--new-session',
          '--ro-bind','/runtime','/']
        argv += ['--ro-bind',str(runtime.BUNDLE),str(runtime.BUNDLE), '--ro-bind','/opt/shimos-numpy','/opt/shimos-numpy','--ro-bind','/opt/shimos-numpy-deps','/opt/shimos-numpy-deps']
        for source,target in runtime.CANDIDATE_OVERLAYS: argv += ['--ro-bind',source,target]
        return argv + ['--proc','/proc','--dev','/dev','--tmpfs','/tmp',
          '--ro-bind',str(P),'/probe','--ro-bind','/assets','/tools','--ro-bind',str(R/'src'),'/src',
          '--bind',str(work),'/work','--chdir','/work','--clearenv','--setenv','PATH','/usr/bin:/bin',
          '/probe/domain_init',nonce]+(['cost-on'] if cost.ENABLED else [])
    def __init__(self,supervisor):
        cost.context('R');cost.record('session_begin',force=True);cost.usage('controller_initial_usage');cost.memory('controller_initial_memory');cost.calibration()
        self.supervisor=supervisor;self.lib=bridge(str(P/'bridge.so'))
        assert self.lib.subreaper()==0 and self.lib.set_base_safety()==0
        self.native=ctypes.CDLL(str(P/'native.so'),use_errno=True)
        self.native.bg_spawn.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.POINTER(ctypes.c_char_p),ctypes.POINTER(ctypes.c_int),ctypes.c_int,ctypes.c_int]
        self.z=None;self.waited={};self.wait_records=[];self.rows=[];self.nochildren=False;self.seq=0
        event({'event':'CONTROLLER_START','pid':os.getpid(),'ppid':os.getppid(),'identity':identity()})
    def rpc_supervisor(self,obj,fds=()):
        started=cost.now()
        send(self.supervisor,obj,fds);self.supervisor.settimeout(5)
        m,fs,_=recv(self.supervisor);assert not fs and m.get('nonce')==obj.get('nonce'),m
        assert m['event']=={'REGISTER':'REGISTERED','RETIRE':'RETIRED','DONE':'DONE_ACK'}[obj['op']],m
        cost.span('rpc_'+obj['op'].lower(),started);cost.record({'REGISTER':'registered','RETIRE':'retire_done','DONE':'done_ack'}[obj['op']])
        return m
    def reap(self):
        self.nochildren=False
        while True:
            started=cost.mark()
            try:p,s=os.waitpid(-1,os.WNOHANG)
            except ChildProcessError:
                cost.finish('waitpid_poll',started,result='ECHILD');self.nochildren=True;return
            cost.finish('waitpid_poll',started,waited_pid=p,wait_status=s)
            if not p:return
            self.waited[p]=s;r={'event':'CONTROLLER_WAIT','pid':p,'wait_status':s,'seq':len(self.wait_records),'time_ns':time.monotonic_ns()}
            self.wait_records.append(r);event(r)
    def start_z(self):
        cost.record('zygote_create_begin')
        cg=writecg(CG/'template');a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        argv=[str(runtime.BUNDLE/'lib/ld-linux-x86-64.so.2'),'--library-path',str(runtime.BUNDLE/'lib')+':/opt/shimos-numpy-deps:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu','/usr/bin/python3','-B',str(P/'zygote.py'),str(P/'bridge_d.so')]
        log=(O/f'zygote-{self.seq}.log').open('wb')
        old_preload=os.environ.pop('LD_PRELOAD',None)
        if os.environ.get('NP_AUDIT','0')=='1':os.environ['LD_PRELOAD']=str(P/'numpy_atfork_audit.so')
        try:p,pf=self.spawn(argv,cg,log.fileno(),b.fileno())
        finally:
            os.environ.pop('LD_PRELOAD',None)
            if old_preload is not None:os.environ['LD_PRELOAD']=old_preload
        b.close()
        # A reused numeric PID may never inherit an old wait result.
        self.waited.pop(p,None)
        a.settimeout(5);m,f,_=recv(a);assert not f and m['event']=='ZYGOTE_READY' and m['threads']==1,m
        maps=Path('/proc/'+str(p)+'/maps').read_text();mapping_checks=runtime.check_candidate_mappings(maps)
        (O/f'zygote-{self.seq}-maps.txt').write_text(maps)
        dump(f'zygote-{self.seq}-runtime.json',{'argv':argv,'runtime':runtime.CANDIDATE_METADATA,'mapping_checks':mapping_checks})
        cost.record('zygote_ready_received');cost.memory('zygote_ready_memory',p);event(m);self.z={'sock':a,'pid':p,'pidfd':pf,'cg':cg,'log':log,'ready':m,'alive':True};self.seq+=1
    def stop_z(self):
        z=self.z
        if z['alive']:
            z['sock'].settimeout(5);send(z['sock'],{'op':'STOP'})
            m,f,_=recv(z['sock']);assert not f and m['event']=='ZYGOTE_STOP' and m['state_unchanged'],m
            event(m)
        deadline=time.monotonic()+5
        while z['pid'] not in self.waited:
            self.reap();assert time.monotonic()<deadline;time.sleep(.002)
        if z['alive']:assert self.waited[z['pid']]==0
        assert empty(z['cg'])
        z['sock'].close();os.close(z['pidfd']);z['log'].close();z['cg'].rmdir();self.z=None
    def domain(self,case):
        n=len(self.rows);nonce=os.urandom(16).hex();cost.context('R',nonce,repeat=n,warmup=n<int(os.environ.get('COST_WARMUP','0')));cost.record('request_begin',force=True);cost.usage('request_cpu_begin');cg=CG/('d-'+nonce);work=R/('work-'+nonce)
        row={'case':case,'nonce':nonce,'zygote_pid':self.z['pid'],'admission':'OPEN','s_state':'ABSENT','w_state':'ABSENT',
             'business':'NOT_EXECUTED','business_permit':False,'result':None,'resources':'PENDING','output_eof':False,
             'failure':None,'events':[],'worker':None,'s_wait':None,'w_wait':None,'qualification':'PENDING',
             'controller_fd_before':fdcount(),'wait_start':len(self.wait_records),
             'diagnostics':cost.DIAGNOSTICS,'journal_writes':0,'journal_updates_buffered':0}
        def journal(force=False):
            if cost.DIAGNOSTICS=='low' and not force:
                row['journal_updates_buffered']+=1
                cost.record('controller_journal_buffered',kind='diagnostic_policy')
                return
            row['journal_writes']+=1
            t=cost.mark();dump(f'attempt-{nonce}.json',row);cost.finish('controller_journal',t,forced=force)
        journal(force=True)
        cost.record('domain_build_begin');cg.mkdir();(cg/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        for k,v in [('memory.max',str(512*1024**2)),('pids.max','256'),('cpu.max','400000 100000')]: (cg/k).write_text(v)
        control=writecg(cg/'control');trans=writecg(cg/'transition');business=writecg(cg/'business');work.mkdir()
        if case=='pid_budget':(trans/'pids.max').write_text('0')
        if case=='second_budget':(business/'pids.max').write_text('0')
        ds,ch=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);ds.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);ds.settimeout(5)
        cost.record('bwrap_spawn_begin');log=(O/f'{n}-{case}-bwrap.log').open('wb');argv=self.bwrap(work,nonce);mon,monfd=self.spawn(argv,control,log.fileno(),ch.fileno());ch.close();self.waited.pop(mon,None)
        cost.record('bwrap_spawn_return');ready,export,cred=recv(ds);cost.record('domain_fd_received',domain_ready_ns=ready.get('monotonic_ns'),pid1_record=ready);assert ready['event']=='DOMAIN_READY' and ready['nonce']==nonce and len(export)==7
        row['domain_ready_record']=ready
        fd_validation=cost.mark()
        assert cred and cred[1:]==(65534,65534) and str(cred[0]) in (control/'cgroup.procs').read_text().split()
        initpid=cred[0];initfd=os.pidfd_open(initpid);base=fcntl.ioctl(export[1],0xb701);baseino=os.fstat(base).st_ino
        types=[0x10000000,0x20000,0x20000000,0x40000000,0x08000000,0x04000000]
        for f,t in zip(export,types):assert fcntl.ioctl(f,0xb703)==t
        parent=fcntl.ioctl(export[0],0xb702);assert os.fstat(parent).st_ino==baseino;os.close(parent)
        owner=array.array('I',[0]);fcntl.ioctl(base,0xb704,owner,True);assert owner[0]==os.getuid()
        assert stat.S_ISDIR(os.fstat(export[6]).st_mode)
        for f in export[1:6]:
            q=fcntl.ioctl(f,0xb701);assert os.fstat(q).st_ino==baseino;os.close(q)
        ns={name:f'{name}:[{os.fstat(f).st_ino}]' for name,f in zip(['user','mnt','pid','net','ipc','uts'],export)}
        cost.finish('domain_reference_validation',fd_validation)
        cost.record('domain_ready');st,sc=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);rd,wr=os.pipe2(os.O_CLOEXEC);os.set_blocking(rd,False)
        # Surviving product supervisor receives ONLY a read endpoint before SPAWN.
        self.rpc_supervisor({'op':'REGISTER','nonce':nonce,'cgroup':str(cg),'workspace':str(work)},[rd])
        tc=os.open(trans,os.O_RDONLY|os.O_DIRECTORY);bc=os.open(business,os.O_RDONLY|os.O_DIRECTORY)
        mode='nonzero' if case=='nonzero' else ('normal' if case in ('normal','pid_budget','second_budget','fork_ack_loss','reap_ack_loss','created_drop','reaped_drop','result_loss_side_effect') else 'hang')
        req={'op':'SPAWN','nonce':nonce,'full_profile':os.environ.get('FULL_PROFILE','legacy'),'test_descendant':os.environ.get('ARCH_TEST_DESCENDANT','1')=='1','numpy_level':os.environ.get('NP_LEVEL','import'),'numpy_baseline':os.environ.get('NP_BASELINE','hot'),'numpy_case':os.environ.get('NP_CASE','normal'),'runtime_robust':os.environ.get('RELIABILITY_CASE')=='runtime','mode':mode,'fault':case,'target_ns':ns,'root_identity':[os.fstat(export[6]).st_dev,os.fstat(export[6]).st_ino],'business_cgroup':str(business).removeprefix('/sys/fs/cgroup')}
        row.update(argv=argv,target_ns=ns,base_userns_inode=baseino,init_pid=initpid,monitor_pid=mon,expected_state=self.z['ready']['state'],fd_metadata_validated=True,
          limits={k:{n:(v/n).read_text() for n in ['cpu.max','memory.max','pids.max']} for k,v in [('task',cg),('transition',trans),('business',business)]})
        fds=[base,*export,tc,bc,sc.fileno(),wr,initfd];assert len(fds)==13
        send(self.z['sock'],req,fds)
        for f in [base,*export,tc,bc,wr]:os.close(f)
        sc.close();journal()
        st.setblocking(False);ds.setblocking(False);self.z['sock'].setblocking(False)
        status_open=True;domain_open=True;z_open=True;spid=None;wpid=None;spfd=None;wpfd=None
        sealed=False;seal_sent=False;killed=False;stopped=False;out=b'';outall=b'';faulted=False;cancel_count=0;query_at=time.monotonic()+.12
        deadline=time.monotonic()+8;cancel_deadline=None;business_since=None
        def zs(obj):
            nonlocal z_open,seal_sent
            try:send(self.z['sock'],obj);return True
            except OSError as e:
                row['failure']=row['failure'] or 'TEMPLATE_CHANNEL_LOST'
                z_open=False;seal_sent=True;row['admission']='CREATOR_STOPPING'
                event({'event':'CREATOR_SEND_FAILED','nonce':nonce,'operation':obj['op'],'error':repr(e)})
                try:signal_stable(self.z['pidfd'],signal.SIGKILL)
                except ProcessLookupError:pass
                journal();return False
        def ss(obj):
            nonlocal status_open
            try:send(st,obj);return True
            except OSError as e:
                status_open=False;st.close();event({'event':'TRANSITION_SEND_FAILED','nonce':nonce,'operation':obj['op'],'error':repr(e)})
                fail('TRANSITION_CHANNEL_LOST');return False
        def seal(reason):
            nonlocal seal_sent,cancel_deadline
            if seal_sent:return
            seal_sent=True;row['admission']='REVOKING';row['seal_reason']=reason;journal(force=True)
            if self.z['alive'] and z_open:
                zs({'op':'CANCEL','nonce':nonce,'reason':reason})
                cancel_deadline=time.monotonic()+.5
            else:row['admission']='CREATOR_STOPPING'
        def cancel(reason,twice=False):
            nonlocal cancel_count
            if not row['failure']:row['failure']=reason
            seal(reason);cancel_count+=1
            if twice and self.z['alive'] and z_open:
                zs({'op':'CANCEL','nonce':nonce,'reason':reason});cancel_count+=1
            event({'event':'CANCEL_REQUEST','nonce':nonce,'reason':reason,'count':cancel_count});journal(force=True)
        def fail(reason):
            if not row['failure']:row['failure']=reason
            seal(reason)
        while True:
            self.reap()
            if self.z['pid'] in self.waited:
                self.z['alive']=False
                if not row['failure']:row['failure']='TEMPLATE_LOST'
                # True wait of creator proves no future S; adoption is handled below.
                sealed=True;row['admission']='SEALED_CREATOR_WAITED'
            if mon in self.waited and not stopped and not row['failure']:fail('DOMAIN_LOST')
            if cancel_deadline and not sealed and time.monotonic()>cancel_deadline:
                # Missing revoke acknowledgment: terminate creator by stable pidfd,
                # wait/adopt. Never interpret an empty task as a sealed source.
                event({'event':'REVOKE_ACK_TIMEOUT','nonce':nonce});signal_stable(self.z['pidfd'],signal.SIGKILL);cancel_deadline=None
            if row['failure'] and sealed and not killed:killcg(cg);killed=True
            if time.monotonic()>deadline:
                row['resources']='INCOMPLETE';row['failure']=row['failure'] or 'DEADLINE';journal(force=True);raise TimeoutError(row)
            reads=([st] if status_open else [])+([ds] if domain_open else [])+([self.z['sock']] if z_open else [])+([rd] if not row['output_eof'] else [])
            poll_started=cost.mark();readylist,_,_=select.select(reads,[],[],.01);cost.finish('controller_poll',poll_started,ready_count=len(readylist))
            for item in readylist:
                if item==rd:
                    d=os.read(rd,65536)
                    if not d:row['output_eof']=True;cost.record('output_eof');event({'event':'OUTPUT_EOF','nonce':nonce});continue
                    out+=d;outall+=d
                    while b'\n' in out:
                        line,out=out.split(b'\n',1)
                        try:m=json.loads(line)
                        except ValueError:continue
                        # stdout is an oracle only, never an execution permission.
                        if m.get('event')=='WORKER_READY' and m.get('nonce')==nonce:
                            row['worker']=m;event(m);business_since=time.monotonic()
                            if not all(m['checks'].values()):fail('BUSINESS_CHECK_FAILED')
                            if not faulted and case in ('controller_death','zygote_death','pid1_death','cancel','double_cancel'):
                                faulted=True;event({'event':'FAULT','case':case,'nonce':nonce});journal(force=True)
                                if case=='controller_death':os.kill(os.getpid(),signal.SIGKILL)
                                elif case=='zygote_death':signal_stable(self.z['pidfd'],signal.SIGKILL)
                                elif case=='pid1_death':signal_stable(initfd,signal.SIGKILL)
                                else:cancel('CANCELLED',case=='double_cancel')
                    continue
                try:m,fs,_=recv(item)
                except EOFError:
                    if item==st:status_open=False
                    elif item==ds:
                        domain_open=False
                        if not stopped:fail('DOMAIN_CHANNEL_LOST')
                    else:
                        z_open=False;fail('TEMPLATE_CHANNEL_LOST')
                        # If creator closed protocol but remains live, conservative stop.
                        if self.z['pid'] not in self.waited:signal_stable(self.z['pidfd'],signal.SIGKILL)
                    continue
                typ=m.get('event');message_started=cost.mark();event(m)
                # PID1 legacy DRAINED has no nonce, private channel binds domain.
                if item==ds:
                    assert typ=='DRAINED' and not fs and m.get('echild'),m
                    row['drained']=m;cost.record('pid1_drained',pid1_record=m);journal();cost.finish('controller_message_service',message_started,message=typ);continue
                if m.get('nonce')!=nonce:
                    for f in fs:os.close(f)
                    fail('PROTOCOL_ID_MISMATCH');cost.finish('controller_message_service',message_started,message=typ);continue
                row['events'].append(m)
                try:
                    if typ=='PREPARED':
                        cost.record('prepared')
                        if case=='cancel_queued':cancel('CANCELLED',True)
                        else:
                            row['admission']='COMMITTED';row['s_state']='POSSIBLE';journal(force=True);zs({'op':'COMMIT','nonce':nonce})
                    elif typ in ('TRANSITION_CREATED','SNAPSHOT'):
                        p=m.get('pid',m.get('s_pid'))
                        if p:spid=p;row['s_pid']=p
                        if fs:
                            if spfd is not None:os.close(spfd)
                            spfd=fs.pop(0)
                        if typ=='TRANSITION_CREATED':
                            if row['s_state']!='REAPED':row['s_state']='CREATED'
                        else:
                            row['snapshots']=row.get('snapshots',0)+1
                            row['s_state']=m['s_state']
                            if m.get('s_wait') is not None:row['s_wait']=m['s_wait']
                    elif typ=='TRANSITION_BORN':
                        row['s_identity']=m.get('identity');row['s_pid']=m['pid'];spid=m['pid']
                        if row['s_state']!='REAPED':row['s_state']='CREATED'
                        if case=='controller_during_entry':event({'event':'FAULT','case':case,'nonce':nonce});journal(force=True);os.kill(os.getpid(),signal.SIGKILL)
                    elif typ=='ENTERED':
                        cost.record('entered')
                        if case=='cancel_during_entry':cancel('CANCELLED')
                        elif case=='control_eof':st.close();status_open=False;fail('STATUS_CHANNEL_LOST')
                        elif not row['failure']:
                            row['w_state']='POSSIBLE';journal(force=True);ss({'op':'START_WORKER','nonce':nonce})
                    elif typ in ('WORKER_CREATED','WORKER_GATED'):
                        wpid=m['worker_host_pid'];row['w_pid']=wpid;row['w_state']='CREATED_GATED'
                        if fs:
                            if wpfd is not None:os.close(wpfd)
                            wpfd=fs.pop(0)
                        if typ=='WORKER_GATED':
                            cost.record('worker_gated')
                            row['numpy_memory_gated']={'clock':'CLOCK_MONOTONIC','nonce':nonce,'start_ns':time.monotonic_ns(),'samples':{role:NW.memory(pid) for role,pid in [('Z',self.z['pid']),('S',spid),('W',wpid),('R',os.getpid())]}}
                            if case in ('cancel_before_business','revoke_ack_loss'):cancel('CANCELLED')
                            elif not row['failure']:
                                # Journal POSSIBLE business before granting: crash never claims NOT_EXECUTED.
                                row['business_permit']=True;row['business']='UNKNOWN';journal(force=True);ss({'op':'RUN_BUSINESS','nonce':nonce})
                    elif typ=='BUSINESS_RELEASED':row['business_release_ack']=True
                    elif typ=='WORKER_WAITED':
                        row['w_wait']=m;row['w_state']='REAPED';row['business']='KNOWN' if row['business_permit'] else 'NOT_EXECUTED'
                    elif typ=='TRANSITION_REAPED':row['s_state']='REAPED';row['s_wait']=m['wait_status'];row['s_pid']=m['pid'];spid=m['pid']
                    elif typ=='SPAWN_REJECTED':
                        row['s_state']='ABSENT';row['w_state']='ABSENT';row['business']='NOT_EXECUTED';row['spawn_errno']=m.get('errno');fail('RESOURCE_REJECTED')
                    elif typ=='WORKER_REJECTED':row['w_state']='ABSENT';row['business']='NOT_EXECUTED';row['worker_errno']=m.get('errno');fail('RESOURCE_REJECTED')
                    elif typ=='CANCEL_ACK':
                        assert m['sealed'];sealed=True;row['admission']='SEALED';row['cancel_acks']=row.get('cancel_acks',0)+1
                        if m.get('s_state')=='ABSENT':row['s_state']='ABSENT';row['w_state']='ABSENT'
                        if case=='cancel_queued' and not row.get('late_commit_sent'):
                            row['late_commit_sent']=True;zs({'op':'COMMIT','nonce':nonce})
                    elif typ=='COMMIT_REJECTED':row['late_commit_rejected']=True
                    elif typ in ('TRANSITION_ERROR','SPAWN_ERROR'):
                        if m.get('w_state')=='ABSENT':row['w_state']='ABSENT'
                        fail(typ)
                    else:raise RuntimeError(('unknown message',m))
                finally:
                    for f in fs:os.close(f)
                    cost.finish('controller_message_service',message_started,message=typ)
                journal()
            if business_since and case=='timeout' and not faulted and time.monotonic()-business_since>.08:
                faulted=True;cancel('TIMED_OUT')
            if self.z['alive'] and z_open and time.monotonic()>=query_at:
                zs({'op':'QUERY','nonce':nonce});query_at=time.monotonic()+.12
            self.reap()
            adopted={r['pid']:r['wait_status'] for r in self.wait_records[row['wait_start']:]}
            if spid is not None and spid in adopted:
                row['s_state']='REAPED';row['s_wait']=adopted[spid];row['s_reaper']='Controller'
            if wpid is not None and wpid in adopted:
                row['w_wait']={'event':'ADOPTED_WORKER_WAIT','nonce':nonce,'wait_status':adopted[wpid],'exit_code':os.waitstatus_to_exitcode(adopted[wpid])};row['w_state']='REAPED'
                row['business']='KNOWN' if row['business_permit'] else 'NOT_EXECUTED'
            if not self.z['alive']:
                if self.nochildren and empty(cg):
                    if row['s_state'] not in ('ABSENT','REAPED'):row['s_state']='RECLAIMED_STATUS_UNKNOWN'
                    if row['w_state'] not in ('ABSENT','REAPED'):row['w_state']='RECLAIMED_STATUS_UNKNOWN'
                    row['adopted_echild']=True
            sdone=row['s_state'] in ('ABSENT','REAPED','RECLAIMED_STATUS_UNKNOWN')
            if sdone and status_open is False and not row['w_wait'] and row['business_permit'] and not row['failure']:fail('RESULT_UNKNOWN')
            if sdone and row['s_wait'] not in (None,0) and not row['failure']:fail('TRANSITION_FAILED')
            if not row['failure'] and sdone and row['w_wait'] and row['output_eof'] and empty(business):
                seal('COMPLETE')
                if sealed and not stopped:
                    t=cost.now();ds.send(b'STOP');cost.ipc('send',{'op':'STOP','nonce':nonce},t,ds.fileno());stopped=True
            if row['failure'] and not seal_sent:seal(row['failure'])
            if mon in self.waited and empty(cg) and sdone and sealed and row['output_eof'] and not status_open and (case!='cancel_queued' or row.get('late_commit_rejected')) and (row['failure'] or row.get('drained')):
                remaining_children=[int(p) for p in Path(f'/proc/self/task/{os.getpid()}/children').read_text().split()]
                expected_children=[self.z['pid']] if self.z['alive'] else []
                if sorted(remaining_children)==sorted(expected_children):
                    row['children_at_release']=remaining_children
                    if row['w_state'] not in ('ABSENT','REAPED'):row['w_state']='RECLAIMED_STATUS_UNKNOWN'
                    break
        cost.record('domain_quiescent');row['monitor_wait']=self.waited[mon];row['wait_records']=self.wait_records[row['wait_start']:]
        row['side_effect']=(work/'result').read_text() if (work/'result').exists() else None
        row['stats']={k:stats(v) for k,v in [('task',cg),('control',control),('transition',trans),('business',business)]}
        row['domain_empty']=empty(cg)
        if row['w_wait'] is not None:row['result']={'exit_code':row['w_wait']['exit_code'],'source':row['w_wait']['event']}
        # Lost infrastructure status cannot be promoted to successful execution.
        row['outcome']=row['failure'] or ('SUCCEEDED' if row['result']['exit_code']==0 else 'NONZERO')
        if row['failure'] and row['business_permit'] and row['w_wait'] is None:row['business']='UNKNOWN'
        if self.z['alive']:
            self.z['sock'].settimeout(5)
            if case=='double_cancel':
                send(self.z['sock'],{'op':'CANCEL','nonce':nonce,'reason':'DUPLICATE_TERMINAL'})
                while True:
                    m,fs,_=recv(self.z['sock'])
                    for f in fs:os.close(f)
                    assert m.get('nonce')==nonce
                    if m['event']=='CANCEL_ACK':row['terminal_duplicate_ack']=m;break
            forget_start=cost.now();cost.record('forget_begin');send(self.z['sock'],{'op':'FORGET','nonce':nonce})
            while True:
                m,fs,_=recv(self.z['sock'])
                for f in fs:os.close(f)
                assert m.get('nonce')==nonce,m
                if m['event']=='FORGOTTEN':break
            cost.span('rpc_forget',forget_start);cost.record('forget_done')
        close_started=cost.mark()
        for f in [rd,initfd,monfd,spfd,wpfd]:
            if f is not None:os.close(f)
        st.close();ds.close();log.close()
        cost.finish('controller_close_attempt_fds',close_started)
        if (work/'numpy-output.npz').is_file():
            target=O/f'{n}-{case}-numpy-output.npz';shutil.copyfile(work/'numpy-output.npz',target)
            row['numpy_output']={'file':target.name,'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}
        output_write=cost.mark()
        (O/f'{n}-{case}-output.log').write_bytes(outall)
        cost.finish('output_evidence_write',output_write,bytes=len(outall))
        cg_delete=cost.mark()
        for p in [business,trans,control,cg]:p.rmdir()
        cost.finish('cgroup_delete',cg_delete)
        work_delete=cost.mark();shutil.rmtree(work);cost.finish('workspace_delete',work_delete)
        cost.record('resources_deleted');row['resources']='RELEASED';row['resources_removed']=not cg.exists() and not work.exists()
        row['controller_fd_after']=fdcount();assert row['controller_fd_after']==row['controller_fd_before'],row
        if self.z['alive']:
            ping_start=cost.now();send(self.z['sock'],{'op':'PING','nonce':nonce});m,f,_=recv(self.z['sock']);assert not f and m['event']=='PONG' and m['state_unchanged'],m
            cost.span('rpc_ping',ping_start);row['zygote_post']=m
            assert m['nonce']==nonce and m['session']==self.z['ready']['session'] and m['identity']['pid']==self.z['pid'] and m['active_attempts']==0,m
            assert set(m['identity']['fds'])==set(self.z['ready']['identity']['fds']),('Z FD leak',m)
        journal(force=True);self.validate(row);cost.record('validation_done')
        self.rpc_supervisor({'op':'RETIRE','nonce':nonce,'outcome':row['outcome'],'output_eof':row['output_eof']})
        row['qualification']='PASS';row['response_committed']=True;journal(force=True);dump(f'{n}-{case}.json',row);self.rows.append(row);cost.record('response_ready',force=True);cost.usage('request_cpu_end');return row
    def validate(self,r):
        c=r['case'];assert r['resources_removed'] and r['output_eof'] and r['domain_empty'] and r['admission'].startswith('SEALED'),r
        if r['worker']:
            assert all(r['worker']['checks'].values()) and r['worker']['inherited']==r['expected_state'],r
            assert all(r['worker']['numpy']['checks'].values()),r
            assert r.get('numpy_output',{}).get('sha256')==r['worker']['numpy']['output_sha256'],r
        if c in ('normal','nonzero','created_drop','reaped_drop'):
            assert not r['failure'] and r['s_wait']==0 and r['monitor_wait']==0 and r.get('drained'),r
            assert r['result']['exit_code']==(7 if c=='nonzero' else 0) and r['worker'],r
        elif c in ('pid_budget','second_budget'):
            assert r['failure']=='RESOURCE_REJECTED' and r['business']=='NOT_EXECUTED' and r['side_effect'] is None and self.z['alive'],r
            assert (r['spawn_errno'] if c=='pid_budget' else r['worker_errno'])==11,r
            assert r['w_state']=='ABSENT' and (r['s_state']=='ABSENT' if c=='pid_budget' else r['s_state']=='REAPED'),r
        elif c in ('cancel_queued','cancel_before_business','cancel_during_entry','revoke_ack_loss'):
            assert r['failure']=='CANCELLED' and r['business']=='NOT_EXECUTED' and r['side_effect'] is None,r
            if c=='cancel_queued':assert r.get('late_commit_rejected') and r['s_state']=='ABSENT',r
        elif c=='result_loss_side_effect':assert r['business']=='UNKNOWN' and r['side_effect']=='2650100' and r['result'] is None and r['outcome']!='SUCCEEDED',r
        else:assert r['failure'] and r['outcome']!='SUCCEEDED',r
        if c=='double_cancel':assert r.get('terminal_duplicate_ack',{}).get('sealed'),r
    def run(self):
        case=os.environ.get('RELIABILITY_CASE','control')
        suites={'runtime':['normal','normal','nonzero'],'control':['normal','normal','nonzero'],'budgets':['pid_budget','normal','second_budget','normal'],
          'receipts':['created_drop','reaped_drop','result_loss_side_effect','normal'],
          'cancels':['cancel_queued','cancel_before_business','cancel_during_entry','double_cancel','timeout','revoke_ack_loss','normal'],
          'failures':['fork_ack_loss','reap_ack_loss','zygote_death','pid1_death','control_eof','normal']}
        if case=='performance':suites[case]=['normal']*(int(os.environ.get('COST_REQUESTS','35'))+int(os.environ.get('COST_WARMUP','5')))
        for i,c in enumerate(suites.get(case,[case])):
            cost.record('numpy_call_begin',force=True,call_index=i)
            if self.z is None:self.start_z()
            self.domain(c)
            if not self.z['alive'] or os.environ.get('NP_BASELINE','hot')=='cold':self.stop_z()
            cost.record('numpy_call_complete',force=True,call_index=i)
        if self.z is not None:self.stop_z()
        self.reap();assert self.nochildren
        dump('summary.json',{'all_passed':True,'case':case,'rows':[{k:r.get(k) for k in ('case','nonce','outcome','business','s_state','w_state','resources','qualification','zygote_pid')} for r in self.rows],
            'controller_echild':self.nochildren,'wait_records':self.wait_records,'performance_benchmark':False})
        self.rpc_supervisor({'op':'DONE'});cost.record('session_end',force=True);cost.usage('controller_final_usage');cost.memory('controller_final_memory')

def main():
    from supervisor import run_supervised
    R.mkdir(exist_ok=True);(R/'src').mkdir(exist_ok=True);(R/'src/input').write_text('readonly-input\n')
    for n in ['probe','src','work','tools']:(Path('/runtime')/n).mkdir(exist_ok=True)
    for src,out,flags in [('bridge.c','bridge.so',['-shared','-fPIC','-ldl']),('domain_init.c','domain_init',['-static']),('native.c','native.so',['-shared','-fPIC']),('bridge_d.c','bridge_d.so',['-shared','-fPIC','-ldl']),('runtime_probe.c','libab_probe.so',['-shared','-fPIC','-pthread']),('numpy_atfork_audit.c','numpy_atfork_audit.so',['-shared','-fPIC','-ldl','-pthread'])]+([('domain_init_g0.c','domain_init_g0',['-static'])] if (P/'domain_init_g0.c').is_file() else [])+[(n,n.removesuffix('.c'),['-static']) for n in ['domain_init_local.c'] if (P/n).is_file()]+[(n,n.removesuffix('.c')+'.so',['-shared','-fPIC','-ldl']) for n in ['local_bridge.c'] if (P/n).is_file()]:
        subprocess.run(['gcc','-Wall','-Wextra','-O2',str(P/src),'-o',str(P/out),*flags],check=True);shutil.copy2(P/out,O/out)
    runtime.prepare_candidate();runtime.probe_missing_candidate_api()
    # Trusted VM fixture prepares empty mountpoints before the root view becomes read-only.
    for target in ("/opt/shimos-numpy", "/opt/shimos-numpy-deps"):
        (Path("/runtime") / target.lstrip("/")).mkdir(parents=True,exist_ok=True)
    # Independent cold reference, only in VM and under unprivileged UID + NNP.
    os.chown(R/'src',65534,65534)
    def reference_identity():
        os.setgroups([]);os.setgid(65534);os.setuid(65534)
        lib=ctypes.CDLL(None,use_errno=True);assert lib.prctl(38,1,0,0,0)==0
    refenv=dict(os.environ);refenv.pop('LD_PRELOAD',None);refenv.pop('LD_AUDIT',None)
    refargv=[str(runtime.BUNDLE/'lib/ld-linux-x86-64.so.2'),'--library-path',str(runtime.BUNDLE/'lib')+':/opt/shimos-numpy-deps:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu','/usr/bin/python3','-B',str(P/'numpy_reference.py'),str(R/'src')]
    with (O/'numpy-cold-reference.log').open('wb') as refout:
        subprocess.run(refargv,env=refenv,preexec_fn=reference_identity,stdout=refout,stderr=subprocess.STDOUT,check=True,timeout=30)
    for fn in ('numpy-reference.npz','numpy-reference.json'):shutil.copyfile(R/'src'/fn,O/fn)
    dump('numpy-reference-command.json',{'argv':refargv,'uid':65534,'nnp':1,'performance_sample':False})
    if os.environ.get('FULL_MODE')=='G2_MIXED':
        from run_mixed import prepare_references
        prepare_references(refargv,refenv,reference_identity)
    dump('build.json',{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in P.iterdir() if p.is_file()})
    dump('environment.json',{'kernel':os.uname().release,'python':sys.version,'glibc':os.confstr('CS_GNU_LIBC_VERSION'),'case':os.environ.get('RELIABILITY_CASE'),'uid':65534,'diagnostics':cost.DIAGNOSTICS,'cost_enabled':cost.ENABLED,'architecture_group':os.environ.get('ARCH_GROUP','G2'),'session_deadline_seconds':float(os.environ.get('SESSION_DEADLINE_SECONDS','240')),'test_descendant':os.environ.get('ARCH_TEST_DESCENDANT','1')=='1'})
    CG.mkdir();
    if os.environ.get('FULL_MEMORY_MIB'):(CG/'memory.max').write_text(str(int(os.environ['FULL_MEMORY_MIB'])*1024**2))
    (CG/'cgroup.subtree_control').write_text('+cpu +memory +pids');delegate(CG)
    client=CG/'client';client.mkdir();delegate(client);os.chown(R,65534,65534);os.chown(O,65534,65534)
    # Read back actual installed limits; no limit or execution policy changes.
    root_limits_read_begin=time.monotonic_ns()
    root_limits_readback={name:(CG/name).read_text().strip() for name in ('memory.max','cpu.max','pids.max')}
    client_limits_readback={name:(client/name).read_text().strip() for name in ('memory.max','cpu.max','pids.max')}
    dump('root-budget-readback.json',{'clock':'CLOCK_MONOTONIC','start_ns':root_limits_read_begin,'end_ns':time.monotonic_ns(),
         'path':str(CG),'actual_limits':root_limits_readback,'client_actual_limits':client_limits_readback,
         'configured_FULL_MEMORY_MIB':os.environ.get('FULL_MEMORY_MIB'),
         'scope':'direct cgroup limits read after setup and before H; not inferred from env, does not claim ancestor or host effective limits',
         'changes_limits':False,'phase':'root fixture before fixture_session_start'})
    trace=Path('/sys/kernel/tracing');subprocess.run(['mount','-t','tracefs','tracefs',str(trace)],check=True)
    (trace/'trace').write_text('');(trace/'buffer_size_kb').write_text('4096')
    for name in ['sched_process_fork','sched_process_exec','sched_process_exit']:(trace/'events/sched'/name/'enable').write_text('1')
    (trace/'trace_clock').write_text('mono')
    syscall_names=[edge+'_'+call for call in ['clone3','clone','unshare','setns','mount','mount_setattr','execve','chroot'] for edge in ['sys_enter','sys_exit']]
    if os.environ.get('COST_SYSCALL_TRACE')=='1':
        for name in syscall_names:
            enabled=trace/'events/syscalls'/name/'enable'
            if enabled.exists():enabled.write_text('1')
    (trace/'tracing_on').write_text('1' if os.environ.get('COST_TRACE','1')=='1' else '0')
    dump('trace-config.json',{'trace_clock':(trace/'trace_clock').read_text(),'tracing_on':(trace/'tracing_on').read_text(),'syscall_requested':os.environ.get('COST_SYSCALL_TRACE')=='1','syscall_names_requested':syscall_names,'syscall_unavailable':[n for n in syscall_names if not (trace/'events/syscalls'/n/'enable').exists()],'events':{str(f.relative_to(trace)):f.read_text() for group,names in [('sched',['sched_process_fork','sched_process_exec','sched_process_exit']),('syscalls',syscall_names)] for name in names for f in [trace/'events'/group/name/'enable'] if f.exists()}})
    cost.record('fixture_session_start',force=True)
    p=os.fork()
    if p==0:
        (client/'cgroup.procs').write_text(str(os.getpid()));os.setgroups([]);os.setgid(65534);os.setuid(65534)
        cost.context('H');cost.record('supervisor_forked')
        def execute(sock):
            try:
                if os.environ.get('FULL_MODE')=='G2_CONCURRENT':
                    from run_concurrent import Controller as ConcurrentController
                    ConcurrentController(sock).run()
                elif os.environ.get('FULL_MODE')=='G3_CONCURRENT':
                    from run_local_concurrent import Controller as ConcurrentLocalController
                    ConcurrentLocalController(sock).run()
                elif os.environ.get('FULL_MODE')=='G2_MIXED':
                    from run_mixed import Controller as MixedController
                    MixedController(sock).run()
                elif os.environ.get('FULL_MODE') in ('G3','G4'):
                    from run_local import Controller as LocalController
                    LocalController(sock).run()
                elif os.environ.get('FULL_MODE')=='G2_REUSE':
                    from run_cross_reuse import Controller as CrossController
                    CrossController(sock).run()
                elif os.environ.get('ARCH_GROUP','G2')=='G0':
                    from run_g0 import Controller as G0Controller
                    G0Controller(sock).run()
                else:Controller(sock).run()
            except BaseException:
                dump('controller-failure.json',{'traceback':traceback.format_exc()});traceback.print_exc();raise
        try:rc=run_supervised(execute,CG,R,O,str(P/'bridge.so'))
        except BaseException:dump('supervisor-failure.json',{'traceback':traceback.format_exc(),'release_state':'INCOMPLETE','business_result':'UNKNOWN'});traceback.print_exc();rc=1
        os._exit(rc)
    # Root read-only sampler starts only after H has forked; never inherited by H/R/Z.
    import resource_sampler
    sample_ms=int(os.environ.get('ARCH_RESOURCE_SAMPLE_MS','100'));assert sample_ms==0 or sample_ms>=25
    sample_handle=resource_sampler.start(p,CG,O,cost.SESSION,interval_ms=sample_ms) if sample_ms else None
    _,status=os.waitpid(p,0);cost.record('session_supervisor_waited',force=True)
    dump('resource-observer-status.json',resource_sampler.stop(sample_handle) if sample_handle else {'status':'DISABLED_PAIRED_DIAGNOSTIC','product_cleanup_used':False})
    dump('session-resource-ledger.json',{'clock':'CLOCK_MONOTONIC','at_ns':time.monotonic_ns(),'accounting':'root cgroup contains H/R plus template and all task descendants; do not add child counters','session_parent':stats(CG),'H_R_client':stats(client),'scope':'excludes fixture, read-only resource sampler and VM boot; inherited pages may remain charged outside parent'})
    # Root observer never kills workers or removes product-owned work/cgroups.
    dump('observer-after.json',snapshot(CG,R));time.sleep(.1);dump('observer-later.json',snapshot(CG,R))
    (trace/'tracing_on').write_text('0');(O/'process-trace.txt').write_text((trace/'trace').read_text())
    dump('trace-stats.json',{str(f.relative_to(trace)):f.read_text() for f in (trace/'per_cpu').glob('cpu*/stats')})
    remaining=[str(x) for x in CG.iterdir() if x.is_dir()];released=False
    if remaining==[str(client)] and empty(client):client.rmdir();CG.rmdir();released=True
    dump('external-final-release.json',{'supervisor_wait_status':status,'remaining_before_fixture_release':remaining,'delegation_removed':released,'observer_killed_processes':False,'observer_removed_product_resources':False})
    cost.record('fixture_release',force=True,released=released);cost.flush()
    return 0 if status==0 and released else 1
if __name__=='__main__':raise SystemExit(main())
