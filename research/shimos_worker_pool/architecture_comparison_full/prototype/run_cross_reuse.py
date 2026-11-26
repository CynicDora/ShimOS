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



from run import Controller as BaseController
class Controller(BaseController):
    def __init__(self,supervisor):
        super().__init__(supervisor);self.d=None;self.domains=[]
    def open_domain(self):
        assert self.d is None
        nonce=os.urandom(16).hex();cg=CG/('d-'+nonce);work=R/('work-'+nonce)
        started=time.monotonic_ns();cost.record('retained_domain_begin',domain_nonce=nonce,force=True)
        cg.mkdir();(cg/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        (cg/'memory.max').write_text(str(512*1024**2));(cg/'pids.max').write_text('256');(cg/'cpu.max').write_text('400000 100000')
        control=writecg(cg/'control');work.mkdir()
        ds,ch=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);ds.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);ds.settimeout(10)
        rd,wr=os.pipe2(os.O_CLOEXEC);os.set_blocking(rd,False)
        self.rpc_supervisor({'op':'REGISTER','nonce':nonce,'cgroup':str(cg),'workspace':str(work)},[rd])
        log=(O/('domain-'+nonce+'.log')).open('wb');argv=self.bwrap(work,nonce)
        mon,pfd=self.spawn(argv,control,wr,ch.fileno());ch.close();os.close(wr);self.waited.pop(mon,None)
        ready,export,cred=recv(ds)
        assert ready['event']=='DOMAIN_READY' and ready['nonce']==nonce and len(export)==7 and cred[1:]==(65534,65534)
        assert str(cred[0]) in (control/'cgroup.procs').read_text().split()
        self.d={'nonce':nonce,'cg':cg,'work':work,'control':control,'sock':ds,'log':log,'argv':argv,'pid':mon,'pidfd':pfd,'ready':ready,'export':export,'cred':cred,'hold_read':rd,'begin_ns':started,'ready_ns':time.monotonic_ns()}
        cost.record('retained_domain_ready',domain_nonce=nonce,force=True)
    def request_quiesce(self,nonce):
        d=self.d
        if d['pid'] in self.waited:return
        d['sock'].settimeout(8);d['sock'].send(('QUIESCE '+nonce).encode());m,f,_=recv(d['sock'])
        assert not f and m.get('event')=='QUIESCENT' and m.get('nonce')==nonce and m.get('echild'),m
        event(m);d.setdefault('quiescence',[]).append(m)
    def close_domain(self):
        d=self.d;assert d is not None
        if d['pid'] not in self.waited:
            d['sock'].settimeout(8);d['sock'].send(b'STOP');m,f,_=recv(d['sock']);assert not f and m.get('event')=='DRAINED' and m.get('echild') and m.get('nonce',d['nonce'])==d['nonce'];d['drained']=m
        until=time.monotonic()+8
        while d['pid'] not in self.waited:
            self.reap();assert time.monotonic()<until;time.sleep(.002)
        assert empty(d['cg']);state=stats(d['cg']);wait=self.waited[d['pid']]
        while True:
            chunk=os.read(d['hold_read'],65536)
            if not chunk:break
            d['log'].write(chunk)
        os.close(d['hold_read'])
        for f in d['export']+[d['pidfd']]:os.close(f)
        d['sock'].close();d['log'].close();d['control'].rmdir();d['cg'].rmdir();shutil.rmtree(d['work'])
        self.rpc_supervisor({'op':'RETIRE','nonce':d['nonce'],'outcome':'DOMAIN_CLOSED','output_eof':True})
        row={'nonce':d['nonce'],'output_eof':True,'output_channel_role':'real monitor/PID1 output','quiescence':d.get('quiescence',[]),'monitor_wait':wait,'drained':d.get('drained'),'begin_ns':d['begin_ns'],'ready_ns':d['ready_ns'],'released_ns':time.monotonic_ns(),'stats':state,'resources_removed':not d['cg'].exists() and not d['work'].exists()}
        self.domains.append(row);dump('persistent-domains.json',self.domains);self.d=None
        cost.record('retained_domain_released',domain_nonce=d['nonce'],force=True)
    def validate(self,r):
        assert r['resources_removed'] and r['output_eof'] and r['domain_empty'] and r['admission'].startswith('SEALED'),r
        if r['worker']:
            assert all(r['worker']['checks'].values()) and r['worker']['inherited']==r['expected_state'],r
            assert all(r['worker']['numpy']['checks'].values()),r
            assert r.get('numpy_output',{}).get('sha256')==r['worker']['numpy']['output_sha256'],r
        if r['case'] in ('normal','nonzero','created_drop','reaped_drop'):
            assert not r['failure'] and r['s_wait']==0 and r['result']['exit_code']==(7 if r['case']=='nonzero' else 0) and r['worker'],r
        else:
            assert r['outcome']!='SUCCEEDED' and r['failure'],r
        if r['case']=='double_cancel':assert r.get('terminal_duplicate_ack',{}).get('sealed'),r
    def run(self):
        D=int(os.environ.get('FULL_DOMAINS','1'));K=int(os.environ.get('FULL_PER_DOMAIN','2'))
        case=os.environ.get('RELIABILITY_CASE','performance');cases=['normal']*K if case=='performance' else case.split(',')
        assert D>0 and K>0
        for di in range(D):
            if self.z is None:self.start_z()
            self.open_domain()
            for c in cases:
                cost.record('numpy_call_begin',force=True,call_index=len(self.rows));self.domain(c);cost.record('numpy_call_complete',force=True,call_index=len(self.rows)-1)
                if not self.z['alive']:break
            self.close_domain()
            if not self.z['alive']:self.stop_z()
        if self.z is not None:self.stop_z()
        self.reap();assert self.nochildren
        dump('summary.json',{'all_passed':True,'case':case,'rows':self.rows,'persistent_domains':self.domains,'controller_echild':True,'wait_records':self.wait_records,'full_mode':'G2_REUSE'})
        self.rpc_supervisor({'op':'DONE'});cost.record('session_end',force=True)

    def domain(self,case):
        n=len(self.rows);nonce=os.urandom(16).hex();cost.context('R',nonce,repeat=n,warmup=n<int(os.environ.get('COST_WARMUP','0')));cost.record('request_begin',force=True);cost.usage('request_cpu_begin');cg=CG/('d-'+nonce);work=R/('work-'+nonce)
        row={'release_scope':'REQUEST_GROUP','workspace_scope':'same-trust retained /work; request taskwork is registration directory','persistent_domain_nonce':self.d['nonce'],'case':case,'nonce':nonce,'zygote_pid':self.z['pid'],'admission':'OPEN','s_state':'ABSENT','w_state':'ABSENT',
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
        cost.record('request_group_begin');cg.mkdir();(cg/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        for key,value in [('memory.max',str(512*1024**2)),('pids.max','256'),('cpu.max','400000 100000')]:(cg/key).write_text(value)
        trans=writecg(cg/'transition');business=writecg(cg/'business');control=self.d['control'];work.mkdir()
        taskwork=work;work=self.d['work']
        if case=='pid_budget':(trans/'pids.max').write_text('0')
        if case=='second_budget':(business/'pids.max').write_text('0')
        ds=self.d['sock'];log=self.d['log'];argv=self.d['argv'];mon=self.d['pid'];monfd=None
        ready=self.d['ready'];export=[os.dup(f) for f in self.d['export']];cred=self.d['cred']
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
        self.rpc_supervisor({'op':'REGISTER','nonce':nonce,'cgroup':str(cg),'workspace':str(taskwork)},[rd])
        tc=os.open(trans,os.O_RDONLY|os.O_DIRECTORY);bc=os.open(business,os.O_RDONLY|os.O_DIRECTORY)
        mode='nonzero' if case=='nonzero' else ('normal' if case in ('normal','pid_budget','second_budget','fork_ack_loss','reap_ack_loss','created_drop','reaped_drop','result_loss_side_effect') else 'hang')
        req={'op':'SPAWN','nonce':nonce,'domain_nonce':self.d['nonce'],'full_profile':os.environ.get('FULL_PROFILE','legacy'),'full_profile':os.environ.get('FULL_PROFILE','legacy'),'test_descendant':os.environ.get('ARCH_TEST_DESCENDANT','1')=='1','numpy_level':os.environ.get('NP_LEVEL','import'),'numpy_baseline':os.environ.get('NP_BASELINE','hot'),'numpy_case':os.environ.get('NP_CASE','normal'),'runtime_robust':os.environ.get('RELIABILITY_CASE')=='runtime','mode':mode,'fault':case,'target_ns':ns,'root_identity':[os.fstat(export[6]).st_dev,os.fstat(export[6]).st_ino],'business_cgroup':str(business).removeprefix('/sys/fs/cgroup')}
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
                    self.d['drained']=m;row['drained']=m;cost.record('pid1_drained',pid1_record=m);journal();cost.finish('controller_message_service',message_started,message=typ);continue
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
                if sorted(int(p) for p in Path(f'/proc/self/task/{os.getpid()}/children').read_text().split())==([mon] if mon not in self.waited else []) and empty(cg):
                    if row['s_state'] not in ('ABSENT','REAPED'):row['s_state']='RECLAIMED_STATUS_UNKNOWN'
                    if row['w_state'] not in ('ABSENT','REAPED'):row['w_state']='RECLAIMED_STATUS_UNKNOWN'
                    row['adopted_echild']=True
            sdone=row['s_state'] in ('ABSENT','REAPED','RECLAIMED_STATUS_UNKNOWN')
            if sdone and status_open is False and not row['w_wait'] and row['business_permit'] and not row['failure']:fail('RESULT_UNKNOWN')
            if sdone and row['s_wait'] not in (None,0) and not row['failure']:fail('TRANSITION_FAILED')
            if not row['failure'] and sdone and row['w_wait'] and row['output_eof'] and empty(business):
                seal('COMPLETE')
                if sealed:stopped=True
            if row['failure'] and not seal_sent:seal(row['failure'])
            if empty(cg) and sdone and sealed and row['output_eof'] and not status_open and (case!='cancel_queued' or row.get('late_commit_rejected')):
                remaining_children=[int(p) for p in Path(f'/proc/self/task/{os.getpid()}/children').read_text().split()]
                expected_children=([self.z['pid']] if self.z['alive'] else [])+([mon] if mon not in self.waited else [])
                if sorted(remaining_children)==sorted(expected_children):
                    row['children_at_release']=remaining_children
                    if row['w_state'] not in ('ABSENT','REAPED'):row['w_state']='RECLAIMED_STATUS_UNKNOWN'
                    break
        self.request_quiesce(nonce);cost.record('request_group_quiescent');row['monitor_wait']=self.waited.get(mon);row['domain_retained']=mon not in self.waited;row['wait_records']=self.wait_records[row['wait_start']:]
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
        st.close();ds.setblocking(True)
        cost.finish('controller_close_attempt_fds',close_started)
        if (work/'numpy-output.npz').is_file():
            target=O/f'{n}-{case}-numpy-output.npz';shutil.copyfile(work/'numpy-output.npz',target)
            row['numpy_output']={'file':target.name,'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}
        output_write=cost.mark()
        (O/f'{n}-{case}-output.log').write_bytes(outall)
        cost.finish('output_evidence_write',output_write,bytes=len(outall))
        cg_delete=cost.mark()
        for p in [business,trans,cg]:p.rmdir()
        cost.finish('cgroup_delete',cg_delete)
        work_delete=cost.mark();shutil.rmtree(taskwork);cost.finish('workspace_delete',work_delete)
        cost.record('resources_deleted');row['resources']='RELEASED';row['resources_removed']=not cg.exists() and not taskwork.exists()
        
        for name in ('numpy-output.npz','result'):
            f=work/name
            if f.exists():f.unlink()
        row['controller_fd_after']=fdcount();assert row['controller_fd_after']==row['controller_fd_before'],row
        if self.z['alive']:
            ping_start=cost.now();send(self.z['sock'],{'op':'PING','nonce':nonce});m,f,_=recv(self.z['sock']);assert not f and m['event']=='PONG' and m['state_unchanged'],m
            cost.span('rpc_ping',ping_start);row['zygote_post']=m
            assert m['nonce']==nonce and m['session']==self.z['ready']['session'] and m['identity']['pid']==self.z['pid'] and m['active_attempts']==0,m
            assert set(m['identity']['fds'])==set(self.z['ready']['identity']['fds']),('Z FD leak',m)
        journal(force=True);self.validate(row);cost.record('validation_done')
        self.rpc_supervisor({'op':'RETIRE','nonce':nonce,'outcome':row['outcome'],'output_eof':row['output_eof']})
        row['qualification']='PASS';row['response_committed']=True;journal(force=True);dump(f'{n}-{case}.json',row);self.rows.append(row);cost.record('response_ready',force=True);cost.usage('request_cpu_end');return row
