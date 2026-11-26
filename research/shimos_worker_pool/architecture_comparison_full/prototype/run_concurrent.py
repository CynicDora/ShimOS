#!/usr/bin/env python3
"""G2 concurrent candidate: one R thread, one Z, independent request domains.

Static dispatch only. No pool or adaptive scheduler. Each attempt keeps the
serial implementation's permits, true waits, output EOF and H registration.
Final SUCCESS/qualification is withheld until a batch-level template/FD check.
This is a separately qualified candidate, never an alias for serial admission.
"""
import os,time,json,socket,ctypes,select,signal,fcntl,hashlib,shutil,array,stat,errno
from pathlib import Path
from run import Controller as SerialController
from run import R,P,O,CG,dump,event,empty,stats,killcg,writecg,signal_stable,fdcount
from common import send,recv,identity
from concurrent_router import Router
import cost
import numpy_workload as NW

SOURCE_DOMAIN_SHA256 = '4dd2862e3cca3d749c21550154e8f5a4a93fdb001ed7174b479ca97ba50ef401'
SOURCE_DOMAIN_LINES = (116,399)


def fd_object(fd):
    try:
        st=os.fstat(fd)
    except OSError as error:
        if error.errno==errno.EBADF:return None
        raise
    # A live descriptor with unreadable metadata is not evidence of closure.
    return {'device':st.st_dev,'inode':st.st_ino,'mode':st.st_mode,
            'target':os.readlink('/proc/self/fd/'+str(fd)),
            'fd_flags':fcntl.fcntl(fd,fcntl.F_GETFD),'open_flags':fcntl.fcntl(fd,fcntl.F_GETFL)}


def fd_inventory():
    # The transient descriptor opened by listdir is already closed here.
    return {str(fd):value for fd in sorted(map(int,os.listdir('/proc/self/fd')))
            if (value:=fd_object(fd)) is not None}


def process_object(pid):
    try:
        raw=Path('/proc/'+str(pid)+'/stat').read_text();fields=raw[raw.rfind(')')+2:].split()
        return {'pid':pid,'start_ticks':int(fields[19]),'state':fields[0],'ppid':int(fields[1]),
                'cgroup':Path('/proc/'+str(pid)+'/cgroup').read_text()}
    except (OSError,ValueError,IndexError):return None


class Attempt(SerialController):
    def __init__(self,manager,index,nonce,case,endpoint):
        # R remains the sole subreaper/native launcher; do not run base __init__.
        self.manager=manager;self.index=index;self.nonce=nonce;self.case=case
        self.supervisor=manager.supervisor;self.lib=manager.lib;self.native=manager.native
        self.waited=manager.waited;self.wait_records=manager.wait_records;self.nochildren=False
        self.z=dict(manager.z);self.z['sock']=endpoint;self.rows=[]

    def spawn(self,argv,cg,log,fd):
        return self.manager.spawn_owned(self.nonce,argv,cg,log,fd)

    def reap(self):
        self.manager.reap();self.nochildren=self.manager.nochildren
        self.z['alive']=self.manager.z['alive']

    def validate(self,row):
        # Preserve serial per-case acceptance. Global template loss is admitted
        # only by a separate batch-fault verifier, never as normal success.
        return SerialController.validate(self,row)

    def domain(self,case):
        n=self.index;nonce=self.nonce;cost.context('R',nonce,repeat=n,warmup=n<int(os.environ.get('COST_WARMUP','0')));cost.record('request_begin',force=True);cost.usage('request_cpu_begin');cg=CG/('d-'+nonce);work=R/('work-'+nonce)
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
            # One R thread resumes one attempt at a time. No fork from threads.
            yield {'phase':'service','nonce':nonce}
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
            poll_started=cost.mark();readylist,_,_=select.select(reads,[],[],0);cost.finish('controller_poll',poll_started,ready_count=len(readylist))
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
                            if case=='adoption_after_snapshot' and not faulted:
                                faulted=True
                                self.manager.adoption_probe(nonce,spid,spfd)
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
            adopted={r['pid']:r['wait_status'] for r in self.wait_records[row['wait_start']:] if r.get('owner_nonce')==nonce}
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
                scoped_children=self.manager.child_scope(nonce)
                if not scoped_children['own'] and not scoped_children['unknown']:
                    row['children_at_release']=scoped_children
                    row['child_assertion_scope']='this attempt; other identified active attempts allowed; global ECHILD at batch end'
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
        owned_fds={str(f):fd_object(f) for f in [rd,initfd,monfd,spfd,wpfd,st.fileno(),ds.fileno(),log.fileno()] if f is not None and f>=0}
        close_started=cost.mark()
        for f in [rd,initfd,monfd,spfd,wpfd]:
            if f is not None:os.close(f)
        st.close();ds.close();log.close()
        cost.finish('controller_close_attempt_fds',close_started)
        row['closed_fd_objects']=owned_fds
        row['owned_fd_close_confirmed']=all(fd_object(int(f)) is None for f in owned_fds)
        assert row['owned_fd_close_confirmed'],row
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
        row['controller_fd_after']=fdcount()
        row['fd_assertion_scope']='owned endpoints closed here; global R identity set and Z PING checked after every active attempt is forgotten'
        row['batch_template_check']='PENDING'
        journal(force=True);self.validate(row);cost.record('validation_done')
        self.rpc_supervisor({'op':'RETIRE','nonce':nonce,'outcome':'BATCH_CHECK_PENDING:'+row['outcome'],'output_eof':row['output_eof']})
        row['qualification']='PENDING_BATCH_TEMPLATE_CHECK';row['response_committed']=False
        row['execution_resources_complete_ns']=time.monotonic_ns()
        journal(force=True);dump(f'{n}-{case}.json',row);cost.record('attempt_resources_complete',force=True);cost.usage('request_cpu_end');return row


class Controller(SerialController):
    def __init__(self,supervisor):
        super().__init__(supervisor)
        assert len(os.listdir('/proc/self/task'))==1,'R must not be threaded'
        self.registry={};self.registry_history=[];self.next_index=0
        self.active_nonces=set();self.retired_nonces=set();self.router=None

    def spawn_owned(self,owner,argv,cg,log,fd):
        pid,pidfd=SerialController.spawn(self,argv,cg,log,fd)
        self.waited.pop(pid,None)
        value=process_object(pid)
        if value is None:
            # A child, even exited, remains a zombie until this R waits it.
            raise RuntimeError('new real child identity unavailable',pid,owner)
        entry={**value,'owner_nonce':owner,'source':'native spawn return','pidfd':pidfd}
        self.registry[pid]=entry;self.registry_history.append(entry.copy())
        event({'event':'CONCURRENT_CHILD_REGISTERED',**entry})
        return pid,pidfd

    def spawn(self,argv,cg,log,fd):
        return self.spawn_owned('TEMPLATE',argv,cg,log,fd)

    def stop_z(self):
        # Unlike the serial reap(), this manager marks a genuinely waited Z
        # dead immediately for every live attempt. Preserve the normal STOP
        # exit-status assertion rather than losing it to that state update.
        pid=self.z['pid'];expected_normal=self.z['alive']
        SerialController.stop_z(self)
        if expected_normal:assert self.waited[pid]==0,('Z STOP abnormal wait',pid,self.waited[pid])

    def child_scope(self,nonce):
        own=[];other=[];unknown=[];observed=[]
        children=[int(x) for x in Path('/proc/self/task/'+str(os.getpid())+'/children').read_text().split()]
        for pid in children:
            current=process_object(pid);entry=self.registry.get(pid)
            if current is None:
                unknown.append(pid);continue
            if entry is None or entry['start_ticks']!=current['start_ticks']:
                owner=None
                for candidate in self.active_nonces|self.retired_nonces:
                    if '/d-'+candidate+'/' in current['cgroup'] or current['cgroup'].rstrip().endswith('/d-'+candidate):
                        owner=candidate;break
                if self.z and pid==self.z['pid']:owner='TEMPLATE'
                entry={**current,'owner_nonce':owner,'source':'actual R child and cgroup identity','pidfd':None}
                self.registry[pid]=entry;self.registry_history.append(entry.copy())
                event({'event':'CONCURRENT_ADOPTED_CHILD_OBSERVED',**entry})
            observed.append({**current,'owner_nonce':entry['owner_nonce']})
            if entry['owner_nonce']==nonce:own.append(pid)
            elif entry['owner_nonce']=='TEMPLATE' or entry['owner_nonce'] in self.active_nonces:other.append(pid)
            else:unknown.append(pid)
        return {'own':own,'other_identified':other,'unknown':unknown,'observed':observed}

    def reap(self):
        self.nochildren=False
        while True:
            started=cost.mark()
            try:selected=os.waitid(os.P_ALL,0,os.WEXITED|os.WNOHANG|os.WNOWAIT)
            except ChildProcessError:
                cost.finish('waitid_poll',started,result='ECHILD');self.nochildren=True;return
            cost.finish('waitid_poll',started,selected_pid=selected.si_pid if selected else 0)
            if selected is None:return
            pid=selected.si_pid
            # WNOWAIT retains this actual child zombie: it cannot disappear or
            # recycle its PID while the single R verifies object identity.
            current=process_object(pid);again=process_object(pid)
            try:
                if not current or not again or current!=again or current['state']!='Z' or current['ppid']!=os.getpid():
                    raise RuntimeError('selected child zombie identity unavailable or unstable',current,again)
                membership=current['cgroup'].splitlines()
                root=str(CG).removeprefix('/sys/fs/cgroup')
                members=[line[3:] for line in membership if line.startswith('0::')]
                if len(members)!=1:raise RuntimeError('selected child cgroup not unique',membership)
                member=members[0];owners=[]
                if member==root+'/template':owners.append('TEMPLATE')
                for nonce in self.active_nonces|self.retired_nonces:
                    path=root+'/d-'+nonce
                    if member==path or member.startswith(path+'/'):owners.append(nonce)
                if len(owners)!=1:raise RuntimeError('selected child owner not established',current,owners)
                owner=owners[0];previous=self.registry.get(pid)
                if previous and previous['start_ticks']==current['start_ticks'] and previous['owner_nonce']!=owner:
                    raise RuntimeError('same child identity changed owned domain',previous,current,owner)
                entry={**current,'owner_nonce':owner,'source':'waitid WNOWAIT selected child zombie and current proc identity',
                       'pidfd':previous.get('pidfd') if previous and previous['start_ticks']==current['start_ticks'] else None}
                self.registry[pid]=entry;self.registry_history.append(entry.copy())
                peek={'pid':pid,'si_code':selected.si_code,'si_status':selected.si_status,
                      'owner_nonce':owner,'identity':current,'registry_previous':previous,
                      'not_yet_reaped':True,'single_R_thread':len(os.listdir('/proc/self/task'))==1}
                if not peek['single_R_thread']:raise RuntimeError('wait ownership requires single R thread')
                event({'event':'CONCURRENT_WAITID_SELECTED',**peek})
            except BaseException as error:
                event({'event':'CONCURRENT_WAIT_IDENTITY_REJECTED','pid':pid,
                       'si_code':selected.si_code,'si_status':selected.si_status,'identity':current,
                       'error':repr(error),'actual_R_wait_performed':False,'business_result':'UNKNOWN',
                       'remaining_wait_owner':'surviving H after R exits'})
                raise
            wait_started=cost.mark();waited,status=os.waitpid(pid,0)
            cost.finish('wait_selected_child',wait_started,waited_pid=waited,wait_status=status)
            if waited!=pid:raise RuntimeError('exact selected child wait mismatch',pid,waited)
            self.waited[pid]=status
            row={'event':'CONTROLLER_WAIT','pid':pid,'wait_status':status,'seq':len(self.wait_records),
                 'time_ns':time.monotonic_ns(),'owner_nonce':entry['owner_nonce'],
                 'start_ticks':entry['start_ticks'],'identity_source':entry['source'],
                 'waitid_si_code':selected.si_code,'waitid_si_status':selected.si_status,
                 'selected_identity':current,'waited_exact_selected_pid':True}
            self.wait_records.append(row);event(row)
            expected=selected.si_status if selected.si_code==os.CLD_EXITED else -selected.si_status
            if selected.si_code not in (os.CLD_EXITED,os.CLD_KILLED,os.CLD_DUMPED) or os.waitstatus_to_exitcode(status)!=expected:
                raise RuntimeError('waitid and actual wait disagree',selected,status)
            if self.z and pid==self.z['pid']:self.z['alive']=False

    def adoption_probe(self,nonce,pid,pidfd):
        if self.router.test_fault!='adoption_after_snapshot' or pidfd is None:
            raise RuntimeError('adoption probe missing explicit scope or real pidfd')
        deadline=time.monotonic()+2
        while True:
            before=process_object(pid)
            if before and before['state']=='T':break
            if time.monotonic()>deadline:raise TimeoutError('transition did not stop for adoption probe')
            time.sleep(.001)
        children=[int(x) for x in Path('/proc/self/task/'+str(os.getpid())+'/children').read_text().split()]
        if before['ppid']!=self.z['pid'] or pid in children:
            raise RuntimeError('probe child already adopted before selected snapshot',before,children)
        event({'event':'CONCURRENT_TEST_ADOPTION_CHILD_SNAPSHOT','nonce':nonce,
               'R_pid':os.getpid(),'R_children':children,'transition':before,'Z_pid':self.z['pid']})
        signal_stable(self.z['pidfd'],signal.SIGKILL)
        while True:
            adopted=process_object(pid)
            if adopted and adopted['ppid']==os.getpid():break
            if time.monotonic()>deadline:raise TimeoutError('real adoption after snapshot not observed')
            time.sleep(.001)
        if adopted['start_ticks']!=before['start_ticks'] or adopted['state']!='T':
            raise RuntimeError('adoption probe identity changed',before,adopted)
        event({'event':'CONCURRENT_TEST_ADOPTION_AFTER_CHILD_SNAPSHOT','nonce':nonce,
               'R_pid':os.getpid(),'original':before,'adopted':adopted,'business_authorized':False})
        signal_stable(pidfd,signal.SIGKILL)
        while pid not in self.waited:
            self.reap()
            if time.monotonic()>deadline:raise TimeoutError('adopted child was not truly waited')
            time.sleep(.001)
        event({'event':'CONCURRENT_TEST_ADOPTION_TRUE_WAIT_COMPLETE','nonce':nonce,
               'pid':pid,'wait_status':self.waited[pid],'start_ticks':before['start_ticks']})

    def cases(self):
        suite=os.environ.get('RELIABILITY_CASE','control')
        presets={
            'control':['normal']*self.width,
            'runtime':['normal']*self.width,
            'concurrent_mixed':['cancel_before_business','normal','second_budget','normal'],
            'concurrent_cancel':['cancel_queued','normal','double_cancel','normal'],
            'concurrent_receipts':['created_drop','reaped_drop','normal','normal'],
            'concurrent_budget':['pid_budget','normal','second_budget','normal'],
            'concurrent_timeout':['timeout','normal','nonzero','normal'],
        }
        explicit=os.environ.get('FULL_CONCURRENT_CASES')
        if explicit:
            cases=explicit.split(',')
            allowed={'normal','nonzero','created_drop','reaped_drop','result_loss_side_effect',
                     'cancel_queued','cancel_before_business','cancel_during_entry','double_cancel','timeout',
                     'revoke_ack_loss','pid_budget','second_budget','controller_death','controller_during_entry',
                     'zygote_death','pid1_death','control_eof','fork_ack_loss','reap_ack_loss','adoption_after_snapshot'}
            if not cases or any(x not in allowed for x in cases):raise ValueError('unregistered concurrent case')
            return cases
        if suite=='performance':
            if int(os.environ.get('COST_WARMUP','0')):raise ValueError('concurrent session counts all requests; no hidden warmup')
            return ['normal']*int(os.environ.get('COST_REQUESTS','4'))
        if suite not in presets:raise ValueError('select explicit concurrent fault cases')
        return presets[suite]

    def run(self):
        self.width=int(os.environ.get('FULL_CONCURRENCY','2'))
        if self.width not in (1,2,4,8):raise ValueError('fixed C1/C2/C4/C8 candidate only')
        if os.environ.get('NP_BASELINE','hot')!='hot':raise ValueError('one warm Z only, not a cold-A comparison')
        if os.environ.get('ARCH_GROUP','G2')!='G2':raise ValueError('concurrent candidate is G2')
        cases=self.cases()
        if not cases:raise ValueError('empty batch')
        if len(cases)%self.width:raise ValueError('complete fixed-size batches required')
        cost.record('concurrent_batch_begin',force=True,width=self.width,requests=len(cases))
        self.start_z();self.z_pid=self.z['pid'];self.z_ready=self.z['ready']
        # The existing RPC helper sets this same timeout on first REGISTER.
        # Apply it before the FD baseline so required O_NONBLOCK bookkeeping
        # is not mistaken for a leaked or substituted file object at batch end.
        self.supervisor.settimeout(5)
        baseline_fds=fd_inventory();self.router=Router(self.z['sock'],event)
        batch_nonce=os.urandom(16).hex();control=self.router.endpoint(batch_nonce,control=True)
        pending=list(enumerate(cases));active={};completed=[];batch_index=-1
        try:
            while pending or active:
                admit_batch=not active
                if admit_batch:
                    batch_index+=1
                    event({'event':'CONCURRENT_BURST_BEGIN','burst':batch_index,'width':self.width,
                           'domain_contract':'fresh independent domain, one request per domain'})
                while admit_batch and pending and len(active)<self.width:
                    index,case=pending.pop(0);nonce=os.urandom(16).hex()
                    if nonce in self.active_nonces|self.retired_nonces:raise RuntimeError('attempt nonce collision')
                    self.active_nonces.add(nonce)
                    endpoint=self.router.endpoint(nonce)
                    task=Attempt(self,index,nonce,case,endpoint)
                    active[nonce]=(task,task.domain(case))
                    cost.context('R',nonce,repeat=index,warmup=False)
                    cost.record('numpy_call_begin',force=True,call_index=index,concurrency=self.width)
                    event({'event':'CONCURRENT_REQUEST_ADMITTED','nonce':nonce,'index':index,'case':case,'active':len(active),'zygote_pid':self.z_pid})
                self.router.pump(0)
                for nonce,(task,iterator) in list(active.items()):
                    cost.context('R',nonce,repeat=task.index,warmup=False)
                    try:next(iterator)
                    except StopIteration as done:
                        row=done.value
                        if not isinstance(row,dict):raise RuntimeError('attempt did not return lifecycle row')
                        completed.append((task.index,row));del active[nonce]
                        self.active_nonces.remove(nonce);self.retired_nonces.add(nonce)
                        self.router.retire(nonce)
                        event({'event':'CONCURRENT_REQUEST_RESOURCES_RELEASED','nonce':nonce,'index':task.index,
                               'response_committed':False,'outcome':row['outcome'],'active':len(active)})
                if not active:event({'event':'CONCURRENT_BURST_RESOURCES_RELEASED','burst':batch_index})
                if active:self.router.pump(.001)
                if self.router.failed:raise RuntimeError('router failed closed',self.router.failed)
            self.reap()
            scope=self.child_scope(None)
            actual=[x['pid'] for x in scope['observed']]
            assert not scope['unknown'] and sorted(actual)==[self.z_pid],scope
            if not self.z['alive']:raise RuntimeError('template died; normal batch cannot commit')
            cost.context('R',batch_nonce);check_start=cost.now()
            control.settimeout(5);send(control,{'op':'PING','nonce':batch_nonce})
            post,fds,_=recv(control)
            try:
                if self.router.test_fault!='none':
                    event({'event':'CONCURRENT_BATCH_TEMPLATE_SNAPSHOT','batch_nonce':batch_nonce,
                           'template_post':post,'unexpected_fd_count':len(fds),
                           'response_committed':False})
                assert not fds and post['event']=='PONG' and post['state_unchanged'],post
                assert post['nonce']==batch_nonce and post['session']==self.z_ready['session'],post
                assert post['identity']['pid']==self.z_pid and post['active_attempts']==0,post
                assert set(post['identity']['fds'])==set(self.z_ready['identity']['fds']),('Z FD leak',post)
            finally:
                for fd in fds:os.close(fd)
            cost.span('rpc_batch_ping',check_start)
            router_evidence=self.router.evidence();self.router.close()
            restored_fds=fd_inventory();assert restored_fds==baseline_fds,('R FD identity set changed',baseline_fds,restored_fds)
            batch={'status':'PASS','batch_nonce':batch_nonce,'session':self.z_ready['session'],'width':self.width,
                   'zygote_pid':self.z_pid,'requests':len(completed),'template_post':post,
                   'domain_contract':'fresh independent domain, one request per domain','bursts':batch_index+1,
                   'R_fds_before':baseline_fds,'R_fds_after':restored_fds,'actual_R_children_before_Z_stop':actual,
                   'router':router_evidence,'single_R_thread':len(os.listdir('/proc/self/task'))==1,
                   'ownership_registry':self.registry_history,'scope':'per-request resource release plus batch final template integrity; no response committed before this check'}
            assert batch['single_R_thread']
            dump('concurrent-batch-check.json',batch)
            self.rows=[]
            for index,row in sorted(completed):
                cost.context('R',row['nonce'],repeat=index,warmup=False)
                row.update(qualification='PASS',response_committed=True,batch_template_check='PASS',
                           batch_check_file='concurrent-batch-check.json',response_commit_ns=time.monotonic_ns())
                dump('attempt-'+row['nonce']+'.json',row);dump(str(index)+'-'+row['case']+'.json',row)
                self.rows.append(row);cost.record('response_ready',force=True)
                cost.record('numpy_call_complete',force=True,call_index=index,includes_batch_integrity_wait=True)
            self.stop_z();self.reap();assert self.nochildren
            dump('summary.json',{'all_passed':True,'case':os.environ.get('RELIABILITY_CASE','control'),
                 'architecture_group':'G2','execution_mode':'G2_CONCURRENT','concurrency':self.width,
                 'one_zygote_pid':self.z_pid,'request_count':len(self.rows),'batch_check':batch,
                 'rows':[{k:r.get(k) for k in ('case','nonce','outcome','business','s_state','w_state','resources','qualification','zygote_pid','response_committed')} for r in self.rows],
                 'controller_echild':self.nochildren,'wait_records':self.wait_records,'performance_benchmark':False})
            self.rpc_supervisor({'op':'DONE'});cost.context('R');cost.record('session_end',force=True)
            cost.usage('controller_final_usage');cost.memory('controller_final_memory')
        except BaseException:
            event({'event':'CONCURRENT_BATCH_ABORT','active':sorted(self.active_nonces),
                   'completed_uncommitted':[r['nonce'] for _,r in completed],
                   'business_result':'UNKNOWN_UNLESS_TRUE_WAIT_RECORDED','cleanup_owner':'surviving H; never observer'})
            if self.router:self.router.close()
            raise
