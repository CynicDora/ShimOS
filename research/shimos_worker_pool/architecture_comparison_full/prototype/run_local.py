"""G3/G4 fixed same-trust persistent-domain experiment Controller.

H still owns real registered d-NONCE/work-NONCE paths. Domain lifetime and
request lifetime are separate, explicit records; a held domain is never called
released merely because one request ended. Only this independent copy is used.
"""
import os, time, json, socket, array, fcntl, stat, select, signal, hashlib, shutil
from pathlib import Path
from run import Controller as BaseController, R, P, O, CG, dump, event, writecg, empty, stats, killcg, signal_stable, fdcount
from common import send, recv
import runtime_support as runtime
import cost
from g4_controller_methods import G4Mixin


class Controller(G4Mixin,BaseController):
    def __init__(self,supervisor):
        super().__init__(supervisor)
        self.group=os.environ.get('FULL_MODE',os.environ.get('ARCH_GROUP','G3'))
        assert self.group in ('G3','G4')
        self.local=None;self.domain_records=[]

    def drain_domain(self):
        d=self.local
        if not d or d['output_eof']:return
        while True:
            try:data=os.read(d['rd'],65536)
            except BlockingIOError:return
            if not data:d['output_eof']=True;return
            d['log'].write(data);d['log'].flush()

    def zsend(self,op,nonce=None,fds=(),**fields):
        d=self.local
        send(d['zs'],dict(op=op,nonce=nonce or d['nonce'],domain_nonce=d['nonce'],**fields),fds)

    def dsend(self,op):
        d=self.local;raw=(op+' '+d['nonce']).encode();t=cost.now()
        d['ds'].send(raw);cost.ipc('send',dict(op=op,nonce=d['nonce']),t,d['ds'].fileno())

    def wait_message(self,channel,wanted,nonce,timeout=8):
        deadline=time.monotonic()+timeout;d=self.local
        while time.monotonic()<deadline:
            self.drain_domain();self.reap()
            readable=select.select([channel],[],[],.01)[0]
            if not readable:
                if d['mon'] in self.waited:raise RuntimeError('domain monitor exited before '+wanted)
                continue
            obj,fds,cred=recv(channel)
            for fd in fds:os.close(fd)
            event(dict(event='LOCAL_CONTROL_RECEIVED',channel='Z' if channel is d['zs'] else 'PID1',message=obj,credentials=cred))
            if obj.get('event')==wanted and obj.get('nonce')==nonce:return obj,cred
            d['pending_messages'].append(obj)
        raise TimeoutError('local wait '+wanted)

    def create_domain(self,index):
        assert self.local is None
        nonce=os.urandom(16).hex();cost.context('R',nonce);cost.record('persistent_domain_begin',force=True,domain_index=index)
        cg=CG/('d-'+nonce);work=R/('work-'+nonce)
        cg.mkdir();(cg/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        for k,v in [('memory.max',str(512*1024**2)),('pids.max','256'),('cpu.max','400000 100000')]: (cg/k).write_text(v)
        control=writecg(cg/'control');template=writecg(cg/'template');work.mkdir()
        rd,wr=os.pipe2(os.O_CLOEXEC);os.set_blocking(rd,False)
        self.rpc_supervisor({'op':'REGISTER','nonce':nonce,'cgroup':str(cg),'workspace':str(work)},[rd])
        ds,ch=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);ds.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        argv=super().bwrap(work,nonce);argv=argv[:argv.index('/probe/domain_init')]
        for key in ('COST_ENABLED','COST_SESSION','COST_VARIANT','ARCH_DIAGNOSTICS','FULL_PROFILE','FULL_COST_MODE'):
            if key in os.environ:argv+=['--setenv',key,os.environ[key]]
        argv+=['/probe/domain_init_local',nonce,self.group]
        cost.record('bwrap_spawn_begin');mon,monfd=self.spawn(argv,control,wr,ch.fileno());ch.close();self.waited.pop(mon,None)
        cost.record('bwrap_spawn_return')
        ready,refs,cred=recv(ds)
        assert ready.get('event')=='DOMAIN_READY' and ready['nonce']==nonce and len(refs)==7
        assert cred and cred[1:]==(65534,65534) and str(cred[0]) in (control/'cgroup.procs').read_text().split()
        base=fcntl.ioctl(refs[1],0xb701);baseino=os.fstat(base).st_ino
        for fd,typ in zip(refs,[0x10000000,0x20000,0x20000000,0x40000000,0x08000000,0x04000000]):assert fcntl.ioctl(fd,0xb703)==typ
        parent=fcntl.ioctl(refs[0],0xb702);assert os.fstat(parent).st_ino==baseino;os.close(parent)
        owner=array.array('I',[0]);fcntl.ioctl(base,0xb704,owner,True);assert owner[0]==os.getuid()
        for fd in refs[1:6]:q=fcntl.ioctl(fd,0xb701);assert os.fstat(q).st_ino==baseino;os.close(q)
        assert stat.S_ISDIR(os.fstat(refs[6]).st_mode)
        ns={name:f'{name}:[{os.fstat(fd).st_ino}]' for name,fd in zip(['user','mnt','pid','net','ipc','uts'],refs)}
        root=[os.fstat(refs[6]).st_dev,os.fstat(refs[6]).st_ino]
        for fd in [base,*refs]:os.close(fd)
        zs,zc=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);zs.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        d=dict(nonce=nonce,index=index,cg=cg,work=work,control=control,template=template,
               rd=rd,output_eof=False,log=(O/f'local-domain-{index}.log').open('wb'),ds=ds,zs=zs,
               mon=mon,monfd=monfd,initpid=cred[0],initfd=os.pidfd_open(cred[0]),target_ns=ns,
               root_identity=root,pending_messages=[],argv=argv,dead=False)
        self.local=d
        cf=os.open(template,os.O_RDONLY|os.O_DIRECTORY)
        ds.sendmsg([('START_LOCAL '+nonce).encode()],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[cf,zc.fileno(),wr]))])
        os.close(cf);zc.close();os.close(wr)
        self.zsend('BOOTSTRAP',group=self.group,numpy_level=os.environ.get('NP_LEVEL','blas'))
        message,zcred=self.wait_message(zs,'LOCAL_READY',nonce)
        assert zcred and zcred[1:]==(65534,65534) and str(zcred[0]) in (template/'cgroup.procs').read_text().split()
        assert message['identity']['ns']==ns and message['identity']['uid']==65534
        assert all(int(message['identity']['status'][k],16)==0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
        assert message['identity']['status']['NoNewPrivs']=='1' and message['identity']['status']['Seccomp']=='2'
        mapping_checks=runtime.check_candidate_mappings(message['maps']);assert all(mapping_checks.values())
        d.update(zpid=zcred[0],zpidfd=os.pidfd_open(zcred[0]),ready=message)
        dump(f'local-domain-{index}-ready.json',dict(domain_nonce=nonce,group=self.group,argv=argv,
             target_ns=ns,root_identity=root,pid1_host=d['initpid'],runtime_host=d['zpid'],ready=message,
             mapping_checks=mapping_checks,registration_scope='whole persistent domain'))
        cost.record('persistent_domain_ready',force=True,domain_index=index)

    def reset_workspace(self):
        d=self.local;before=[]
        for p in d['work'].iterdir():
            if p.is_symlink() or not p.is_file() or not (p.name=='result' or (p.name.startswith('numpy-output-') and p.suffix=='.npz')):
                raise RuntimeError('unexpected persistent-workspace object',str(p))
            before.append(dict(name=p.name,size=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest()));p.unlink()
        assert not list(d['work'].iterdir())
        event(dict(event='PERSISTENT_WORKSPACE_RESET',domain_nonce=d['nonce'],removed=before,empty=True))
        return dict(removed=before,empty=True)

    def request_g3(self,case):
        d=self.local;n=len(self.rows);nonce=os.urandom(16).hex()
        cost.context('R',nonce,repeat=n,warmup=False);cost.record('request_begin',force=True);cost.usage('request_cpu_begin')
        beforefd=fdcount();reset=self.reset_workspace()
        cg=CG/('d-'+nonce);work=R/('work-'+nonce);cg.mkdir();(cg/'cgroup.subtree_control').write_text('+cpu +memory +pids');work.mkdir()
        for k,v in [('memory.max',str(512*1024**2)),('pids.max','256'),('cpu.max','400000 100000')]: (cg/k).write_text(v)
        business=writecg(cg/'business')
        if case in ('second_budget','pid_budget'):(business/'pids.max').write_text('0')
        rd,wr=os.pipe2(os.O_CLOEXEC);os.set_blocking(rd,False)
        self.rpc_supervisor({'op':'REGISTER','nonce':nonce,'cgroup':str(cg),'workspace':str(work)},[rd])
        ws,wc=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);ws.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        cf=os.open(business,os.O_RDONLY|os.O_DIRECTORY)
        mode='nonzero' if case=='nonzero' else ('normal' if case in ('normal','pid_budget','second_budget','created_drop','reaped_drop','result_loss_side_effect') else 'hang')
        req=dict(mode=mode,fault=case,target_ns=d['target_ns'],root_identity=d['root_identity'],
                 business_cgroup=str(business).removeprefix('/sys/fs/cgroup'),numpy_baseline='hot',
                 numpy_level=os.environ.get('NP_LEVEL','blas'),numpy_case=os.environ.get('NP_CASE','normal'),
                 full_profile=os.environ.get('FULL_PROFILE','legacy'),numpy_output_name='numpy-output-'+nonce+'.npz',
                 repeat=n,warmup=False,test_descendant=os.environ.get('ARCH_TEST_DESCENDANT','1')=='1')
        row=dict(group=self.group,case=case,nonce=nonce,domain_nonce=d['nonce'],domain_scope='PERSISTENT_HELD',
                 business='NOT_EXECUTED',business_permit=False,admission='OPEN',w_state='ABSENT',s_state='NOT_APPLICABLE',
                 w_wait=None,result=None,worker=None,failure=None,events=[],output_eof=False,resources='PENDING',
                 workspace_reset=reset,workspace_contract='trusted fixed same-domain workspace; per-attempt H workspace is empty ledger',
                 target_ns=d['target_ns'],root_identity=d['root_identity'],zygote_pid=d['zpid'],
                 controller_fd_before=beforefd,limits={k:{q:(p/q).read_text() for q in ('cpu.max','memory.max','pids.max')}
                 for k,p in [('task',cg),('business',business)]})
        dump('attempt-'+nonce+'.json',row)
        self.zsend('SPAWN',nonce,[cf,wc.fileno(),wr],**req);os.close(cf);wc.close();os.close(wr)
        sealed=False;cancel_count=0;cancel_acks=0;committed=False;ws_open=True;zs_open=True;out=b'';pfd=None;wpid=None;business_at=None
        deadline=time.monotonic()+8;nextquery=time.monotonic()+.12;canceldeadline=None;latecommit=False
        def seal(reason=None,twice=False):
            nonlocal cancel_count,canceldeadline
            if reason and not row['failure']:row['failure']=reason
            if not cancel_count:
                row['admission']='REVOKING';self.zsend('CANCEL',nonce);cancel_count+=1;canceldeadline=time.monotonic()+.5
            if twice:self.zsend('CANCEL',nonce);cancel_count+=1
        while True:
            self.drain_domain();self.reap()
            if time.monotonic()>deadline:raise TimeoutError('local request cleanup exceeded; H must recover')
            if case=='controller_during_entry' and committed:os.kill(os.getpid(),signal.SIGKILL)
            if self.local['mon'] in self.waited or not (d['control']/'cgroup.procs').read_text().split():
                d['dead']=True;zs_open=False;sealed=True;row['admission']='SEALED_CREATOR_STOPPED'
                row['failure']=row['failure'] or 'DOMAIN_DIED';killcg(cg)
            if canceldeadline and time.monotonic()>canceldeadline and (not sealed or cancel_acks<cancel_count):
                signal_stable(d['initfd'],signal.SIGKILL);canceldeadline=None
            handles=[rd]+([ws] if ws_open else [])+([d['zs']] if zs_open else [])
            ready,_,_=select.select(handles,[],[],.01)
            for sock in ready:
                if sock==rd:
                    while True:
                        try:data=os.read(rd,65536)
                        except BlockingIOError:break
                        if not data:row['output_eof']=True;break
                        out+=data
                    continue
                try:obj,fds,cred=recv(sock)
                except (EOFError,ConnectionResetError,BrokenPipeError):
                    if sock is ws:ws_open=False
                    else:zs_open=False;signal_stable(d['initfd'],signal.SIGKILL)
                    continue
                for fd in fds:os.close(fd)
                if obj.get('nonce')!=nonce:
                    row['events'].append(dict(event='OTHER_ATTEMPT_MESSAGE',message=obj));continue
                row['events'].append(obj);event(dict(event='LOCAL_REQUEST_MESSAGE',nonce=nonce,channel='W' if sock is ws else 'Z',message=obj,credentials=cred))
                kind=obj.get('event')
                if sock is ws:
                    if kind!='WORKER_GATED':raise RuntimeError('unexpected local worker message',obj)
                    assert cred and cred[1:]==(65534,65534) and str(cred[0]) in (business/'cgroup.procs').read_text().split()
                    wpid=cred[0];pfd=os.pidfd_open(wpid);row.update(w_pid=wpid,w_state='CREATED',gated=obj)
                    assert obj['identity']['ns']==d['target_ns'];assert obj['identity']['ppid']==d['ready']['identity']['pid']
                    assert all(runtime.check_candidate_mappings(obj['maps']).values())
                    event(dict(event='LOCAL_WORKER_BIND',nonce=nonce,domain_nonce=d['nonce'],host_pid=wpid,
                               credentials=cred,worker_local_pid=obj['pid_local'],parent_local=obj['parent_local'],
                               business_members=(business/'cgroup.procs').read_text().split()))
                    if row['failure'] or cancel_count:continue
                    if case in ('cancel_before_business','double_cancel'):seal('CANCELLED',case=='double_cancel');continue
                    row['business_permit']=True;row['business']='UNKNOWN';dump('attempt-'+nonce+'.json',row)
                    send(ws,{'op':'RUN_BUSINESS','nonce':nonce});ws.close();ws_open=False;business_at=time.monotonic()
                elif kind=='PREPARED':
                    row['w_state']='ABSENT'
                    if case=='cancel_queued':seal('CANCELLED')
                    else:self.zsend('COMMIT',nonce);committed=True
                elif kind=='WORKER_CREATED':row['w_state']='CREATED';row['worker_creation']=obj
                elif kind=='WORKER_REJECTED':
                    assert obj['w_state']=='ABSENT';row.update(failure='RESOURCE_REJECTED',worker_errno=obj['errno'],w_state='ABSENT');seal()
                elif kind in ('WORKER_WAITED','SNAPSHOT','CANCEL_ACK'):
                    row['w_state']=obj['w_state']
                    row['zygote_wait_echild']=obj.get('wait_echild',False)
                    row['descendants_reaped']=obj.get('descendants_reaped',[])
                    if obj.get('wait_known'):
                        row['w_wait']={'wait_status':obj['wait_status'],'exit_code':obj['exit_code'],'source':'LOCAL_Z_REAL_WAIT'}
                        row['result']={'exit_code':obj['exit_code'],'source':'LOCAL_Z_REAL_WAIT'}
                        row['business']='KNOWN' if row['business_permit'] else 'NOT_EXECUTED'
                    if kind=='CANCEL_ACK':
                        cancel_acks+=1;sealed=True;row['admission']='SEALED';killcg(cg)
                        if case=='cancel_queued' and not latecommit:self.zsend('COMMIT',nonce);latecommit=True
                    if obj['w_state']=='REAPED' and not cancel_count:seal()
                elif kind=='START_REJECTED':row['late_commit_rejected']=True
            if business_at:
                elapsed=time.monotonic()-business_at
                if case=='controller_death' and elapsed>.04:os.kill(os.getpid(),signal.SIGKILL)
                if case=='pid1_death' and elapsed>.04:signal_stable(d['initfd'],signal.SIGKILL)
                if case=='zygote_death' and elapsed>.04:signal_stable(d['zpidfd'],signal.SIGKILL);row['failure']='ZYGOTE_DIED';signal_stable(d['initfd'],signal.SIGKILL)
                if case=='control_eof' and elapsed>.04 and zs_open:d['zs'].close();zs_open=False;row['failure']='CONTROL_EOF';signal_stable(d['initfd'],signal.SIGKILL)
                if case=='timeout' and elapsed>.08 and not cancel_count:seal('TIMEOUT')
            if zs_open and time.monotonic()>nextquery:
                self.zsend('QUERY',nonce);nextquery=time.monotonic()+.12
            if sealed and cancel_acks>=cancel_count and row['output_eof'] and empty(cg) and ((row['w_state'] in ('ABSENT','REAPED') and row.get('zygote_wait_echild')) or d['dead']):
                if case!='cancel_queued' or row.get('late_commit_rejected'):break
            if d['dead'] and row['output_eof'] and empty(cg):break
        row['stats']={k:stats(p) for k,p in [('task',cg),('business',business)]};row['domain_empty']=empty(cg)
        if not d['dead']:
            self.zsend('FORGET',nonce);forgot,_=self.wait_message(d['zs'],'FORGOTTEN',nonce)
            assert forgot['state_unchanged'] and forgot['active_requests']==0 and forgot['wait_echild'];row['template_after']=forgot
        else:row['w_state']='RECLAIMED_STATUS_UNKNOWN' if row['w_wait'] is None else 'REAPED'
        for line in out.decode(errors='replace').splitlines():
            try:message=json.loads(line)
            except ValueError:continue
            if message.get('event')=='WORKER_READY' and message.get('nonce')==nonce:row['worker']=message
        (O/f'{n}-{case}-output.log').write_bytes(out)
        output=d['work']/req['numpy_output_name']
        if output.exists():
            target=O/f'{n}-{case}-numpy-output.npz';shutil.copyfile(output,target)
            row['numpy_output']={'file':target.name,'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}
        row['side_effect']=(d['work']/'result').read_text() if (d['work']/'result').exists() else None
        if case=='result_loss_side_effect':row.update(failure='RESULT_UNKNOWN',business='UNKNOWN',result=None)
        if row['failure'] is None and row['result'] is None:row['failure']='RESULT_UNKNOWN'
        row['outcome']=row['failure'] or ('SUCCEEDED' if row['result']['exit_code']==0 else 'NONZERO')
        os.close(rd);ws.close()
        if pfd is not None:os.close(pfd)
        business.rmdir();cg.rmdir();work.rmdir();row['resources_removed']=not cg.exists() and not work.exists()
        row['resources']='RELEASED';row['controller_fd_after']=fdcount();row['cancel_ack_count']=cancel_acks
        assert row['controller_fd_after']==beforefd-(1 if case=='control_eof' else 0)
        assert row['output_eof'] and row['domain_empty'] and row['resources_removed']
        if row['worker']:assert len(row['worker']['checks'])==19 and all(row['worker']['checks'].values())
        if case in ('normal','nonzero','created_drop','reaped_drop'):
            assert row['failure'] is None and row['result']['exit_code']==(7 if case=='nonzero' else 0) and row['worker']
        elif case in ('pid_budget','second_budget'):assert row['failure']=='RESOURCE_REJECTED' and row['worker_errno']==11 and row['business']=='NOT_EXECUTED'
        elif case=='double_cancel':assert cancel_acks>=2 and row['business']=='NOT_EXECUTED'
        self.rpc_supervisor({'op':'RETIRE','nonce':nonce,'outcome':row['outcome'],'output_eof':True})
        row.update(qualification='PASS',response_committed=True);dump('attempt-'+nonce+'.json',row);dump(f'{n}-{case}.json',row);self.rows.append(row)
        cost.record('response_ready',force=True);cost.usage('request_cpu_end');return row

    def close_domain(self):
        d=self.local;assert d
        cost.context('R',d['nonce']);cost.record('persistent_domain_stop_begin',force=True)
        if not d['dead']:
            self.zsend('STOP');self.wait_message(d['zs'],'ZYGOTE_STOP',d['nonce'])
            self.wait_message(d['ds'],'LOCAL_WAITED',d['nonce'])
            self.dsend('CANCEL');self.wait_message(d['ds'],'CANCEL_ACK',d['nonce'])
            self.dsend('STOP');drained,_=self.wait_message(d['ds'],'DRAINED',d['nonce'])
            assert drained.get('echild')
        else:drained=None;killcg(d['cg'])
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            self.reap();self.drain_domain()
            if d['mon'] in self.waited and empty(d['cg']) and d['output_eof']:break
            time.sleep(.005)
        assert d['mon'] in self.waited and empty(d['cg']) and d['output_eof']
        if not d['dead']:assert self.waited[d['mon']]==0
        record=dict(domain_nonce=d['nonce'],group=self.group,output_eof=d['output_eof'],drained=drained,
                    monitor_wait=self.waited[d['mon']],domain_empty=True,stats={k:stats(v) for k,v in [('domain',d['cg']),('control',d['control']),('template',d['template'])]},
                    init_pid=d['initpid'],runtime_pid=d['zpid'],dead=d['dead'])
        for fd in (d['rd'],d['monfd'],d['initfd'],d['zpidfd']):os.close(fd)
        d['ds'].close();d['zs'].close();d['log'].close()
        d['template'].rmdir();d['control'].rmdir();d['cg'].rmdir();shutil.rmtree(d['work'])
        self.rpc_supervisor({'op':'RETIRE','nonce':d['nonce'],'outcome':'DOMAIN_RETIRED' if not d['dead'] else 'UNKNOWN','output_eof':True})
        record['resources_removed']=not d['cg'].exists() and not d['work'].exists();record['resources']='RELEASED'
        dump(f'local-domain-{d["index"]}-released.json',record);self.domain_records.append(record);self.local=None
        cost.record('persistent_domain_released',force=True)

    def run(self):
        case=os.environ.get('RELIABILITY_CASE','control')
        suites={'control':['normal','normal','nonzero'],'budgets':['second_budget','normal'],
                'cancels':['cancel_queued','cancel_before_business','double_cancel','timeout','normal'],
                'receipts':['created_drop','reaped_drop','result_loss_side_effect','normal']}
        explicit=os.environ.get('FULL_LOCAL_BATCHES_JSON')
        if explicit:
            batches=json.loads(explicit)
            allowed={'normal','nonzero','cancel_queued','cancel_before_business','double_cancel','timeout',
                     'controller_death','controller_during_entry','pid1_death','zygote_death','control_eof',
                     'result_loss_side_effect','session_deadline'}
            allowed|={'second_budget','pid_budget','created_drop','reaped_drop'} if self.group=='G3' else {'reset_failure','fd_leak'}
            assert isinstance(batches,list) and batches and all(isinstance(b,list) and b and all(isinstance(x,str) and x in allowed for x in b) for b in batches)
        elif case=='performance':
            domains=int(os.environ.get('FULL_DOMAINS','1'));per=int(os.environ.get('FULL_PER_DOMAIN',os.environ.get('COST_REQUESTS','1')))
            batches=[['normal']*per for _ in range(domains)]
        else:batches=[suites.get(case,[case])]
        dump('local-case-plan.json',dict(group=self.group,case=case,batches=batches,
             explicitly_configured=bool(explicit),domain_replaced_after_fault=True))
        for domain_index,cases in enumerate(batches):
            cost.record('domain_group_begin',force=True,domain_index=domain_index)
            self.create_domain(domain_index)
            for request_case in cases:
                cost.record('numpy_call_begin',force=True,call_index=len(self.rows))
                if self.group=='G3':self.request_g3(request_case)
                else:self.request_g4(request_case)
                cost.record('numpy_call_complete',force=True,call_index=len(self.rows)-1)
                if self.local['dead']:break
            self.close_domain();cost.record('domain_group_complete',force=True,domain_index=domain_index)
        self.reap();assert self.nochildren
        dump('summary.json',dict(all_passed=True,group=self.group,case=case,controller_echild=True,
             rows=[{k:r.get(k) for k in ('case','nonce','domain_nonce','outcome','business','w_state','resources','qualification','zygote_pid')} for r in self.rows],
             domains=self.domain_records,wait_records=self.wait_records))
        self.rpc_supervisor({'op':'DONE'});cost.record('session_end',force=True)
