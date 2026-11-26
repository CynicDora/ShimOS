"""G3 concurrency: independent persistent domains, one serial local Z per lane.

One trusted R thread owns all actual monitor waits and H RPCs. No shared
workspace is used concurrently. This static C-lane candidate requires its own
VM qualification; serial G3 qualification alone does not admit concurrency.
"""
import os,time,json,socket,array,fcntl,stat,select,signal,hashlib,shutil
from pathlib import Path
from run import R,P,O,CG,dump,event,writecg,empty,stats,killcg,signal_stable,fdcount
from run_local import Controller as LocalController
from run_concurrent import Controller as WaitOwner,fd_inventory,fd_object
from common import send,recv
import runtime_support as runtime
import cost

SOURCE_LOCAL_SHA256='1c819d195990b263b725d3ddbb744b7960cdc5ce889d001739c1b7d3f9d2905f'
SOURCE_REQUEST_LINES=(115,255)


class Lane(LocalController):
    def __init__(self,manager,lane):
        # No repeated subreaper setup or CPython/native launcher initialization.
        self.manager=manager;self.lane=lane;self.group='G3'
        self.supervisor=manager.supervisor;self.native=manager.native;self.lib=manager.lib
        self.waited=manager.waited;self.wait_records=manager.wait_records;self.nochildren=False
        self.z=None;self.local=None;self.domain_records=[];self.rows=[]
        self.request_index=None;self.request_nonce=None

    def spawn(self,argv,cg,log,fd):
        domain=Path(cg).parent.name
        if not domain.startswith('d-'):raise ValueError('local child outside domain')
        nonce=domain[2:];self.manager.active_nonces.add(nonce)
        return self.manager.spawn_owned(nonce,argv,cg,log,fd)

    def reap(self):
        self.manager.reap();self.nochildren=self.manager.nochildren

    def create_domain_async(self,index):
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
        # Start this local Z, then yield to start/service the other domains.
        # NumPy initialization happens in independent child processes in parallel;
        # R itself remains single-threaded and never calls raw fork from threads.
        ready_deadline=time.monotonic()+8
        while True:
            yield {'phase':'LOCAL_READY_PENDING','domain_nonce':nonce,'domain_index':index}
            self.drain_domain();self.reap()
            if time.monotonic()>ready_deadline:raise TimeoutError('local parallel initialization deadline')
            if mon in self.waited:raise RuntimeError('domain died before LOCAL_READY')
            if not select.select([zs],[],[],0)[0]:continue
            message,ready_fds,zcred=recv(zs)
            for fd in ready_fds:os.close(fd)
            event(dict(event='LOCAL_CONTROL_RECEIVED',channel='Z',message=message,credentials=zcred))
            if message.get('event')=='LOCAL_READY' and message.get('nonce')==nonce:break
            d['pending_messages'].append(message)

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

    def request_g3(self,case):
        d=self.local;n=self.request_index;nonce=self.request_nonce
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
            yield {'phase':'local_request_service','nonce':nonce}
            self.drain_domain();self.reap()
            if time.monotonic()>deadline:raise TimeoutError('local request cleanup exceeded; H must recover')
            if case=='controller_during_entry' and committed:os.kill(os.getpid(),signal.SIGKILL)
            if self.local['mon'] in self.waited or not (d['control']/'cgroup.procs').read_text().split():
                d['dead']=True;zs_open=False;sealed=True;row['admission']='SEALED_CREATOR_STOPPED'
                row['failure']=row['failure'] or 'DOMAIN_DIED';killcg(cg)
            if canceldeadline and time.monotonic()>canceldeadline and (not sealed or cancel_acks<cancel_count):
                signal_stable(d['initfd'],signal.SIGKILL);canceldeadline=None
            handles=[rd]+([ws] if ws_open else [])+([d['zs']] if zs_open else [])
            ready,_,_=select.select(handles,[],[],0)
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
        closed_fds={str(fd):fd_object(fd) for fd in (rd,ws.fileno(),pfd) if fd is not None and fd>=0}
        os.close(rd);ws.close()
        if pfd is not None:os.close(pfd)
        business.rmdir();cg.rmdir();work.rmdir();row['resources_removed']=not cg.exists() and not work.exists()
        row['resources']='RELEASED';row['controller_fd_after']=fdcount();row['cancel_ack_count']=cancel_acks
        row['closed_fd_objects']=closed_fds
        row['owned_fd_close_confirmed']=all(fd_object(int(fd)) is None for fd in closed_fds)
        assert row['owned_fd_close_confirmed']
        row['fd_assertion_scope']='per-request owned endpoints; full R identity set after all domains close'
        assert row['output_eof'] and row['domain_empty'] and row['resources_removed']
        if row['worker']:assert len(row['worker']['checks'])==19 and all(row['worker']['checks'].values())
        if case in ('normal','nonzero','created_drop','reaped_drop'):
            assert row['failure'] is None and row['result']['exit_code']==(7 if case=='nonzero' else 0) and row['worker']
        elif case in ('pid_budget','second_budget'):assert row['failure']=='RESOURCE_REJECTED' and row['worker_errno']==11 and row['business']=='NOT_EXECUTED'
        elif case=='double_cancel':assert cancel_acks>=2 and row['business']=='NOT_EXECUTED'
        self.rpc_supervisor({'op':'RETIRE','nonce':nonce,'outcome':'BATCH_CHECK_PENDING:'+row['outcome'],'output_eof':True})
        row.update(qualification='PENDING_BATCH_FD_CHECK',response_committed=False,execution_resources_complete_ns=time.monotonic_ns())
        dump('attempt-'+nonce+'.json',row);dump(f'{n}-{case}.json',row)
        cost.record('attempt_resources_complete',force=True);cost.usage('request_cpu_end');return row


class Controller(WaitOwner):
    def run(self):
        width=int(os.environ.get('FULL_CONCURRENCY','2'))
        if width not in (1,2,4,8):raise ValueError('fixed C1/C2/C4/C8 candidates')
        if os.environ.get('NP_BASELINE','hot')!='hot':raise ValueError('G3 local Z is warm')
        if int(os.environ.get('COST_WARMUP','0')):raise ValueError('all calls charged; no hidden warmup')
        cases_env=os.environ.get('FULL_CONCURRENT_CASES')
        case=os.environ.get('RELIABILITY_CASE','control')
        allowed={'normal','nonzero','created_drop','reaped_drop','result_loss_side_effect',
                 'cancel_queued','cancel_before_business','double_cancel','timeout',
                 'pid_budget','second_budget','controller_death','controller_during_entry',
                 'zygote_death','pid1_death','control_eof'}
        if cases_env:cases=cases_env.split(',')
        elif case=='performance':cases=['normal']*int(os.environ.get('COST_REQUESTS','16'))
        elif case=='control':cases=['normal']*width
        elif case=='concurrent_mixed':cases=['cancel_before_business','normal','second_budget','normal']
        elif case=='concurrent_cancel':cases=['cancel_queued','normal','double_cancel','normal']
        elif case=='concurrent_receipts':cases=['created_drop','reaped_drop','normal','normal']
        elif case=='concurrent_timeout':cases=['timeout','normal','nonzero','normal']
        else:raise ValueError('explicit local concurrent cases required')
        if not cases or len(cases)%width or any(x not in allowed for x in cases):raise ValueError('complete fixed-size batches required')
        self.supervisor.settimeout(5);before=fd_inventory();completed=[];domains=[]
        batches=[list(enumerate(cases))[i:i+width] for i in range(0,len(cases),width)]
        cost.record('local_concurrent_batch_begin',force=True,width=width,requests=len(cases))
        dump('local-concurrent-plan.json',dict(mode='G3_CONCURRENT',width=width,batches=batches,
             domains=len(cases),requests_per_domain=1,
             resource_budget='same root cdz; all H/R, local Zs and business cgroups included',
             preparation='parallel local Z initialization after serial Bubblewrap/domain-reference bootstrap',
             routing='fixed bursts; every request has a fresh independent domain; not adaptive'))
        try:
            for batch_index,plan in enumerate(batches):
                lanes=[];active={}
                event({'event':'LOCAL_CONCURRENT_BURST_BEGIN','burst':batch_index,'width':width,
                       'domain_contract':'fresh independent domain, one request per domain'})
                for index,request_case in plan:
                    lane=Lane(self,index);lanes.append(lane)
                    nonce=os.urandom(16).hex()
                    if nonce in self.active_nonces|self.retired_nonces:raise RuntimeError('nonce reuse')
                    self.active_nonces.add(nonce);lane.request_index=index;lane.request_nonce=nonce
                    cost.context('R',nonce,repeat=index,warmup=False)
                    cost.record('numpy_call_begin',force=True,call_index=index,lane=index,concurrency=width,
                                scope='includes fresh domain/local-Z preparation and final batch integrity')
                preparing={lane.lane:(lane,lane.create_domain_async(lane.request_index),request_case)
                           for lane,(_,request_case) in zip(lanes,plan)}
                while preparing or active:
                    for lane_id,(lane,builder,request_case) in list(preparing.items()):
                        cost.context('R',lane.local['nonce'] if lane.local else lane.request_nonce,
                                     repeat=lane.request_index,warmup=False)
                        try:next(builder)
                        except StopIteration:
                            del preparing[lane_id]
                            active[lane_id]=(lane,lane.request_g3(request_case))
                            event({'event':'LOCAL_CONCURRENT_REQUEST_ADMITTED','nonce':lane.request_nonce,
                                   'index':lane.request_index,'lane':lane.lane,'domain_nonce':lane.local['nonce'],
                                   'zygote_pid':lane.local['zpid'],'case':request_case})
                    for lane_id,(lane,iterator) in list(active.items()):
                        cost.context('R',lane.request_nonce,repeat=lane.request_index,warmup=False)
                        try:next(iterator)
                        except StopIteration as done:
                            row=done.value
                            if not isinstance(row,dict):raise RuntimeError('local attempt did not return row')
                            completed.append((lane.request_index,row));del active[lane_id]
                            self.active_nonces.remove(lane.request_nonce);self.retired_nonces.add(lane.request_nonce)
                            domain_nonce=lane.local['nonce'];lane.close_domain()
                            self.active_nonces.remove(domain_nonce);self.retired_nonces.add(domain_nonce)
                            domains.extend(lane.domain_records)
                    if preparing or active:select.select([],[],[],.001)
                self.reap();assert self.nochildren
                event({'event':'LOCAL_CONCURRENT_BURST_RESOURCES_RELEASED','burst':batch_index,
                       'actual_R_ECHILD':True,'fresh_domains_next_burst':True})
            after=fd_inventory();assert after==before,('R FD identity set changed',before,after)
            check=dict(status='PASS',mode='G3_CONCURRENT',width=width,request_count=len(completed),
                       single_R_thread=len(os.listdir('/proc/self/task'))==1,R_fds_before=before,R_fds_after=after,
                       controller_echild=self.nochildren,domains=domains,bursts=len(batches),
                       domain_contract='fresh independent domain, one request per domain',
                       ownership_registry=self.registry_history,scope='each local Z single active request; all domains truly closed before final commit')
            assert check['single_R_thread']
            dump('local-concurrent-batch-check.json',check)
            self.rows=[]
            for index,row in sorted(completed):
                cost.context('R',row['nonce'],repeat=index,warmup=False)
                row.update(qualification='PASS',response_committed=True,batch_fd_check='PASS',
                           batch_check_file='local-concurrent-batch-check.json',response_commit_ns=time.monotonic_ns())
                dump('attempt-'+row['nonce']+'.json',row);dump(str(index)+'-'+row['case']+'.json',row)
                self.rows.append(row);cost.record('response_ready',force=True)
                cost.record('numpy_call_complete',force=True,call_index=index,includes_batch_integrity_wait=True)
            dump('summary.json',dict(all_passed=True,group='G3',execution_mode='G3_CONCURRENT',case=case,
                 concurrency=width,controller_echild=True,request_count=len(self.rows),batch_check=check,
                 domains=domains,wait_records=self.wait_records,
                 rows=[{k:r.get(k) for k in ('case','nonce','domain_nonce','outcome','business','w_state','resources','qualification','zygote_pid','response_committed')} for r in self.rows]))
            self.rpc_supervisor({'op':'DONE'});cost.context('R');cost.record('session_end',force=True)
            cost.usage('controller_final_usage');cost.memory('controller_final_memory')
        except BaseException:
            event({'event':'LOCAL_CONCURRENT_BATCH_ABORT','active':sorted(self.active_nonces),
                   'completed_uncommitted':[r['nonce'] for _,r in completed],
                   'business_result':'UNKNOWN_UNLESS_REAL_WAIT_RECORDED','cleanup_owner':'surviving H; never observer'})
            raise
