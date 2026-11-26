"""G4 controller mixin for the explicitly trusted persistent-function contract.

No per-request process wait, cgroup-empty or whole-domain release is invented.
Domain/PID1 completion belongs to run_local.Controller.close_domain().
"""
import os,time,json,socket,select,signal,hashlib,shutil
from run import O,dump,event,empty,signal_stable,fdcount
from common import recv
import runtime_support as runtime
import cost


class G4Mixin:
    def request_g4(self,case):
        d=self.local;n=len(self.rows);nonce=os.urandom(16).hex()
        cost.context('R',nonce,repeat=n,warmup=False);cost.record('request_begin',force=True);cost.usage('request_cpu_begin')
        beforefd=fdcount();workspace_reset=self.reset_workspace()
        rd,wr=os.pipe2(os.O_CLOEXEC);os.set_blocking(rd,False)
        modes={'normal':'normal','nonzero':'nonzero','result_loss_side_effect':'normal','reset_failure':'normal','fd_leak':'normal'}
        req=dict(mode=modes.get(case,'hang'),fault=case,target_ns=d['target_ns'],root_identity=d['root_identity'],
                 business_cgroup=str(d['template']).removeprefix('/sys/fs/cgroup'),numpy_baseline='hot',numpy_persistent=True,
                 numpy_level=os.environ.get('NP_LEVEL','blas'),numpy_case=os.environ.get('NP_CASE','normal'),
                 full_profile=os.environ.get('FULL_PROFILE','legacy'),numpy_output_name='numpy-output-'+nonce+'.npz',
                 repeat=n,warmup=False,test_descendant=os.environ.get('ARCH_TEST_DESCENDANT','1')=='1')
        row=dict(group='G4',case=case,nonce=nonce,domain_nonce=d['nonce'],domain_scope='PERSISTENT_HELD',
                 business='NOT_EXECUTED',business_permit=False,admission='OPEN',w_state='RETAINED',s_state='NOT_APPLICABLE',
                 w_wait=None,result=None,worker=None,failure=None,events=[],output_eof=False,
                 resources='RETAINED_WORKER_AND_DOMAIN',resources_removed=False,domain_empty=False,
                 workspace_reset=workspace_reset,workspace_contract='fixed trusted function, same subject/workspace; explicit state reset',
                 request_completion_contract='known function return + reset + pipe EOF; actual W wait only at final domain teardown',
                 target_ns=d['target_ns'],root_identity=d['root_identity'],w_pid=d['zpid'],
                 controller_fd_before=beforefd,limits={k:{q:(p/q).read_text() for q in ('cpu.max','memory.max','pids.max')}
                 for k,p in [('task',d['cg']),('business_persistent',d['template'])]})
        dump('attempt-'+nonce+'.json',row)
        self.zsend('PREPARE',nonce,[wr],**req);os.close(wr)
        out=b'';zs_open=True;sealed=False;cancel_count=0;cancel_acks=0;canceldeadline=None;business_at=None;latepermit=False
        deadline=time.monotonic()+8;nextquery=time.monotonic()+.12
        def seal(reason,twice=False):
            nonlocal cancel_count,canceldeadline
            row['failure']=row['failure'] or reason
            if not cancel_count:
                row['admission']='REVOKING';self.zsend('CANCEL',nonce);cancel_count+=1;canceldeadline=time.monotonic()+.5
            if twice:self.zsend('CANCEL',nonce);cancel_count+=1
        while True:
            self.drain_domain();self.reap()
            if time.monotonic()>deadline:raise TimeoutError('persistent request unresolved; H must recover')
            if d['mon'] in self.waited or not (d['control']/'cgroup.procs').read_text().split():
                d['dead']=True;zs_open=False;sealed=True;row['admission']='SEALED_CREATOR_STOPPED'
                row['failure']=row['failure'] or 'DOMAIN_DIED';row['w_state']='RECLAIMED_PENDING_DOMAIN_WAIT'
            if canceldeadline and time.monotonic()>canceldeadline and (not sealed or cancel_acks<cancel_count):
                signal_stable(d['initfd'],signal.SIGKILL);canceldeadline=None
            ready,_,_=select.select([rd]+([d['zs']] if zs_open else []),[],[],.01)
            for channel in ready:
                if channel==rd:
                    while True:
                        try:data=os.read(rd,65536)
                        except BlockingIOError:break
                        if not data:row['output_eof']=True;break
                        out+=data
                    continue
                try:obj,fds,cred=recv(channel)
                except (EOFError,ConnectionResetError,BrokenPipeError):
                    zs_open=False;row['failure']=row['failure'] or 'WORKER_CHANNEL_LOST';signal_stable(d['initfd'],signal.SIGKILL);continue
                for fd in fds:os.close(fd)
                if fds:raise RuntimeError('persistent Worker sent unexpected FD')
                if obj.get('nonce')!=nonce:
                    row['events'].append(dict(event='OTHER_ATTEMPT_MESSAGE',message=obj));continue
                assert cred and cred[0]==d['zpid'] and cred[1:]==(65534,65534)
                row['events'].append(obj);event(dict(event='LOCAL_REQUEST_MESSAGE',nonce=nonce,channel='PERSISTENT_W',message=obj,credentials=cred))
                kind=obj.get('event')
                if kind=='PERSISTENT_GATED':
                    assert obj['identity']['ns']==d['target_ns']
                    assert str(d['zpid']) in (d['template']/'cgroup.procs').read_text().split()
                    assert all(runtime.check_candidate_mappings(obj['maps']).values())
                    assert set(obj['identity']['fds'])<={'0','1','2'}
                    row['gated']=obj
                    event(dict(event='LOCAL_WORKER_BIND',nonce=nonce,domain_nonce=d['nonce'],host_pid=d['zpid'],credentials=cred,
                               worker_local_pid=obj['identity']['pid'],parent_local=obj['identity']['ppid'],
                               business_members=(d['template']/'cgroup.procs').read_text().split(),reused=True))
                    if case=='controller_during_entry':os.kill(os.getpid(),signal.SIGKILL)
                    if case in ('cancel_queued','cancel_before_business','double_cancel'):
                        seal('CANCELLED',case=='double_cancel');continue
                    row['business_permit']=True;row['business']='UNKNOWN';dump('attempt-'+nonce+'.json',row)
                    self.zsend('RUN_BUSINESS',nonce);business_at=time.monotonic()
                elif kind=='CANCEL_ACK':
                    cancel_acks+=1;sealed=True;row['admission']='SEALED'
                    if obj['state']=='NOT_EXECUTED':row['business']='NOT_EXECUTED'
                    if case=='cancel_queued' and not latepermit:self.zsend('RUN_BUSINESS',nonce);latepermit=True
                elif kind=='START_REJECTED':row['late_start_rejected']=True
                elif kind=='REQUEST_COMPLETE' or (kind=='PERSISTENT_SNAPSHOT' and obj.get('result_known')):
                    assert obj['sealed'] and obj['reset'] and obj['reset']['wait_echild']
                    row['result']={'return_code':obj['return_code'],'source':'PERSISTENT_FUNCTION_RETURN','process_exit':False}
                    row['business']='KNOWN';row['reset']=obj['reset'];row['admission']='SEALED';sealed=True
                elif kind=='PERSISTENT_SNAPSHOT' and case=='result_loss_side_effect' and obj['state']=='COMPLETED':
                    row['failure']='RESULT_UNKNOWN';row['business']='UNKNOWN';signal_stable(d['initfd'],signal.SIGKILL)
            if business_at:
                elapsed=time.monotonic()-business_at
                if case=='controller_death' and elapsed>.04:os.kill(os.getpid(),signal.SIGKILL)
                if case in ('pid1_death','zygote_death') and elapsed>.04:
                    if case=='zygote_death':signal_stable(d['zpidfd'],signal.SIGKILL)
                    signal_stable(d['initfd'],signal.SIGKILL)
                if case=='control_eof' and elapsed>.04 and zs_open:
                    d['zs'].close();zs_open=False;row['failure']='CONTROL_EOF';signal_stable(d['initfd'],signal.SIGKILL)
                if case=='timeout' and elapsed>.08 and not cancel_count:seal('TIMEOUT')
            if zs_open and time.monotonic()>nextquery:
                self.zsend('QUERY',nonce);nextquery=time.monotonic()+.12
            if d['dead'] and row['output_eof'] and empty(d['cg']):break
            if sealed and cancel_acks>=cancel_count and row['output_eof'] and (row['result'] is not None or row['business']=='NOT_EXECUTED'):
                if case!='cancel_queued' or row.get('late_start_rejected'):break
        if not d['dead']:
            self.zsend('FORGET',nonce);forgot,_=self.wait_message(d['zs'],'PERSISTENT_FORGOTTEN',nonce)
            assert forgot['active_requests']==0 and forgot['sealed'];row['persistent_after']=forgot
            if case in ('cancel_queued','double_cancel'):
                self.zsend('CANCEL',nonce);old,_=self.wait_message(d['zs'],'STALE_REJECTED',nonce)
                row['late_cancel_rejected']=old
        else:
            row['resources']='PENDING_FINAL_DOMAIN_WAIT';row['domain_empty']=empty(d['cg'])
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
        row['outcome']=row['failure'] or ('SUCCEEDED' if row['result']['return_code']==0 else 'NONZERO_RETURN')
        os.close(rd);row['controller_fd_after']=fdcount();row['cancel_ack_count']=cancel_acks
        assert row['controller_fd_after']==beforefd-(1 if case=='control_eof' else 0) and row['output_eof']
        if row['worker']:assert len(row['worker']['checks'])==19 and all(row['worker']['checks'].values())
        if case in ('normal','nonzero'):
            assert not d['dead'] and row['failure'] is None and row['result']['return_code']==(7 if case=='nonzero' else 0) and row['worker']
        elif case=='double_cancel':assert cancel_acks>=2 and row['business']=='NOT_EXECUTED'
        elif case=='reset_failure' or case=='fd_leak':assert d['dead'] and row['business']=='UNKNOWN' and row['result'] is None
        elif case=='result_loss_side_effect':assert d['dead'] and row['business']=='UNKNOWN' and row['result'] is None and row['side_effect']
        row.update(qualification='PASS',response_committed=True)
        dump('attempt-'+nonce+'.json',row);dump(f'{n}-{case}.json',row);self.rows.append(row)
        cost.record('response_ready',force=True,contract='retained Worker fixed-function response; no process release')
        cost.usage('request_cpu_end');return row
