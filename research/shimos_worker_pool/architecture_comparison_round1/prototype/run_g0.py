"""G0 candidate: a fresh, domain-local D-Python per request; no external Z/S.

Reuses the frozen H contract and R utility methods, not the cross-domain state
machine. The domain PID1 serializes START/CANCEL and really waits its child.
Not admitted until independent VM qualification, including failure paths.
"""
import os, time, json, socket, array, fcntl, stat, select, signal, hashlib, shutil
from pathlib import Path
from run import (Controller as BaseController, R, P, O, CG, event, dump, writecg,
                 empty, stats, killcg, signal_stable, fdcount)
from common import send, recv
import runtime_support as runtime
import cost
import numpy_workload as NW


class Controller(BaseController):
    def bwrap(self, work, nonce):
        args = super().bwrap(work, nonce)
        i = args.index('/probe/domain_init')
        args = args[:i]
        # Measured diagnostics may be configured during trusted bootstrap, but
        # the worker clears its environment to the original PATH-only contract.
        for key in ('COST_ENABLED','COST_SESSION','COST_VARIANT','ARCH_DIAGNOSTICS'):
            if key in os.environ: args += ['--setenv', key, os.environ[key]]
        return args + ['/probe/domain_init_g0', nonce, self.g0_case]

    def domain(self, case):
        n = len(self.rows); nonce = os.urandom(16).hex(); self.g0_case = case
        cost.context('R', nonce, repeat=n, warmup=n<int(os.environ.get('COST_WARMUP','0')))
        cost.record('request_begin', force=True); cost.usage('request_cpu_begin')
        cg = CG/('d-'+nonce); work = R/('work-'+nonce)
        row = dict(case=case, nonce=nonce, group='G0', zygote_pid=None, s_state='NOT_APPLICABLE',
                   s_wait=None, w_state='ABSENT', w_wait=None, w_pid=None, worker=None,
                   admission='OPEN', business='NOT_EXECUTED', business_permit=False,
                   resources='PENDING', output_eof=False, result=None, failure=None,
                   events=[], qualification='PENDING', controller_fd_before=fdcount(),
                   wait_start=len(self.wait_records), diagnostics=cost.DIAGNOSTICS,
                   journal_writes=0, journal_updates_buffered=0)

        def journal(force=False):
            if cost.DIAGNOSTICS=='low' and not force:
                row['journal_updates_buffered'] += 1
                cost.record('controller_journal_buffered', kind='diagnostic_policy'); return
            row['journal_writes'] += 1
            t=cost.mark(); dump('attempt-'+nonce+'.json',row); cost.finish('controller_journal',t,forced=force)

        journal(True)
        cost.record('domain_build_begin')
        cg.mkdir(); (cg/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        for k,v in [('memory.max',str(512*1024**2)),('pids.max','256'),('cpu.max','400000 100000')]:
            (cg/k).write_text(v)
        control = writecg(cg/'control'); business = writecg(cg/'business'); work.mkdir()
        if case in ('second_budget','pid_budget'): (business/'pids.max').write_text('0')
        rd,wr = os.pipe2(os.O_CLOEXEC); os.set_blocking(rd,False)
        self.rpc_supervisor({'op':'REGISTER','nonce':nonce,'cgroup':str(cg),'workspace':str(work)},[rd])
        ds,ch = socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        ds.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1); ds.settimeout(5)
        log = (O/f'{n}-{case}-bwrap.log').open('wb'); argv = self.bwrap(work,nonce)
        cost.record('bwrap_spawn_begin'); mon,monfd = self.spawn(argv,control,log.fileno(),ch.fileno())
        ch.close(); self.waited.pop(mon,None); cost.record('bwrap_spawn_return')
        ready,export,cred = recv(ds)
        cost.record('domain_fd_received', domain_ready_ns=ready.get('monotonic_ns'), pid1_record=ready)
        assert ready['event']=='DOMAIN_READY' and ready['nonce']==nonce and len(export)==7
        assert cred and cred[1:]==(65534,65534) and str(cred[0]) in (control/'cgroup.procs').read_text().split()
        initpid=cred[0]; initfd=os.pidfd_open(initpid)
        base=fcntl.ioctl(export[1],0xb701); baseino=os.fstat(base).st_ino
        for fd,typ in zip(export,[0x10000000,0x20000,0x20000000,0x40000000,0x08000000,0x04000000]):
            assert fcntl.ioctl(fd,0xb703)==typ
        parent=fcntl.ioctl(export[0],0xb702)
        assert os.fstat(parent).st_ino==baseino; os.close(parent)
        owner=array.array('I',[0]);fcntl.ioctl(base,0xb704,owner,True);assert owner[0]==os.getuid()
        assert stat.S_ISDIR(os.fstat(export[6]).st_mode)
        for fd in export[1:6]:
            q=fcntl.ioctl(fd,0xb701);assert os.fstat(q).st_ino==baseino;os.close(q)
        target_ns={name:f'{name}:[{os.fstat(fd).st_ino}]' for name,fd in zip(['user','mnt','pid','net','ipc','uts'],export)}
        root_identity=[os.fstat(export[6]).st_dev,os.fstat(export[6]).st_ino]
        for fd in [base,*export]:os.close(fd)
        row.update(argv=argv, target_ns=target_ns, root_identity=root_identity,
                   base_userns_inode=baseino, fd_metadata_validated=True,
                   domain_ready_record=ready, init_pid=initpid, monitor_pid=mon,
                   limits={k:{q:(v/q).read_text() for q in ('cpu.max','memory.max','pids.max')}
                           for k,v in [('task',cg),('control',control),('business',business)]})
        cost.record('domain_ready')
        ws,wc=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        ws.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        bc=os.open(business,os.O_RDONLY|os.O_DIRECTORY)
        mode='nonzero' if case=='nonzero' else ('normal' if case in ('normal','second_budget','pid_budget','created_drop','reaped_drop','result_loss_side_effect') else 'hang')
        req=dict(op='BOOTSTRAP',nonce=nonce,mode=mode,target_ns=target_ns,root_identity=root_identity,
                 business_cgroup=str(business).removeprefix('/sys/fs/cgroup'),
                 numpy_baseline='cold',numpy_level=os.environ.get('NP_LEVEL','blas'),
                 numpy_case=os.environ.get('NP_CASE','normal'),repeat=n,
                 warmup=n<int(os.environ.get('COST_WARMUP','0')),
                 test_descendant=os.environ.get('ARCH_TEST_DESCENDANT','1')=='1')
        pending=[bc,wr]; ws_open=True; ds_open=True; stopped=False; sealed=False; seal_sent=False
        start_sent=False; killed=False; cancel_deadline=None; deadline=time.monotonic()+8
        bootstrap_eof_deadline=None
        next_query=time.monotonic()+.12; wpid=None; wpfd=None; faulted=False; business_since=None
        out=b''; outall=b''

        def ds_send(op,fds=()):
            if not ds_open:return False
            t=cost.now(); raw=(op+' '+nonce).encode()
            anc=[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))] if fds else []
            try:ds.sendmsg([raw],anc)
            except OSError:return False
            cost.ipc('send',{'op':op,'nonce':nonce},t,ds.fileno());return True

        def close_pending():
            nonlocal pending
            for f in pending:os.close(f)
            pending=[]; wc.close()

        def start():
            nonlocal start_sent
            assert not start_sent and not seal_sent
            row['admission']='COMMITTED';row['w_state']='POSSIBLE';journal(True)
            send(ws,req)
            if not ds_send('START_WORKER',[bc,wc.fileno(),wr]):raise RuntimeError('G0 start channel lost')
            start_sent=True;cost.record('start_worker_sent');close_pending()

        def seal(reason):
            nonlocal seal_sent,cancel_deadline
            if seal_sent:return
            seal_sent=True;row['admission']='SEALED' if sealed else 'REVOKING'
            row['seal_reason']=reason;journal(True)
            ds_send('CANCEL');cancel_deadline=time.monotonic()+.5

        def fail(reason,twice=False):
            if not row['failure']:row['failure']=reason
            seal(reason)
            if twice:ds_send('CANCEL')
            event({'event':'CANCEL_REQUEST','nonce':nonce,'reason':reason,'count':2 if twice else 1});journal(True)

        ds.setblocking(False);ws.setblocking(False)
        if case=='cancel_queued':
            fail('CANCELLED');close_pending()
        else:start()
        while True:
            self.reap()
            if mon in self.waited and not stopped and not row['failure']:fail('DOMAIN_LOST')
            # A real monitor wait plus empty control proves that PID1, the only
            # creator in G0, can no longer create W. Empty business alone does not.
            if mon in self.waited and empty(control):
                sealed=True;row['admission']='SEALED_CREATOR_WAITED'
            duplicate_pending = case=='double_cancel' and row.get('cancel_acks',0)<2
            if cancel_deadline and (not sealed or duplicate_pending) and time.monotonic()>cancel_deadline:
                event({'event':'REVOKE_ACK_TIMEOUT','nonce':nonce})
                signal_stable(initfd,signal.SIGKILL);cancel_deadline=None
            if (bootstrap_eof_deadline and not row['failure']
                    and time.monotonic()>bootstrap_eof_deadline):
                fail('BOOTSTRAP_CHANNEL_LOST');bootstrap_eof_deadline=None
            if (row['failure'] and sealed and not killed
                    and (case!='cancel_queued' or row.get('late_start_rejected'))
                    and (not duplicate_pending or row['admission']=='SEALED_CREATOR_WAITED')):
                killcg(cg);killed=True
            if time.monotonic()>deadline:
                row['resources']='INCOMPLETE';row['failure']=row['failure'] or 'DEADLINE';journal(True)
                raise TimeoutError(row)
            reads=([ds] if ds_open else [])+([ws] if ws_open else [])+([rd] if not row['output_eof'] else [])
            t=cost.mark();readable,_,_=select.select(reads,[],[],.01);cost.finish('controller_poll',t,ready_count=len(readable))
            for item in readable:
                if item==rd:
                    data=os.read(rd,65536)
                    if not data:
                        row['output_eof']=True;cost.record('output_eof');event({'event':'OUTPUT_EOF','nonce':nonce});continue
                    out+=data;outall+=data
                    while b'\n' in out:
                        line,out=out.split(b'\n',1)
                        try:m=json.loads(line)
                        except ValueError:continue
                        if m.get('event')=='WORKER_READY' and m.get('nonce')==nonce:
                            row['worker']=m;business_since=time.monotonic();event(m)
                            if not all(m['checks'].values()):fail('BUSINESS_CHECK_FAILED')
                            if not faulted and case in ('controller_death','pid1_death','cancel','double_cancel'):
                                faulted=True;journal(True);event({'event':'FAULT','case':case,'nonce':nonce})
                                if case=='controller_death':os.kill(os.getpid(),signal.SIGKILL)
                                elif case=='pid1_death':signal_stable(initfd,signal.SIGKILL)
                                else:fail('CANCELLED',case=='double_cancel')
                    continue
                try:m,fs,peer=recv(item)
                except (EOFError,ConnectionResetError,BrokenPipeError) as error:
                    event({'event':'G0_CHANNEL_CLOSED','nonce':nonce,
                           'role':'PID1' if item==ds else 'Worker',
                           'error':repr(error),'business_permit':row['business_permit']})
                    if item==ds:
                        ds_open=False
                        if not stopped and not row['failure']:fail('DOMAIN_CHANNEL_LOST')
                    else:
                        ws_open=False
                        # Worker closes this gate channel before business. It is
                        # not a result channel: PID1's real wait is authoritative.
                        if not row['business_permit'] and not row['failure']:
                            # EOF and PID1's rejection/wait cross different
                            # sockets. A rejected clone closes the passed FD too;
                            # do not turn EAGAIN into a fabricated worker death.
                            row['bootstrap_eof_before_permit']=True
                            bootstrap_eof_deadline=time.monotonic()+.5
                            ds_send('QUERY')
                    continue
                typ=m.get('event');row['events'].append(m);event(m)
                try:
                    assert m.get('nonce')==nonce,m
                    if item==ws:
                        assert not fs and peer and peer[1:]==(65534,65534),m
                        if typ=='WORKER_GATED':
                            wpid=peer[0];row['w_pid']=wpid;row['worker_local_pid']=m['pid_local']
                            membership=(business/'cgroup.procs').read_text().split()
                            assert str(wpid) in membership and m['identity']['ns']==target_ns
                            assert m['final_security_installed'] and not m['numpy_loaded']
                            runtime.check_candidate_mappings(m['maps'])
                            row['worker_gated']=m;row['w_state']='CREATED_GATED'
                            if wpfd is None:wpfd=os.pidfd_open(wpid)
                            bound={'event':'G0_WORKER_BIND','nonce':nonce,'host_pid':wpid,
                                   'pid_local':m['pid_local'],'parent_local':m['identity']['ppid'],
                                   'credentials':list(peer),'business_cgroup_members':membership,
                                   'business_cgroup':str(business),'monotonic_ns':time.monotonic_ns()}
                            row['worker_binding']=bound;event(bound);cost.record('worker_gated')
                            row['numpy_memory_gated']={'clock':'CLOCK_MONOTONIC','nonce':nonce,
                                'start_ns':time.monotonic_ns(),'samples':{'W':NW.memory(wpid),'R':NW.memory(os.getpid())}}
                            if case in ('cancel_before_business','cancel_during_entry','revoke_ack_loss'):
                                fail('CANCELLED')
                            elif case=='control_eof':
                                ws.close();ws_open=False;fail('STATUS_CHANNEL_LOST')
                            elif not row['failure']:
                                row['business_permit']=True;row['business']='UNKNOWN';journal(True)
                                send(ws,{'op':'RUN_BUSINESS','nonce':nonce});cost.record('business_permission_sent')
                        elif typ=='WORKER_BOOTSTRAP_ERROR':fail('WORKER_BOOTSTRAP_ERROR')
                        else:raise RuntimeError(('G0 unknown worker message',m))
                        continue
                    assert peer and peer[0]==initpid and peer[1:]==(65534,65534),('PID1 identity',peer)
                    if typ=='WORKER_CREATED':
                        assert len(fs)==1,m
                        if wpfd is None:wpfd=fs.pop(0)
                        row['worker_creation']=m
                        if row['w_state']!='REAPED':row['w_state']='CREATED'
                        if case=='controller_during_entry':journal(True);os.kill(os.getpid(),signal.SIGKILL)
                    elif typ=='WORKER_REJECTED':
                        row['w_state']='ABSENT';row['business']='NOT_EXECUTED';row['worker_errno']=m['errno']
                        sealed=True;row['admission']='SEALED';fail('RESOURCE_REJECTED')
                    elif typ in ('SNAPSHOT','CANCEL_ACK'):
                        if m['sealed']:sealed=True;row['admission']='SEALED'
                        if not start_sent or m['w_state']=='ABSENT':row['w_state']='ABSENT'
                        if m.get('wait_known'):
                            row['w_wait']={**m,'event':'G0_WORKER_WAITED','source':'PID1_QUERY_REAL_WAIT'}
                            row['w_state']='REAPED';row['business']='KNOWN' if row['business_permit'] else 'NOT_EXECUTED'
                        elif m['w_state']=='REAPED':row['w_state']='REAPED_STATUS_UNKNOWN'
                        if typ=='CANCEL_ACK':
                            row['cancel_acks']=row.get('cancel_acks',0)+1
                            if case=='cancel_queued' and not row.get('late_start_sent'):
                                row['late_start_sent']=True;ds_send('START_WORKER')
                    elif typ=='WORKER_WAITED':
                        row['w_wait']={**m,'event':'G0_WORKER_WAITED'};row['w_state']='REAPED'
                        row['business']='KNOWN' if row['business_permit'] else 'NOT_EXECUTED'
                        event({'event':'G0_WORKER_WAITED','nonce':nonce,'pid1_host_pid':initpid,
                               'worker_local_pid':m['worker_local_pid'],'worker_host_pid':wpid,
                               'raw_wait_status':m['wait_status'],'exit_code':m['exit_code']})
                        cost.record('worker_waited')
                        if not row['business_permit'] and not row['failure']:
                            fail('BOOTSTRAP_EXIT_WITHOUT_PERMISSION')
                    elif typ=='START_REJECTED':
                        assert m['sealed'];row['late_start_rejected']=True
                    elif typ=='DRAINED':
                        assert m['echild'];row['drained']=m;cost.record('pid1_drained',pid1_record=m)
                    elif typ in ('PROTOCOL_ERROR','STOP_REJECTED'):fail(typ)
                    else:raise RuntimeError(('G0 unknown PID1 message',m))
                finally:
                    for fd in fs:os.close(fd)
                journal()
            if business_since and case=='timeout' and not faulted and time.monotonic()-business_since>.08:
                faulted=True;fail('TIMED_OUT')
            if not stopped and ds_open and time.monotonic()>=next_query:
                ds_send('QUERY');next_query=time.monotonic()+.12
            self.reap()
            if row['w_wait'] and not row['business_permit'] and not row['failure']:
                fail('BOOTSTRAP_EXIT_WITHOUT_PERMISSION')
            if row['w_state']=='REAPED_STATUS_UNKNOWN' and row['business_permit'] and not row['failure']:
                fail('RESULT_UNKNOWN')
            if row['w_wait'] and row['output_eof'] and empty(business) and not row['failure']:
                seal('COMPLETE')
                if sealed and not stopped:
                    if ds_send('STOP'):stopped=True
            if row['failure'] and not seal_sent:seal(row['failure'])
            if (mon in self.waited and empty(cg) and sealed and row['output_eof'] and not ws_open
                    and (row['failure'] or row.get('drained'))
                    and (case!='cancel_queued' or row.get('late_start_rejected'))):
                children=Path(f'/proc/self/task/{os.getpid()}/children').read_text().split()
                if not children:
                    row['children_at_release']=[]
                    if row['w_state'] not in ('ABSENT','REAPED','REAPED_STATUS_UNKNOWN'):
                        row['w_state']='RECLAIMED_STATUS_UNKNOWN'
                    break
        cost.record('domain_quiescent')
        row['monitor_wait']=self.waited[mon];row['wait_records']=self.wait_records[row['wait_start']:]
        row['stats']={k:stats(v) for k,v in [('task',cg),('control',control),('business',business)]}
        row['domain_empty']=empty(cg)
        row['side_effect']=(work/'result').read_text() if (work/'result').exists() else None
        if row['w_wait'] is not None:row['result']={'exit_code':row['w_wait']['exit_code'],'source':row['w_wait']['source']}
        row['outcome']=row['failure'] or ('SUCCEEDED' if row['result']['exit_code']==0 else 'NONZERO')
        if row['failure'] and row['business_permit'] and row['w_wait'] is None:row['business']='UNKNOWN'
        for fd in [rd,initfd,monfd,wpfd]:
            if fd is not None:os.close(fd)
        ds.close();ws.close();log.close()
        if (work/'numpy-output.npz').is_file():
            target=O/f'{n}-{case}-numpy-output.npz';shutil.copyfile(work/'numpy-output.npz',target)
            row['numpy_output']={'file':target.name,'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}
        (O/f'{n}-{case}-output.log').write_bytes(outall)
        t=cost.mark()
        for path in (business,control,cg):path.rmdir()
        cost.finish('cgroup_delete',t)
        t=cost.mark();shutil.rmtree(work);cost.finish('workspace_delete',t)
        row['resources_removed']=not cg.exists() and not work.exists();row['resources']='RELEASED'
        cost.record('resources_deleted');row['controller_fd_after']=fdcount()
        assert row['controller_fd_after']==row['controller_fd_before'],row
        journal(True);self.validate(row);cost.record('validation_done')
        self.rpc_supervisor({'op':'RETIRE','nonce':nonce,'outcome':row['outcome'],'output_eof':row['output_eof']})
        row['qualification']='PASS';row['response_committed']=True;journal(True)
        dump(f'{n}-{case}.json',row);self.rows.append(row)
        cost.record('response_ready',force=True);cost.usage('request_cpu_end');return row

    def validate(self,row):
        assert row['resources_removed'] and row['output_eof'] and row['domain_empty']
        assert row['admission'].startswith('SEALED') and row['controller_fd_before']==row['controller_fd_after']
        if row['worker']:
            assert len(row['worker']['checks'])==19 and all(row['worker']['checks'].values())
            assert all(row['worker']['numpy']['checks'].values())
            assert row.get('numpy_output',{}).get('sha256')==row['worker']['numpy']['output_sha256']
        c=row['case']
        if c in ('normal','nonzero','created_drop','reaped_drop'):
            assert not row['failure'] and row['monitor_wait']==0 and row.get('drained') and row['worker'],row
            assert row['result']['exit_code']==(7 if c=='nonzero' else 0),row
        elif c in ('second_budget','pid_budget'):
            assert row['failure']=='RESOURCE_REJECTED' and row['worker_errno']==11
            assert row['w_state']=='ABSENT' and row['business']=='NOT_EXECUTED' and row['side_effect'] is None
        elif c in ('cancel_before_business','cancel_during_entry','cancel_queued','revoke_ack_loss'):
            assert row['failure']=='CANCELLED' and row['business']=='NOT_EXECUTED' and row['side_effect'] is None
        else:
            assert row['failure'] and row['outcome']!='SUCCEEDED',row

    def run(self):
        case=os.environ.get('RELIABILITY_CASE','control')
        suites={'control':['normal','normal','nonzero'],
                'budgets':['second_budget','normal'],
                'cancels':['cancel_before_business','double_cancel','timeout','normal'],
                'failures':['pid1_death','control_eof','normal'],
                'receipts':['created_drop','reaped_drop','result_loss_side_effect','normal']}
        if case=='performance':
            suites[case]=['normal']*(int(os.environ.get('COST_REQUESTS','35'))+int(os.environ.get('COST_WARMUP','5')))
        supported={'normal','nonzero','second_budget','pid_budget','created_drop','reaped_drop',
                   'result_loss_side_effect','cancel_before_business','cancel_during_entry','cancel_queued',
                   'revoke_ack_loss','cancel','double_cancel','timeout','controller_death',
                   'controller_during_entry','pid1_death','control_eof','fork_ack_loss','reap_ack_loss','session_deadline'}
        cases=suites.get(case,[case]);assert all(c in supported for c in cases),('G0 unsupported case',case)
        for i,c in enumerate(cases):
            cost.record('numpy_call_begin',force=True,call_index=i,group='G0')
            self.domain(c)
            cost.record('numpy_call_complete',force=True,call_index=i,group='G0')
        self.reap();assert self.nochildren
        dump('summary.json',{'all_passed':True,'group':'G0','case':case,
            'rows':[{k:r.get(k) for k in ('case','nonce','outcome','business','s_state','w_state','resources','qualification','zygote_pid')} for r in self.rows],
            'controller_echild':True,'wait_records':self.wait_records,'performance_benchmark':case=='performance'})
        self.rpc_supervisor({'op':'DONE'});cost.record('session_end',force=True)
        cost.usage('controller_final_usage');cost.memory('controller_final_memory')
