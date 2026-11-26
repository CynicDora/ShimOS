"""Fixed trusted domain-local G3/G4 runtime; no scheduler or arbitrary task API.

G3 keeps a clean template, forks through the complete D/CPython wrapper into
the request's business cgroup, and really waits that child. G4 has an explicitly
different persistent-function contract; it never fabricates a per-call exit.
"""
import os, sys, socket, time, json, ctypes, hashlib, select, signal, errno, traceback
from pathlib import Path
from common import send, recv, bridge, identity, close_except
import cost
import runtime_probe as RP
import numpy_workload as NW

DOMAIN, GROUP = sys.argv[1:3]
assert len(DOMAIN)==32 and all(c in '0123456789abcdef' for c in DOMAIN)
assert GROUP in ('G3','G4')
cost.context('LOCAL_Z' if GROUP=='G3' else 'W',DOMAIN)
CTRL=socket.socket(fileno=3)
LIB=bridge('/probe/bridge_d.so')
STATE=bytearray(os.urandom(65536))
LOOKUP={i:i*i+17 for i in range(200)}
STATE_ORIGIN=os.getpid()


def emit(name,nonce=None,**fields):
    print(json.dumps(dict(event=name,nonce=nonce,domain_nonce=DOMAIN,
                          monotonic_ns=time.monotonic_ns(),**fields)),flush=True)


def closefds(fds):
    for fd in fds:
        try:os.close(fd)
        except OSError:pass


def fp():
    return dict(state_sha256=hashlib.sha256(STATE).hexdigest(),state_id=id(STATE),
                state_origin=STATE_ORIGIN,answer=sum(LOOKUP.values()),numpy=NW.fingerprint())


def stable_snapshot(label):
    value=NW.snapshot(label)
    return {k:value[k] for k in ('threads','fds','environment','signals','signal_handlers')}


def read_command(channel,expected,nonce):
    obj,fds,_=recv(channel)
    closefds(fds)
    if fds or obj.get('op')!=expected or obj.get('nonce')!=nonce:
        raise RuntimeError('invalid local runtime command',obj,expected,nonce)
    return obj


def business(req,base,persistent=False):
    nonce=req['nonce'];cost.context('W',nonce,repeat=req['repeat'],warmup=req['warmup'])
    cost.record('business_enter')
    runtime_state=RP.snapshot('LOCAL_W_business',nonce)
    ident=identity();checks={}
    checks['marker']=Path('/tmp/domain-token').read_text()==DOMAIN
    checks['memory_state']=id(STATE)==base['state_id'] and hashlib.sha256(STATE).hexdigest()==base['state_sha256']
    checks['state_origin']=STATE_ORIGIN==os.getpid() if persistent else STATE_ORIGIN!=os.getpid()
    checks['no_host_path']=not Path('/state').exists() and not Path('/evidence').exists()
    checks['no_other_workspace']=not Path('/work/other-domain-secret').exists()
    try:Path('/src/input').write_text('bad');checks['readonly']=False
    except OSError as e:checks['readonly']=e.errno==errno.EROFS
    Path('/work/result').write_text(str(sum(LOOKUP.values())))
    checks['writable']=Path('/work/result').read_text()==str(sum(i*i+17 for i in range(200)))
    libc=ctypes.CDLL(None,use_errno=True);fd=os.open('/proc/self/ns/mnt',os.O_RDONLY)
    checks['setns_denied']=libc.setns(fd,0)==-1 and ctypes.get_errno()==errno.EPERM;os.close(fd)
    checks['unshare_denied']=libc.unshare(0x10000000)==-1 and ctypes.get_errno()==errno.EPERM
    try:os.chroot('/');checks['chroot_denied']=False
    except PermissionError:checks['chroot_denied']=True
    try:os.execv('/usr/bin/python3',['python3','-c','raise SystemExit(99)']);checks['exec_denied']=False
    except PermissionError:checks['exec_denied']=True
    checks['caps_zero']=all(int(ident['status'][k],16)==0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
    checks['nnp_seccomp']=ident['status']['NoNewPrivs']=='1' and ident['status']['Seccomp']=='2'
    checks['fd_allowlist']=set(ident['fds'])<={'0','1','2'}
    checks['namespaces']=ident['ns']==req['target_ns']
    checks['cgroup']=req['business_cgroup'] in ident['cgroup']
    checks['environment']=dict(os.environ)=={'PATH':'/usr/bin:/bin'}
    checks['cwd']=os.getcwd()=='/work'
    checks['root_identity']=[os.stat('/').st_dev,os.stat('/').st_ino]==req['root_identity']
    if not all(checks.values()):raise RuntimeError('local W boundary failure',checks)
    result=NW.execute(req)
    record=dict(event='WORKER_READY',group=GROUP,nonce=nonce,domain_nonce=DOMAIN,
                identity=ident,checks=checks,inherited=base,runtime=runtime_state,
                numpy={'checks':result['checks'],'output_sha256':result['output_sha256'],
                       'reference_sha256':result['reference_sha256']})
    print(json.dumps(record),flush=True);cost.record('worker_ready_emitted')
    if persistent:return result,record
    if req['mode']=='nonzero':cost.record('business_end');cost.exit(7)
    if req['mode']=='normal':
        if req.get('test_descendant',True):
            p=os.fork()
            if p==0:
                t=cost.mark();time.sleep(.04);cost.finish('artificial_descendant_sleep',t,requested_ns=40000000)
                emit('DESCENDANT_DONE',nonce,pid=os.getpid());cost.exit(0)
        cost.record('business_end');cost.exit(0)
    p=os.fork()
    if p==0:os.setsid()
    while True:time.sleep(1)


def child(req,fds,base):
    nonce=req['nonce'];cost.context('W',nonce,repeat=req['repeat'],warmup=req['warmup'])
    cost.record('fork_child_first_python_point',point='complete D/CPython domain-local fork return')
    c=socket.socket(fileno=fds[1]);c.settimeout(8)
    try:
        nil=os.open('/dev/null',os.O_RDONLY);os.dup2(nil,0)
        os.dup2(fds[2],1);os.dup2(fds[2],2);close_except({c.fileno()})
        if LIB.drop_final() or LIB.forbid_exec():raise RuntimeError('local W final policy')
        cost.drain_bridge(LIB);os.setsid()
        runtime=RP.snapshot('LOCAL_W_gated',nonce);assert all(runtime['checks'].values())
        send(c,dict(event='WORKER_GATED',nonce=nonce,domain_nonce=DOMAIN,pid_local=os.getpid(),
                    parent_local=os.getppid(),identity=identity(),runtime=runtime,
                    final_security_installed=True,maps=Path('/proc/self/maps').read_text()))
        cost.record('worker_business_gate_ready')
        read_command(c,'RUN_BUSINESS',nonce);cost.record('run_business_received')
        c.close();close_except(set());business(req,base)
    except BaseException:traceback.print_exc();cost.exit(90)


def g3(base,baseline):
    attempts={};forgotten=set()
    def snap(e):
        hidden=e['req'].get('fault')=='result_loss_side_effect'
        return dict(nonce=e['nonce'],domain_nonce=DOMAIN,sealed=e['sealed'],w_state=e['state'],
                    worker_local_pid=e.get('pid'),wait_known=e.get('wait') is not None and not hidden,
                    descendants_reaped=e.get('descendants_reaped',[]),wait_echild=e.get('wait_echild',False),
                    wait_status=e.get('wait') if not hidden else None,
                    exit_code=os.waitstatus_to_exitcode(e['wait']) if e.get('wait') is not None and not hidden else None)
    def reap():
        for e in attempts.values():e['wait_echild']=False
        while True:
            try:p,s=os.waitpid(-1,os.WNOHANG)
            except ChildProcessError:
                for e in attempts.values():e['wait_echild']=True
                return
            if not p:return
            matches=[e for e in attempts.values() if e.get('pid')==p]
            if not matches and len(attempts)==1:
                e=next(iter(attempts.values()))
                descendant=dict(pid_local=p,wait_status=s,exit_code=os.waitstatus_to_exitcode(s))
                e.setdefault('descendants_reaped',[]).append(descendant)
                emit('LOCAL_Z_DESCENDANT_WAIT',e['nonce'],**descendant)
                continue
            if len(matches)!=1:raise RuntimeError('unexpected local child wait',p,s)
            e=matches[0];e['wait']=s;e['state']='REAPED';closefds([e.pop('pidfd')])
            emit('LOCAL_Z_ACTUAL_WAIT',e['nonce'],worker_local_pid=p,wait_status=s,exit_code=os.waitstatus_to_exitcode(s))
            if e['req'].get('fault') not in ('reaped_drop','result_loss_side_effect'):
                send(CTRL,dict(event='WORKER_WAITED',source='LOCAL_Z_REAL_WAIT',**snap(e)))
    def seal(e):
        e['sealed']=True
        closefds(e.pop('fds',[]))
        if e['state']=='PREPARED':e['state']='ABSENT'
        if e.get('pidfd') is not None:
            try:signal.pidfd_send_signal(e['pidfd'],signal.SIGKILL)
            except ProcessLookupError:pass
    try:
        while True:
            reap()
            if not select.select([CTRL],[],[],.01)[0]:continue
            req,fds,_=recv(CTRL);op=req.get('op');nonce=req.get('nonce');cost.context('LOCAL_Z',nonce)
            if req.get('domain_nonce')!=DOMAIN:closefds(fds);raise RuntimeError('wrong persistent domain')
            if op=='SPAWN':
                if nonce in forgotten or nonce in attempts or attempts or len(fds)!=3:
                    closefds(fds);send(CTRL,dict(event='SPAWN_REJECTED',nonce=nonce,domain_nonce=DOMAIN));continue
                e=dict(nonce=nonce,req=req,sealed=False,state='PREPARED',fds=fds,wait=None)
                attempts[nonce]=e;RP.set_attempt(nonce)
                send(CTRL,dict(event='PREPARED',**snap(e)));continue
            if fds:closefds(fds);raise RuntimeError('unexpected FDs')
            if op=='STOP':
                if attempts:raise RuntimeError('STOP with active attempts')
                now=stable_snapshot('Z_local_stop');assert now==baseline and fp()==base
                send(CTRL,dict(event='ZYGOTE_STOP',nonce=nonce,domain_nonce=DOMAIN,state_unchanged=True))
                CTRL.close();cost.exit(0)
            e=attempts.get(nonce)
            if e is None:
                send(CTRL,dict(event='STALE_REJECTED',nonce=nonce,domain_nonce=DOMAIN,forgotten=nonce in forgotten));continue
            if op=='COMMIT':
                if e['sealed'] or e['state']!='PREPARED':send(CTRL,dict(event='START_REJECTED',**snap(e)));continue
                RP.snapshot('LOCAL_Z_before_fork',nonce)
                pf=ctypes.c_int(-1);p=LIB.py_fork_cgroup(e['fds'][0],ctypes.byref(pf));error=ctypes.get_errno()
                if p==0:child(e['req'],e['fds'],base);cost.exit(99)
                cost.drain_bridge(LIB);RP.snapshot('LOCAL_Z_after_fork',nonce)
                closefds(e.pop('fds'))
                if p<0:
                    e.update(state='ABSENT',sealed=True)
                    emit('LOCAL_Z_CLONE_REJECTED',nonce,errno=error)
                    send(CTRL,dict(event='WORKER_REJECTED',errno=error,**snap(e)));continue
                e.update(pid=p,pidfd=pf.value,state='CREATED')
                emit('LOCAL_Z_ACTUAL_CLONE',nonce,worker_local_pid=p,waiter_local_pid=os.getpid(),clone_into_cgroup=True)
                if e['req'].get('fault')!='created_drop':send(CTRL,dict(event='WORKER_CREATED',**snap(e)))
            elif op=='CANCEL':
                seal(e);reap();send(CTRL,dict(event='CANCEL_ACK',**snap(e)))
            elif op=='QUERY':send(CTRL,dict(event='SNAPSHOT',**snap(e)))
            elif op=='FORGET':
                reap()
                if not e['sealed'] or e['state'] not in ('ABSENT','REAPED') or not e.get('wait_echild'):raise RuntimeError('FORGET before local wait/seal/ECHILD')
                current=stable_snapshot('Z_local_after_request');fingerprint=fp()
                if current!=baseline or fingerprint!=base:raise RuntimeError('local template contaminated')
                del attempts[nonce];forgotten.add(nonce)
                send(CTRL,dict(event='FORGOTTEN',nonce=nonce,domain_nonce=DOMAIN,state_unchanged=True,
                               fingerprint=fingerprint,snapshot=current,active_requests=len(attempts),
                               wait_echild=True,descendants_reaped=e.get('descendants_reaped',[])))
            else:raise RuntimeError('unknown local operation',op)
    finally:
        for e in attempts.values():seal(e)
        # R/H also kill the private request cgroups; this true parent reaps only
        # its own children and does not claim to own arbitrary descendants.
        while True:
            try:os.waitpid(-1,0)
            except ChildProcessError:break
        CTRL.close()


def g4(base,baseline):
    # FD 0 is the fixed trusted function protocol. No namespace/cgroup/root
    # descriptor survives into business. This is NOT an arbitrary-code reset.
    current=None;finished=set()
    def output_close():
        cost.flush()
        fd=os.open('/dev/null',os.O_WRONLY)
        os.dup2(fd,1);os.dup2(fd,2)
        if fd>2:os.close(fd)
    def answer(name,e,**fields):
        send(CTRL,dict(event=name,nonce=e['nonce'],domain_nonce=DOMAIN,
                       state=e['state'],sealed=e['sealed'],**fields))
    while True:
        req,fds,_=recv(CTRL);op=req.get('op');nonce=req.get('nonce')
        if req.get('domain_nonce')!=DOMAIN:closefds(fds);raise RuntimeError('wrong persistent Worker domain')
        if op=='PREPARE':
            if current is not None or nonce in finished or len(fds)!=1:
                closefds(fds);send(CTRL,dict(event='START_REJECTED',nonce=nonce,domain_nonce=DOMAIN));continue
            os.dup2(fds[0],1);os.dup2(fds[0],2);closefds(fds);close_except(set())
            cost.context('W',nonce,repeat=req['repeat'],warmup=req['warmup']);RP.set_attempt(nonce)
            state=RP.snapshot('LOCAL_PERSISTENT_gated',nonce);assert all(state['checks'].values())
            current=dict(nonce=nonce,req=req,state='PREPARED',sealed=False,reset=None,
                         baseline=stable_snapshot('persistent_request_gate'))
            answer('PERSISTENT_GATED',current,identity=identity(),runtime=state,
                   maps=Path('/proc/self/maps').read_text(),final_security_installed=True)
            continue
        if fds:closefds(fds);raise RuntimeError('unexpected persistent control FDs')
        if op=='STOP':
            if current is not None:raise RuntimeError('persistent STOP with active request')
            answer('ZYGOTE_STOP',dict(nonce=nonce,state='RETAINED',sealed=True),
                   state_unchanged=True,contract='fixed trusted function; all completed resets validated')
            CTRL.close();cost.exit(0)
        if current is None or nonce!=current['nonce']:
            send(CTRL,dict(event='STALE_REJECTED',nonce=nonce,domain_nonce=DOMAIN,forgotten=nonce in finished));continue
        e=current
        if op=='CANCEL':
            e['sealed']=True
            if e['state']=='PREPARED':
                e['state']='NOT_EXECUTED';output_close()
            answer('CANCEL_ACK',e,reset=e['reset'],worker_retained=True)
        elif op=='RUN_BUSINESS':
            if e['sealed'] or e['state']!='PREPARED':answer('START_REJECTED',e);continue
            e['state']='RUNNING';cost.record('run_business_received')
            result,record=business(e['req'],base,persistent=True)
            if e['req']['mode']=='hang':
                # Cancellation cannot claim a serial busy loop consumed CANCEL.
                # R revokes admission and destroys the domain, then waits PID1.
                while True:time.sleep(1)
            if e['req'].get('test_descendant',True):
                p=os.fork()
                if p==0:
                    t=cost.mark();time.sleep(.04);cost.finish('artificial_descendant_sleep',t,requested_ns=40000000)
                    emit('DESCENDANT_DONE',nonce,pid=os.getpid());cost.exit(0)
                q,status=os.waitpid(p,0)
                emit('PERSISTENT_DESCENDANT_WAIT',nonce,pid_local=q,wait_status=status)
                if os.waitstatus_to_exitcode(status)!=0:raise RuntimeError('persistent test descendant failed')
            reset=NW.reset_persistent(result['initial_fingerprint'],nonce)
            if e['req'].get('fault')=='reset_failure':STATE[0]^=1
            if e['req'].get('fault')=='fd_leak':os.open('/dev/null',os.O_RDONLY)
            post=stable_snapshot('persistent_request_reset')
            own_ok=hashlib.sha256(STATE).hexdigest()==base['state_sha256'] and id(STATE)==base['state_id']
            if post!=e['baseline'] or not own_ok:raise RuntimeError('persistent fixed-state restoration failed')
            try:os.waitpid(-1,os.WNOHANG)
            except ChildProcessError:wait_echild=True
            else:raise RuntimeError('persistent request left a child')
            e.update(state='COMPLETED',sealed=True,reset=dict(numpy=reset,process_before=e['baseline'],
                    process_after=post,own_state_unchanged=own_ok,wait_echild=wait_echild),
                    return_code=7 if e['req']['mode']=='nonzero' else 0)
            emit('PERSISTENT_RESET_CONFIRMED',nonce,reset=e['reset'])
            cost.record('business_end');output_close()
            if e['req'].get('fault')!='result_loss_side_effect':
                answer('REQUEST_COMPLETE',e,return_code=e['return_code'],reset=e['reset'],
                       worker_retained=True,result_kind='FIXED_FUNCTION_RETURN_NOT_PROCESS_EXIT')
        elif op=='QUERY':
            answer('PERSISTENT_SNAPSHOT',e,result_known=e['state']=='COMPLETED' and e['req'].get('fault')!='result_loss_side_effect',
                   return_code=e.get('return_code') if e['req'].get('fault')!='result_loss_side_effect' else None,
                   reset=e['reset'])
        elif op=='FORGET':
            if not e['sealed'] or e['state'] not in ('NOT_EXECUTED','COMPLETED'):raise RuntimeError('persistent FORGET before seal/reset')
            if e['state']=='COMPLETED' and e['reset'] is None:raise RuntimeError('persistent FORGET lacks reset')
            finished.add(nonce);current=None
            answer('PERSISTENT_FORGOTTEN',e,worker_retained=True,active_requests=0,reset=e['reset'])
        else:raise RuntimeError('unknown persistent operation',op)


def main():
    global CTRL
    req=read_command(CTRL,'BOOTSTRAP',DOMAIN)
    assert req['group']==GROUP and req['domain_nonce']==DOMAIN
    if GROUP=='G4':
        old=CTRL.detach();os.dup2(old,0);os.close(old);CTRL=socket.socket(fileno=0)
    os.environ.clear();os.environ['PATH']='/usr/bin:/bin'
    sys.path[:]=[str(NW.PACKAGE)]+[p for p in sys.path if p.startswith(('/usr/lib/','/lib/'))]
    close_except({CTRL.fileno()})
    if GROUP=='G3' and LIB.subreaper():raise RuntimeError('local Z subreaper setup failed')
    if LIB.drop_final() or LIB.forbid_exec():raise RuntimeError('local runtime final policy')
    cost.drain_bridge(LIB);RP.install();RP.set_attempt(DOMAIN)
    state=RP.snapshot('LOCAL_runtime_before_preload',DOMAIN);assert all(state['checks'].values())
    NW.initialize(req['numpy_level'],'Z_domain' if GROUP=='G3' else 'W_persistent')
    baseline=stable_snapshot('LOCAL_ready');base=fp()
    send(CTRL,dict(event='LOCAL_READY',nonce=DOMAIN,domain_nonce=DOMAIN,group=GROUP,
                   identity=identity(),maps=Path('/proc/self/maps').read_text(),fingerprint=base,
                   snapshot=baseline,runtime=state,final_security_installed=True))
    cost.record('local_runtime_ready',force=True)
    (g3 if GROUP=='G3' else g4)(base,baseline)


try:main()
except BaseException:traceback.print_exc();cost.exit(88)
