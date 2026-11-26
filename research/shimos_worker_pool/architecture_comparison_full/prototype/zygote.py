"""Pinned trusted NumPy candidate; no arbitrary dependency or user code loader."""
import os,sys,socket,time,json,ctypes,hashlib,traceback,select,signal,errno
from pathlib import Path
from common import send,recv,bridge,fork_cg,identity,close_except
import runtime_probe as RP
import cost
import numpy_workload as NW
import concurrent_faults
CONCURRENT_FAULT=concurrent_faults.configured()
CONCURRENT_FAULT_INJECTED=False
NP_LEVEL=os.environ.get("NP_LEVEL","import")
NP_BASELINE=os.environ.get("NP_BASELINE","hot")
NP_CASE=os.environ.get("NP_CASE","normal")
NP_AUDIT=os.environ.get("NP_AUDIT","0")=="1"
cost.context('Z');cost.record('zygote_python_enter')
LIB=bridge(sys.argv[1]);assert LIB.set_base_safety()==0
class MemoryState:
    def __init__(self):
        self.born_pid=os.getpid();self.bytes=bytearray(os.urandom(65536));self.lookup={i:i*i+17 for i in range(200)}
STATE=MemoryState()
def fingerprint():
    return {'object_id':id(STATE),'born_pid':STATE.born_pid,'sha256':hashlib.sha256(STATE.bytes).hexdigest(),'answer':sum(STATE.lookup.values()), 'numpy':NW.fingerprint()}
CTRL=socket.socket(fileno=3)
RP.install()
if NP_BASELINE=="hot": NW.initialize(NP_LEVEL,"Z")
BASE=fingerprint()
NP_STABLE=NW.snapshot("Z_admitted")

def numpy_template_check(nonce):
    snap=NW.snapshot("Z_after_attempt")
    stable=(len(snap["threads"])==1 and snap["environment"]==NP_STABLE["environment"] and snap["signals"]==NP_STABLE["signals"] and snap["fds"]==NP_STABLE["fds"])
    NW.emit("NP_Z_CHECK",nonce=nonce,fingerprint=NW.fingerprint(),baseline=BASE["numpy"],stable=stable,snapshot=snap)
    return stable

def np_phase(stage,nonce):
    if NP_AUDIT:
        NW.emit("NP_PHASE",nonce=nonce,stage=stage,snapshot={"audit":NW.audit()},fingerprint=NW.fingerprint())

def business(req):
    cost.record('business_enter')
    checks_started=cost.mark()
    # All Python business code starts AFTER final drop/FD close/filter.
    runtime_state=RP.snapshot('W_business',req['nonce']);assert all(runtime_state['checks'].values()),runtime_state
    ident=identity();checks={}
    checks['marker']=Path('/tmp/domain-token').read_text()==req.get('domain_nonce',req['nonce'])
    checks['inherited']=fingerprint()==BASE
    checks['not_recreated']=STATE.born_pid!=os.getpid() and id(STATE)==BASE['object_id']
    checks['no_host_path']=not Path('/state').exists() and not Path('/evidence').exists()
    checks['no_other_workspace']=not Path('/work/other-domain-secret').exists()
    try:Path('/src/input').write_text('bad');checks['readonly']=False
    except OSError as e:checks['readonly']=e.errno==errno.EROFS
    payload_started=cost.mark();Path('/work/result').write_text(str(sum(STATE.lookup.values())));cost.finish('controlled_payload_compute_write',payload_started)
    checks['writable']=Path('/work/result').read_text()==str(sum(i*i+17 for i in range(200)))
    libc=ctypes.CDLL(None,use_errno=True)
    sf=os.open('/proc/self/ns/mnt',os.O_RDONLY);ret=libc.setns(sf,0);checks['setns_denied']=ret==-1 and ctypes.get_errno()==errno.EPERM;os.close(sf)
    ret=libc.unshare(0x10000000);checks['unshare_denied']=ret==-1 and ctypes.get_errno()==errno.EPERM
    try:os.chroot('/');checks['chroot_denied']=False
    except PermissionError:checks['chroot_denied']=True
    try:os.execv('/usr/bin/python3',['python3','-c','raise SystemExit(99)']);checks['exec_denied']=False
    except PermissionError:checks['exec_denied']=True
    checks['caps_zero']=all(int(ident['status'][k],16)==0 for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])
    checks['nnp_seccomp']=ident['status']['NoNewPrivs']=='1' and ident['status']['Seccomp']=='2'
    checks['fd_allowlist']=set(ident['fds'])<=set(['0','1','2'])
    checks['namespaces']=ident['ns']==req['target_ns']
    checks['cgroup']=req['business_cgroup'] in ident['cgroup']
    checks['environment']=dict(os.environ)=={'PATH':'/usr/bin:/bin'}
    checks['cwd']=os.getcwd()=='/work'
    checks['root_identity']=[os.stat('/').st_dev,os.stat('/').st_ino]==req['root_identity']
    STATE.bytes[0]^=255
    cost.finish('worker_qualification_checks',checks_started,checks=len(checks),includes_controlled_payload=True)
    np_result=NW.execute(req)
    emit_started=cost.mark()
    print(json.dumps({'event':'WORKER_READY','nonce':req['nonce'],'identity':ident,'inherited':BASE,'checks':checks,'after_cow':fingerprint(),'runtime':runtime_state,'numpy':{'checks':np_result['checks'],'output_sha256':np_result['output_sha256'],'reference_sha256':np_result['reference_sha256']}}),flush=True)
    cost.finish('worker_ready_evidence_write',emit_started);cost.record('worker_ready_emitted')
    if not all(checks.values()):cost.exit(91)
    if req.get('runtime_robust'):RP.robust_lock(req['nonce'])
    if req['mode']=='nonzero':cost.record('business_end');cost.exit(7)
    if req['mode'] in ('normal','waiter_failure'):
        if not req.get('test_descendant',True):cost.record('business_end');cost.exit(0)
        p=os.fork()
        if p==0:
            delay_started=cost.mark();time.sleep(.04);cost.finish('artificial_descendant_sleep',delay_started,requested_ns=40000000);print(json.dumps({'event':'DESCENDANT_DONE','pid':os.getpid()}),flush=True);cost.exit(0)
        cost.record('business_end');cost.exit(0)
    p=os.fork()
    if p==0:os.setsid()
    while True:time.sleep(1)

def log(event_name, nonce=None, **fields):
    started=cost.mark()
    print(json.dumps({'event': event_name, 'nonce': nonce,
                      'monotonic_ns': time.monotonic_ns(), **fields}), flush=True)
    cost.finish('lifecycle_evidence_write',started,event_name=event_name)


def close_fds(fds):
    started=cost.mark();closed=0
    for fd in fds:
        if fd is not None and fd >= 0:
            try: os.close(fd);closed+=1
            except OSError: pass
    cost.finish('close_explicit_fds',started,closed=closed)


def command(channel, nonce, expected):
    message, extras, _ = recv(channel)
    try:
        if extras or message.get('nonce') != nonce or message.get('op') != expected:
            raise RuntimeError('wrong attempt, command or unexpected descriptors')
        return message
    finally:
        close_fds(extras)


def transition(req, fds):
    # Slots are unchanged: base,inner,mnt,pid,net,ipc,uts,root,
    # transitioncg,businesscg,status,stdout,target-PID1-pidfd.
    nonce = req['nonce']; fault = req.get('fault'); c = socket.socket(fileno=fds[10])
    cost.record('transition_function_enter')
    RP.snapshot('S_after_first_fork',nonce)
    c.settimeout(10)
    close_except(set(fds))
    extra_fds = []
    wpid = None
    try:
        send(c, {'event': 'TRANSITION_BORN', 'nonce': nonce,
                 'pid': os.getpid(), 'identity': identity()})
        if select.select([fds[12]], [], [], 0)[0]:
            raise RuntimeError('target PID1 already exited')
        arr = (ctypes.c_int * 8)(*fds[:8]); r = LIB.enter_target(arr);saved_errno=ctypes.get_errno();cost.drain_bridge(LIB);ctypes.set_errno(saved_errno)
        if r: raise OSError(ctypes.get_errno(), 'enter_target stage ' + str(r))
        if Path('/tmp/domain-token').read_text() != req.get('domain_nonce',nonce):
            raise RuntimeError('target nonce mismatch')
        os.environ.clear(); os.environ['PATH'] = '/usr/bin:/bin'
        sys.path[:] = [str(NW.PACKAGE)] + [p for p in sys.path if p.startswith(('/usr/lib/', '/lib/'))]
        # Final authority is dropped before either control gate. The original
        # filter permits clone3; delegated cgroup object permission is retained,
        # not construction capabilities. No fallback if INTO_CGROUP is refused.
        close_fds(fds[:9])
        r = LIB.drop_final();saved_errno=ctypes.get_errno();cost.drain_bridge(LIB);ctypes.set_errno(saved_errno)
        if r: raise OSError(ctypes.get_errno(), 'transition early drop ' + str(r))
        runtime_state=RP.snapshot('S_early_drop',nonce);assert all(runtime_state['checks'].values()),runtime_state
        cost.record('transition_final_security_installed')
        send(c, {'event': 'ENTERED', 'nonce': nonce, 'pid': os.getpid(),
                 'construction_authority_dropped': True,'runtime':runtime_state})
        command(c, nonce, 'START_WORKER')
        cost.record('start_worker_received')
        if select.select([fds[12]], [], [], 0)[0]:
            raise RuntimeError('target died before clone')
        gate_r, gate_w = os.pipe2(os.O_CLOEXEC)
        ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
        extra_fds = [gate_r, gate_w, ready_r, ready_w]
        try:
            RP.snapshot('S_before_second_fork',nonce);np_phase('S_before_second_fork',nonce)
            p, pfd = fork_cg(LIB, fds[9])
        except OSError as e:
            RP.snapshot('S_second_fork_rejected',nonce)
            close_fds(extra_fds); extra_fds = []
            send(c, {'event': 'WORKER_REJECTED', 'nonce': nonce,
                     'errno': e.errno, 'error': repr(e), 'w_state': 'ABSENT'})
            log('ACTUAL_WORKER_CLONE_REJECTED', nonce, errno=e.errno)
            c.close(); cost.exit(0)
        if p == 0:
            cost.record('worker_branch_enter')
            RP.snapshot('W_after_second_fork',nonce)
            try:
                nil = os.open('/dev/null', os.O_RDONLY)
                os.dup2(nil, 0); os.dup2(fds[11], 1); os.dup2(fds[11], 2)
                close_except({gate_r, ready_w})
                r = LIB.drop_final();saved_errno=ctypes.get_errno();cost.drain_bridge(LIB);ctypes.set_errno(saved_errno)
                if r:
                    print(json.dumps({'event': 'DROP_ERROR', 'nonce': nonce,
                                      'stage': r, 'errno': ctypes.get_errno()}), flush=True)
                    cost.exit(123)
                if LIB.forbid_exec(): cost.exit(124)
                cost.drain_bridge(LIB)
                session_started=cost.mark();os.setsid();cost.finish('worker_setsid',session_started)
                runtime_state=RP.snapshot('W_gated',nonce);assert all(runtime_state['checks'].values()),runtime_state
                cost.record('worker_business_gate_ready')
                os.write(ready_w, b'R'); os.close(ready_w)
                gate_started=cost.mark();permission = os.read(gate_r, 1);cost.finish('worker_business_gate_wait',gate_started,allowed=permission==b'G');os.close(gate_r)
                # Business starts only here. Trusted Python/native atfork callbacks
                # have already run inside the fork wrapper, before this gate.
                # EOF, wrong token and Controller loss never authorize work.
                if permission != b'G': cost.exit(126)
                business(req)
            except BaseException:
                traceback.print_exc(); cost.exit(90)
        wpid = p
        RP.snapshot('S_after_second_parent',nonce);np_phase('S_after_second_parent',nonce)
        log('ACTUAL_WORKER_FORK', nonce, worker_host_pid=p, waiter_host_pid=os.getpid())
        # S cannot enumerate /proc/self after entering a descendant PID view.
        close_fds([gate_r, ready_w, fds[9], fds[11], fds[12]])
        extra_fds = [gate_w, ready_r, pfd]
        gate_ready_started=cost.mark()
        if not select.select([ready_r], [], [], 10)[0] or os.read(ready_r, 1) != b'R':
            raise RuntimeError('worker did not reach post-drop gate')
        cost.finish('transition_wait_worker_gate',gate_ready_started)
        os.close(ready_r); extra_fds.remove(ready_r)
        send(c, {'event': 'WORKER_GATED', 'nonce': nonce,
                 'worker_host_pid': p, 'waiter_host_pid': os.getpid(),
                 'final_security_installed': True}, [pfd])
        os.close(pfd); extra_fds.remove(pfd)
        command(c, nonce, 'RUN_BUSINESS')
        cost.record('run_business_received');release_started=cost.mark();os.write(gate_w, b'G');cost.finish('business_gate_write',release_started);os.close(gate_w);extra_fds.remove(gate_w)
        send(c, {'event': 'BUSINESS_RELEASED', 'nonce': nonce,
                 'worker_host_pid': p})
        wait_begin=cost.mark();q, status = os.waitpid(p, 0)
        cost.finish('wait_worker',wait_begin,waited_pid=q,wait_status=status);cost.record('worker_waited')
        log('ACTUAL_WORKER_WAIT', nonce, worker_host_pid=q,
            wait_status=status, exit_code=os.waitstatus_to_exitcode(status))
        if req.get('runtime_robust'):RP.robust_recover(nonce)
        if fault != 'result_loss_side_effect':
            send(c, {'event': 'WORKER_WAITED', 'nonce': nonce,
                     'worker_host_pid': q, 'wait_status': status,
                     'exit_code': os.waitstatus_to_exitcode(status)})
        else:
            log('FAULT_WORKER_WAIT_RECEIPT_DROPPED', nonce,
                worker_host_pid=q, wait_status=status)
        c.close(); cost.exit(17 if req['mode'] == 'waiter_failure' else 0)
    except BaseException as e:
        # Closing the unspent gate is fail-closed. Controller additionally kills
        # and waits the entire attempt, including the external transition.
        close_fds(extra_fds)
        try:
            send(c, {'event': 'TRANSITION_ERROR', 'nonce': nonce,
                     'error': repr(e), 'errno': getattr(e, 'errno', None),
                     'w_state': 'ABSENT' if wpid is None else 'CREATED',
                     'traceback': traceback.format_exc()})
        except OSError: pass
        cost.exit(125)


send(CTRL, {'event': 'ZYGOTE_READY', 'identity': identity(), 'state': BASE,
            'threads': len(os.listdir('/proc/self/task')),'numpy_config':{'level':NP_LEVEL,'baseline':NP_BASELINE,'case':NP_CASE},'runtime':RP.snapshot('Z_ready'),'session':cost.SESSION})
cost.record('zygote_ready');cost.usage('zygote_ready_usage')
attempts = {}
children = {}
used = set()


def snapshot(entry):
    return {'nonce': entry['req']['nonce'], 's_state': entry['s_state'],
            's_pid': entry['s_pid'], 's_wait': entry['s_wait'],
            'error': entry['error'], 'admission': entry['admission']}


def close_pending(entry):
    close_fds(entry['fds']); entry['fds'] = []


def commit(entry):
    nonce = entry['req']['nonce']; req = entry['req']; fds = entry['fds']
    if entry['admission'] != 'OPEN':
        send(CTRL, {'event': 'COMMIT_REJECTED', **snapshot(entry)})
        return
    # The serial Z event loop is the authority for this atomic decision.
    entry['admission'] = 'COMMITTED'; entry['s_state'] = 'POSSIBLE'
    death_gate = None
    if req.get('fault') == 'fork_ack_loss':
        death_gate = os.pipe2(os.O_CLOEXEC)
    try:
        RP.set_attempt(nonce);RP.snapshot('Z_before_first_fork',nonce);np_phase('Z_before_first_fork',nonce)
        p, pfd = fork_cg(LIB, fds[8])
        if p == 0:
            if req.get('fault')=='adoption_after_snapshot':
                if CONCURRENT_FAULT!='adoption_after_snapshot':
                    raise RuntimeError('unregistered adoption probe')
                log('CONCURRENT_TEST_TRANSITION_STOPPING_FOR_ADOPTION',nonce,
                    pid=os.getpid(),parent_pid=os.getppid())
                os.kill(os.getpid(),signal.SIGSTOP)
            if death_gate:
                close_except(set(fds) | {death_gate[0]})
                os.read(death_gate[0], 1); os.close(death_gate[0])
            transition(req, fds)
            cost.exit(127)
        RP.snapshot('Z_after_first_parent',nonce);np_phase('Z_after_first_parent',nonce)
        entry.update(s_state='CREATED', s_pid=p, pidfd=pfd)
        children[p] = nonce
        log('ACTUAL_TRANSITION_FORK', nonce, pid=p)
        if death_gate:
            os.close(death_gate[0])
            log('FAULT_Z_DIES_BEFORE_CREATED', nonce, pid=p)
            os.kill(os.getpid(), signal.SIGKILL)
        if req.get('fault') != 'created_drop':
            send(CTRL, {'event': 'TRANSITION_CREATED', 'nonce': nonce,
                        'pid': p, 's_state': 'CREATED'}, [pfd])
        else:
            log('FAULT_CREATED_RECEIPT_DROPPED', nonce, pid=p)
    except OSError as e:
        if entry['s_state'] != 'POSSIBLE':
            # The clone succeeded: a send failure is NOT a spawn rejection.
            raise
        RP.snapshot('Z_first_fork_rejected',nonce)
        entry.update(s_state='ABSENT', error={'stage': 'first_clone',
                     'errno': e.errno, 'error': repr(e)}, admission='SEALED')
        log('ACTUAL_TRANSITION_CLONE_REJECTED', nonce, errno=e.errno)
        send(CTRL, {'event': 'SPAWN_REJECTED', 'nonce': nonce,
                    'errno': e.errno, 's_state': 'ABSENT',
                    'error': repr(e), 'admission': 'SEALED'})
    finally:
        if death_gate: close_fds(death_gate)
        close_pending(entry)


try:
    while True:
        for p in list(children):
            wait_started=cost.mark();q, status = os.waitpid(p, os.WNOHANG);cost.finish('waitpid_poll',wait_started,waited_pid=q,wait_status=status)
            if not q: continue
            nonce = children.pop(p);cost.context('Z',nonce);cost.record('transition_waited');entry = attempts[nonce]
            entry.update(s_state='REAPED', s_wait=status)
            log('ACTUAL_TRANSITION_WAIT', nonce, pid=p, wait_status=status)
            if entry['req'].get('fault') == 'reap_ack_loss':
                log('FAULT_Z_DIES_BEFORE_REAPED', nonce, pid=p, wait_status=status)
                os.kill(os.getpid(), signal.SIGKILL)
            if entry['req'].get('fault') != 'reaped_drop':
                send(CTRL, {'event': 'TRANSITION_REAPED', 'nonce': nonce,
                            'pid': p, 's_state': 'REAPED', 'wait_status': status})
            else:
                log('FAULT_REAPED_RECEIPT_DROPPED', nonce, pid=p, wait_status=status)
        poll_started=cost.mark();ready, _, _ = select.select([CTRL], [], [], .01);cost.finish('zygote_poll',poll_started,ready_count=len(ready))
        if not ready: continue
        try: req, received, _ = recv(CTRL)
        except EOFError: break
        service_started=cost.mark()
        try:
            op = req.get('op'); nonce = req.get('nonce');cost.context('Z',nonce)
            if op == 'PING':
                if received: raise RuntimeError('PING descriptors')
                if not CONCURRENT_FAULT_INJECTED:
                    CONCURRENT_FAULT_INJECTED=concurrent_faults.corrupt_owned_template(
                        CONCURRENT_FAULT,STATE,attempts,children,log,nonce)
                send(CTRL, {'event': 'PONG', 'state_unchanged': fingerprint() == BASE and numpy_template_check(nonce),
                            'identity': identity(), 'active_attempts': len(attempts),'session':cost.SESSION,'nonce':nonce})
                continue
            if op == 'STOP':
                if received: raise RuntimeError('STOP descriptors')
                if children or any(e['fds'] for e in attempts.values()):
                    send(CTRL, {'event': 'STOP_REJECTED', 'reason': 'live or prepared attempts'})
                    continue
                send(CTRL, {'event': 'ZYGOTE_STOP', 'state_unchanged': fingerprint() == BASE and numpy_template_check(None),
                            'state': fingerprint()})
                break
            if not isinstance(nonce, str) or not nonce or len(nonce) > 128:
                raise RuntimeError('missing or invalid attempt identity')
            if op == 'SPAWN':
                if nonce in used or len(received) != 13:
                    raise RuntimeError('reused attempt identity or wrong descriptor count')
                used.add(nonce)
                attempts[nonce] = {'req': req, 'fds': received[:], 'admission': 'OPEN',
                                   's_state': 'ABSENT', 's_pid': None, 's_wait': None,
                                   'pidfd': None, 'error': None}
                received.clear()
                send(CTRL, {'event': 'PREPARED', **snapshot(attempts[nonce])})
                continue
            if received: raise RuntimeError('unexpected operation descriptors')
            entry = attempts.get(nonce)
            if entry is None:
                send(CTRL, {'event': 'ATTEMPT_UNKNOWN', 'nonce': nonce,
                            'seen_before': nonce in used, 'op': op})
                continue
            if op == 'COMMIT':
                commit(entry)
            elif op == 'CANCEL':
                entry['admission'] = 'SEALED'; close_pending(entry)
                if entry['req'].get('fault')=='revoke_ack_loss':
                    log('FAULT_REVOKE_ACK_DROPPED',nonce)
                else:
                    send(CTRL, {'event': 'CANCEL_ACK', 'sealed': True, **snapshot(entry)})
            elif op == 'QUERY':
                fds = [entry['pidfd']] if entry['pidfd'] is not None else []
                send(CTRL, {'event': 'SNAPSHOT', 'has_pidfd': bool(fds), **snapshot(entry)}, fds)
            elif op == 'FORGET':
                if entry['admission'] != 'SEALED' or entry['s_state'] not in ('ABSENT', 'REAPED'):
                    send(CTRL, {'event': 'FORGET_REJECTED', **snapshot(entry)})
                    continue
                close_pending(entry); close_fds([entry['pidfd']]); del attempts[nonce]
                send(CTRL, {'event': 'FORGOTTEN', 'nonce': nonce})
            else:
                raise RuntimeError('unknown operation')
        except (AssertionError, KeyError, ValueError, RuntimeError) as e:
            send(CTRL, {'event': 'PROTOCOL_ERROR', 'nonce': req.get('nonce'), 'error': repr(e)})
        finally:
            close_fds(received)
            cost.finish('zygote_message_service',service_started,message=req.get('op'))
finally:
    # EOF retires this creator. The surviving product Controller/Supervisor is
    # responsible for kill + real adoption/wait; exit alone is not cleanup ACK.
    for entry in attempts.values():
        close_pending(entry); close_fds([entry['pidfd']])
    CTRL.close();cost.usage('zygote_final_usage');cost.flush()
