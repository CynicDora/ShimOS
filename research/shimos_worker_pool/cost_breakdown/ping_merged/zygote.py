"""Trusted single-threaded test template. No third-party import, no user code loader."""
import os,sys,socket,time,json,ctypes,hashlib,traceback,select,signal,errno
from pathlib import Path
from common import send,recv,bridge,fork_cg,identity,close_except
import runtime_probe as RP
import cost
cost.context('Z');cost.record('zygote_python_enter')
LIB=bridge(sys.argv[1]);assert LIB.set_base_safety()==0
class MemoryState:
    def __init__(self):
        self.born_pid=os.getpid();self.bytes=bytearray(os.urandom(65536));self.lookup={i:i*i+17 for i in range(200)}
STATE=MemoryState()
def fingerprint():
    return {'object_id':id(STATE),'born_pid':STATE.born_pid,'sha256':hashlib.sha256(STATE.bytes).hexdigest(),'answer':sum(STATE.lookup.values())}
BASE=fingerprint()
CTRL=socket.socket(fileno=3)
RP.install()

def business(req):
    cost.record('business_enter')
    # All Python business code starts AFTER final drop/FD close/filter.
    runtime_state=RP.snapshot('W_business',req['nonce']);assert all(runtime_state['checks'].values()),runtime_state
    ident=identity();checks={}
    checks['marker']=Path('/tmp/domain-token').read_text()==req['nonce']
    checks['inherited']=fingerprint()==BASE
    checks['not_recreated']=STATE.born_pid!=os.getpid() and id(STATE)==BASE['object_id']
    checks['no_host_path']=not Path('/state').exists() and not Path('/evidence').exists()
    checks['no_other_workspace']=not Path('/work/other-domain-secret').exists()
    try:Path('/src/input').write_text('bad');checks['readonly']=False
    except OSError as e:checks['readonly']=e.errno==errno.EROFS
    Path('/work/result').write_text(str(sum(STATE.lookup.values())))
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
    print(json.dumps({'event':'WORKER_READY','nonce':req['nonce'],'identity':ident,'inherited':BASE,'checks':checks,'after_cow':fingerprint(),'runtime':runtime_state}),flush=True)
    if not all(checks.values()):cost.exit(91)
    if req.get('runtime_robust'):RP.robust_lock(req['nonce'])
    if req['mode']=='nonzero':cost.record('business_end');cost.exit(7)
    if req['mode'] in ('normal','waiter_failure'):
        p=os.fork()
        if p==0:
            time.sleep(.04);print(json.dumps({'event':'DESCENDANT_DONE','pid':os.getpid()}),flush=True);cost.exit(0)
        cost.record('business_end');cost.exit(0)
    p=os.fork()
    if p==0:os.setsid()
    while True:time.sleep(1)

def log(event_name, nonce=None, **fields):
    print(json.dumps({'event': event_name, 'nonce': nonce,
                      'monotonic_ns': time.monotonic_ns(), **fields}), flush=True)


def close_fds(fds):
    for fd in fds:
        if fd is not None and fd >= 0:
            try: os.close(fd)
            except OSError: pass


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
        if Path('/tmp/domain-token').read_text() != nonce:
            raise RuntimeError('target nonce mismatch')
        os.environ.clear(); os.environ['PATH'] = '/usr/bin:/bin'
        sys.path[:] = [p for p in sys.path if p.startswith(('/usr/lib/', '/lib/'))]
        # Final authority is dropped before either control gate. The original
        # filter permits clone3; delegated cgroup object permission is retained,
        # not construction capabilities. No fallback if INTO_CGROUP is refused.
        close_fds(fds[:9])
        r = LIB.drop_final();saved_errno=ctypes.get_errno();cost.drain_bridge(LIB);ctypes.set_errno(saved_errno)
        if r: raise OSError(ctypes.get_errno(), 'transition early drop ' + str(r))
        runtime_state=RP.snapshot('S_early_drop',nonce);assert all(runtime_state['checks'].values()),runtime_state
        send(c, {'event': 'ENTERED', 'nonce': nonce, 'pid': os.getpid(),
                 'construction_authority_dropped': True,'runtime':runtime_state})
        command(c, nonce, 'START_WORKER')
        if select.select([fds[12]], [], [], 0)[0]:
            raise RuntimeError('target died before clone')
        gate_r, gate_w = os.pipe2(os.O_CLOEXEC)
        ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
        extra_fds = [gate_r, gate_w, ready_r, ready_w]
        try:
            RP.snapshot('S_before_second_fork',nonce)
            p, pfd = fork_cg(LIB, fds[9])
        except OSError as e:
            RP.snapshot('S_second_fork_rejected',nonce)
            close_fds(extra_fds); extra_fds = []
            send(c, {'event': 'WORKER_REJECTED', 'nonce': nonce,
                     'errno': e.errno, 'error': repr(e), 'w_state': 'ABSENT'})
            log('ACTUAL_WORKER_CLONE_REJECTED', nonce, errno=e.errno)
            c.close(); cost.exit(0)
        if p == 0:
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
                os.setsid()
                runtime_state=RP.snapshot('W_gated',nonce);assert all(runtime_state['checks'].values()),runtime_state
                os.write(ready_w, b'R'); os.close(ready_w)
                permission = os.read(gate_r, 1); os.close(gate_r)
                # Business starts only here. Trusted Python/native atfork callbacks
                # have already run inside the fork wrapper, before this gate.
                # EOF, wrong token and Controller loss never authorize work.
                if permission != b'G': cost.exit(126)
                business(req)
            except BaseException:
                traceback.print_exc(); cost.exit(90)
        wpid = p
        RP.snapshot('S_after_second_parent',nonce)
        log('ACTUAL_WORKER_FORK', nonce, worker_host_pid=p, waiter_host_pid=os.getpid())
        # S cannot enumerate /proc/self after entering a descendant PID view.
        close_fds([gate_r, ready_w, fds[9], fds[11], fds[12]])
        extra_fds = [gate_w, ready_r, pfd]
        if not select.select([ready_r], [], [], 10)[0] or os.read(ready_r, 1) != b'R':
            raise RuntimeError('worker did not reach post-drop gate')
        os.close(ready_r); extra_fds.remove(ready_r)
        send(c, {'event': 'WORKER_GATED', 'nonce': nonce,
                 'worker_host_pid': p, 'waiter_host_pid': os.getpid(),
                 'final_security_installed': True}, [pfd])
        os.close(pfd); extra_fds.remove(pfd)
        command(c, nonce, 'RUN_BUSINESS')
        os.write(gate_w, b'G'); os.close(gate_w); extra_fds.remove(gate_w)
        send(c, {'event': 'BUSINESS_RELEASED', 'nonce': nonce,
                 'worker_host_pid': p})
        wait_begin=cost.now();q, status = os.waitpid(p, 0)
        cost.span('wait_worker',wait_begin);cost.record('worker_waited')
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
            'threads': len(os.listdir('/proc/self/task')),'runtime':RP.snapshot('Z_ready'),'session':cost.SESSION})
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
        RP.set_attempt(nonce);RP.snapshot('Z_before_first_fork',nonce)
        p, pfd = fork_cg(LIB, fds[8])
        if p == 0:
            if death_gate:
                close_except(set(fds) | {death_gate[0]})
                os.read(death_gate[0], 1); os.close(death_gate[0])
            transition(req, fds)
            cost.exit(127)
        RP.snapshot('Z_after_first_parent',nonce)
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
            q, status = os.waitpid(p, os.WNOHANG)
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
        ready, _, _ = select.select([CTRL], [], [], .01)
        if not ready: continue
        try: req, received, _ = recv(CTRL)
        except EOFError: break
        try:
            op = req.get('op'); nonce = req.get('nonce');cost.context('Z',nonce)
            if op == 'STOP':
                if received: raise RuntimeError('STOP descriptors')
                if children or any(e['fds'] for e in attempts.values()):
                    send(CTRL, {'event': 'STOP_REJECTED', 'reason': 'live or prepared attempts'})
                    continue
                send(CTRL, {'event': 'ZYGOTE_STOP', 'state_unchanged': fingerprint() == BASE,
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
                # Retain the original seal/real-wait precondition. A snapshot
                # is prepared only after releasing this request's Z references.
                fault = entry['req'].get('fault', '')
                counter = fault.startswith('counter_')
                leaked_fd = os.dup(entry['pidfd']) if fault == 'counter_fd_leak' else None
                terminal = {'admission': entry['admission'], 's_state': entry['s_state']}
                close_pending(entry); close_fds([entry['pidfd']]); del attempts[nonce]
                if counter:
                    log('FORGET_APPLIED', nonce, **terminal,
                        active_attempts=len(attempts), tombstone_retained=nonce in used)
                if fault == 'counter_state_corruption':
                    before = fingerprint(); STATE.bytes[0] ^= 1
                    log('COUNTEREXAMPLE_INJECTED', nonce, kind='state_corruption',
                        before=before, after=fingerprint())
                elif fault == 'counter_fd_leak':
                    log('COUNTEREXAMPLE_INJECTED', nonce, kind='fd_leak', fd=leaked_fd,
                        target=os.readlink('/proc/self/fd/' + str(leaked_fd)))
                reply = {'event': 'FORGOTTEN', 'nonce': nonce, 'session': cost.SESSION,
                         'state_unchanged': fingerprint() == BASE,
                         'identity': identity(), 'active_attempts': len(attempts)}
                if counter: log('POST_FORGET_SNAPSHOT', nonce, snapshot=reply)
                if fault == 'counter_forgotten_drop':
                    log('COUNTEREXAMPLE_INJECTED', nonce, kind='forgotten_drop',
                        response_event='FORGOTTEN', sent=False)
                    continue
                if fault == 'counter_late_ack':
                    # A deliberately foreign/stale-looking receipt, not a claim
                    # that another natural attempt has already used this ID.
                    wrong = '0' * 32 if nonce != '0' * 32 else '1' * 32
                    log('COUNTEREXAMPLE_INJECTED', nonce, kind='late_ack',
                        response_event='FORGOTTEN', sent_nonce=wrong, attempted_send=True)
                    send(CTRL, dict(reply, nonce=wrong))
                    continue
                send(CTRL, reply)
                if counter: log('FORGOTTEN_SENT', nonce)
                if fault == 'counter_post_forget_zygote_death':
                    log('COUNTEREXAMPLE_INJECTED', nonce, kind='post_forget_zygote_death',
                        phase='after_forget_receipt_before_local_release', zygote_pid=os.getpid())
                    os.kill(os.getpid(), signal.SIGKILL)
            else:
                raise RuntimeError('unknown operation')
        except (AssertionError, KeyError, ValueError, RuntimeError) as e:
            send(CTRL, {'event': 'PROTOCOL_ERROR', 'nonce': req.get('nonce'), 'error': repr(e)})
        finally:
            close_fds(received)
finally:
    # EOF retires this creator. The surviving product Controller/Supervisor is
    # responsible for kill + real adoption/wait; exit alone is not cleanup ACK.
    for entry in attempts.values():
        close_pending(entry); close_fds([entry['pidfd']])
    CTRL.close();cost.usage('zygote_final_usage');cost.flush()
