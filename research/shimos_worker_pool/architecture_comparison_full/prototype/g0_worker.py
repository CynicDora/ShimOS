"""G0 fixed fresh D-Python bootstrap. Trusted code, not a general exec API.

PID1 has already atomically created this process in the business cgroup.
Only the fixed bootstrap can exec; business starts after original final policy,
no-exec filter, FD close and a nonce-bound controller permission.
"""
import os, sys, socket, time, json, ctypes, hashlib, traceback, errno
from pathlib import Path
from common import send, recv, bridge, identity, close_except
import cost
import runtime_probe as RP
import numpy_workload as NW

BOOT_NONCE = sys.argv[1]
if len(BOOT_NONCE) != 32 or any(c not in '0123456789abcdef' for c in BOOT_NONCE):
    raise RuntimeError('invalid trusted bootstrap identity')
cost.context('W', BOOT_NONCE); cost.record('worker_python_enter')
channel = socket.socket(fileno=3)
channel.settimeout(10)


def command(expected, nonce=None):
    message, fds, _ = recv(channel)
    try:
        if fds or message.get('op') != expected or (nonce is not None and message.get('nonce') != nonce):
            raise RuntimeError('G0 unexpected command, attempt identity or descriptors')
        return message
    finally:
        for fd in fds: os.close(fd)


def run():
    req = command('BOOTSTRAP', BOOT_NONCE)
    nonce = req['nonce']
    if len(nonce) != 32 or any(c not in '0123456789abcdef' for c in nonce):
        raise RuntimeError('invalid attempt identity')
    cost.context('W', nonce, repeat=req['repeat'], warmup=req['warmup'])
    lib = bridge('/probe/bridge_d.so')
    assert lib.set_base_safety() == 0
    RP.install(); RP.set_attempt(nonce)
    # This is new interpreter state, never inherited from a NumPy template.
    state = bytearray(os.urandom(65536))
    lookup = {i: i*i+17 for i in range(200)}
    fresh = dict(pid=os.getpid(), object_id=id(state), sha256=hashlib.sha256(state).hexdigest())
    os.environ.clear(); os.environ['PATH'] = '/usr/bin:/bin'
    sys.path[:] = [str(NW.PACKAGE)] + [p for p in sys.path if p.startswith(('/usr/lib/', '/lib/'))]
    close_except({channel.fileno()})
    rc = lib.drop_final(); saved_errno = ctypes.get_errno(); cost.drain_bridge(lib)
    if rc: raise OSError(saved_errno, 'G0 final security stage '+str(rc))
    if lib.forbid_exec(): raise OSError(ctypes.get_errno(), 'G0 forbid business exec')
    cost.drain_bridge(lib)
    os.setsid()
    gated_runtime = RP.snapshot('G0_W_gated', nonce)
    assert all(gated_runtime['checks'].values())
    # Actual ABI closure is observed while process is alive. This private
    # channel is closed before any NumPy/business code, never passed onward.
    send(channel, {'event': 'WORKER_GATED', 'nonce': nonce, 'pid_local': os.getpid(),
                   'identity': identity(), 'runtime': gated_runtime,
                   'maps': Path('/proc/self/maps').read_text(),
                   'fresh_state': fresh, 'numpy_loaded': NW.NP is not None,
                   'final_security_installed': True})
    cost.record('worker_business_gate_ready')
    command('RUN_BUSINESS', nonce)
    cost.record('run_business_received')
    channel.close()
    close_except(set())
    business(req, fresh, state, lookup)


def business(req, fresh, state, lookup):
    cost.record('business_enter')
    started = cost.mark()
    runtime_state = RP.snapshot('G0_W_business', req['nonce'])
    assert all(runtime_state['checks'].values())
    ident = identity()
    checks = {}
    checks['marker'] = Path('/tmp/domain-token').read_text() == req['nonce']
    checks['fresh_runtime'] = fresh['pid'] == os.getpid() and id(state) == fresh['object_id']
    checks['no_preloaded_numpy'] = NW.NP is None
    checks['no_host_path'] = not Path('/state').exists() and not Path('/evidence').exists()
    checks['no_other_workspace'] = not Path('/work/other-domain-secret').exists()
    try:
        Path('/src/input').write_text('bad'); checks['readonly'] = False
    except OSError as e:
        checks['readonly'] = e.errno == errno.EROFS
    payload = cost.mark()
    Path('/work/result').write_text(str(sum(lookup.values())))
    cost.finish('controlled_payload_compute_write', payload)
    checks['writable'] = Path('/work/result').read_text() == str(sum(i*i+17 for i in range(200)))
    libc = ctypes.CDLL(None, use_errno=True)
    f = os.open('/proc/self/ns/mnt', os.O_RDONLY)
    ret = libc.setns(f, 0); checks['setns_denied'] = ret == -1 and ctypes.get_errno() == errno.EPERM
    os.close(f)
    ret = libc.unshare(0x10000000); checks['unshare_denied'] = ret == -1 and ctypes.get_errno() == errno.EPERM
    try:
        os.chroot('/'); checks['chroot_denied'] = False
    except PermissionError: checks['chroot_denied'] = True
    try:
        os.execv('/usr/bin/python3', ['python3', '-c', 'raise SystemExit(99)']); checks['exec_denied'] = False
    except PermissionError: checks['exec_denied'] = True
    checks['caps_zero'] = all(int(ident['status'][k], 16) == 0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
    checks['nnp_seccomp'] = ident['status']['NoNewPrivs'] == '1' and ident['status']['Seccomp'] == '2'
    checks['fd_allowlist'] = set(ident['fds']) <= {'0','1','2'}
    checks['namespaces'] = ident['ns'] == req['target_ns']
    checks['cgroup'] = req['business_cgroup'] in ident['cgroup']
    checks['environment'] = dict(os.environ) == {'PATH':'/usr/bin:/bin'}
    checks['cwd'] = os.getcwd() == '/work'
    checks['root_identity'] = [os.stat('/').st_dev, os.stat('/').st_ino] == req['root_identity']
    cost.finish('worker_qualification_checks', started, checks=len(checks), includes_controlled_payload=True)
    assert len(checks) == 19
    if not all(checks.values()):
        print(json.dumps({'event':'G0_BOUNDARY_FAILURE','nonce':req['nonce'],'checks':checks}), flush=True)
        cost.exit(91)
    # Same immutable workload implementation and output validation as G1/G2.
    assert req['numpy_baseline'] == 'cold'
    result = NW.execute(req)
    print(json.dumps({'event':'WORKER_READY','group':'G0','nonce':req['nonce'],
                      'identity':ident,'fresh_state':fresh,'checks':checks,'runtime':runtime_state,
                      'numpy':{'checks':result['checks'],'output_sha256':result['output_sha256'],
                               'reference_sha256':result['reference_sha256']}}), flush=True)
    cost.record('worker_ready_emitted')
    if req['mode'] == 'nonzero': cost.record('business_end'); cost.exit(7)
    if req['mode'] == 'normal':
        if req.get('test_descendant', True):
            p = os.fork()
            if p == 0:
                started = cost.mark(); time.sleep(.04)
                cost.finish('artificial_descendant_sleep', started, requested_ns=40000000)
                print(json.dumps({'event':'DESCENDANT_DONE','pid':os.getpid()}), flush=True)
                cost.exit(0)
        cost.record('business_end'); cost.exit(0)
    p = os.fork()
    if p == 0: os.setsid()
    while True: time.sleep(1)


try:
    run()
except BaseException as e:
    try:
        send(channel, {'event':'WORKER_BOOTSTRAP_ERROR','nonce':cost.NONCE,
                       'error':repr(e),'traceback':traceback.format_exc()})
    except BaseException: pass
    traceback.print_exc()
    cost.exit(125)
