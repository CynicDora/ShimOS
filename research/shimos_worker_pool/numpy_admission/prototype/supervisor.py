"""Small trusted, unprivileged product supervisor for the reliability experiment.

This is part of the product path, not the VM's root observer.  It is the actual
ancestor/subreaper of the Controller.  It owns no namespace-construction privilege
and only manages its already delegated, private cgroup subtree and work-* dirs.
It deliberately does not attempt to recover business results after a crash.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import stat
import time
import traceback
import cost

from common import bridge, recv, send


_NONCE = re.compile(r"(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\Z")


def _fds():
    result = {}
    for name in os.listdir('/proc/self/fd'):
        try:
            result[name] = os.readlink('/proc/self/fd/' + name)
        except FileNotFoundError:
            pass  # The directory iterator itself has already closed.
    return result


def _atomic_json(path, value):
    started=cost.mark()
    temp = path.with_name(path.name + '.tmp-' + str(os.getpid()))
    with temp.open('w') as output:
        json.dump(value, output, indent=2, ensure_ascii=False)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    os.replace(temp, path)
    cost.finish('supervisor_final_json_fsync',started)


def run_supervised(controller_callable, CG, R, O, bridge_path):
    """Run a Controller and discharge crash-cleanup responsibility.

    Controller receives a private SOCK_SEQPACKET endpoint. Protocol:
      REGISTER(nonce,cgroup,workspace) + one pipe read FD -> REGISTERED(nonce)
      RETIRE(nonce,outcome,output_eof=True) -> RETIRED(nonce)
      DONE -> DONE_ACK; then Controller must exit(0).
    DONE_ACK means receipt only, not final release. Final authority is the atomic
    supervisor.json. Return 0 means all supervisor-owned resources are released;
    it never means a crashed Controller's business request succeeded.
    """
    cost.context('H');cost.record('supervisor_enter');cost.usage('supervisor_initial_usage');cost.memory('supervisor_initial_memory')
    CG, R, O = Path(CG), Path(R), Path(O)
    assert CG.is_absolute() and R.is_absolute() and O.is_absolute()
    lib = bridge(str(bridge_path))
    if lib.subreaper() or lib.set_base_safety():
        raise RuntimeError('supervisor must be a subreaper with no_new_privs')
    before = _fds()
    events_path = O / 'supervisor-events.jsonl'
    attempts, errors, wait_records, protocol_errors = {}, [], [], []
    all_reaped, controller_status = False, None
    done, eof, failure = False, False, None
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    fork_started=cost.mark();controller_pid = os.fork()
    if controller_pid == 0:
        cost.context('R');cost.record('controller_forked')
        parent.close()
        try:
            result = controller_callable(child)
            child.close()
            cost.exit(int(result or 0))
        except BaseException:
            traceback.print_exc()
            child.close()
            cost.exit(1)
    child.close()
    cost.finish('supervisor_controller_fork',fork_started,child_pid=controller_pid)
    controller_pidfd = os.pidfd_open(controller_pid)

    def event(kind, **fields):
        started=cost.mark()
        row = {'monotonic_ns': time.monotonic_ns(), 'event': kind, **fields}
        with events_path.open('a') as output:
            output.write(json.dumps(row, ensure_ascii=False) + '\n')
        cost.finish('supervisor_event_write',started,event_name=kind,nonce=fields.get('nonce',cost.NONCE),fsync=False)

    def error(message, **fields):
        item = {'message': message, **fields}
        errors.append(item)
        event('SUPERVISOR_ERROR', **item)

    def reap():
        nonlocal all_reaped, controller_status
        while True:
            started=cost.mark()
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                cost.finish('waitpid_poll',started,result='ECHILD')
                all_reaped = True
                return
            cost.finish('waitpid_poll',started,waited_pid=pid,wait_status=status)
            all_reaped = False
            if pid == 0:
                return
            item = {'pid': pid, 'wait_status': status,
                    'exitcode': os.waitstatus_to_exitcode(status),
                    'role': 'controller' if pid == controller_pid else 'adopted-child',
                    'monotonic_ns': time.monotonic_ns()}
            wait_records.append(item)
            event('SUPERVISOR_REAL_WAIT', **item)
            if pid == controller_pid:
                controller_status = status

    def close_fd(attempt):
        fd = attempt.pop('_output_fd', None)
        if fd is not None:
            os.close(fd)

    def reply(message):
        # A dead Controller cannot acknowledge our acknowledgement. Its queued
        # REGISTER still transfers useful cleanup responsibility and must be read.
        try:
            send(parent, message)
        except (BrokenPipeError, ConnectionResetError):
            event('SUPERVISOR_REPLY_PEER_GONE', message=message)

    def validate_paths(message):
        nonce = message.get('nonce', '')
        if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
            raise ValueError('invalid attempt nonce')
        cg, work = CG / ('d-' + nonce), R / ('work-' + nonce)
        if message.get('cgroup') != str(cg) or message.get('workspace') != str(work):
            raise ValueError('attempt paths do not match nonce and owned roots')
        for path in (cg, work):
            if path.exists() and (path.is_symlink() or not path.is_dir()):
                raise ValueError('owned path must be a real directory: ' + str(path))
        return nonce, cg, work

    def receive():
        nonlocal eof, done
        try:
            message, passed, _ = recv(parent)
        except EOFError:
            eof = True
            event('CONTROLLER_CHANNEL_EOF')
            return
        cost.context('H',message.get('nonce'));service_started=cost.mark()
        try:
            operation = message.get('op', message.get('event'))
            if operation == 'REGISTER':
                nonce, cg, work = validate_paths(message)
                if len(passed) != 1:
                    raise ValueError('REGISTER requires exactly one output read FD')
                fd = passed[0]
                if not stat.S_ISFIFO(os.fstat(fd).st_mode):
                    raise ValueError('REGISTER output must be a pipe')
                if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
                    raise ValueError('REGISTER output must be read-only')
                if nonce not in attempts:
                    os.set_blocking(fd, False)
                    attempts[nonce] = {
                        'nonce': nonce, 'cgroup': str(cg), 'workspace': str(work),
                        'registered': True, 'retired': False, 'business_result': 'UNKNOWN',
                        'output_eof': False, 'recovered_output_bytes': 0, '_output_fd': fd,
                        'registered_ns': time.monotonic_ns(),
                    }
                    passed.clear()
                else:
                    if attempts[nonce]['retired']:
                        raise ValueError('cannot reuse retired attempt identity')
                    old = os.fstat(attempts[nonce]['_output_fd'])
                    new = os.fstat(fd)
                    if (old.st_dev, old.st_ino) != (new.st_dev, new.st_ino):
                        raise ValueError('duplicate REGISTER changes output object')
                event('ATTEMPT_REGISTERED', nonce=nonce, cgroup=str(cg), workspace=str(work))
                reply({'event': 'REGISTERED', 'nonce': nonce})
            elif operation == 'RETIRE':
                nonce = message.get('nonce')
                if passed or nonce not in attempts:
                    raise ValueError('RETIRE requires a registered attempt and no FDs')
                attempt = attempts[nonce]
                if message.get('output_eof') is not True:
                    raise ValueError('RETIRE requires observed output EOF')
                if Path(attempt['cgroup']).exists() or Path(attempt['workspace']).exists():
                    raise ValueError('RETIRE before domain and workspace release')
                close_fd(attempt)
                attempt.update(retired=True, output_eof=True,
                               outcome=message.get('outcome'), business_result=message.get('outcome'),
                               resources_removed=True, retired_ns=time.monotonic_ns())
                event('ATTEMPT_RETIRED', nonce=nonce, outcome=message.get('outcome'))
                reply({'event': 'RETIRED', 'nonce': nonce})
            elif operation == 'DONE':
                if passed or done:
                    raise ValueError('duplicate DONE or unexpected FDs')
                if any(not item['retired'] for item in attempts.values()):
                    raise ValueError('DONE with unretired attempts')
                done = True
                reply({'event': 'DONE_ACK'})
                event('CONTROLLER_DONE_RECEIVED')
            else:
                raise ValueError('unknown supervisor operation: ' + repr(operation))
        finally:
            for fd in passed:
                os.close(fd)
            cost.finish('supervisor_message_service',service_started,message=message.get('op',message.get('event')))

    def owned_domains():
        result = []
        for path in CG.iterdir():
            if not path.is_dir() or path.name == 'client':
                continue
            if path.is_symlink():
                error('refuse symlink cgroup', path=str(path))
            elif path.name == 'template' or (path.name.startswith('d-') and _NONCE.fullmatch(path.name[2:])):
                result.append(path)
            else:
                error('unrecognized private cgroup; not removed', path=str(path))
        return result

    def kill_domain(path):
        try:
            (path / 'cgroup.kill').write_text('1')
            event('SUPERVISOR_CGROUP_KILL', cgroup=str(path))
        except FileNotFoundError:
            pass
        except OSError as exc:
            error('cgroup kill failed', path=str(path), detail=repr(exc))

    def is_empty(path):
        try:
            return 'populated 0' in (path / 'cgroup.events').read_text()
        except FileNotFoundError:
            return True
        except OSError as exc:
            error('cannot observe cgroup emptiness', path=str(path), detail=repr(exc))
            return False

    def cgroup_state(path):
        result = {'path': str(path), 'exists': path.exists()}
        if result['exists']:
            for name in ('cgroup.events', 'cgroup.procs', 'pids.current', 'memory.current'):
                try:
                    result[name] = (path / name).read_text()
                except OSError as exc:
                    result[name] = {'error': repr(exc)}
        return result

    def drain():
        for nonce, attempt in attempts.items():
            fd = attempt.get('_output_fd')
            if fd is None or attempt['output_eof']:
                continue
            for _ in range(128):
                try:
                    data = os.read(fd, 65536)
                except BlockingIOError:
                    break
                except OSError as exc:
                    error('cannot drain output', nonce=nonce, detail=repr(exc))
                    close_fd(attempt)
                    break
                if not data:
                    attempt['output_eof'] = True
                    event('SUPERVISOR_OUTPUT_EOF', nonce=nonce)
                    close_fd(attempt)
                    break
                with (O / ('supervisor-output-' + nonce + '.log')).open('ab') as output:
                    output.write(data)
                attempt['recovered_output_bytes'] += len(data)

    event('SUPERVISOR_STARTED', pid=os.getpid(), controller_pid=controller_pid,
          uid=os.getuid(), private_cgroup=str(CG), fd_before=before)
    deadline = time.monotonic() + 60  # Fault containment, not a measured latency.
    try:
        while True:
            reap()
            if controller_status is not None and controller_status != 0:
                failure = 'CONTROLLER_NONZERO_OR_SIGNAL'
                break
            if not eof:
                poll_started=cost.mark()
                readable, _, _ = select.select([parent], [], [], .01)
                cost.finish('supervisor_poll',poll_started,ready_count=len(readable))
                if readable:
                    receive()
            if eof and not done:
                failure = 'CONTROL_CHANNEL_CLOSED_WITHOUT_DONE'
                break
            if controller_status is not None:
                if not done:
                    # A message sent just before exit may still be queued.
                    if not eof:
                        continue
                    failure = 'CONTROLLER_EXITED_WITHOUT_DONE'
                break
            if time.monotonic() >= deadline:
                failure = 'CONTROLLER_DEADLINE'
                break
    except BaseException as exc:
        failure = 'SUPERVISOR_PROTOCOL_OR_RUNTIME_ERROR'
        item = {'reason': failure, 'detail': repr(exc), 'traceback': traceback.format_exc()}
        protocol_errors.append(item)
        event('SUPERVISOR_PROTOCOL_ERROR', **item)

    if failure is None:
        reap()
        if not all_reaped or owned_domains() or any(R.glob('work-*')):
            failure = 'DONE_WITH_RESIDUAL_RESOURCES'
            protocol_errors.append({'reason': failure})
            event(failure)

    recovery_started_ns = None
    if failure is not None:
        recovery_started_ns = time.monotonic_ns()
        cost.record('supervisor_recovery_begin',reason=failure)
        event('SUPERVISOR_RECOVERY_START', reason=failure)
        # Stop the Controller if still alive, so it cannot create another domain.
        # The pidfd remains tied to this actual child, even after a concurrent exit.
        if controller_status is None:
            try:
                signal.pidfd_send_signal(controller_pidfd, signal.SIGKILL)
                event('SUPERVISOR_STOP_CONTROLLER', pid=controller_pid)
            except ProcessLookupError:
                pass
            except OSError as exc:
                error('cannot stop controller', detail=repr(exc))
        # The last REGISTER/RETIRE may be queued even if real wait already
        # observed Controller SIGKILL. Receive and retain its SCM_RIGHTS object.
        while not eof:
            readable, _, _ = select.select([parent], [], [], 0)
            if not readable:
                break
            try:
                receive()
            except BaseException as exc:
                item = {'reason': 'QUEUED_CONTROL_MESSAGE_ERROR', 'detail': repr(exc)}
                protocol_errors.append(item)
                event('SUPERVISOR_PROTOCOL_ERROR', **item)
                break
        # Seal the process creator before terminating domains. cgroup.kill itself
        # is not a persistent admission barrier. No new work is admitted here.
        template = CG / 'template'
        if template.exists():
            kill_domain(template)
        recovery_deadline = time.monotonic() + 8
        while time.monotonic() < recovery_deadline:
            reap()
            if is_empty(template) and controller_status is not None:
                break
            time.sleep(.005)
        if not is_empty(template):
            error('template creator not confirmed stopped')
        event('SUPERVISOR_CREATORS_STOPPED', controller_wait_status=controller_status,
              template=cgroup_state(template))
        for path in owned_domains():
            if path != template:
                nonce = path.name[2:]
                attempts.setdefault(nonce, {
                    'nonce': nonce, 'workspace': str(R / ('work-' + nonce)), 'cgroup': str(path),
                    'registered': False, 'retired': False, 'business_result': 'UNKNOWN',
                    'output_eof': None, 'output_observation': 'not registered before Controller died',
                })
                kill_domain(path)
        while time.monotonic() < recovery_deadline:
            reap()
            drain()
            if all_reaped and all(is_empty(path) for path in owned_domains()):
                break
            time.sleep(.005)
        reap()
        drain()
        if not all_reaped:
            error('real wait did not reach ECHILD')
        event('SUPERVISOR_QUIESCENCE', echild=all_reaped,
              cgroups=[cgroup_state(path) for path in owned_domains()])
        # There is no active Controller or Zygote now. Snapshot ordinary result
        # files before deletion, but never promote their content to success.
        for work in R.glob('work-*'):
            nonce = work.name[5:]
            if not _NONCE.fullmatch(nonce) or work.is_symlink() or not work.is_dir():
                error('refuse unrecognized workspace', path=str(work))
                continue
            attempt = attempts.setdefault(nonce, {
                'nonce': nonce, 'workspace': str(work), 'cgroup': str(CG / ('d-' + nonce)),
                'registered': False, 'retired': False, 'business_result': 'UNKNOWN',
                'output_eof': None, 'output_observation': 'not registered before Controller died',
            })
            safe_to_read = all_reaped and all(is_empty(path) for path in owned_domains())
            attempt['side_effects'] = {}
            if safe_to_read:
                for entry in work.iterdir():
                    try:
                        mode = entry.lstat().st_mode
                        record = {'type': 'other'}
                        if stat.S_ISLNK(mode):
                            record = {'type': 'symlink', 'target': os.readlink(entry)}
                        elif stat.S_ISREG(mode):
                            fd = os.open(entry, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
                            with os.fdopen(fd, 'rb') as source:
                                size = os.fstat(source.fileno()).st_size
                                content = source.read(65537)
                            record = {'type': 'file', 'size': size,
                                      'text_prefix': content[:65536].decode(errors='replace'),
                                      'truncated': len(content) > 65536}
                        attempt['side_effects'][entry.name] = record
                    except OSError as exc:
                        error('side effect observation failed', path=str(entry), detail=repr(exc))
                try:
                    shutil.rmtree(work)
                    event('SUPERVISOR_WORKSPACE_REMOVED', path=str(work))
                except OSError as exc:
                    error('workspace removal failed', path=str(work), detail=repr(exc))
        if all_reaped:
            for root in owned_domains():
                if not is_empty(root):
                    error('domain still populated', path=str(root))
                    continue
                paths = sorted((p for p in root.rglob('*') if p.is_dir()),
                               key=lambda p: len(p.parts), reverse=True) + [root]
                for path in paths:
                    try:
                        path.rmdir()
                        event('SUPERVISOR_CGROUP_REMOVED', path=str(path))
                    except OSError as exc:
                        error('cgroup removal failed', path=str(path), detail=repr(exc))

    # Release the supervisor's own kernel references before claiming release.
    release_started=cost.mark()
    for attempt in attempts.values():
        close_fd(attempt)
        attempt['resources_removed'] = (not Path(attempt['cgroup']).exists()
                                        and not Path(attempt['workspace']).exists())
    parent.close()
    os.close(controller_pidfd)
    reap()
    after = _fds()
    leftovers = [str(p) for p in CG.iterdir() if p.is_dir() and p.name != 'client']
    work_leftovers = [str(p) for p in R.glob('work-*')]
    if before != after:
        error('supervisor FD inventory differs after release', before=before, after=after)
    output_confirmed = all(item.get('output_eof') is True for item in attempts.values()
                           if item.get('registered'))
    if not output_confirmed:
        error('registered attempt output EOF not confirmed')
    released = not leftovers and not work_leftovers and all_reaped and output_confirmed and not errors
    cost.finish('supervisor_final_resource_validation',release_started,released=released)
    result = {
        'pid': os.getpid(), 'controller_pid': controller_pid,
        'controller_wait_status': controller_status, 'done_received': done,
        'failure_reason': failure, 'recovery_started_ns': recovery_started_ns,
        'wait_records': wait_records, 'echild': all_reaped,
        'fd_before': before, 'fd_after': after, 'errors': errors, 'protocol_errors': protocol_errors,
        'attempts': list(attempts.values()), 'remaining_cgroups': leftovers,
        'remaining_workspaces': work_leftovers, 'resources_removed': released,
        'release_state': 'RELEASED' if released else 'INCOMPLETE',
        'business_result': 'CONTROLLER_REPORTED' if failure is None else 'UNKNOWN',
        'observer_cleanup_used': False,
    }
    _atomic_json(O / 'supervisor.json', result)
    event('SUPERVISOR_FINISHED', release_state=result['release_state'], business_result=result['business_result'])
    cost.record('supervisor_released',released=released);cost.usage('supervisor_final_usage');cost.memory('supervisor_final_memory');cost.flush()
    return 0 if released else 1
