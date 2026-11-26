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
_RECOVERY_STREAM_LIMIT = 1024 * 1024
_SIDE_EFFECT_ENTRY_LIMIT = 128
_SIDE_EFFECT_TOTAL_LIMIT = 1024 * 1024


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
      Warm REGISTER(nonce,cgroup,workspace) + one pipe read FD -> REGISTERED(nonce)
      Tool REGISTER(...,streams=['stdout','stderr']) + two read FDs in that order
      RETIRE(nonce,outcome,output_eof=True[,stream_eof={...}]) -> RETIRED(nonce)
      Tool RETIRE requires both named stream EOF assertions. Optional
      stream_complete reports content completeness separately from EOF.
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

    def close_stream(stream):
        fd = stream.pop('_fd', None)
        if fd is not None:
            os.close(fd)

    def output_totals(attempt):
        streams = list(attempt.get('output_streams', {}).values())
        if not streams:
            return
        attempt['output_eof'] = all(stream['output_eof'] for stream in streams)
        # Historical recovered_output_bytes means bytes read by H, including
        # bytes deliberately discarded after the bounded storage allowance.
        attempt['recovered_output_bytes'] = sum(stream['drained_bytes'] for stream in streams)
        attempt['stored_output_bytes'] = sum(stream['stored_bytes'] for stream in streams)
        attempt['discarded_output_bytes'] = sum(stream['discarded_bytes'] for stream in streams)
        attempt['output_truncated'] = any(stream['truncated'] for stream in streams)
        completeness = [stream['complete'] for stream in streams]
        attempt['output_complete'] = (False if False in completeness else
                                      True if all(value is True for value in completeness) else None)

    def close_fd(attempt):
        for stream in attempt.get('output_streams', {}).values():
            close_stream(stream)

    def outputs_eof():
        return all(item.get('output_eof') is True for item in attempts.values()
                   if item.get('registered'))

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
                names = message.get('streams', ['combined'])
                if ('streams' in message and names != ['stdout', 'stderr']) or not isinstance(names, list):
                    raise ValueError('Tool REGISTER streams must be stdout,stderr in that order')
                if len(passed) != len(names):
                    raise ValueError('REGISTER requires one read FD per named output stream')
                identities = []
                for fd in passed:
                    info = os.fstat(fd)
                    if not stat.S_ISFIFO(info.st_mode):
                        raise ValueError('REGISTER output must be a pipe')
                    if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
                        raise ValueError('REGISTER output must be read-only')
                    identities.append((info.st_dev, info.st_ino))
                if len(set(identities)) != len(identities):
                    raise ValueError('REGISTER streams must be distinct pipe objects')
                if nonce not in attempts:
                    streams = {}
                    for name, fd in zip(names, passed):
                        os.set_blocking(fd, False)
                        streams[name] = {
                            'output_eof': False, 'eof_source': None,
                            'drained_bytes': 0, 'stored_bytes': 0, 'discarded_bytes': 0,
                            'stored_bytes_exact': True, 'truncated': False, 'complete': None,
                            'storage_limit_bytes': _RECOVERY_STREAM_LIMIT, '_fd': fd,
                        }
                    attempts[nonce] = {
                        'nonce': nonce, 'cgroup': str(cg), 'workspace': str(work),
                        'registered': True, 'retired': False, 'business_result': 'UNKNOWN',
                        'streams': list(names), 'output_streams': streams,
                        'output_observation': 'controller_not_retired',
                        'registered_ns': time.monotonic_ns(),
                    }
                    output_totals(attempts[nonce])
                    passed.clear()
                else:
                    if attempts[nonce]['retired']:
                        raise ValueError('cannot reuse retired attempt identity')
                    if names != attempts[nonce]['streams']:
                        raise ValueError('duplicate REGISTER changes output stream names')
                    for name, identity in zip(names, identities):
                        old_fd = attempts[nonce]['output_streams'][name].get('_fd')
                        if old_fd is None:
                            raise ValueError('duplicate REGISTER after output stream closed')
                        old = os.fstat(old_fd)
                        if (old.st_dev, old.st_ino) != identity:
                            raise ValueError('duplicate REGISTER changes output object')
                event('ATTEMPT_REGISTERED', nonce=nonce, cgroup=str(cg), workspace=str(work), streams=names)
                reply({'event': 'REGISTERED', 'nonce': nonce})
            elif operation == 'RETIRE':
                nonce = message.get('nonce')
                if passed or nonce not in attempts:
                    raise ValueError('RETIRE requires a registered attempt and no FDs')
                attempt = attempts[nonce]
                if message.get('output_eof') is not True:
                    raise ValueError('RETIRE requires observed output EOF')
                names = attempt['streams']
                if names == ['stdout', 'stderr']:
                    stream_eof = message.get('stream_eof')
                    if (not isinstance(stream_eof, dict) or set(stream_eof) != set(names)
                            or any(value is not True for value in stream_eof.values())):
                        raise ValueError('Tool RETIRE requires EOF for both stdout and stderr')
                stream_complete = message.get('stream_complete')
                if stream_complete is not None:
                    if (not isinstance(stream_complete, dict) or set(stream_complete) != set(names)
                            or any(value is not None and type(value) is not bool
                                   for value in stream_complete.values())):
                        raise ValueError('RETIRE stream_complete must map every stream to bool or null')
                if Path(attempt['cgroup']).exists() or Path(attempt['workspace']).exists():
                    raise ValueError('RETIRE before domain and workspace release')
                for name, stream in attempt['output_streams'].items():
                    stream.update(output_eof=True, eof_source='controller_retire',
                                  complete=stream_complete[name] if stream_complete is not None else None)
                close_fd(attempt)
                output_totals(attempt)
                attempt.update(retired=True, output_observation='controller_retired',
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
            for name, stream in attempt.get('output_streams', {}).items():
                fd = stream.get('_fd')
                if fd is None or stream['output_eof']:
                    continue
                attempt['output_observation'] = 'supervisor_recovery_only_controller_prefix_may_be_missing'
                # R may already have read bytes without persisting them. Neither
                # the last EOF nor the recovered suffix proves content complete.
                stream['complete'] = None
                for _ in range(128):
                    try:
                        data = os.read(fd, 65536)
                    except BlockingIOError:
                        break
                    except OSError as exc:
                        error('cannot drain output', nonce=nonce, stream=name, detail=repr(exc))
                        stream['read_error'] = repr(exc)
                        close_stream(stream)
                        break
                    if not data:
                        stream.update(output_eof=True, eof_source='supervisor_read')
                        event('SUPERVISOR_OUTPUT_EOF', nonce=nonce, stream=name)
                        close_stream(stream)
                        break
                    stream['drained_bytes'] += len(data)
                    remaining = max(0, _RECOVERY_STREAM_LIMIT - stream['stored_bytes'])
                    saved = 0
                    if remaining and 'storage_error' not in stream:
                        suffix = '' if name == 'combined' else '-' + name
                        path = O / ('supervisor-output-' + nonce + suffix + '.log')
                        try:
                            with path.open('ab') as output:
                                saved = output.write(data[:remaining])
                            stream['stored_bytes'] += saved
                        except OSError as exc:
                            saved = 0
                            stream['storage_error'] = repr(exc)
                            stream['stored_bytes_exact'] = False
                            error('cannot save recovered output', nonce=nonce, stream=name, detail=repr(exc))
                    discarded = len(data) - saved
                    stream['discarded_bytes'] += discarded
                    stream['truncated'] = stream['truncated'] or discarded > 0
            output_totals(attempt)

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
            if all_reaped and all(is_empty(path) for path in owned_domains()) and outputs_eof():
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
                attempt['side_effect_snapshot_limits'] = {
                    'max_entries': _SIDE_EFFECT_ENTRY_LIMIT,
                    'max_total_content_bytes': _SIDE_EFFECT_TOTAL_LIMIT,
                    'max_file_content_bytes': 65536,
                }
                snapshot_bytes = 0
                snapshot_entries = 0
                # scandir streams directory entries; Path.iterdir would eagerly
                # materialize every untrusted filename on this Python version.
                with os.scandir(work) as entries:
                    for item in entries:
                        if snapshot_entries >= _SIDE_EFFECT_ENTRY_LIMIT:
                            attempt['side_effect_snapshot_truncated'] = True
                            break
                        snapshot_entries += 1
                        entry = Path(item.path)
                        try:
                            mode = entry.lstat().st_mode
                            record = {'type': 'other', 'content_read': False}
                            if stat.S_ISLNK(mode):
                                record = {'type': 'symlink', 'target': os.readlink(entry)}
                            elif stat.S_ISREG(mode):
                                # The tree has quiesced. Still use NOFOLLOW,
                                # NONBLOCK and fstat on the opened object so a FIFO,
                                # device or changed symlink cannot block this read.
                                fd = os.open(entry, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
                                with os.fdopen(fd, 'rb') as source:
                                    info = os.fstat(source.fileno())
                                    if not stat.S_ISREG(info.st_mode):
                                        raise OSError('side effect object changed to non-regular file')
                                    allowance = min(65536, _SIDE_EFFECT_TOTAL_LIMIT - snapshot_bytes)
                                    content = source.read(allowance) if allowance else b''
                                snapshot_bytes += len(content)
                                record = {'type': 'file', 'size': info.st_size,
                                          'text_prefix': content.decode(errors='replace'),
                                          'content_bytes': len(content), 'content_read': bool(allowance),
                                          'truncated': info.st_size > len(content)}
                                if info.st_size > len(content):
                                    attempt['side_effect_snapshot_truncated'] = True
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
    output_confirmed = outputs_eof()
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
