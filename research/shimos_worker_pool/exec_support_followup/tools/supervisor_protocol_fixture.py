"""Private-guest-only real H protocol and workspace recovery fixture.

The VM driver calls run_fixture after creating/delegating the private roots and
dropping to H's ordinary identity. This file starts no VM and emulates no H wait
or cleanup. Product H receives real SCM_RIGHTS and runs its usual recovery path.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import sys
import time
import traceback
import uuid


CASES = (
    'register_missing_fds', 'register_extra_fd', 'register_duplicate_pipe',
    'register_nonpipe', 'register_write_end', 'register_bad_order',
    'register_bad_names', 'register_path_identity', 'register_same_nonce_new_pipe',
    'register_same_nonce_swapped_pipe', 'register_identical_duplicate',
    'register_first_swapped_pipe', 'retire_missing_stream', 'retire_false_stream',
    'retire_fake_eof_buffered', 'retire_fake_eof_open_writer', 'retire_dropped',
    'retire_late_queued', 'retire_duplicate', 'done_unretired',
    'unknown_op_with_fd', 'malformed_json_with_fd',
    'workspace_fifo_symlink_sparse', 'workspace_many_entries',
    'workspace_total_bytes', 'workspace_read_denied', 'workspace_scan_denied',
    'workspace_delete_denied',
    'register_named_fifo',
)

_EXPECTED_REJECTION = set(CASES[:10]) | {
    'retire_missing_stream', 'retire_false_stream', 'retire_fake_eof_buffered',
    'retire_fake_eof_open_writer', 'done_unretired', 'unknown_op_with_fd',
    'malformed_json_with_fd',
    'register_named_fifo',
}


def _event(path, kind, **fields):
    row = {'event': kind, 'pid': os.getpid(), 'monotonic_ns': time.monotonic_ns(), **fields}
    data = (json.dumps(row, sort_keys=True) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise OSError('fixture journal short write')
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _controller(case, channel, CG, R, O):
    from common import recv, send
    journal = O / 'protocol-fixture-controller-events.jsonl'
    nonce = uuid.uuid4().hex
    cg, work = CG / ('d-' + nonce), R / ('work-' + nonce)
    cg.mkdir()
    work.mkdir()
    opened = []

    def pipe():
        pair = os.pipe2(os.O_CLOEXEC)
        opened.extend(pair)
        return pair

    out_r, out_w = pipe()
    err_r, err_w = pipe()
    message = {'op': 'REGISTER', 'nonce': nonce, 'cgroup': str(cg),
               'workspace': str(work), 'streams': ['stdout', 'stderr']}
    _event(journal, 'FIXTURE_STARTED', case=case, nonce=nonce,
           cgroup=str(cg), workspace=str(work),
           pipe_objects={name: {'dev': os.fstat(fd).st_dev, 'ino': os.fstat(fd).st_ino,
                                'capacity': fcntl.fcntl(fd, fcntl.F_GETPIPE_SZ)}
                         for name, fd in [('stdout', out_r), ('stderr', err_r)]})

    def transmit(obj, fds=(), await_reply=True):
        _event(journal, 'FIXTURE_SEND', message=obj, fd_count=len(fds))
        send(channel, obj, fds)
        if not await_reply:
            return None
        channel.settimeout(3)
        answer, passed, _ = recv(channel)
        try:
            _event(journal, 'FIXTURE_REPLY', message=answer, fd_count=len(passed))
            return answer
        finally:
            for fd in passed:
                os.close(fd)

    def close(fd):
        if fd in opened:
            os.close(fd)
            opened.remove(fd)

    def remove_empty_roots():
        cg.rmdir()
        work.rmdir()
        _event(journal, 'FIXTURE_REMOVED_EMPTY_ROOTS')

    def retire(**changes):
        obj = {'op': 'RETIRE', 'nonce': nonce, 'outcome': 'FIXTURE_ONLY',
               'output_eof': True, 'stream_eof': {'stdout': True, 'stderr': True}}
        obj.update(changes)
        return obj

    def crash():
        _event(journal, 'FIXTURE_CONTROLLER_SIGKILL')
        os.kill(os.getpid(), signal.SIGKILL)
        raise AssertionError('SIGKILL unexpectedly returned')

    try:
        if case == 'malformed_json_with_fd':
            import array
            _event(journal, 'FIXTURE_SEND_MALFORMED_JSON', fd_count=1)
            channel.sendmsg([b'{invalid'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                           array.array('i', [out_r]))])
            time.sleep(2)
            return 0
        if case == 'unknown_op_with_fd':
            transmit({'op': 'NOT_AN_OPERATION'}, [out_r])
            return 0
        if case.startswith('register_') and case in _EXPECTED_REJECTION and case not in (
                'register_same_nonce_new_pipe', 'register_same_nonce_swapped_pipe'):
            fds = [out_r, err_r]
            if case == 'register_missing_fds':
                fds = [out_r]
            elif case == 'register_extra_fd':
                extra, _ = pipe()
                fds.append(extra)
            elif case == 'register_duplicate_pipe':
                fds = [out_r, out_r]
            elif case == 'register_nonpipe':
                regular = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
                opened.append(regular)
                fds = [out_r, regular]
            elif case == 'register_write_end':
                fds = [out_r, err_w]
            elif case == 'register_bad_order':
                message['streams'] = ['stderr', 'stdout']
            elif case == 'register_bad_names':
                message['streams'] = ['stdout', 'wrong']
            elif case == 'register_path_identity':
                message['workspace'] = str(R / ('work-' + '0' * 32))
            elif case == 'register_named_fifo':
                fifo_path = work / 'named-fifo'
                os.mkfifo(fifo_path, 0o600)
                fifo_fd = os.open(fifo_path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                opened.append(fifo_fd)
                fds = [out_r, fifo_fd]
            transmit(message, fds)
            if case == 'register_named_fifo':
                _event(journal, 'NAMED_FIFO_WAS_REGISTERED', path=str(fifo_path))
                fifo_path.unlink()
                close(out_w)
                close(err_w)
                remove_empty_roots()
                transmit(retire())
                transmit({'op': 'DONE'})
            return 0

        fds = [err_r, out_r] if case == 'register_first_swapped_pipe' else [out_r, err_r]
        transmit(message, fds)
        if case == 'register_same_nonce_new_pipe':
            new_r, _ = pipe()
            transmit(message, [out_r, new_r])
            return 0
        if case == 'register_same_nonce_swapped_pipe':
            transmit(message, [err_r, out_r])
            return 0
        if case == 'register_identical_duplicate':
            transmit(message, [out_r, err_r])
        if case == 'done_unretired':
            transmit({'op': 'DONE'})
            return 0

        if case.startswith('workspace_'):
            if case == 'workspace_fifo_symlink_sparse':
                os.mkfifo(work / 'fifo', 0o600)
                (work / 'symlink').symlink_to('/state')
                with (work / 'sparse').open('wb') as output:
                    output.truncate(1 << 40)
            elif case == 'workspace_many_entries':
                for number in range(200):
                    (work / ('entry-%03d' % number)).write_text('bounded fixture\n')
            elif case == 'workspace_total_bytes':
                for number in range(20):
                    with (work / ('sparse-%02d' % number)).open('wb') as output:
                        output.truncate(70000)
            elif case == 'workspace_read_denied':
                (work / 'unreadable').write_text('cannot read as H\n')
                (work / 'unreadable').chmod(0)
            elif case == 'workspace_scan_denied':
                (work / 'inside').write_text('cannot enumerate as H\n')
                work.chmod(0)
            elif case == 'workspace_delete_denied':
                locked = work / 'locked'
                locked.mkdir()
                (locked / 'inside').write_text('cannot unlink as H\n')
                locked.chmod(0o500)
            os.write(out_w, b'workspace recovery stdout\n')
            os.write(err_w, b'workspace recovery stderr\n')
            close(out_w)
            close(err_w)
            crash()

        if case in ('retire_fake_eof_buffered', 'retire_fake_eof_open_writer'):
            if case.endswith('buffered'):
                os.write(out_w, b'not-yet-drained-stdout\n')
                os.write(err_w, b'not-yet-drained-stderr\n')
            remove_empty_roots()
            transmit(retire())
            # A baseline RETIRED reply while these writers remain alive proves
            # H accepted the false assertion; this is recorded before exit.
            _event(journal, 'FALSE_EOF_WAS_ACKNOWLEDGED', writers_still_open=True)
            close(out_w)
            close(err_w)
            transmit({'op': 'DONE'})
            return 0

        close(out_w)
        close(err_w)
        remove_empty_roots()
        if case == 'retire_missing_stream':
            transmit(retire(stream_eof={'stdout': True}))
        elif case == 'retire_false_stream':
            transmit(retire(stream_eof={'stdout': True, 'stderr': False}))
        elif case == 'retire_dropped':
            _event(journal, 'RETIRE_DELIBERATELY_DROPPED')
            return 0
        elif case == 'retire_late_queued':
            transmit(retire(), await_reply=False)
            crash()
        else:
            transmit(retire())
            if case == 'retire_duplicate':
                transmit(retire())
            transmit({'op': 'DONE'})
        return 0
    finally:
        for fd in opened:
            os.close(fd)


def run_fixture(case, CG, R, O, bridge_path, options=None):
    """Use real product H with the faulty Controller; return its actual status.

    options may explicitly contain h_faults for supervisor_faults.install().
    A fixture verdict is separate from H release status and business result.
    """
    if case not in CASES:
        raise ValueError('unknown supervisor protocol fixture case')
    if Path('/run/native-benchmark-lab').read_text().strip() != 'private-stock-linux-benchmark-vm':
        raise RuntimeError('only the private benchmark guest may run this fixture')
    if os.getuid() == 0:
        raise RuntimeError('run H fixture only after dropping guest root identity')
    CG, R, O = [Path(x) for x in (CG, R, O)]
    if any(not x.is_absolute() or not x.is_dir() for x in (CG, R, O)):
        raise ValueError('existing absolute delegated roots are required')
    options = dict(options or {})
    if set(options) - {'h_faults'}:
        raise ValueError('unknown fixture options')
    from supervisor import run_supervised
    fault = None
    if options.get('h_faults') is not None:
        from supervisor_faults import install
        fault = install(options['h_faults'], O)
    try:
        rc = run_supervised(lambda channel: _controller(case, channel, CG, R, O),
                            CG, R, O, bridge_path)
    except BaseException as exc:
        _event(O / 'protocol-fixture-h-events.jsonl', 'PRODUCT_H_EXCEPTION',
               case=case, exception=repr(exc), traceback=traceback.format_exc())
        raise
    finally:
        if fault is not None:
            fault.restore()
    result = json.loads((O / 'supervisor.json').read_text())
    rejected = bool(result['protocol_errors'])
    expected_rejection = case in _EXPECTED_REJECTION
    verdict = {
        'case': case, 'h_exit_code': rc, 'h_release_state': result['release_state'],
        'expected_protocol_rejection': expected_rejection,
        'observed_protocol_rejection': rejected,
        'protocol_expectation_met': rejected == expected_rejection,
        'first_registration_stream_identity_limit': case == 'register_first_swapped_pipe',
        'business_success_claimed': False,
        'observer_cleanup_used': False,
    }
    (O / 'protocol-fixture-verdict.json').write_text(json.dumps(verdict, indent=2) + '\n')
    return rc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prototype', required=True)
    parser.add_argument('--cgroup', required=True)
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--bridge', required=True)
    parser.add_argument('--case', required=True, choices=CASES)
    parser.add_argument('--h-faults-json')
    args = parser.parse_args()
    sys.path.insert(0, args.prototype)
    options = {'h_faults': json.loads(args.h_faults_json)} if args.h_faults_json else None
    return run_fixture(args.case, args.cgroup, args.workspace, args.evidence, args.bridge, options)


if __name__ == '__main__':
    sys.exit(main())
