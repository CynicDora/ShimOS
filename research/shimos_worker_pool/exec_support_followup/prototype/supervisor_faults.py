"""Explicit, process-scoped fault injection for H recovery qualification only.

Install in the actual H process before run_supervised(). The forked Controller
inherits these Python objects but is excluded by PID. Ordinary product runs do
not import or install this module. No filesystem capacity or kernel policy is
changed. Only writes to H's specifically named recovered-output files can fail;
supervisor.json and the event/fixture journals use their normal healthy paths.
"""
import errno
import json
import os
from pathlib import Path
import re
import time


_RECOVERED = re.compile(
    r'supervisor-output-(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})'
    r'(?:-(stdout|stderr))?\.log\Z')


class _InjectedOutput:
    def __init__(self, file, owner, path, stream):
        self._file, self._owner, self._path, self._stream = file, owner, path, stream

    def __enter__(self):
        self._file.__enter__()
        return self

    def __exit__(self, *args):
        return self._file.__exit__(*args)

    def __getattr__(self, name):
        return getattr(self._file, name)

    def write(self, data):
        owner, stream = self._owner, self._stream
        prior = owner.bytes_written.get(stream, 0)
        allowance = max(0, owner.after_bytes - prior)
        if len(data) <= allowance:
            n = self._file.write(data)
            owner.bytes_written[stream] = prior + n
            return n
        # A controlled partial write can precede the exception. H must not then
        # present its logical stored-byte counter as an exact file length.
        partial = 0
        if allowance:
            partial = self._file.write(data[:allowance])
            self._file.flush()
            owner.bytes_written[stream] = prior + partial
        owner.event('H_RECOVERY_WRITE_FAULT', path=str(self._path), stream=stream,
                    errno=owner.errno, errno_name=errno.errorcode[owner.errno],
                    requested_bytes=len(data), partial_bytes=partial,
                    successful_bytes_before_fault=owner.bytes_written.get(stream, 0))
        raise OSError(owner.errno, 'explicit H recovered-output write fault', str(self._path))


class InstalledFault:
    def __init__(self, config, evidence_dir):
        allowed = {'output_write_errno', 'streams', 'after_bytes'}
        if set(config) - allowed:
            raise ValueError('unknown H fault configuration keys')
        fault_name = config.get('output_write_errno')
        if fault_name not in ('ENOSPC', 'EIO'):
            raise ValueError('output_write_errno must be ENOSPC or EIO')
        self.streams = config.get('streams', ['stdout', 'stderr'])
        if (not isinstance(self.streams, list) or not self.streams
                or len(set(self.streams)) != len(self.streams)
                or any(x not in ('stdout', 'stderr', 'combined') for x in self.streams)):
            raise ValueError('streams must be distinct known stream names')
        self.after_bytes = config.get('after_bytes', 0)
        if type(self.after_bytes) is not int or self.after_bytes < 0:
            raise ValueError('after_bytes must be a nonnegative integer')
        self.pid, self.errno = os.getpid(), getattr(errno, fault_name)
        self.evidence_dir = Path(evidence_dir).resolve(strict=True)
        if not self.evidence_dir.is_dir():
            raise ValueError('evidence directory must exist')
        self.journal = self.evidence_dir / 'fault-injection-events.jsonl'
        self.original_open = Path.open
        self.bytes_written = {}
        self.active = True
        owner = self

        def guarded_open(path, mode='r', *args, **kwargs):
            file = owner.original_open(path, mode, *args, **kwargs)
            # Resolve only the already trusted evidence parent, never an arbitrary
            # workload-controlled path. All other Path.open behavior is unchanged.
            match = _RECOVERED.fullmatch(Path(path).name)
            if (owner.active and os.getpid() == owner.pid and mode == 'ab'
                    and Path(path).parent == owner.evidence_dir and match):
                stream = match.group(1) or 'combined'
                if stream in owner.streams:
                    return _InjectedOutput(file, owner, Path(path), stream)
            return file

        self.guarded_open = guarded_open
        self.event('H_RECOVERY_FAULT_INSTALLED', configuration=config,
                   scope='only H recovered-output .write; event/final persistence unaffected')
        Path.open = guarded_open

    def event(self, kind, **fields):
        row = {'event': kind, 'pid': os.getpid(), 'target_h_pid': self.pid,
               'monotonic_ns': time.monotonic_ns(), **fields}
        data = (json.dumps(row, sort_keys=True) + '\n').encode()
        fd = os.open(self.journal, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC, 0o600)
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                if n <= 0:
                    raise OSError('fault journal short write')
                view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)

    def restore(self):
        if not self.active:
            return
        if os.getpid() != self.pid:
            raise RuntimeError('only the installing H process may restore the fault')
        if Path.open is not self.guarded_open:
            raise RuntimeError('Path.open replaced unexpectedly during fault fixture')
        Path.open = self.original_open
        self.active = False
        self.event('H_RECOVERY_FAULT_REMOVED', successful_bytes=self.bytes_written)


def install(config, evidence_dir):
    """Return a handle with restore(); never enables faults implicitly."""
    return InstalledFault(dict(config), evidence_dir)


class PreforkPipeTransfer:
    """Fixture transport for root-prepared pipes; not a product recovery hook.

    The inherited descriptors belong to the VM fixture. The Controller inherits
    them at H's ordinary fork, then H drops all of its inherited copies. H later
    obtains its responsible read ends only through the real REGISTER protocol.
    The initial product FD inventory excludes exactly these declared transport
    descriptors; the final inventory is untouched, so a newly leaked FD cannot
    be hidden by reusing the same descriptor number.
    """
    def __init__(self, fds, evidence_dir):
        import supervisor
        self.supervisor = supervisor
        self.pid = os.getpid()
        self.fds = list(fds)
        if (not self.fds or len(set(self.fds)) != len(self.fds)
                or any(type(fd) is not int or fd <= 2 for fd in self.fds)):
            raise ValueError('prefork transport requires distinct non-stdio FDs')
        self.evidence_dir = Path(evidence_dir).resolve(strict=True)
        self.journal = self.evidence_dir / 'prefork-pipe-transfer-events.jsonl'
        self.original_fork = os.fork
        self.original_inventory = supervisor._fds
        self.before_seen = False
        self.fork_seen = False
        self.active = True
        self.objects = {}
        import stat
        import fcntl
        for fd in self.fds:
            info = os.fstat(fd)
            if not stat.S_ISFIFO(info.st_mode):
                raise ValueError('prefork transfer accepts only already-created pipe FDs')
            self.objects[str(fd)] = {
                'dev': info.st_dev, 'ino': info.st_ino,
                'target': os.readlink('/proc/self/fd/' + str(fd)),
                'access_mode': fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE,
                'capacity': fcntl.fcntl(fd, fcntl.F_GETPIPE_SZ),
            }
        owner = self

        def inventory():
            result = owner.original_inventory()
            if os.getpid() == owner.pid and not owner.before_seen:
                owner.before_seen = True
                owner.event('FIXTURE_FD_INVENTORY_BEFORE_TRANSFER', actual=result,
                            excluded_fixture_transport_fds=owner.fds)
                return {key: value for key, value in result.items() if int(key) not in owner.fds}
            return result

        def fork():
            target = os.getpid() == owner.pid and not owner.fork_seen
            if target and not owner.before_seen:
                raise RuntimeError('fixture transfer requires H baseline inventory before fork')
            pid = owner.original_fork()
            if target:
                owner.fork_seen = True
                if pid > 0:
                    for fd in owner.fds:
                        os.close(fd)
                    owner.event('FIXTURE_PIPE_FDS_CLOSED_IN_H', controller_pid=pid,
                                closed_fds=owner.fds)
                else:
                    owner.event('FIXTURE_PIPE_FDS_INHERITED_BY_R', inherited_fds=owner.fds)
            return pid

        self.inventory_wrapper, self.fork_wrapper = inventory, fork
        self.event('FIXTURE_PIPE_TRANSFER_INSTALLED', objects=self.objects)
        supervisor._fds, os.fork = inventory, fork

    # Use the raw healthy journal writer, not a monkeypatched Path.open.
    event = InstalledFault.event

    def restore(self):
        if not self.active:
            return
        if os.getpid() != self.pid:
            raise RuntimeError('only H may restore its pipe transfer fixture')
        if self.supervisor._fds is not self.inventory_wrapper or os.fork is not self.fork_wrapper:
            raise RuntimeError('fixture transfer hook replaced unexpectedly')
        self.supervisor._fds = self.original_inventory
        os.fork = self.original_fork
        self.active = False
        self.event('FIXTURE_PIPE_TRANSFER_REMOVED', before_seen=self.before_seen,
                   fork_seen=self.fork_seen)


def install_prefork_pipe_transfer(fds, evidence_dir):
    """Explicit VM-fixture-only transfer; do not enable for ordinary workloads."""
    return PreforkPipeTransfer(fds, evidence_dir)
