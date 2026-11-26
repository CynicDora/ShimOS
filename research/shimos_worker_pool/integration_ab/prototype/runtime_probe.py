"""Trusted A+B correctness probes. No Worker implementation or fallback path.

install() loads libab_probe.so beside this file, registers two Python/native
callback groups and allocates one shared robust-mutex diagnostic page in Z.
set_attempt(nonce) MUST precede each first fork; callbacks inherit that identity.
snapshot(stage, nonce) uses native syscalls for permissions and TID; /proc is
optional (S cannot see itself through target PID namespace's proc mount).
W calls robust_lock(nonce), then exits while holding the diagnostic mutex.
Only S after real wait(W) calls robust_recover(nonce), requiring EOWNERDEAD.
Logging uses FD 1; no extra FD survives into business. Not a dependency grant.
"""
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path

_lib = None
_nonce = 'session'
_counts = dict(prepare1=0, prepare2=0, parent1=0, parent2=0, child1=0, child2=0)


def _emit(event, **fields):
    row = dict(event=event, nonce=_nonce, trusted_instrumentation=True, **fields)
    raw = (json.dumps(row, separators=(',', ':'), sort_keys=True) + '\n').encode()
    if os.write(1, raw) != len(raw):
        raise RuntimeError('runtime probe short log write')
    return row


def _callback(name):
    def callback():
        _counts[name] += 1
        _emit('AB_PYTHON_FORK_CALLBACK', name=name, pid=os.getpid())
    return callback


def install(library=None):
    global _lib
    if _lib is not None:
        raise RuntimeError('runtime probe already installed')
    _lib = ctypes.PyDLL(str(library or Path(__file__).with_name('libab_probe.so')), use_errno=True)
    _lib.rp_context.argtypes = [ctypes.c_char_p]
    _lib.rp_snapshot.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    for function in ('rp_install', 'rp_robust_prepare'):
        error = getattr(_lib, function)()
        if error:
            raise OSError(error, function)
    for index in (1, 2):
        os.register_at_fork(before=_callback('prepare' + str(index)),
                            after_in_parent=_callback('parent' + str(index)),
                            after_in_child=_callback('child' + str(index)))
    _emit('AB_PROBE_INSTALLED', pid=os.getpid(), single_thread_count=len(os.listdir('/proc/self/task')),
          diagnostic_shared_mutex=True, purpose='trusted correctness instrumentation only')


def set_attempt(nonce):
    global _nonce
    if _lib is None:
        raise RuntimeError('runtime probe not installed')
    error = _lib.rp_context(nonce.encode('ascii'))
    if error:
        raise OSError(error, 'probe attempt identity')
    _nonce = nonce


def _fd_snapshot():
    # /proc enumeration's own temporary FD is already closed by listdir return.
    try:
        candidates = sorted(int(name) for name in os.listdir('/proc/self/fd'))
        method, complete = 'proc-self-fd', True
    except OSError:
        # Diagnostic fallback only; correctness still uses external A checks.
        candidates = range(4096)
        method, complete = 'fcntl-bounded-scan-0-through-4095', False
    rows = []
    for fd in candidates:
        try:
            flags = fcntl.fcntl(fd, fcntl.F_GETFD)
            stat = os.fstat(fd)
            rows.append(dict(fd=fd, flags=flags, device=stat.st_dev, inode=stat.st_ino, mode=stat.st_mode))
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
    return dict(entries=rows, method=method, complete=complete)


def snapshot(stage, nonce=None):
    if nonce is not None:
        set_attempt(nonce)
    buffer = ctypes.create_string_buffer(4096)
    error = _lib.rp_snapshot(buffer, len(buffer))
    if error:
        raise OSError(error, 'runtime snapshot')
    native = json.loads(buffer.value)
    checks = dict(native_owner=native['native_owner_matches'],
                  tid_matches=native['cpuclock_rc'] == 0 and native['cpuclock_tid'] == native['tid'],
                  thread_clock=native['clock_gettime_rc'] == 0,
                  robust_registered=native['robust_rc'] == 0 and native['robust_head'] != 0,
                  tls_cookie=native['tls_cookie'] == 0x51a7c0de)
    return _emit('AB_RUNTIME_SNAPSHOT', stage=stage, native=native, python_counts=dict(_counts),
                 fds=_fd_snapshot(), checks=checks)


def robust_lock(nonce):
    set_attempt(nonce)
    error = _lib.rp_robust_lock()
    _emit('AB_ROBUST_LOCK', pid=os.getpid(), return_code=error)
    if error:
        raise OSError(error, 'diagnostic robust mutex lock')
    return error


def robust_recover(nonce):
    set_attempt(nonce)
    error = _lib.rp_robust_recover()
    consistent = _lib.rp_robust_consistent_result()
    unlock = _lib.rp_robust_unlock_result()
    row = _emit('AB_ROBUST_RECOVER', pid=os.getpid(), return_code=error,
                expected=errno.EOWNERDEAD, consistent_return=consistent, unlock_return=unlock,
                passed=error == errno.EOWNERDEAD and consistent == 0 and unlock == 0,
                caller_contract='S has already performed real waitpid(W)')
    if not row['passed']:
        raise RuntimeError('diagnostic robust owner-death recovery failed: ' + repr(row))
    return row
