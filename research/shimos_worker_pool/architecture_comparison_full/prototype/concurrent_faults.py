"""Explicit private-VM negative tests, not a new business control API.

Normal sessions have no fault object and no changed message/state. Faults use
only trusted self-owned memory/FDs; they neither grant authority nor clean up.
"""
import os
from pathlib import Path

KINDS = {'none', 'template_state', 'template_fd', 'reply_unknown_nonce', 'reply_retired_nonce', 'adoption_after_snapshot'}


def configured():
    kind = os.environ.get('FULL_CONCURRENT_FAULT', 'none')
    if kind not in KINDS:
        raise ValueError('unregistered concurrent negative test')
    if kind != 'none':
        if os.environ.get('FULL_MODE') != 'G2_CONCURRENT':
            raise RuntimeError('concurrent negative test requires explicit G2 candidate')
        if Path('/run/native-benchmark-lab').read_text().strip() != 'private-stock-linux-benchmark-vm':
            raise RuntimeError('negative test requires the private VM fixture')
    return kind


def corrupt_owned_template(kind, state, attempts, children, log, nonce):
    if kind not in ('template_state', 'template_fd'):
        return False
    if attempts or children or os.getpid() != state.born_pid:
        raise RuntimeError('template injection only after all real waits and FORGETs')
    if kind == 'template_state':
        before = state.bytes[0]
        state.bytes[0] ^= 1
        log('CONCURRENT_TEST_TEMPLATE_STATE_CHANGED', nonce, owner_pid=os.getpid(),
            original_byte=before, changed_byte=state.bytes[0], active_attempts=len(attempts),
            children=len(children), note='trusted self-owned object; no response/cleanup synthesized')
    else:
        fd = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
        st = os.fstat(fd)
        log('CONCURRENT_TEST_TEMPLATE_FD_LEAKED', nonce, owner_pid=os.getpid(), fd=fd,
            fd_target=os.readlink('/proc/self/fd/'+str(fd)), device=st.st_dev, inode=st.st_ino,
            active_attempts=len(attempts), children=len(children),
            note='intentionally open until product terminates Z; observer never closes it')
    return True
