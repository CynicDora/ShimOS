#!/usr/bin/env python3
"""Apply the narrowly scoped merge only to the new ping_merged experiment copy.

Refuses modified inputs; never writes baseline_instrumented or historical trees.
Changes only run.py and zygote.py. No workload or VM is executed.
"""
import ast
import hashlib
import json
from pathlib import Path

STUDY = Path(__file__).resolve().parent.parent
TARGET = STUDY / 'ping_merged'


def replace_one(text, old, new):
    if text.count(old) != 1:
        raise ValueError('expected exactly one source fragment: ' + old[:90])
    return text.replace(old, new, 1)


def main():
    frozen = json.loads((STUDY / 'analysis/baseline-instrumented-freeze.json').read_text())['files']
    sources = {}
    for name in ('run.py', 'zygote.py'):
        path = TARGET / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != frozen[name]:
            raise ValueError('refuse a modified or redirected merge input: ' + str(path))
        sources[name] = path.read_text()
    z = sources['zygote.py']
    z = replace_one(z, """            if op == 'PING':
                if received: raise RuntimeError('PING descriptors')
                send(CTRL, {'event': 'PONG', 'state_unchanged': fingerprint() == BASE,
                            'identity': identity(), 'active_attempts': len(attempts),'session':cost.SESSION,'nonce':nonce})
                continue
""", '')
    z = replace_one(z, """                close_pending(entry); close_fds([entry['pidfd']]); del attempts[nonce]
                send(CTRL, {'event': 'FORGOTTEN', 'nonce': nonce})
""", """                # Retain the original seal/real-wait precondition. A snapshot
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
""")
    r = sources['run.py']
    r = replace_one(r, """        req={'op':'SPAWN','nonce':nonce,'runtime_robust':os.environ.get('RELIABILITY_CASE')=='runtime','mode':mode,""", """        if case in ('counter_state_corruption','counter_fd_leak','counter_forgotten_drop','counter_late_ack','counter_post_ack_controller_death'):mode='normal'
        req={'op':'SPAWN','nonce':nonce,'runtime_robust':os.environ.get('RELIABILITY_CASE')=='runtime','mode':mode,""")
    r = replace_one(r, """                for f in fs:os.close(f)
                assert m.get('nonce')==nonce,m
                if m['event']=='FORGOTTEN':break
            cost.span('rpc_forget',forget_start);cost.record('forget_done')
""", """                had_fds=bool(fs)
                for f in fs:os.close(f)
                if m.get('nonce')!=nonce:
                    event({'event':'FINALIZATION_ID_REJECTED','nonce':nonce,'received_nonce':m.get('nonce'),'received_event':m.get('event')})
                    raise RuntimeError('finalization attempt identity mismatch')
                if m['event']=='FORGOTTEN':
                    assert not had_fds,m
                    row['zygote_post']=m
                    break
                # Earlier same-attempt notifications can precede FORGOTTEN on
                # this ordered channel. Their passed FDs were closed above.
            cost.span('rpc_forget',forget_start);cost.record('forget_done')
            if case=='counter_post_ack_controller_death':
                event({'event':'FINALIZATION_RECEIVED','nonce':nonce,'message':m})
                event({'event':'COUNTEREXAMPLE_INJECTED','nonce':nonce,'kind':'post_ack_controller_death','phase':'after_forget_ack_before_local_release'})
                journal();os.kill(os.getpid(),signal.SIGKILL)
""")
    r = replace_one(r, """            ping_start=cost.now();send(self.z['sock'],{'op':'PING','nonce':nonce});m,f,_=recv(self.z['sock']);assert not f and m['event']=='PONG' and m['state_unchanged'],m
            cost.span('rpc_ping',ping_start);row['zygote_post']=m
""", """            # Same validation point as the baseline, after R's own resource
            # deletion. The fresh Z snapshot arrived in the FORGOTTEN receipt;
            # it does not replace real resource release or H retirement.
            m=row['zygote_post'];assert m['event']=='FORGOTTEN' and m['state_unchanged'],m
""")
    outputs = {'run.py': r, 'zygote.py': z}
    for name, text in outputs.items():
        ast.parse(text, filename=name)
    for name, text in outputs.items():
        (TARGET / name).write_text(text)
    print(json.dumps({name: hashlib.sha256((TARGET/name).read_bytes()).hexdigest()
                      for name in outputs}, indent=2))


if __name__ == '__main__':
    main()
