#!/usr/bin/env python3
"""Read-only fail-closed evidence checks for the PING merge counterexamples.

An expected Controller failure is not enough: require a recorded injected
condition, a post-forget snapshot when applicable, no committed response or
RETIRE, and actual product H wait/EOF/resource cleanup. No experiment is run.
Complements rather than disables the original lifecycle/security requirements.
"""
import argparse
import hashlib
import json
from pathlib import Path

import verify_qualification as qualification

STUDY = Path(__file__).resolve().parent.parent
KINDS = {
    'counter_state_corruption': 'state_corruption',
    'counter_fd_leak': 'fd_leak',
    'counter_forgotten_drop': 'forgotten_drop',
    'counter_late_ack': 'late_ack',
    'counter_post_ack_controller_death': 'post_ack_controller_death',
    'counter_post_forget_zygote_death': 'post_forget_zygote_death',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def analyze(name):
    run = STUDY / 'runs' / name
    if Path(name).name != name or not run.is_dir():
        raise ValueError('expected an existing run basename')
    checks, evidence = [], {}

    def check(label, value, detail=None):
        checks.append({'check': label, 'value': bool(value), 'evidence': detail})

    def read(filename, optional=False):
        path = run / filename
        if not path.is_file():
            if not optional:
                check('present:' + filename, False)
            return {}
        evidence[filename] = sha(path)
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            check('valid JSON:' + filename, False, repr(exc))
            return {}

    def records(path, strict=False):
        if not path.is_file():
            check('present:' + path.name, False)
            return []
        evidence[path.name] = sha(path)
        result = []
        for number, text in enumerate(path.read_text(errors='replace').splitlines(), 1):
            try:
                item = json.loads(text)
            except ValueError:
                if strict or text.startswith('{'):
                    check(f'parse:{path.name}:{number}', False, text)
                continue
            if isinstance(item, dict):
                result.append(dict(item, _file=path.name, _line=number))
        return result

    base = qualification.analyze(name, counterexample=True)
    check('full source/security/lifecycle recovery requirements', base['status'] == 'PASS',
          {'status': base['status'], 'failed_checks': [c['check'] for c in base['failures']],
           'blockers': base.get('blockers', [])})
    config = read('review-config.json')
    case = config.get('case')
    kind = KINDS.get(case)
    check('known counterexample, separate from 29-attempt qualification', kind is not None, case)
    check('counterexample is not a performance sample', config.get('performance_benchmark') is False)
    variant = read('variant-manifest.json').get('variant')
    check('counterexample exercises the explicitly merged variant', variant == 'ping_merged')
    sup = read('supervisor.json')
    events = records(run / 'events.jsonl', True)
    se = records(run / 'supervisor-events.jsonl', True)
    z = [item for path in sorted(run.glob('zygote-*.log')) for item in records(path)]
    rows = [read(path.name) for path in sorted(run.glob('attempt-*.json'))]
    check('one complete attempt identity, no hidden retry', len(rows) == 1)
    row = rows[0] if len(rows) == 1 else {}
    nonce = row.get('nonce')
    check('counterexample case matches the actual journal', row.get('case') == case)
    check('no successful committed response file', not list(run.glob('[0-9]*-*.json'))
          and row.get('response_committed') is not True
          and row.get('qualification') != 'PASS' and not (run / 'summary.json').exists())
    own = [r for r in z + events if r.get('nonce') == nonce]
    faults = [r for r in own if r.get('event') == 'COUNTEREXAMPLE_INJECTED'
              and r.get('kind') == kind]
    check('exact intended fault was really injected', len(faults) == 1, faults)
    fault = faults[0] if len(faults) == 1 else {}
    applied = [r for r in own if r.get('event') == 'FORGET_APPLIED']
    check('forget happened only after seal and real terminal S state', len(applied) == 1
          and applied[0].get('admission') == 'SEALED'
          and applied[0].get('s_state') in ('ABSENT', 'REAPED')
          and applied[0].get('active_attempts') == 0
          and applied[0].get('tombstone_retained') is True, applied)
    snapshots = [r for r in own if r.get('event') == 'POST_FORGET_SNAPSHOT']
    check('one newly observed post-forget snapshot', len(snapshots) == 1, snapshots)
    observed = snapshots[0] if len(snapshots) == 1 else {}
    snap = observed.get('snapshot') or {}
    check('snapshot belongs to this attempt and live template', snap.get('event') == 'FORGOTTEN'
          and snap.get('nonce') == nonce
          and snap.get('identity', {}).get('pid') == row.get('zygote_pid')
          and snap.get('active_attempts') == 0, snap)
    if len(applied) == len(snapshots) == 1:
        check('snapshot follows actual forget in the same Z log',
              applied[0]['_file'] == observed['_file']
              and applied[0]['_line'] < observed['_line'])

    ready = [r for r in events if r.get('event') == 'ZYGOTE_READY'
             and r.get('identity', {}).get('pid') == row.get('zygote_pid')]
    check('original template identity recorded', len(ready) == 1)
    initial_fds = ready[0].get('identity', {}).get('fds', {}) if len(ready) == 1 else {}
    current_fds = snap.get('identity', {}).get('fds', {})
    if case == 'counter_state_corruption':
        before, after = fault.get('before'), fault.get('after')
        check('real template bytes changed rather than merely changing a status flag',
              isinstance(before, dict) and isinstance(after, dict)
              and len(ready) == 1 and before == ready[0].get('state')
              and before.get('sha256') != after.get('sha256')
              and before.get('object_id') == after.get('object_id')
              and before.get('born_pid') == after.get('born_pid'), fault)
        check('fresh snapshot detects the injected state change', snap.get('state_unchanged') is False)
    elif case == 'counter_fd_leak':
        fd = str(fault.get('fd'))
        check('extra live FD really appears in the snapshot', bool(initial_fds)
              and fd not in initial_fds and fd in current_fds
              and current_fds[fd] == fault.get('target')
              and set(current_fds) != set(initial_fds), fault)
        check('FD counterexample did not also poison the template data', snap.get('state_unchanged') is True)
    elif case == 'counter_forgotten_drop':
        check('post-forget response deliberately omitted', fault.get('response_event') == 'FORGOTTEN'
              and fault.get('sent') is False
              and not any(r.get('event') == 'FORGOTTEN_SENT' for r in own))
        failure = read('controller-failure.json')
        check('lost acknowledgment produced bounded timeout, not an invented success',
              'TimeoutError' in failure.get('traceback', ''))
    elif case == 'counter_late_ack':
        check('foreign/stale-looking attempt identity queued for send',
              fault.get('response_event') == 'FORGOTTEN'
              and isinstance(fault.get('sent_nonce'), str)
              and fault.get('sent_nonce') != nonce and fault.get('attempted_send') is True, fault)
        rejected = [r for r in events if r.get('event') == 'FINALIZATION_ID_REJECTED'
                    and r.get('nonce') == nonce and r.get('received_nonce') == fault.get('sent_nonce')]
        check('Controller explicitly rejected the mismatched receipt', len(rejected) == 1, rejected)
    elif case == 'counter_post_ack_controller_death':
        ack = [r for r in events if r.get('event') == 'FINALIZATION_RECEIVED'
               and r.get('nonce') == nonce]
        check('Controller died after matching acknowledgment and before local release', len(ack) == 1
              and fault.get('phase') == 'after_forget_ack_before_local_release'
              and ack[0].get('monotonic_ns', float('inf')) <= fault.get('monotonic_ns', -1),
              {'ack': ack, 'fault': fault})
    elif case == 'counter_post_forget_zygote_death':
        ack = [r for r in events if r.get('event') == 'FINALIZATION_RECEIVED' and r.get('nonce') == nonce]
        sent = [r for r in own if r.get('event') == 'FORGOTTEN_SENT']
        boundary = [r for r in events if r.get('event') == 'COUNTEREXAMPLE_BOUNDARY_REACHED'
                    and r.get('nonce') == nonce and r.get('kind') == 'post_forget_zygote_death']
        rejected = [r for r in events if r.get('event') == 'FINALIZATION_Z_EXIT_REJECTED' and r.get('nonce') == nonce]
        check('Z sent the matching receipt before killing itself', len(sent) == len(ack) == 1
              and sent[0].get('monotonic_ns', float('inf')) <= fault.get('monotonic_ns', -1)
              and ack[0].get('message', {}).get('nonce') == nonce
              and fault.get('zygote_pid') == row.get('zygote_pid')
              and fault.get('phase') == 'after_forget_receipt_before_local_release')
        check('controlled interleaving reached a readable Z pidfd', len(boundary) == 1
              and boundary[0].get('pidfd_readable') is True
              and boundary[0].get('zygote_pid') == row.get('zygote_pid'), boundary)
        check('normal product final validation rejected the exited template', len(rejected) == 1
              and rejected[0].get('pidfd_readable') is True
              and rejected[0].get('resources_removed') is True
              and rejected[0].get('zygote_pid') == row.get('zygote_pid')
              and len(boundary) == 1
              and boundary[0].get('monotonic_ns', float('inf')) <= rejected[0].get('monotonic_ns', -1), rejected)
        failure = read('controller-failure.json')
        check('failure came from product final validation, not test synchronization',
              'template exited before final response validation' in failure.get('traceback', ''))
        check('H truly waited the SIGKILLed Z, not just observed its pidfd', any(
              r.get('event') == 'SUPERVISOR_REAL_WAIT' and r.get('pid') == row.get('zygote_pid')
              and r.get('wait_status') == 9 for r in se))
    if case not in ('counter_state_corruption', 'counter_fd_leak'):
        check('receipt/control fault retains normal template snapshot', snap.get('state_unchanged') is True
              and bool(initial_fds) and set(current_fds) == set(initial_fds))

    retired = [r for r in se if r.get('event') == 'ATTEMPT_RETIRED' and r.get('nonce') == nonce]
    check('failed finalization never retired cleanup ownership', not retired)
    sas = [r for r in sup.get('attempts', []) if r.get('nonce') == nonce]
    check('H retains authoritative UNKNOWN for the uncommitted request', len(sas) == 1
          and sas[0].get('registered') is True and sas[0].get('retired') is False
          and sas[0].get('business_result') == 'UNKNOWN'
          and sas[0].get('output_eof') is True and sas[0].get('resources_removed') is True,
          sas)
    check('H completed recovery with true wait and no observer cleanup', sup.get('business_result') == 'UNKNOWN'
          and sup.get('echild') is True and sup.get('release_state') == 'RELEASED'
          and sup.get('observer_cleanup_used') is False and sup.get('errors') == [])
    forks = [r for r in own if r.get('event') in ('ACTUAL_TRANSITION_FORK', 'ACTUAL_WORKER_FORK')]
    if len(applied) == 1:
        check('no transition/worker created after forget', all(
              r.get('monotonic_ns', float('inf')) <= applied[0].get('monotonic_ns', -1)
              for r in forks), forks)
    failures = [r for r in checks if not r['value']]
    return {'run': name, 'case': case, 'variant': variant,
            'status': 'BLOCKED' if base['status'] == 'BLOCKED' else ('FAIL' if failures else 'PASS'),
            'checks': checks, 'failures': failures, 'qualification': base,
            'verifier_sha256': sha(Path(__file__)), 'evidence_sha256': evidence,
            'limitations': ['One controlled interleaving per counterexample, not exhaustive races.',
                           'Fault rejection is separate from the original 29-attempt qualification.',
                           'State fingerprint and FD-number tests cover explicit probe objects only.',
                           'No performance conclusion follows from intentional failure handling.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs', nargs='+')
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    failed = False
    for name in args.runs:
        result = analyze(name)
        if not args.check_only:
            out = STUDY / 'analysis' / (name + '-counterexample.json')
            with out.open('x') as stream:
                json.dump(result, stream, ensure_ascii=False, indent=2)
                stream.write('\n')
        print(json.dumps({k: result[k] for k in ('run', 'case', 'status', 'failures')}, ensure_ascii=False))
        failed |= result['status'] != 'PASS'
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
