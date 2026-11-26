#!/usr/bin/env python3
"""Read-only architecture_cost native/Python runtime evidence checker.

Does not execute a workload. Complements verify_qualification.py, never replaces its lifecycle
and isolation qualification. No finite probe implies general fork compatibility.
Process identity is attempt nonce + role + kernel fork edges; target PID 2 alone
is intentionally not treated as a host/global process identity.
"""
import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

STUDY = Path(__file__).resolve().parent.parent
PARENT = ['python:prepare2', 'python:prepare1', 'native:prepare2', 'native:prepare1',
          'native:parent1', 'native:parent2', 'python:parent1', 'python:parent2']
CHILD = ['native:child1', 'native:child2', 'python:child1', 'python:child2']
COUNTS = {'prepare1', 'prepare2', 'parent1', 'parent2', 'child1', 'child2'}
SNAP_CHECKS = {'native_owner', 'tid_matches', 'thread_clock', 'robust_registered', 'tls_cookie'}
FULL_STAGES = {'Z_before_first_fork', 'Z_after_first_parent', 'S_after_first_fork',
               'S_early_drop', 'S_before_second_fork', 'S_after_second_parent',
               'W_after_second_fork', 'W_gated', 'W_business'}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def analyze(name):
    run = STUDY / 'runs' / name
    if Path(name).name != name or not run.is_dir():
        raise ValueError('expected a frozen run basename')
    checks, evidence, observations, blockers = [], {}, [], []

    def check(label, value, detail=None):
        checks.append({'check': label, 'value': None if value is None else bool(value), 'evidence': detail})
        if value is None:
            blockers.append({'check': label, 'evidence': detail or 'required observation missing'})

    def read(filename, optional=False):
        path = run / filename
        if not path.exists():
            if not optional:
                check('present:' + filename, None)
            return {}
        evidence[filename] = sha(path)
        try:
            return json.loads(path.read_text())
        except (ValueError, OSError) as exc:
            check('valid JSON:' + filename, False, repr(exc))
            return {}

    def records(path):
        evidence[path.name] = sha(path)
        result = []
        for line, text in enumerate(path.read_text(errors='replace').splitlines(), 1):
            try:
                row = json.loads(text)
            except ValueError:
                if text.startswith('{') or '"AB_' in text:
                    check(f'parse:{path.name}:{line}', False, text)
                continue
            if isinstance(row, dict):
                row['_file'], row['_line'] = path.name, line
                result.append(row)
        return result

    config = read('review-config.json')
    variant_manifest = read('variant-manifest.json')
    check('runtime qualification belongs to an explicit variant',
          variant_manifest.get('variant') in {'full', 'low'}
          and config.get('variant') == variant_manifest.get('variant'))
    diagnostics = config.get('diagnostics')
    check('explicit diagnostic mode matches actual variant manifest',
          diagnostics in ('full', 'low') and diagnostics == variant_manifest.get('diagnostics')
          == config.get('variant') == variant_manifest.get('variant'))
    check('performance samples are not runtime qualification', config.get('case') != 'performance')
    summary = read('summary.json', True)
    rows = [read(p.name) for p in sorted(run.glob('[0-9]*-*.json'), key=lambda p: int(p.name.split('-')[0]))]
    if not rows:
        rows = [read(p.name) for p in sorted(run.glob('attempt-*.json'))]
    check('attempt evidence present', bool(rows))
    check('trusted runtime instrumentation enabled', config.get('runtime_probe') is True)
    zlogs = sorted(run.glob('zygote-*.log'))
    outputs = sorted(run.glob('[0-9]*-output.log'), key=lambda p: int(p.name.split('-')[0]))
    check('Z runtime logs present', bool(zlogs))
    # W child callbacks and first snapshot occur before dup2 and are in Z's log;
    # W gate/business records occur after dup2 in output. Never globally sort by
    # local PID or compare records belonging to separate attempts.
    logs = [r for p in zlogs + outputs for r in records(p)]
    # Controller SIGKILL can lose its in-memory output accumulator before it
    # writes *-output.log. A WORKER_READY event is separately journaled before
    # that fault and embeds the exact W_business runtime snapshot. Recover only
    # that independently corroborated observation, never invent unlogged stages
    # or infer a wait result from it. The supervisor still returns UNKNOWN.
    embedded_sources = []
    controller_events = records(run / 'events.jsonl') if (run / 'events.jsonl').exists() else []
    for row in rows:
        nonce = row.get('nonce')
        if any(r.get('event') == 'AB_RUNTIME_SNAPSHOT' and r.get('nonce') == nonce
               and r.get('stage') == 'W_business' for r in logs):
            continue
        saved = (row.get('worker') or {}).get('runtime')
        matches = [r for r in controller_events if r.get('event') == 'WORKER_READY'
                   and r.get('nonce') == nonce and isinstance(saved, dict)
                   and r.get('runtime') == saved]
        if saved:
            valid = (len(matches) == 1 and saved.get('event') == 'AB_RUNTIME_SNAPSHOT'
                     and saved.get('nonce') == nonce and saved.get('stage') == 'W_business')
            check(f'{nonce}:crash-persisted W snapshot corroborated by actual stdout event', valid)
            if valid:
                recovered = dict(saved, _file='events.jsonl', _line=matches[0]['_line'],
                                 _origin='WORKER_READY.runtime; exact match to attempt journal')
                logs.append(recovered)
                embedded_sources.append({'nonce': nonce, 'stage': 'W_business',
                                         'file': 'events.jsonl', 'line': matches[0]['_line']})
    snapshots = [r for r in logs if r.get('event') == 'AB_RUNTIME_SNAPSHOT']
    check('runtime snapshots actually present', True if snapshots else None)
    callback_buffer_sources = []
    if diagnostics == 'low':
        # Reconstruct only actually recorded callbacks, not the expected order.
        # Python buffers retain COW copies of earlier callbacks: pid+nonce and
        # recorded monotonic time distinguish the process that executed each.
        seen = {}
        for snap in snapshots:
            native = snap.get('native', {})
            label = str(snap.get('nonce')) + ':' + str(snap.get('stage'))
            check(label + ':low snapshot mode explicit', snap.get('diagnostics') == 'low')
            check(label + ':native callback buffer did not overflow',
                  native.get('native_callback_order_dropped') == 0
                  and native.get('native_callback_log_enabled') is False)
            for field, container, event_name in [
                    ('native_callback_events', native, 'AB_NATIVE_FORK_CALLBACK'),
                    ('python_callback_events', snap, 'AB_PYTHON_FORK_CALLBACK')]:
                payload = container.get(field)
                check(label + ':' + field + ' present', True if isinstance(payload, list) else None)
                if not isinstance(payload, list):
                    continue
                for record in payload:
                    if record.get('pid') != native.get('pid'):
                        continue  # inherited parent history is not a child invocation
                    if record.get('nonce', snap.get('nonce')) != snap.get('nonce'):
                        check(label + ':callback belongs to current attempt', False, record)
                        continue
                    stamp = record.get('monotonic_ns')
                    check(label + ':callback has an actual guest monotonic timestamp',
                          isinstance(stamp, int) and stamp > 0, record)
                    key = (snap.get('nonce'), event_name, record.get('pid'), record.get('name'), stamp)
                    callback = dict(record, event=event_name, nonce=snap.get('nonce'),
                                    trusted_instrumentation=True, _file=snap['_file'], _line=snap['_line'],
                                    _origin=field + ' in actual snapshot')
                    identity = {k:v for k,v in callback.items() if not k.startswith('_')}
                    if key in seen:
                        check(label + ':duplicate callback buffer entry consistent', seen[key][0] == identity)
                        continue
                    seen[key] = (identity, callback)
        reconstructed = [value[1] for value in seen.values()]
        reconstructed.sort(key=lambda r: (str(r.get('nonce')), r.get('pid', -1), r.get('monotonic_ns', 0)))
        logs.extend(reconstructed)
        callback_buffer_sources = [{'nonce': r['nonce'], 'event': r['event'], 'pid': r['pid'],
                                    'name': r['name'], 'monotonic_ns': r['monotonic_ns'],
                                    'file': r['_file'], 'line': r['_line']} for r in reconstructed]
    ab = [r for r in logs if str(r.get('event', '')).startswith('AB_')]
    check('every probe explicitly trusted instrumentation', all(r.get('trusted_instrumentation') is True for r in ab))
    allowed = {r.get('nonce') for r in rows} | {'session'}
    check('probe records use only current attempt identities', all(r.get('nonce') in allowed for r in ab))

    edges, execs = {}, {}
    trace = run / 'process-trace.txt'
    if trace.exists():
        evidence[trace.name] = sha(trace)
        for line in trace.read_text().splitlines():
            if 'sched_process_fork:' in line:
                match = re.search(r' pid=(\d+) child_comm=.* child_pid=(\d+)', line)
                if match:
                    parent, child = map(int, match.groups())
                    check('no host PID reuse in process trace:' + str(child), child not in edges)
                    edges[child] = parent
            elif 'sched_process_exec:' in line:
                match = re.search(r'filename=(\S+) pid=(\d+)', line)
                if match:
                    execs.setdefault(int(match[2]), []).append(match[1])
    else:
        check('process trace present', None)

    zready = [r for r in snapshots if r.get('stage') == 'Z_ready']
    installed = [r for r in ab if r['event'] == 'AB_PROBE_INSTALLED']
    check('one single-thread probe installation per template', bool(installed)
          and len(installed) == len(zready)
          and all(r.get('single_thread_count') == 1 for r in installed))
    zinitial = {r.get('native', {}).get('pid'): r for r in zready}
    for snap in snapshots:
        n = snap.get('native', {})
        stage = snap.get('stage', '')
        label = f'{snap.get("nonce")}:{stage}:{snap["_file"]}:{snap["_line"]}:'
        derived = {
            'native_owner': n.get('native_owner_matches') is True and n.get('native_owner') == n.get('pid'),
            'tid_matches': n.get('cpuclock_rc') == 0 and n.get('cpuclock_tid') == n.get('tid'),
            'thread_clock': n.get('clock_gettime_rc') == 0,
            'robust_registered': n.get('robust_rc') == 0 and isinstance(n.get('robust_head'), int) and n['robust_head'] > 0,
            'tls_cookie': n.get('tls_cookie') == 0x51a7c0de,
        }
        check(label + 'raw runtime checks and reported checks agree', set(snap.get('checks', {})) == SNAP_CHECKS
              and snap.get('checks') == derived and all(derived.values()), derived)
        check(label + 'single-thread pid/tid and generation', n.get('pid') == n.get('tid')
              and n.get('generation') == {'Z': 0, 'S': 1, 'W': 2}.get(stage[:1]))
        check(label + 'Python/native callback counters agree', set(n.get('native_counts', {})) == COUNTS
              and n.get('native_counts') == snap.get('python_counts'))
        zbase = zinitial.get(n.get('initial_pid'), {}).get('native', {})
        check(label + 'template TLS/pthread address and signal state inherited', bool(zbase)
              and all(n.get(k) == zbase.get(k) for k in ('pthread_self', 'tls_address', 'tls_cookie', 'blocked_signal_bits'))
              and n.get('signal_mask_rc') == 0)
        if stage.startswith('W_') or stage in ('S_early_drop', 'S_before_second_fork', 'S_after_second_parent', 'S_second_fork_rejected'):
            check(label + 'full drop retained in second-generation path', n.get('capget_rc') == 0
                  and all(n.get(k) == 0 for k in ('cap_eff', 'cap_prm', 'cap_inh', 'cap_bnd', 'cap_amb'))
                  and n.get('nnp') == 1 and n.get('seccomp') == 2)
        if diagnostics == 'low':
            fds = snap.get('fds', {})
            check(label + 'omitted RP FD inventory explicitly not observed',
                  fds.get('complete') is False and fds.get('entries') == []
                  and fds.get('method') == 'not_observed_low_diagnostics', fds)
        if stage == 'W_business':
            if diagnostics == 'full':
                fds = snap.get('fds', {})
                check(label + 'no management FD in actual business', fds.get('complete') is True
                      and {r.get('fd') for r in fds.get('entries', [])} == {0, 1, 2}, fds)
            else:
                actual = [row.get('worker') for row in rows if row.get('nonce') == snap.get('nonce')]
                observed = [worker for worker in actual if isinstance(worker, dict)]
                check(label + 'business FD inventory independently observed in this low run',
                      len(observed) == 1 and observed[0].get('checks', {}).get('fd_allowlist') is True
                      and set(observed[0].get('identity', {}).get('fds', {})) == {'0', '1', '2'}
                      and observed[0].get('runtime') == {k:v for k,v in snap.items() if not k.startswith('_')},
                      'WORKER_READY.identity is the unchanged business-side /proc observation; not inferred from full')

    def callback_key(r):
        return ('native:' if r['event'] == 'AB_NATIVE_FORK_CALLBACK' else 'python:') + r['name']

    for row in rows:
        nonce, case = row.get('nonce'), row.get('case')
        prefix = f'{case}:{nonce}:'
        own = [r for r in logs if r.get('nonce') == nonce]
        snaps = [r for r in own if r.get('event') == 'AB_RUNTIME_SNAPSHOT']
        by_stage = {r['stage']: r for r in snaps}
        check(prefix + 'no duplicate runtime stage', len(by_stage) == len(snaps))
        zpid = row.get('zygote_pid')
        s_snap = by_stage.get('S_after_first_fork', {})
        w_snap = by_stage.get('W_after_second_fork', {})
        spid = s_snap.get('native', {}).get('pid') or row.get('s_pid')
        wlocal = w_snap.get('native', {}).get('pid')
        whost = row.get('w_pid')
        # In interrupted controller journals, ACTUAL_WORKER_FORK may be the only
        # durable association. It is still checked against the kernel trace.
        wforks = [r for r in own if r.get('event') == 'ACTUAL_WORKER_FORK']
        if whost is None and wforks:
            whost = wforks[0].get('worker_host_pid')
        if spid is not None:
            check(prefix + 'S probe bound to real Z child', edges.get(spid) == zpid and not execs.get(spid),
                  {'Z_host': zpid, 'S_host_and_local': spid})
        if whost is not None:
            check(prefix + 'W probe bound to real S child without exec', edges.get(whost) == spid
                  and not execs.get(whost), {'S_host': spid, 'W_host': whost, 'W_local': wlocal})
        if w_snap and row.get('worker'):
            check(prefix + 'local W PID agrees with isolated business identity',
                  wlocal == row['worker'].get('identity', {}).get('pid'))
        if case in ('normal', 'nonzero', 'created_drop', 'reaped_drop', 'result_loss_side_effect'):
            check(prefix + 'full actual Z-S-W path observed', FULL_STAGES <= set(by_stage), sorted(by_stage))
        if row.get('worker'):
            check(prefix + 'runtime business evidence required when business ran', 'W_business' in by_stage)
        if case == 'pid_budget':
            check(prefix + 'first EAGAIN has parent completion and no child callback',
                  'Z_first_fork_rejected' in by_stage and spid is None
                  and not any(r.get('event') in ('AB_NATIVE_FORK_CALLBACK', 'AB_PYTHON_FORK_CALLBACK')
                              and r.get('name', '').startswith('child') for r in own))
        if case == 'second_budget':
            check(prefix + 'second EAGAIN has parent completion and no W',
                  'S_second_fork_rejected' in by_stage and not w_snap and whost is None)
        if case == 'cancel_queued':
            check(prefix + 'cancelled prepared attempt never entered fork callbacks', not snaps
                  and not any('FORK_CALLBACK' in r.get('event', '') for r in own))

        callback_rows = [r for r in own if r.get('event') in ('AB_NATIVE_FORK_CALLBACK', 'AB_PYTHON_FORK_CALLBACK')]
        for role, pid in [('Z', zpid), ('S', spid), ('W', wlocal)]:
            if pid is None:
                continue
            crows = [r for r in callback_rows if r.get('pid') == pid]
            if diagnostics == 'low':crows.sort(key=lambda r:r.get('monotonic_ns', 0))
            actual = [callback_key(r) for r in crows]
            if role == 'Z':
                expected = PARENT
                complete = bool({'Z_after_first_parent', 'Z_first_fork_rejected'} & by_stage.keys())
            elif role == 'S':
                expected = CHILD + (PARENT if 'S_before_second_fork' in by_stage else [])
                complete = bool({'S_after_second_parent', 'S_second_fork_rejected'} & by_stage.keys()) or (
                    'S_after_first_fork' in by_stage and 'S_before_second_fork' not in by_stage)
            else:
                extra_parent = any(r.get('name', '').startswith(('prepare', 'parent')) for r in crows)
                expected = CHILD + (PARENT if extra_parent else [])
                complete = bool(w_snap) and not extra_parent
            check(prefix + role + ' callback order/completion', actual == expected if complete else actual == expected[:len(actual)],
                  {'actual': actual, 'expected': expected, 'complete_stage_observed': complete})
        # Native callbacks at S's second fork, W's child branch and W's later
        # business children must inherit early drop. First S child1 logs before
        # child2 increments generation, so classify by role/name, not gen alone.
        for r in callback_rows:
            if r.get('event') not in ('AB_NATIVE_FORK_CALLBACK','AB_PYTHON_FORK_CALLBACK'):
                continue
            second = (r.get('pid') == spid and r.get('name', '').startswith(('prepare', 'parent'))) or r.get('generation', 0) >= 2 or r.get('pid') == wlocal
            if second:
                check(prefix + r.get('event') + ' callback already downgraded:' + str(r.get('pid')) + ':' + r['name'],
                      r.get('capget_rc') == 0 and r.get('cap_eff') == r.get('cap_prm') == 0
                      and r.get('nnp') == 1 and r.get('seccomp') == 2, r)

        # Check cumulative counters against their real pre-fork snapshots;
        # parent callbacks do not retroactively appear in the COW child.
        for before, after, branch in [('Z_before_first_fork', 'Z_after_first_parent', 'parent'),
                                      ('Z_before_first_fork', 'Z_first_fork_rejected', 'parent'),
                                      ('Z_before_first_fork', 'S_after_first_fork', 'child'),
                                      ('S_before_second_fork', 'S_after_second_parent', 'parent'),
                                      ('S_before_second_fork', 'S_second_fork_rejected', 'parent'),
                                      ('S_before_second_fork', 'W_after_second_fork', 'child')]:
            if before in by_stage and after in by_stage:
                old = by_stage[before]['native']['native_counts']
                wanted = {k: old[k] + int(k.startswith('prepare') or k.startswith(branch)) for k in COUNTS}
                check(prefix + 'counter transition:' + before + '->' + after,
                      by_stage[after]['native']['native_counts'] == wanted, wanted)

        locks = [r for r in own if r.get('event') == 'AB_ROBUST_LOCK']
        recoveries = [r for r in own if r.get('event') == 'AB_ROBUST_RECOVER']
        waits = [r for r in own if r.get('event') == 'ACTUAL_WORKER_WAIT']
        if config.get('case') == 'runtime':
            check(prefix + 'real W robust lock and S owner-death recovery present', len(locks) == len(recoveries) == len(waits) == 1)
            if len(locks) == len(recoveries) == len(waits) == 1:
                lock, recover, waited = locks[0], recoveries[0], waits[0]
                check(prefix + 'W held robust mutex until real wait', lock.get('pid') == wlocal
                      and lock.get('return_code') == 0 and waited.get('worker_host_pid') == whost
                      and waited.get('exit_code') == (7 if case == 'nonzero' else 0))
                check(prefix + 'S wait precedes actual EOWNERDEAD recovery', recover.get('pid') == spid
                      and recover.get('return_code') == recover.get('expected') == 130
                      and recover.get('consistent_return') == recover.get('unlock_return') == 0
                      and recover.get('passed') is True and recover['_file'] == waited['_file']
                      and recover['_line'] > waited['_line'])
        else:
            check(prefix + 'lifecycle faults do not silently add robust locking', not locks and not recoveries)
        observations.append({'nonce': nonce, 'case': case, 'Z_host': zpid, 'S_host': spid,
                             'W_host': whost, 'W_local': wlocal, 'stages': sorted(by_stage),
                             'robust_lock_count': len(locks), 'robust_recovery_count': len(recoveries)})

    if config.get('case') in ('control', 'runtime'):
        check('full three-request cross-domain sequence', [r.get('case') for r in rows] == ['normal', 'normal', 'nonzero'])
        cold = config.get('numpy_baseline') == 'cold'
        check('cold has three fresh templates' if cold else 'one live template served three distinct released domains',
              len({r.get('zygote_pid') for r in rows}) == (3 if cold else 1)
              and len({r.get('nonce') for r in rows}) == 3
              and all(r.get('resources') == 'RELEASED' and r.get('resources_removed') is True
                      and r.get('zygote_post', {}).get('state_unchanged') is True for r in rows))
        if cold:
            for row in rows:
                zpid = row.get('zygote_pid')
                waited = [r for r in controller_events if r.get('event') == 'CONTROLLER_WAIT' and r.get('pid') == zpid]
                stopped = [r for r in controller_events if r.get('event') == 'ZYGOTE_STOP'
                           and r.get('state', {}).get('born_pid') == zpid]
                check('cold template truly stopped and waited:' + str(zpid),
                      len(waited) == len(stopped) == 1 and waited[0].get('wait_status') == 0
                      and stopped[0].get('state_unchanged') is True)
        check('no missing complete runtime stages in control group', all(set(o['stages']) >= FULL_STAGES for o in observations))

    failures = [r for r in checks if r['value'] is not True]
    return {'run': name, 'diagnostics': diagnostics,
            'status': 'FAIL' if any(r['value'] is False for r in failures) else ('BLOCKED' if blockers else 'PASS'),
            'blockers': blockers, 'runtime_combination_only': True,
            'checks': checks, 'failures': failures, 'attempts': observations,
            'snapshot_count': len(snapshots), 'native_callback_count': sum(r['event'] == 'AB_NATIVE_FORK_CALLBACK' for r in ab),
            'python_callback_count': sum(r['event'] == 'AB_PYTHON_FORK_CALLBACK' for r in ab),
            'robust_recovery_count': sum(r['event'] == 'AB_ROBUST_RECOVER' for r in ab),
            'crash_persisted_embedded_snapshots': embedded_sources,
            'low_actual_callback_buffer_sources': callback_buffer_sources,
            'verifier_sha256': sha(Path(__file__)), 'evidence_sha256': evidence,
            'limitations': ['Complements verify_qualification.py; does not replace source admission, 19 business checks and lifecycle qualification.',
                           'Trusted self-written single-thread probes, not arbitrary dependencies or general fork safety.',
                           'Missing phases during intentional faults are not claimed to have passed unexecuted probes.',
                           'Only private diagnostic robust mapping is shared; not a production sharing contract.',
                           'Full FD bound scan for S is incomplete; low RP FD inventory is explicitly not observed. Final W business identity remains a complete /proc observation.',
                           'Native callback permissions are independently observed in both modes for both cross-domain forks; no inference from a prior full run.',
                           'Low does not export callbacks from the extra ordinary business fork after W_business; its fork/exit and PID1 reaping remain lifecycle observations, not callback qualification.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs', nargs='+')
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--output-suffix', default='runtime', help='exclusive analysis filename suffix')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+',args.output_suffix):parser.error('invalid output suffix')
    failed = False
    for name in args.runs:
        result = analyze(name)
        if not args.check_only:
            out = STUDY / 'analysis' / (name + '-' + args.output_suffix + '.json')
            out.parent.mkdir(exist_ok=True)
            with out.open('x') as stream:
                json.dump(result, stream, indent=2, ensure_ascii=False)
                stream.write('\n')
        print(json.dumps({k: result[k] for k in ('run', 'status', 'snapshot_count', 'robust_recovery_count', 'failures')}, ensure_ascii=False))
        failed |= result['status'] != 'PASS'
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
