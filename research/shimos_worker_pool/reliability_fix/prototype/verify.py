#!/usr/bin/env python3
"""Independent, read-only verifier of frozen reliability VM evidence.

Never executes a workload, sends a signal, or modifies a run. Default writes one
new analysis/<run>.json with exclusive creation. --check-only writes nothing.
Trace exit is corroboration, not a substitute for a real wait record. All times
compared below are the guest's monotonic_ns, never ftrace vs userspace clocks.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path


STUDY = Path(__file__).resolve().parent.parent
CG = '/sys/fs/cgroup/cdz'
SECURITY = ('bridge.c', 'native.c', 'domain_init.c', 'policy.h', 'common.py')
CHECK_NAMES = {'marker', 'inherited', 'not_recreated', 'no_host_path',
               'no_other_workspace', 'readonly', 'writable', 'setns_denied',
               'unshare_denied', 'chroot_denied', 'exec_denied', 'caps_zero',
               'nnp_seccomp', 'fd_allowlist', 'namespaces', 'cgroup',
               'environment', 'cwd', 'root_identity'}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def analyze(name):
    run = STUDY / 'runs' / name
    if Path(name).name != name or not run.is_dir():
        raise ValueError('expected an existing run basename')
    checks = []

    def check(label, value, evidence=None, required=True):
        checks.append({'check': label, 'value': value if value is None else bool(value),
                       'required': required, 'evidence': evidence})

    def read(filename, required=True):
        path = run / filename
        if not path.exists():
            if required:
                check('present:' + filename, None, 'missing raw evidence')
            return {}
        try:
            return json.loads(path.read_text())
        except (ValueError, OSError) as exc:
            check('parse:' + filename, False, repr(exc))
            return {}

    def lines(path, strict=False):
        values = []
        if not path.exists():
            check('present:' + path.name, None)
            return values
        for number, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
            try:
                value = json.loads(line)
                if isinstance(value, dict):
                    values.append(value)
            except ValueError:
                if strict:
                    check(f'jsonl:{path.name}:{number}', False, line)
        return values

    events = lines(run / 'events.jsonl', True)
    se = lines(run / 'supervisor-events.jsonl', True)
    zl = [r for path in sorted(run.glob('zygote-*.log')) for r in lines(path)]
    summary = read('summary.json', False)
    sup = read('supervisor.json')
    ext = read('external-final-release.json')
    result = read('result.json')
    config = read('review-config.json')
    manifest = read('source-sha.json')
    build = read('build.json')
    frozen = json.loads((STUDY / 'historical-source-freeze.json').read_text())

    check('private VM completed without emergency timeout',
          result.get('complete') is True and result.get('timeout') is False
          and result.get('qemu_rc') == 0, 'result.json')
    check('not a benchmark or observer cleanup', config.get('performance_benchmark') is False
          and config.get('observer_cleanup_performed') is False, 'review-config.json')
    for name_, expected in manifest.items():
        p = run / 'prototype' / name_
        check('frozen source:' + name_, p.exists() and sha(p) == expected,
              ['source-sha.json', 'prototype/' + name_])
    security_hashes = {}
    for name_ in SECURITY:
        expected = frozen.get('cross_domain_zygote/prototype/' + name_)
        current = run / 'prototype' / name_
        security_hashes[name_] = {'original': expected,
                                 'run': sha(current) if current.exists() else None}
        check('security implementation unchanged:' + name_,
              expected is not None and security_hashes[name_]['run'] == expected,
              security_hashes[name_])
    old = STUDY.parent / 'cross_domain_zygote/runs/qualification-02'
    binary_hashes = {}
    for name_ in ('bridge.so', 'native.so', 'domain_init'):
        p, original = run / name_, old / name_
        binary_hashes[name_] = {'run': sha(p) if p.exists() else None,
                               'original': sha(original) if original.exists() else None,
                               'build_manifest': build.get(name_)}
        v = binary_hashes[name_]
        check('security binary matches qualification:' + name_,
              v['run'] is not None and v['run'] == v['original'] == v['build_manifest'], v)

    edges, execs, exits = {}, {}, set()
    trace = run / 'process-trace.txt'
    if not trace.exists():
        check('kernel process trace present', None)
    else:
        for line in trace.read_text().splitlines():
            if 'sched_process_fork:' in line:
                m = re.search(r' pid=(\d+) child_comm=.* child_pid=(\d+)', line)
                if not m:
                    check('fork trace parse', False, line)
                    continue
                parent, child = map(int, m.groups())
                if child in edges:
                    check('no PID reuse ambiguity in trace', False, child)
                edges[child] = parent
            elif 'sched_process_exec:' in line:
                m = re.search(r'filename=(\S+) pid=(\d+)', line)
                if m:
                    execs.setdefault(int(m[2]), []).append(m[1])
                else:
                    check('exec trace parse', False, line)
            elif 'sched_process_exit:' in line:
                m = re.search(r' pid=(\d+) ', line)
                if m:
                    exits.add(int(m[1]))
                else:
                    check('exit trace parse', False, line)
    losses = read('trace-stats.json')
    for cpu, stat in losses.items():
        values = dict(re.findall(r'^(overrun|commit overrun|dropped events): (\d+)$', stat, re.M))
        check('trace loss:' + cpu, len(values) == 3 and all(int(x) == 0 for x in values.values()), values)
    check('trace covers CPUs', bool(losses), 'trace-stats.json')

    check('supervisor actual child of traced fixture', sup.get('pid') in edges, 'process-trace.txt')
    check('cleanup supervisor runs as delegated UID, not root observer', any(
          e.get('event') == 'SUPERVISOR_STARTED' and e.get('uid') == 65534
          and e.get('pid') == sup.get('pid') for e in se))
    check('Controller actual child of surviving supervisor',
          sup.get('controller_pid') is not None and edges.get(sup['controller_pid']) == sup.get('pid'))
    swaits = [e for e in se if e.get('event') == 'SUPERVISOR_REAL_WAIT']
    check('supervisor Controller status comes from real wait log', any(
          e.get('pid') == sup.get('controller_pid') and e.get('wait_status') == sup.get('controller_wait_status')
          for e in swaits), 'supervisor-events.jsonl')
    for w in sup.get('wait_records', []):
        check('supervisor wait corroborated:' + str(w.get('pid')), any(
              e.get('pid') == w.get('pid') and e.get('wait_status') == w.get('wait_status')
              for e in swaits), w)
    check('supervisor real wait reached ECHILD', sup.get('echild') is True, 'supervisor.json')
    check('supervisor final FD inventory restored',
          sup.get('fd_before') is not None and sup.get('fd_before') == sup.get('fd_after'))
    check('supervisor product release complete', sup.get('release_state') == 'RELEASED'
          and sup.get('resources_removed') is True and sup.get('remaining_cgroups') == []
          and sup.get('remaining_workspaces') == [] and sup.get('errors') == [])
    check('root observer did not perform product cleanup',
          sup.get('observer_cleanup_used') is False and ext.get('observer_killed_processes') is False
          and ext.get('observer_removed_product_resources') is False)
    check('fixture removed only empty outer delegation', ext.get('delegation_removed') is True
          and ext.get('remaining_before_fixture_release') == [CG + '/client']
          and ext.get('supervisor_wait_status') == 0)
    for name_ in ('observer-after.json', 'observer-later.json'):
        obs = read(name_)
        groups = obs.get('cgroups', {})
        check(name_ + ': no unprivileged process or workspace',
              obs.get('uid65534_processes') == {} and obs.get('workspaces') == {})
        check(name_ + ': only empty delegation/client remains',
              set(groups) == {CG, CG + '/client'} and all(
                  'populated 0' in g.get('cgroup.events', '') and g.get('cgroup.procs') == ''
                  and g.get('cgroup.threads') == '' and int(g.get('pids.current', '-1')) == 0
                  for g in groups.values()), 'sampling is not atomic; corroborated by real wait and removal')

    complete_rows = [read(p.name) for p in sorted(run.glob('[0-9]*-*.json'),
                       key=lambda p: int(p.name.split('-')[0]))]
    journals = [read(p.name) for p in sorted(run.glob('attempt-*.json'))]
    rows = complete_rows if summary else journals
    nonces = [r.get('nonce') for r in rows]
    check('unique attempt identities', bool(rows) and len(nonces) == len(set(nonces))
          and all(isinstance(x, str) and re.fullmatch(r'[0-9a-f]{32}', x) for x in nonces))
    if summary:
        check('summary matches independent attempt records',
              summary.get('all_passed') is True and summary.get('controller_echild') is True
              and len(summary.get('rows', [])) == len(rows)
              and all(all(r.get(k) == s.get(k) for k in s)
                      for r, s in zip(rows, summary.get('rows', []))))
        check('normal Controller shutdown', sup.get('controller_wait_status') == 0
              and sup.get('done_received') is True and sup.get('failure_reason') is None)
    else:
        check('no summary is an intended Controller SIGKILL test',
              config.get('case') in ('controller_death', 'controller_during_entry'))
        check('Controller failure not converted to business success',
              sup.get('controller_wait_status') == 9 and sup.get('done_received') is False
              and sup.get('business_result') == 'UNKNOWN' and sup.get('recovery_started_ns') is not None)
        check('surviving supervisor sealed creators before domain kills',
              any(e.get('event') == 'SUPERVISOR_CREATORS_STOPPED' for e in se)
              and any(e.get('event') == 'SUPERVISOR_QUIESCENCE' and e.get('echild') is True for e in se))

    attempt_results = []
    cwaits = [e for e in events if e.get('event') == 'CONTROLLER_WAIT']
    for index, r in enumerate(rows):
        nonce, case = r.get('nonce'), r.get('case')
        pre = f'{case}:{nonce}:'
        ev = [e for e in events if e.get('nonce') == nonce]
        z = [e for e in zl if e.get('nonce') == nonce]
        etypes = {e.get('event') for e in ev}
        ztypes = {e.get('event') for e in z}
        regs = [e for e in se if e.get('event') == 'ATTEMPT_REGISTERED' and e.get('nonce') == nonce]
        forks = [e for e in z if e.get('event') == 'ACTUAL_TRANSITION_FORK']
        check(pre + 'registered before any S fork', len(regs) == 1 and all(
              e['monotonic_ns'] >= regs[0]['monotonic_ns'] for e in forks))
        check(pre + 'all control responses identity-bound',
              all(e.get('nonce') == nonce for e in r.get('events', [])))
        for f in forks:
            check(pre + 'kernel Z-to-S edge', edges.get(f['pid']) == r.get('zygote_pid'), f)
            check(pre + 'S did not exec and exited', not execs.get(f['pid']) and f['pid'] in exits, f)
            for child, parent in edges.items():
                if parent == f['pid']:
                    check(pre + f'S child {child} inherited without exec and exited',
                          not execs.get(child) and child in exits)
        for f in (e for e in z if e.get('event') == 'ACTUAL_WORKER_FORK'):
            check(pre + 'kernel S-to-W edge', edges.get(f['worker_host_pid']) == f['waiter_host_pid'], f)
        cancel_acks = [e for e in ev if e.get('event') == 'CANCEL_ACK']
        if cancel_acks:
            first = min(e['monotonic_ns'] for e in cancel_acks)
            check(pre + 'no actual S fork after revoke ACK',
                  all(e['monotonic_ns'] <= first for e in forks),
                  {'ack_guest_monotonic_ns': first, 'fork_guest_monotonic_ns': [e['monotonic_ns'] for e in forks]})
        else:
            check(pre + 'revoke ACK not applicable or creator died', None,
                  'no revoke ACK; creator wait and recovery checked instead', required=False)
        worker = r.get('worker')
        if worker:
            check(pre + '19 business/security checks present and pass',
                  set(worker.get('checks', {})) == CHECK_NAMES and all(worker['checks'].values()))
            check(pre + 'actual memory inheritance and child COW',
                  worker.get('inherited') == r.get('expected_state')
                  and worker.get('after_cow', {}).get('sha256') != worker.get('inherited', {}).get('sha256')
                  and worker.get('after_cow', {}).get('object_id') == worker.get('inherited', {}).get('object_id'))
            ident = worker.get('identity', {})
            status = ident.get('status', {})
            check(pre + 'namespace identity and final security', ident.get('ns') == r.get('target_ns')
                  and status.get('NoNewPrivs') == '1' and status.get('Seccomp') == '2'
                  and all(int(status.get(k, '1'), 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'))
                  and set(ident.get('fds', {})) <= {'0', '1', '2'})
            check(pre + 'business raw output corroborates oracle', any(
                  e.get('event') == 'WORKER_READY' and all(e.get(k) == worker.get(k) for k in worker)
                  for e in ev), 'events.jsonl actual stdout observation')
            check(pre + 'post-drop gate preceded business authorization',
                  r.get('business_permit') is True and 'WORKER_GATED' in etypes)
        limits = r.get('limits', {})
        expected_limits = {'task': ('400000 100000', str(512*1024**2), '256'),
                           'transition': ('200000 100000', str(256*1024**2), '0' if case == 'pid_budget' else '128'),
                           'business': ('200000 100000', str(256*1024**2), '0' if case == 'second_budget' else '128')}
        check(pre + 'same cgroup safety limits', all(tuple(limits.get(k, {}).get(n, '').strip()
              for n in ('cpu.max', 'memory.max', 'pids.max')) == want for k, want in expected_limits.items()))
        argv = r.get('argv', [])
        check(pre + 'namespace and capability setup retained', all(x in argv for x in (
              '--unshare-user', '--disable-userns', '--unshare-pid', '--unshare-net',
              '--unshare-ipc', '--unshare-uts', '--cap-drop', 'ALL', '--as-pid-1', '--die-with-parent')))
        if summary:
            check(pre + 'complete release and output EOF', r.get('qualification') == 'PASS'
                  and r.get('resources_removed') is True and r.get('resources') == 'RELEASED'
                  and r.get('domain_empty') is True and r.get('output_eof') is True
                  and str(r.get('admission', '')).startswith('SEALED'))
            check(pre + 'cgroups really empty', bool(r.get('stats')) and all(
                  'populated 0' in v.get('cgroup.events', '') and int(v.get('pids.current', '-1')) == 0
                  for v in r.get('stats', {}).values()))
            check(pre + 'Controller FD inventory restored', r.get('controller_fd_before') == r.get('controller_fd_after'))
            check(pre + 'monitor exit from actual Controller wait', any(
                  e.get('pid') == r.get('monitor_pid') and e.get('wait_status') == r.get('monitor_wait') for e in cwaits))
            if r.get('s_state') == 'REAPED':
                check(pre + 'S result backed by true waiter', any(
                      e.get('event') == 'ACTUAL_TRANSITION_WAIT' and e.get('pid') == r.get('s_pid')
                      and e.get('wait_status') == r.get('s_wait') for e in z) or any(
                      e.get('pid') == r.get('s_pid') and e.get('wait_status') == r.get('s_wait') for e in cwaits))
            if r.get('w_wait') is not None:
                wait = r['w_wait']
                check(pre + 'W result backed by true waiter', any(
                      e.get('event') == 'ACTUAL_WORKER_WAIT' and e.get('worker_host_pid') == r.get('w_pid')
                      and e.get('wait_status') == wait.get('wait_status') for e in z) or any(
                      e.get('pid') == r.get('w_pid') and e.get('wait_status') == wait.get('wait_status') for e in cwaits))
            if r.get('s_state') == 'RECLAIMED_STATUS_UNKNOWN':
                check(pre + 'unknown S exit not invented', r.get('s_wait') is None
                      and r.get('adopted_echild') is True and r.get('failure') is not None)
            if r.get('business') == 'UNKNOWN':
                check(pre + 'unknown result not turned into success', r.get('result') is None
                      and r.get('outcome') not in ('SUCCEEDED', 'NONZERO'))
            if case in ('normal', 'nonzero', 'created_drop', 'reaped_drop'):
                expected_exit = 7 if case == 'nonzero' else 0
                check(pre + 'expected business exit from wait', r.get('result', {}).get('exit_code') == expected_exit
                      and r.get('outcome') == ('NONZERO' if expected_exit else 'SUCCEEDED')
                      and r.get('failure') is None and worker is not None and r.get('side_effect') == '2650100'
                      and r.get('s_wait') == 0 and r.get('monitor_wait') == 0 and bool(r.get('drained')))
            else:
                check(pre + 'fault never acknowledged successful', r.get('outcome') not in ('SUCCEEDED', 'NONZERO'))
            if case in ('cancel_queued', 'cancel_before_business', 'cancel_during_entry'):
                check(pre + 'cancel before business has no effect or permit', r.get('business') == 'NOT_EXECUTED'
                      and r.get('side_effect') is None and r.get('business_permit') is False and worker is None
                      and r.get('outcome') == 'CANCELLED')
                boundary = {'cancel_queued': 'PREPARED', 'cancel_before_business': 'WORKER_GATED',
                            'cancel_during_entry': 'ENTERED'}[case]
                check(pre + 'intended cancellation gate actually reached', boundary in etypes
                      and any(e.get('event') == 'CANCEL_REQUEST' and e.get('reason') == 'CANCELLED' for e in ev))
            if case == 'cancel_queued':
                check(pre + 'queued request irrevocably rejected late COMMIT', not forks
                      and r.get('late_commit_rejected') is True and 'COMMIT_REJECTED' in etypes
                      and r.get('s_state') == 'ABSENT' and r.get('cancel_acks', 0) >= 2)
            if case == 'double_cancel':
                check(pre + 'duplicate cancels including terminal cancel sealed',
                      r.get('cancel_acks', 0) >= 2 and r.get('terminal_duplicate_ack', {}).get('sealed') is True
                      and r.get('outcome') == 'CANCELLED' and worker is not None)
            if case == 'timeout':
                check(pre + 'actual timeout after business started', worker is not None
                      and r.get('outcome') == 'TIMED_OUT' and any(e.get('event') == 'CANCEL_REQUEST'
                      and e.get('reason') == 'TIMED_OUT' for e in ev))
            if case in ('zygote_death', 'pid1_death'):
                check(pre + 'requested live-process fault actually injected', worker is not None
                      and any(e.get('event') == 'FAULT' and e.get('case') == case for e in ev))
            if case == 'control_eof':
                check(pre + 'control close exercised after namespace entry', 'ENTERED' in etypes
                      and r.get('outcome') == 'STATUS_CHANNEL_LOST' and worker is None
                      and r.get('business_permit') is False)
            if case in ('pid_budget', 'second_budget'):
                field = 'spawn_errno' if case == 'pid_budget' else 'worker_errno'
                event_name = 'ACTUAL_TRANSITION_CLONE_REJECTED' if case == 'pid_budget' else 'ACTUAL_WORKER_CLONE_REJECTED'
                check(pre + 'EAGAIN classified as definite no execution', r.get(field) == 11
                      and r.get('business') == 'NOT_EXECUTED' and r.get('side_effect') is None
                      and r.get('w_state') == 'ABSENT' and event_name in ztypes)
                if case == 'pid_budget':
                    check(pre + 'first clone rejection never created S', not forks and r.get('s_state') == 'ABSENT')
                next_ = rows[index+1] if index+1 < len(rows) else {}
                check(pre + 'healthy template handles next normal request', next_.get('case') == 'normal'
                      and next_.get('zygote_pid') == r.get('zygote_pid') and next_.get('outcome') == 'SUCCEEDED')
            if case in ('created_drop', 'reaped_drop'):
                fault = 'FAULT_CREATED_RECEIPT_DROPPED' if case == 'created_drop' else 'FAULT_REAPED_RECEIPT_DROPPED'
                dropped = 'TRANSITION_CREATED' if case == 'created_drop' else 'TRANSITION_REAPED'
                check(pre + 'receipt genuinely omitted, state recovered', fault in ztypes and dropped not in etypes)
                if case == 'reaped_drop':
                    check(pre + 'snapshot returns retained real wait', any(e.get('event') == 'SNAPSHOT'
                          and e.get('s_state') == 'REAPED' and e.get('s_wait') == 0 for e in ev))
            if case == 'result_loss_side_effect':
                check(pre + 'lost result after effect stays UNKNOWN', 'FAULT_WORKER_WAIT_RECEIPT_DROPPED' in ztypes
                      and 'WORKER_WAITED' not in etypes and r.get('side_effect') == '2650100'
                      and r.get('business') == 'UNKNOWN' and r.get('result') is None)
            if case in ('fork_ack_loss', 'reap_ack_loss'):
                fault = 'FAULT_Z_DIES_BEFORE_CREATED' if case == 'fork_ack_loss' else 'FAULT_Z_DIES_BEFORE_REAPED'
                check(pre + 'historical creator death fault actually fired', fault in ztypes and any(
                      e.get('pid') == r.get('zygote_pid') and e.get('wait_status') == 9 for e in cwaits))
            if case == 'revoke_ack_loss':
                check(pre + 'revoke acknowledgment deliberately lost at business gate',
                      'FAULT_REVOKE_ACK_DROPPED' in ztypes and 'WORKER_GATED' in etypes
                      and 'CANCEL_ACK' not in etypes and 'REVOKE_ACK_TIMEOUT' in etypes)
                check(pre + 'creator genuinely waited after conservative stop', any(
                      e.get('pid') == r.get('zygote_pid') and e.get('wait_status') == 9 for e in cwaits)
                      and r.get('admission') == 'SEALED_CREATOR_WAITED')
                check(pre + 'missing revoke ACK cannot release business gate',
                      r.get('business') == 'NOT_EXECUTED' and r.get('business_permit') is False
                      and r.get('side_effect') is None and worker is None
                      and r.get('outcome') not in ('SUCCEEDED', 'NONZERO'))
        else:
            sa = next((a for a in sup.get('attempts', []) if a.get('nonce') == nonce), {})
            check(pre + 'supervisor owns UNKNOWN result and real release',
                  sa.get('business_result') == 'UNKNOWN' and sa.get('output_eof') is True
                  and sa.get('resources_removed') is True and sa.get('registered') is True)
            check(pre + 'registered before killed Controller', len(regs) == 1 and any(
                  e.get('event') == 'FAULT' and e.get('case') == case for e in ev))
            if case == 'controller_death':
                check(pre + 'business effect retained in recovery evidence',
                      sa.get('side_effects', {}).get('result', {}).get('text_prefix') == '2650100')
        attempt_results.append({k: r.get(k) for k in ('case', 'nonce', 'zygote_pid', 's_pid', 'w_pid',
                                's_state', 'w_state', 'business', 'result', 'outcome', 'resources')})

    owned = {sup['pid']} if sup.get('pid') is not None else set()
    while True:
        added = {p for p, parent in edges.items() if parent in owned} - owned
        if not added:
            break
        owned.update(added)
    check('all supervised descendants have kernel exit events', bool(owned) and owned <= exits,
          {'owned': sorted(owned), 'missing_exit': sorted(owned - exits)})
    for zp in {r.get('zygote_pid') for r in rows} - {None}:
        check('Zygote single initial Python exec:' + str(zp), execs.get(zp) == ['/usr/bin/python3'])
    failures = [c for c in checks if c['required'] and c['value'] is not True]
    return {'run': name, 'status': 'FAIL' if failures else 'PASS', 'checks': checks,
            'verifier_sha256': sha(Path(__file__)),
            'failures': failures, 'attempts': attempt_results, 'security_source_sha': security_hashes,
            'security_binary_sha': binary_hashes, 'trace_forks': len(edges),
            'owned_processes': len(owned), 'trace_loss_checks': len(losses),
            'limitations': ['Controlled serial prototype qualification; no performance benchmark.',
                           'Guest monotonic timestamps only; no ftrace/user clock subtraction.',
                           'Trace exits corroborate process disappearance, not exit-status ownership.',
                           'Final /proc observations are non-atomic; real wait, empty cgroups and removal also required.',
                           'No result inferred from side-effect files after Controller loss.'],
            'evidence_sha256': {str(p.relative_to(run)): sha(p) for p in sorted(run.rglob('*'))
                               if p.is_file() and (p.suffix in ('.json', '.jsonl', '.txt', '.log', '.py', '.c', '.h', '.sh')
                                                   or p.name in ('bridge.so', 'native.so', 'domain_init'))}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs', nargs='+', help='frozen run basenames')
    parser.add_argument('--check-only', action='store_true', help='do not write or overwrite anything')
    args = parser.parse_args()
    failed = False
    for name in args.runs:
        result = analyze(name)
        if not args.check_only:
            out = STUDY / 'analysis' / (name + '.json')
            out.parent.mkdir(exist_ok=True)
            with out.open('x') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
                f.write('\n')
        print(json.dumps({'run': name, 'status': result['status'], 'checks': len(result['checks']),
                          'failures': result['failures']}, ensure_ascii=False))
        failed |= result['status'] != 'PASS'
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
