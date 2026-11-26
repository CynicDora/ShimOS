#!/usr/bin/env python3
"""Index existing results and independently verified reports; never run a VM.

This index does not replace a verifier. Missing or rejected reports remain
visible, incomplete series never enter paired full-N performance comparisons.
Outputs are exclusively created; regenerate under a new name after more runs.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

STUDY = Path(__file__).resolve().parent.parent


def read(path):
    return json.loads(path.read_text())


def ref(path):
    return {'path': str(path.relative_to(STUDY)),
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def save(path, value):
    with path.open('x') as out:
        json.dump(value, out, ensure_ascii=False, indent=2)
        out.write('\n')


def resource_facts(path):
    hpath = path / 'supervisor.json'
    if not hpath.exists():
        return {'observed': False}
    h = read(hpath)
    names = ('release_state', 'controller_wait_status', 'echild', 'errors',
             'protocol_errors', 'resources_removed', 'remaining_cgroups',
             'remaining_workspaces', 'observer_cleanup_used')
    attempts = h.get('attempts', [])
    counts = Counter(row.get('business_result', 'NOT_RECORDED') for row in attempts)
    return {'observed': True, 'evidence': ref(hpath), **{k: h.get(k) for k in names},
            'registered_attempts': len(attempts), 'business_result_counts': dict(counts),
            'retired_attempts': sum(row.get('retired') is True for row in attempts),
            'fd_restored': h.get('fd_before') == h.get('fd_after')}


def main_matrix():
    pre = STUDY / 'analysis/paired-numpy-01/predeclared.json'
    schedule = read(pre)['schedule']
    rows = []
    for count, repeat, order in schedule:
        name = f'paired-numpy-01-n{count}-r{repeat}'
        path = STUDY / 'runs' / name
        result = read(path / 'result.json')
        config = read(path / 'batch-config.json')
        assert config['requests'] == count and config['order'] == order.split(',')
        report_path = STUDY / 'analysis' / (name + '-performance.json')
        if count == 100:
            report_path = STUDY / 'analysis/paired-numpy-01-n100-observed-performance.json'
        report = read(report_path)
        sessions = []
        for spec in config['sessions']:
            session = path / spec['relative_dir']
            matches = [r for r in report['runs']
                       if (STUDY / r['run']).resolve() == session.resolve()]
            np_path = STUDY / 'analysis' / (name + '-' + session.name + '-numpy.json')
            observed = bool(matches)
            np = read(np_path) if np_path.exists() else {}
            actual = matches[0] if len(matches) == 1 else {}
            accepted = actual.get('status') == np.get('status') == 'PASS'
            sessions.append({'session': session.name, 'baseline': spec['baseline'],
                             'status': 'PASS' if accepted else 'FAIL' if observed else 'NOT_RUN',
                             'performance_status': actual.get('status', 'NOT_RUN'),
                             'numpy_status': np.get('status', 'NOT_RUN'),
                             'numeric_counts': np.get('numeric_counts', {}),
                             'accepted_complete_requests': count if accepted else 0,
                             'numpy_report': ref(np_path) if np_path.exists() else None,
                             'resources': resource_facts(session)})
        complete_pair = result.get('complete') is True and all(s['status'] == 'PASS' for s in sessions)
        rows.append({'run': name, 'N': count, 'repeat': repeat, 'order': config['order'],
                     'pair_status': 'PASS' if complete_pair else 'FAIL',
                     'complete_pair_admitted': complete_pair, 'result': ref(path / 'result.json'),
                     'configuration': ref(path / 'batch-config.json'),
                     'performance_report': ref(report_path), 'sessions': sessions})
    return {'schema': 1, 'status': 'PASS' if all(r['complete_pair_admitted'] for r in rows) else 'PARTIAL',
            'predeclared': ref(pre), 'runs': rows,
            'planned_pair_count': len(rows),
            'complete_pairs_admitted': sum(r['complete_pair_admitted'] for r in rows),
            'incomplete_pairs_not_admitted': sum(not r['complete_pair_admitted'] for r in rows),
            'planned_requests': sum(2 * r['N'] for r in rows),
            'accepted_complete_session_requests': sum(s['accepted_complete_requests'] for r in rows for s in r['sessions']),
            'saved_numeric_passes_in_rejected_sessions': sum(s['numeric_counts'].get('PASS', 0) for r in rows
                                                            for s in r['sessions'] if s['status'] != 'PASS'),
            'interpretation': 'PARTIAL is not overall qualification PASS. Only complete paired series may enter full-N paired timing. Saved arrays from rejected sessions never turn UNKNOWN into success.',
            'generator': ref(Path(__file__))}


def failure_ledger():
    runs = []
    for rp in sorted((STUDY / 'runs').glob('*/result.json')):
        path = rp.parent; result = read(rp)
        phase = ('pilot' if path.name.startswith('pilot-') else 'qualification' if path.name.startswith('qualification-')
                 else 'formal_paired' if path.name.startswith('paired-numpy-01-') else 'diagnostic_or_other')
        entry = {'run': path.name, 'phase': phase, 'result': ref(rp),
                 'transport_complete': result.get('complete'), 'qemu_rc': result.get('qemu_rc'),
                 'host_timeout': result.get('timeout'), 'sessions': []}
        sessions = sorted((path / 'sessions').iterdir()) if (path / 'sessions').is_dir() else [path]
        for session in sessions:
            sp = session / 'summary.json'; summary = read(sp) if sp.exists() else {}
            entry['sessions'].append({'session': str(session.relative_to(path)) or '.',
                                      'summary_present': sp.exists(), 'summary_all_passed': summary.get('all_passed'),
                                      'summary_evidence': ref(sp) if sp.exists() else None,
                                      'finalized_attempts': len(summary.get('rows', [])),
                                      'resources': resource_facts(session)})
        if phase == 'pilot':
            entry['performance_exclusion'] = 'Pilot: not included in formal repetitions, regardless of outcome.'
        elif phase == 'qualification':
            entry['performance_exclusion'] = 'Fault/correctness qualification: not a performance repetition. Expected failure outcomes are judged by their own contract.'
        elif phase == 'diagnostic_or_other':
            entry['performance_exclusion'] = 'Separate diagnostic scope; do not merge with predeclared timing=1 main matrix.'
        elif not result.get('complete'):
            entry['performance_exclusion'] = 'Full paired series incomplete. Do not extrapolate partial cold completion to N=100; independently complete hot session may be reported separately.'
        runs.append(entry)
    rejected = []
    reasons = {
        'pilot-import-hot-02-numpy-initial.json': 'Checker path filter initially omitted the frozen NumPy support DSO directory; raw run retained. Not proof of runtime corruption.',
        'pilot-import-hot-02-numpy-parser-recheck.json': 'Pilot manifest lacks required NumPy case/audit identity; never backfilled.',
        'qualification-blas-cold-control-01-numpy.json': 'Initial report lacks explicit same-run verifier binding and requests dependency-audit for audit=0. Later explicit boundary-only report retained separately.',
        'qualification-numpy-compute-failure-01-numpy-final-v2.json': 'Wrong default dependency-audit profile for audit=0 correctly BLOCKED; final-v3 explicitly boundary-only, same unchanged raw run.'}
    for path in sorted((STUDY / 'analysis').glob('*.json')):
        value = read(path)
        if not isinstance(value, dict):
            continue
        reports = [(value.get('run'), value)] if value.get('status') in ('FAIL', 'BLOCKED') else []
        reports += [(r.get('run'), r) for r in value.get('runs', []) if isinstance(r, dict) and r.get('status') in ('FAIL', 'BLOCKED')]
        for run, report in reports:
            errors = report.get('failures', []) + report.get('blockers', [])
            rejected.append({'report': ref(path), 'run': run, 'status': report['status'],
                             'reason': reasons.get(path.name, 'See actual failed checks; not removed or upgraded by this index.'),
                             'checks': [{k: e.get(k) for k in ('name', 'check', 'value', 'passed')} for e in errors if isinstance(e, dict)]})
    return {'schema': 1, 'scope': 'All completed top-level runs and rejected direct checker reports existing when generated; source data never modified.',
            'runs': runs, 'rejected_or_blocked_reports': rejected,
            'explicit_development_failure': {'run': 'pilot-import-hot-01',
                'reason': 'First pilot failed because read-only runtime target mountpoints did not yet exist. VM completion/exit 0 is not product qualification.',
                'final_scope': 'Excluded; source revision and later new runs preserved.'},
            'qualification_summary': ref(STUDY / 'analysis/qualification-all-final.json'),
            'rules': ['Expected injected business failure/UNKNOWN can satisfy its fault contract; it is not automatically a product failure.',
                      'Transport complete or QEMU exit 0 never means all requests passed.',
                      'N100 timeout partial outputs remain evidence, not complete-N performance samples.',
                      'No attempts, timeouts, logs or rejected checker outputs deleted.'],
            'generator': ref(Path(__file__))}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--matrix-out', type=Path)
    p.add_argument('--ledger-out', type=Path)
    a = p.parse_args()
    if not a.matrix_out and not a.ledger_out:
        p.error('choose at least one exclusive output')
    if a.matrix_out:
        value = main_matrix(); save(a.matrix_out, value)
        print(json.dumps({k: v for k, v in value.items() if k not in ('runs', 'predeclared', 'generator')}, ensure_ascii=False))
    if a.ledger_out:
        value = failure_ledger(); save(a.ledger_out, value)
        print(json.dumps({'indexed_runs': len(value['runs']), 'rejected_reports': len(value['rejected_or_blocked_reports'])}))


if __name__ == '__main__':
    main()
