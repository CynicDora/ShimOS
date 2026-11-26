#!/usr/bin/env python3
"""Read-only admission for the isolated NP_INIT_STAGE diagnostic copy.

Runs no workload and performs no cleanup. The original immutable v2 mechanism
checker still verifies actual numeric arrays, boundaries, waits and release.
This wrapper additionally binds the reviewed exact 36-file diagnostic copy and
checks raw stage attribution. PASS is not formal performance admission.
"""
import argparse
import collections
import json
import traceback
from pathlib import Path

import verify_full_mechanism_observer_v2 as mechanism

S = Path(__file__).resolve().parent.parent
P = S / '03_initialization_cow/initialization_probe'
REVIEW = P / 'diagnostic-source-review.json'
STATIC_SHA = '4d27cf671557843802e5b7115f190cfad1aa792c1452fa58d60fdcd1f4d3bc49'
MECHANISM_SHA = 'c6eb6f66de0d34499fd0964ad7d69d24330c820a38779742e4967f64f07dfae6'
sha = mechanism.sha
LEVELS = ('none', 'base', 'import', 'data', 'blas')
NAMES = {
    'base_python_state': ('base_python_state', 'initialization'),
    'numpy_import': ('numpy_import', 'initialization'),
    'data_allocation': ('fixed_array_allocation', 'initialization'),
    'blas_warmup': ('fixed_128x128_blas_warmup', 'initialization'),
    'snapshot_before': (None, 'diagnostic_snapshot'),
    'snapshot_imported': (None, 'diagnostic_snapshot'),
    'snapshot_after': (None, 'diagnostic_snapshot'),
    'fingerprint_after': (None, 'diagnostic_fingerprint'),
}


def status(checks):
    return ('FAIL' if any(x['value'] is False for x in checks) else
            'BLOCKED' if any(x['value'] is None for x in checks) else 'PASS')


def analyze(name):
    run = (S / 'runs' / name).resolve(strict=True)
    run.relative_to((S / 'runs').resolve())
    e = mechanism.Evidence(run)
    e.section = 'initialization_diagnostic'
    static = e.json(P / 'independent-static-review.json')
    review = e.json(REVIEW)
    e.check('exact independent static audit retained', sha(P / 'independent-static-review.json') == STATIC_SHA)
    e.check('immutable v2 mechanism verifier retained', sha(Path(mechanism.__file__)) == MECHANISM_SHA)
    e.check('diagnostic review cannot admit performance', review.get('performance_admitted') is False
            and review.get('admission_keys') == [] and review.get('runtime_observations') == 'PENDING')
    sources = e.json(run / 'source-sha.json')
    e.check('exact 36 diagnostic files independently reviewed', len(sources) == 36
            and sources == static.get('probe_source_sha256')
            and static.get('changed_files') == ['numpy_workload.py']
            and all(static.get('checks', {}).values()))
    full = e.json(run / 'full-session.json')
    config = full.get('configuration', {})
    matrices = []
    for item in review.get('diagnostic_matrices', []):
        path = mechanism.npcheck.within_run(S, item['path'])
        matrix = e.json(path)
        e.check('registered diagnostic matrix unchanged:' + path.name, sha(path) == item['sha256'])
        if isinstance(matrix, list):
            matrices += matrix
    e.check('exact finite diagnostic configuration, not arbitrary source admission',
            sum(x == config for x in matrices) == 1 and full.get('requests') == 2)
    base = mechanism.analyze(name, 'boundary', str(REVIEW.relative_to(S)))
    logs = e.records(sorted(set(list(run.glob('*.log')) + [run / 'events.jsonl', run / 'supervisor-events.jsonl'])))
    unique = mechanism.old.unique
    all_admissions = unique([x for x in logs if x.get('event') == 'NP_ADMISSION'])
    admissions = [x for x in all_admissions if x.get('location') != 'cold_reference']
    reference_admissions = [x for x in all_admissions if x.get('location') == 'cold_reference']
    reference = e.json(run / 'numpy-reference.json')
    spans = unique([x for x in logs if x.get('event') == 'NP_INIT_STAGE'])
    results = unique([x for x in logs if x.get('event') == 'NP_RESULT'])
    mode = base.get('mode')
    level = base.get('level')
    expected_initializations = 2 if mode == 'G0' else 1 + (0 if level == 'blas' else 2)
    e.check('all intended initialization calls observed', len(admissions) == expected_initializations,
            {'observed': len(admissions), 'expected': expected_initializations})
    e.check('independent oracle initialization explicitly separate', len(reference_admissions) == 1,
            'These spans are checked but not charged to template/Worker initialization.')
    e.check('actual normal tasks complete and numerically verified', base.get('attempts') == 2
            and len(results) == 2 and all(x.get('numeric_status') == 'PASS' for x in base.get('numeric', [])))
    keys = [(x.get('start_ns'), x.get('pid_namespace_local'), x.get('location')) for x in all_admissions]
    e.check('initialization identities are unique within session', len(keys) == len(set(keys)))
    expected_z = 'Z_domain' if mode == 'G3' else 'Z'
    e.check('correct placement of actual initialization calls',
            collections.Counter(x.get('location') for x in admissions) ==
            (collections.Counter({'W_cold': 2}) if mode == 'G0' else
             collections.Counter({expected_z: 1, **({'W_completion': 2} if level != 'blas' else {})})))
    observed = []
    owned = set()
    for admission in all_admissions:
        start = admission.get('start_ns')
        pid = admission.get('pid_namespace_local')
        location = admission.get('location')
        prefix = f'init:{location}:{pid}:{start}'
        before = admission.get('previous_level')
        target = admission.get('level')
        local = [(i, x) for i, x in enumerate(spans) if x.get('admission_start_ns') == start
                 and x.get('pid_namespace_local') == pid and x.get('location') == location]
        owned.update(i for i, _ in local)
        e.check(prefix + ':valid exact level transition', before in LEVELS and target in LEVELS[1:]
                and LEVELS.index(before) <= LEVELS.index(target))
        expected = ['snapshot_before']
        stages = []
        if before in LEVELS and target in LEVELS:
            for step, tag in [('base', 'base_python_state'), ('import', 'numpy_import'),
                              ('data', 'data_allocation'), ('blas', 'blas_warmup')]:
                if LEVELS.index(before) < LEVELS.index(step) <= LEVELS.index(target):
                    expected.append(tag)
                    stages.append(NAMES[tag][0])
                    if step == 'import': expected.append('snapshot_imported')
        expected += ['fingerprint_after', 'snapshot_after']
        ordered = sorted((x for _, x in local), key=lambda x: x.get('start_ns', -1))
        e.check(prefix + ':exact nonduplicated operation coverage', [x.get('stage') for x in ordered] == expected)
        e.check(prefix + ':actual preparation list agrees with probes', admission.get('preparation_stages') == stages)
        e.check(prefix + ':existing init invariants held', bool(admission.get('checks'))
                and all(x is True for x in admission['checks'].values()))
        e.check(prefix + ':same process snapshots', all(admission.get(k, {}).get('pid_namespace_local') == pid
                for k in ('before', 'imported', 'after')))
        linked_nonce = None
        if location.startswith('W_'):
            matches = [x for x in results if x.get('pid_namespace_local') == pid
                       and x.get('call_start_ns', 2**64) <= start
                       and admission.get('complete_ns', 2**64) <= x.get('compute_begin_ns', -1)]
            e.check(prefix + ':exact Worker and attempt linked by actual execution interval', len(matches) == 1)
            if len(matches) == 1:
                result = matches[0]
                linked_nonce = result.get('nonce')
                e.check(prefix + ':completion profile/level/operations agree with request',
                        result.get('profile') == admission.get('profile') and target == 'blas'
                        and result.get('completion_stages') == stages
                        and before == ('none' if mode == 'G0' else level))
        elif location == 'cold_reference':
            e.check(prefix + ':actual independent oracle identity and interval',
                    reference.get('event') == 'NP_COLD_REFERENCE' and reference.get('pid') == pid
                    and reference.get('profile') == admission.get('profile')
                    and reference.get('started_ns', 2**64) <= start
                    and admission.get('complete_ns', 2**64) <= reference.get('finished_ns', -1)
                    and before == 'none' and target == 'import')
        else:
            ready_event = 'LOCAL_READY' if mode == 'G3' else 'ZYGOTE_READY'
            ready = unique([x for x in logs if x.get('event') == ready_event
                            and x.get('identity', {}).get('pid') == pid])
            # LOCAL_READY is retained in its exact domain JSON rather than R log.
            if mode == 'G3':
                ready = []
                for path in sorted(run.glob('local-domain-*-ready.json')):
                    value = e.json(path).get('ready', {})
                    if value.get('identity', {}).get('pid') == pid:
                        ready.append(value)
            e.check(prefix + ':actual ready process backs template initialization', len(ready) == 1
                    and before == 'none' and target == level)
        previous_end = start
        for _, span in local:
            tag = span.get('stage')
            label = prefix + ':' + str(tag)
            e.check(label + ':same profile/process/level and explicit clocks',
                    span.get('profile') == admission.get('profile') and span.get('level') == target
                    and span.get('previous_level') == before and span.get('clock') == 'CLOCK_MONOTONIC'
                    and span.get('cpu_clock') == 'CLOCK_PROCESS_CPUTIME_ID'
                    and span.get('nested_in_admission') is True and span.get('initializer_checks_pass') is True)
            a, b, wall, cpu = (span.get(k) for k in ('start_ns', 'end_ns', 'wall_ns', 'cpu_ns'))
            valid = all(isinstance(x, int) for x in (a, b, wall, cpu, start, admission.get('complete_ns')))
            e.check(label + ':recorded raw nonnegative nested duration', valid and
                    start <= a <= b <= admission['complete_ns'] and wall == b-a and cpu >= 0)
            e.check(label + ':correct mechanism/diagnostic classification', tag in NAMES
                    and span.get('category') == NAMES[tag][1])
            e.check(label + ':serialization follows recorded envelope',
                    isinstance(span.get('monotonic_ns'), int) and span['monotonic_ns'] >= admission.get('complete_ns', 2**64))
        for span in ordered:
            e.check(prefix + ':no overlap between these sequential operation spans:' + str(span.get('stage')),
                    isinstance(span.get('start_ns'), int) and span['start_ns'] >= previous_end)
            previous_end = span.get('end_ns', 2**64)
        observed.append({'admission_start_ns': start, 'pid_namespace_local': pid, 'location': location,
                         'nonce': linked_nonce, 'level': target, 'previous_level': before,
                         'operation_count': len(local), 'envelope_wall_ns': admission.get('complete_ns', start)-start,
                         'stages': [mechanism.old.clean(x) for x in ordered]})
    e.check('no orphaned or extra stage records', owned == set(range(len(spans))))
    checks = base['checks'] + e.checks
    return dict(run=name, status=status(checks), scope='INITIALIZATION_DIAGNOSTIC_ONLY_NOT_FORMAL_PERFORMANCE',
                attempts=base.get('attempts'), mechanism_observations_status=base.get('mechanism_observations_status'),
                mode=mode, level=level,
                actual_initializations=[x for x in observed if x['location'] != 'cold_reference'],
                cold_reference_initializations=[x for x in observed if x['location'] == 'cold_reference'],
                checks=checks,
                failed=[x for x in checks if x['value'] is False], missing=[x for x in checks if x['value'] is None],
                source_sha256=base.get('source_sha256'), binary_sha256=base.get('binary_sha256'),
                numeric=base.get('numeric'), verifier_sha256=sha(Path(__file__)),
                mechanism_verifier_sha256=sha(Path(mechanism.__file__)),
                dependency_verifier_sha256=base.get('dependency_verifier_sha256'),
                evidence_sha256_study_relative={**base.get('evidence_sha256_study_relative', {}), **e.evidence},
                limits=['Single independent instrumented copy; no formal v2 performance ranking',
                        'Stage wall includes scheduling; process CPU is not pure kernel CPU',
                        'Nested stages cannot be added to enclosing initialization/session totals',
                        'base_python_state is not interpreter startup',
                        'Stage serialization is outside recorded admission envelope but inside actual session',
                        'Kernel exec/ancestry trace is not collected by this boundary diagnostic'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs', nargs='+', help='run batch names or runs-relative session paths')
    parser.add_argument('--out-dir', required=True, help='new study-relative directory, exclusive create')
    args = parser.parse_args()
    out = (S / args.out_dir).resolve(); out.relative_to(S.resolve());out.mkdir(parents=True, exist_ok=False)
    sessions=[]
    for name in args.runs:
        path=(S/'runs'/name).resolve(strict=True);path.relative_to((S/'runs').resolve())
        sessions += sorted((path/'sessions').iterdir()) if (path/'sessions').is_dir() else [path]
    reports=[]
    for index, path in enumerate(sessions):
        name=str(path.relative_to(S/'runs'))
        try: result=analyze(name)
        except Exception as error:
            result=dict(run=name,status='BLOCKED',verifier_error=repr(error),traceback=traceback.format_exc(),
                        verifier_sha256=sha(Path(__file__)))
        dest=out/f'{index:02d}-{path.name}.json'
        with dest.open('x') as file:json.dump(result,file,ensure_ascii=False,indent=2);file.write('\n')
        reports.append(dict(run=name,status=result['status'],attempts=result.get('attempts',0),
                            report=str(dest.relative_to(S)),sha256=sha(dest)))
        print(json.dumps(reports[-1]),flush=True)
    summary=dict(scope='LOCAL_DIAGNOSTIC_NOT_FORMAL_RANKING',session_count=len(reports),
                 attempt_count=sum(x['attempts'] for x in reports),
                 status='FAIL' if any(x['status']=='FAIL' for x in reports) else
                        'BLOCKED' if any(x['status']!='PASS' for x in reports) else 'PASS',
                 status_counts=dict(collections.Counter(x['status'] for x in reports)),sessions=reports,
                 verifier_sha256=sha(Path(__file__)),mechanism_verifier_sha256=MECHANISM_SHA)
    with (out/'summary.json').open('x') as file:json.dump(summary,file,ensure_ascii=False,indent=2);file.write('\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='sessions'}),flush=True)
    return 0 if summary['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
