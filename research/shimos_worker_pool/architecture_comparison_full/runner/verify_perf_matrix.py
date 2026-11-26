#!/usr/bin/env python3
"""Read-only paired-run qualification; never starts or waits for a VM.

Only complete pairs are eligible. Existing report files are never overwritten;
reuse requires the same checker hash and run identity. Pass a new suffix after
any checker revision. All NumPy numerical arrays are still checked separately.
"""
import argparse
import hashlib
import json
from pathlib import Path

import verify_numpy
import verify_performance

S = Path(__file__).resolve().parent.parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path):
    return json.loads(path.read_text())


def save(path, value):
    with path.open('x') as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write('\n')


def canonical_run(value):
    path = Path(value)
    if not path.is_absolute() and path.parts and path.parts[0] == 'runs':
        path = S / path
    return path.resolve()


def check_pair(name, suffix, qualification):
    assert Path(name).name == name
    run = S / 'runs' / name
    result, config = load(run / 'result.json'), load(run / 'batch-config.json')
    if result.get('complete') is not True:
        return {'run': name, 'status': 'BLOCKED', 'reason': 'paired VM not complete; no performance admission'}
    assert config.get('pilot') is False, 'pilot is not a formal sample'
    sessions = [run / row['relative_dir'] for row in config['sessions']]
    performance_path = S / 'analysis' / (name + '-performance' + suffix + '.json')
    if performance_path.exists():
        report = load(performance_path)
        assert all(item.get('verifier_sha256') == sha(Path(verify_performance.__file__)) for item in report['runs'])
        assert {canonical_run(item['run']) for item in report['runs']} == {p.resolve() for p in sessions}
        for item in report['runs']:
            base = canonical_run(item['run'])
            assert item.get('evidence_sha256') and all(
                sha(verify_numpy.within_run(base, relative)) == digest for relative, digest in item['evidence_sha256'].items())
    else:
        report = {'runs': [verify_performance.analyze(p, qualification) for p in sessions]}
        save(performance_path, report)
    output = []
    for path in sessions:
        relative = str(path.relative_to(S / 'runs'))
        numpy_path = S / 'analysis' / (name + '-' + path.name + '-numpy' + suffix + '.json')
        if numpy_path.exists():
            numpy = load(numpy_path)
            assert numpy.get('run') == relative and numpy.get('verifier_sha256') == sha(Path(verify_numpy.__file__))
            assert numpy.get('evidence_sha256_study_relative') and all(
                sha(verify_numpy.within_run(S, p)) == h for p, h in numpy['evidence_sha256_study_relative'].items())
        else:
            numpy = verify_numpy.analyze(relative, profile='performance', performance_report=performance_path)
            save(numpy_path, numpy)
        actual = [r for r in report['runs'] if canonical_run(r['run']) == path.resolve()]
        assert len(actual) == 1
        output.append({'session': path.name, 'baseline': numpy['numpy_baseline'],
                       'performance_status': actual[0]['status'], 'numpy_status': numpy['status'],
                       'numeric_counts': numpy.get('numeric_counts'),
                       'numpy_file': str(numpy_path.relative_to(S)), 'numpy_sha256': sha(numpy_path)})
    return {'run': name, 'requests_per_session': config['requests'],
            'status': 'PASS' if all(r['performance_status'] == r['numpy_status'] == 'PASS' for r in output) else 'FAIL',
            'performance_file': str(performance_path.relative_to(S)), 'performance_sha256': sha(performance_path),
            'sessions': output}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pairs', nargs='+')
    parser.add_argument('--suffix', default='', help='optional new report suffix, e.g. -recheck-v2')
    parser.add_argument('--qualification', type=Path, default=S / 'analysis/qualification-plain-final.json')
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    rows = []
    for name in args.pairs:
        row = check_pair(name, args.suffix, args.qualification.resolve())
        rows.append(row)
        print(json.dumps(row, ensure_ascii=False), flush=True)
    value = {'status': 'PASS' if all(r['status'] == 'PASS' for r in rows) else 'FAIL', 'runs': rows,
             'verifier_sha256': {p.name: sha(p) for p in (Path(__file__), Path(verify_numpy.__file__), Path(verify_performance.__file__))},
             'scope': 'Actual same-session timing and numerical checks; auditable dependency admission separately pinned. No VM execution by this checker.'}
    save(args.out, value)
    return int(value['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
