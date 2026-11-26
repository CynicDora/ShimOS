#!/usr/bin/env python3
"""Read only the frozen predecessor; write an exclusive new audit in this study."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import stat

STUDY = Path(__file__).resolve().parents[1]
OLD = STUDY.with_name('exec_support')


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(8 << 20), b''):
            value.update(data)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(STUDY.resolve()) or out.is_relative_to((STUDY / 'runs').resolve()):
        parser.error('output must be in the new study, outside raw runs')
    if out.exists(): parser.error('existing audits are never overwritten')
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    frozen_path = STUDY / 'frozen/exec-support-inputs.json'
    frozen = json.loads(frozen_path.read_text())
    manifest_path = OLD / 'analysis/delivery-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    checks = []
    for name, expected in manifest['files'].items():
        rel = Path(name)
        if rel.is_absolute() or '..' in rel.parts:
            raise ValueError('unsafe manifest path')
        path = OLD / rel
        row = {'path': name, 'expected_sha256': expected['sha256'], 'expected_bytes': expected['bytes']}
        try:
            info = path.lstat()
            row.update(actual_bytes=info.st_size, actual_mode=oct(stat.S_IMODE(info.st_mode)))
            if not stat.S_ISREG(info.st_mode):
                row['status'] = 'NONREGULAR'
            else:
                row['actual_sha256'] = sha(path)
                row['status'] = 'PASS' if (row['actual_sha256'] == expected['sha256']
                    and row['actual_bytes'] == expected['bytes'] and row['actual_mode'] == expected['mode']) else 'MISMATCH'
        except OSError as exc:
            row.update(status='MISSING_OR_UNREADABLE', error=repr(exc))
        checks.append(row)
    references = []
    for name, expected in frozen['files'].items():
        expected = expected if isinstance(expected, str) else expected['sha256']
        path = OLD / name
        actual = sha(path) if path.is_file() else None
        references.append({'path': name, 'expected_sha256': expected,
                           'actual_sha256': actual, 'status': 'PASS' if actual == expected else 'MISMATCH'})
    errors = [row for row in checks + references if row['status'] != 'PASS']
    result = {'schema': 1, 'started_utc': start,
        'completed_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'status': 'FAIL' if errors else 'PASS', 'read_only_audit': True,
        'historical_source_root': str(OLD), 'manifest_created_utc': manifest['created_utc'],
        'manifest_sha256': sha(manifest_path), 'frozen_inputs_sha256': sha(frozen_path),
        'manifest_declared_regular_file_count': manifest['regular_file_count'],
        'checked_regular_file_count': len(checks),
        'passed_regular_file_count': sum(row['status'] == 'PASS' for row in checks),
        'logical_regular_bytes_checked': sum(row.get('actual_bytes', 0) for row in checks),
        'historical_file_checks': checks, 'frozen_reference_checks': references, 'errors': errors,
        'coverage_note': 'The historical manifest predates exec-support-consolidated.md. The consolidated document is separately frozen by exec-support-inputs.json; this does not claim the old manifest covers every later file.',
        'auditor_sha256': sha(Path(__file__))}
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('x') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({key: result[key] for key in ('status', 'checked_regular_file_count', 'passed_regular_file_count', 'logical_regular_bytes_checked', 'errors')}, ensure_ascii=False))
    return 0 if not errors else 1


if __name__ == '__main__':
    raise SystemExit(main())
