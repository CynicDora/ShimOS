#!/usr/bin/env python3
"""Offline integrity/denominator audit. No guest workload or historical writes."""
import argparse
import csv
import difflib
import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from urllib.parse import unquote


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(4 << 20), b''):
            h.update(b)
    return h.hexdigest()


def load(path):
    return json.loads(path.read_text())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--skip-artifacts', action='store_true',
                    help='Only input checks; does not produce a complete new artifact manifest')
    args = ap.parse_args()
    study = Path(__file__).resolve().parents[1]
    project = study.parents[1]
    out = args.out.resolve()
    assert out.is_relative_to(study) and not out.exists()
    runs = sorted(p for p in (study / 'runs').iterdir() if p.is_dir())
    assert len(runs) <= 12
    assert all((p / 'result.json').exists() for p in runs), 'do not audit live VM output'
    out.mkdir(parents=True)
    memo = {}

    def actual(path):
        path = path.resolve()
        if path not in memo:
            memo[path] = digest(path) if path.is_file() else None
        return memo[path]

    checks = []

    def check(scope, path, expected):
        got = actual(path)
        checks.append(dict(scope=scope, path=str(path), expected=expected,
                           actual=got, unchanged=got == expected))

    previous = project / 'research/shimos_architecture_challenge/pilot_v1_1'
    audit = previous / 'analysis/delivery-audit-01'
    for row in load(audit / 'protected-input-checks.json'):
        check('historical_protected:' + row['scope'], Path(row['path']), row['expected'])
    for row in load(audit / 'artifact-manifest.json'):
        check('historical_pilot_v1_1_artifact', previous / row['path'], row['sha256'])
    source_changes = []
    patches = []
    for path, sha in load(study / 'sources/copied-v11-inputs.json').items():
        check('copied_source', project / path, sha)
        old = project / path
        relative = old.relative_to(previous)
        new = study / relative
        source_changes.append(dict(source=path, old_sha256=sha,
                                   independent_copy=str(new.relative_to(study)),
                                   new_sha256=actual(new), unchanged=actual(new) == sha))
        if new.is_file() and actual(new) != sha:
            try:
                patches.extend(difflib.unified_diff(old.read_text().splitlines(True),
                                                   new.read_text().splitlines(True),
                                                   fromfile=path,
                                                   tofile=str(new.relative_to(project))))
            except UnicodeError:
                patches.append(f'Binary difference: {path}\n')

    runrows = []
    actions = []
    attempts = []
    for run in runs:
        r = load(run / 'result.json')
        plan = load(run / 'execution-plan.json')
        spec = next(x for x in plan['runs'] if x['run_id'] == run.name)
        for path, sha in load(run / 'source-sha.json').items():
            check('executed_snapshot:' + run.name, run / path, sha)
        rel = r.get('guest_release') or {}
        runrows.append(dict(run_id=run.name, kind=spec['kind'],
                            vm_wall_s=r.get('wall_s'), qemu_rc=r.get('qemu_rc'),
                            timed_out=r.get('timeout'),
                            guest_released=rel.get('released'),
                            driver_completed=rel.get('driver_completed'),
                            observer_assistance_count=rel.get('observer_assistance_count'),
                            not_product_qualification=r.get('not_product_qualification'),
                            private_disk_retained=(run / 'disk.raw').exists()))
        # Count actual Session directories and command records, not planned probes.
        for session in sorted((run / 'sessions').glob('*')):
            if not session.is_dir():
                continue
            receipts = sorted(session.glob('*result*.json'))
            attempts.append(dict(run_id=run.name, session=session.name,
                                 receipt_files=[p.name for p in receipts]))
            # Validation workspaces contain copied research outputs; do not double count.
            for f in sorted(session.glob('actions.jsonl')):
                for n, line in enumerate(f.read_text().splitlines(), 1):
                    if line.strip():
                        row = json.loads(line)
                        actions.append(dict(run_id=run.name, session=session.name,
                                            source=str(f.relative_to(study)), line=n,
                                            action_index=row.get('index', row.get('action_id'))))

    def write(name, obj):
        (out / name).write_text(json.dumps(obj, ensure_ascii=False, indent=2) + '\n')

    write('protected-and-executed-inputs.json', checks)
    write('independent-copy-changes.json', source_changes)
    (out / 'independent-copy-changes.patch').write_text(''.join(patches))
    write('run-status.json', runrows)
    write('actual-session-directories.json', attempts)
    write('actual-action-records.json', actions)
    ledger = [json.loads(s) for s in (study / 'runs/run-ledger.jsonl').read_text().splitlines() if s.strip()]
    reserved = [x['run_id'] for x in ledger if x['event'] == 'RESERVED']
    finished = [x['run_id'] for x in ledger if x['event'] == 'FINISHED']
    ledger_ok = (len(reserved) == len(set(reserved)) == len(runs)
                 and Counter(reserved) == Counter(finished)
                 and set(reserved) == {p.name for p in runs})
    report_links = []
    for md in [study / 'README.md', *sorted((study / 'reports').glob('*.md'))]:
        for target in re.findall(r'\]\(([^\s)]+)(?:\s+[^)]*)?\)', md.read_text()):
            target = unquote(target.strip('<>')).split('#', 1)[0]
            if not target or re.match(r'^[a-zA-Z][\w+.-]*:', target):
                continue
            p = (md.parent / target).resolve()
            report_links.append(dict(document=str(md.relative_to(study)), target=target,
                                     exists=p.exists()))
    write('report-local-links.json', report_links)
    artifacts = []
    if not args.skip_artifacts:
        for path in sorted(study.rglob('*')):
            if path.is_relative_to(out):
                continue
            st = path.lstat()
            if path.is_symlink():
                artifacts.append(dict(path=str(path.relative_to(study)), symlink=os.readlink(path)))
            elif path.is_file():
                artifacts.append(dict(path=str(path.relative_to(study)), sha256=actual(path),
                                      bytes=st.st_size, allocated_bytes=st.st_blocks * 512))
        write('artifact-manifest.json', artifacts)
    summary = dict(
        scope='offline integrity and denominator check; not a runtime qualification',
        new_vm_count=len(runs), vm_limit=12, ledger_ok=ledger_ok,
        actual_session_directories=len(attempts), actual_action_records=len(actions),
        action_records_by_run=dict(Counter(x['run_id'] for x in actions)),
        session_directories_by_run=dict(Counter(x['run_id'] for x in attempts)),
        checked_identity_count=len(checks), unique_hashed_files=len(memo),
        identity_mismatches=[x for x in checks if not x['unchanged']],
        broken_local_links=[x for x in report_links if not x['exists']],
        new_artifact_manifest_complete=not args.skip_artifacts,
        new_artifact_file_count=len(artifacts),
        new_artifact_logical_bytes=sum(x.get('bytes', 0) for x in artifacts),
        new_artifact_allocated_bytes=sum(x.get('allocated_bytes', 0) for x in artifacts),
    )
    write('summary.json', summary)
    with (out / 'run-status.csv').open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(runrows[0])); w.writeheader(); w.writerows(runrows)
    print(json.dumps({k: v for k, v in summary.items() if k not in ('identity_mismatches', 'broken_local_links')}, ensure_ascii=False))
    if summary['identity_mismatches'] or summary['broken_local_links'] or not ledger_ok:
        raise SystemExit('AUDIT FAIL: preserve output; see summary.json')


if __name__ == '__main__':
    main()
