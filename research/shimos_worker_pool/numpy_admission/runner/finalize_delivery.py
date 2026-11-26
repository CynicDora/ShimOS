#!/usr/bin/env python3
"""Read-only checks plus a new-directory delivery inventory, no VM execution."""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import re


def digest(file):
    h = hashlib.sha256()
    with file.open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(data)
    return h.hexdigest()


def main():
    root = Path(__file__).resolve().parents[1]
    review = json.loads((root / 'docs/variant-source-review.json').read_text())
    checks = []
    for mode, spec in review['variants'].items():
        for name, expected in spec['source_sha256'].items():
            actual = digest(root / 'prototype' / name)
            checks.append(dict(check='frozen_prototype', mode=mode, path=name,
                               expected=expected, actual=actual, passed=actual == expected))
    for directory in ('prototype', 'runner'):
        for file in sorted((root / directory).glob('*.py')):
            try:
                ast.parse(file.read_text(), filename=str(file))
                checks.append(dict(check='python_syntax_only', path=str(file.relative_to(root)), passed=True))
            except SyntaxError as error:
                checks.append(dict(check='python_syntax_only', path=str(file.relative_to(root)), passed=False, error=str(error)))
    for name in ('architecture-component-cost.md', 'README.md'):
        file = root / name
        for link in re.findall(r'\[[^\]]*\]\(([^)]+)\)', file.read_text()):
            target = link.split('#')[0]
            if not target or re.match(r'^[a-zA-Z]+://', target):
                continue
            checks.append(dict(check='local_document_link', path=name, target=target,
                               passed=(file.parent / target).exists()))
    result = dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  scope='source freeze, syntax and navigation only; not additional runtime qualification',
                  status='PASS' if all(c['passed'] for c in checks) else 'FAIL', checks=checks)
    (root / 'analysis/delivery-checks.json').write_text(json.dumps(result, indent=2) + '\n')
    manifest = root / 'frozen/delivery-sha256.json'
    files = {}
    for file in sorted(root.rglob('*')):
        if file == manifest:
            continue
        if file.is_symlink():
            files[str(file.relative_to(root))] = dict(kind='symlink', target=str(file.readlink()))
        elif file.is_file():
            files[str(file.relative_to(root))] = dict(kind='regular', bytes=file.stat().st_size, sha256=digest(file))
    manifest.write_text(json.dumps(dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                      exclusions=['frozen/delivery-sha256.json (self reference)'],
                                      files=files), indent=2) + '\n')
    print(json.dumps(dict(check_status=result['status'], checks=len(checks),
                          files=len(files), bytes=sum(v.get('bytes', 0) for v in files.values()),
                          manifest=str(manifest.relative_to(root))), indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
