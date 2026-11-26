#!/usr/bin/env python3
"""Read-only historical check and exclusive SHA inventory; never runs a workload."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', help='new JSON filename under frozen/')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    project = root.parents[2]
    name = Path(args.output)
    assert len(name.parts) == 1 and name.suffix == '.json'
    output = root / 'frozen' / name
    assert not output.exists(), 'never overwrite an inventory'
    inputs = json.loads((root/'frozen/input-sources.json').read_text())['files']
    old = json.loads((root/'frozen/historical-evidence-sha.json').read_text())
    changes = []
    for rel, value in inputs.items():
        path = project/rel
        if not path.is_file() or digest(path) != value['sha256']:
            changes.append({'kind': 'input', 'path': rel})
    for rel, expected in old.items():
        path = root/rel
        if not path.is_file() or digest(path) != expected:
            changes.append({'kind': 'historical_evidence', 'path': rel})
    files = {}
    cache = {}
    for directory, directories, names in os.walk(root, followlinks=False):
        parent = Path(directory)
        for child in sorted(directories + names):
            path = parent/child
            rel = str(path.relative_to(root))
            if path.is_symlink():
                files[rel] = {'type': 'symlink', 'target': os.readlink(path)}
            elif path.is_file() and path != output:
                stat = path.stat()
                identity = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
                if identity not in cache:
                    cache[identity] = digest(path)
                assert identity == (path.stat().st_dev, path.stat().st_ino,
                                    path.stat().st_size, path.stat().st_mtime_ns), rel
                files[rel] = {'sha256': cache[identity], 'bytes': stat.st_size}
    report = {
        'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'scope': 'all current files including failed VM disks; no symlink traversal; output itself excluded',
        'historical_input_files_checked': len(inputs),
        'historical_evidence_files_checked': len(old),
        'historical_changes': changes,
        'files': files,
    }
    with output.open('x') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({'output': str(output), 'files': len(files),
                      'historical_changes': changes, 'sha256': digest(output)}))
    if changes:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
