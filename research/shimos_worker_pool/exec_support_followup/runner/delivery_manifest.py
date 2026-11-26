#!/usr/bin/env python3
"""Checksum delivery artifacts only; never import or execute a workload."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'analysis/delivery-manifest.json'
CHECKSUM = ROOT / 'analysis/delivery-manifest.sha256'


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(8 << 20), b''):
            result.update(data)
    return result.hexdigest()


def inventory(path):
    info = path.lstat()
    result = {'path': str(path.relative_to(ROOT)), 'mode': stat.S_IMODE(info.st_mode)}
    if stat.S_ISLNK(info.st_mode):
        result.update(type='symlink', target=os.readlink(path))
    elif stat.S_ISREG(info.st_mode):
        result.update(type='file', bytes=info.st_size, sha256=digest(path))
    else:
        raise ValueError('unexpected non-regular artifact: ' + str(path))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='create exclusive final manifest; do not overwrite')
    args = parser.parse_args()
    if args.write:
        if MANIFEST.exists() or CHECKSUM.exists():
            raise SystemExit('delivery manifest already exists')
        files = [inventory(path) for path in sorted(ROOT.rglob('*'))
                 if (path.is_symlink() or path.is_file())
                 and path not in (MANIFEST, CHECKSUM)]
        result = {'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'scope': 'All current followup artifacts including retained private VM disks; excludes this manifest and its checksum.',
                  'file_count': len(files),
                  'logical_regular_bytes': sum(row.get('bytes', 0) for row in files),
                  'files': files}
        with MANIFEST.open('x') as stream:
            json.dump(result, stream, indent=2, ensure_ascii=False)
            stream.write('\n')
        with CHECKSUM.open('x') as stream:
            stream.write(digest(MANIFEST) + '  delivery-manifest.json\n')
        print(json.dumps({key: result[key] for key in ('file_count', 'logical_regular_bytes')}))
        return 0
    expected_digest = CHECKSUM.read_text().split()[0]
    if digest(MANIFEST) != expected_digest:
        raise SystemExit('manifest checksum mismatch')
    data = json.loads(MANIFEST.read_text())
    failures = []
    for row in data['files']:
        path = ROOT / row['path']
        if path.is_absolute() and ('..' in Path(row['path']).parts or Path(row['path']).is_absolute()):
            raise SystemExit('unsafe manifest path')
        try:
            actual = inventory(path)
            if actual != row:
                failures.append({'path': row['path'], 'expected': row, 'actual': actual})
        except OSError as error:
            failures.append({'path': row['path'], 'error': repr(error)})
    print(json.dumps({'status': 'FAIL' if failures else 'PASS', 'checked': len(data['files']),
                      'failures': failures}, ensure_ascii=False))
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
