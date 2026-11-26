#!/usr/bin/env python3
"""Read-only audit of the input SHA inventory; never overwrite prior audits."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path

STUDY = Path(__file__).resolve().parents[1]
PROJECT = STUDY.parents[2]

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
    return h.hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args()
    out=args.out if args.out.is_absolute() else STUDY/args.out
    out.resolve().relative_to(STUDY.resolve())
    assert not out.exists()
    manifest=STUDY/'frozen/input-sha256.json'
    inputs=json.loads(manifest.read_text());bad=[];nbytes=0
    for name,expected in inputs['files'].items():
        path=PROJECT/name
        try:
            observed={'bytes':path.stat().st_size,'sha256':sha(path)};nbytes+=observed['bytes']
            if observed!=expected:bad.append({'path':name,'expected':expected,'observed':observed})
        except OSError as error:bad.append({'path':name,'error':repr(error)})
    report={'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'manifest_sha256':sha(manifest),'checker_sha256':sha(Path(__file__)),
            'files_checked':len(inputs['files']),'bytes_checked':nbytes,
            'status':'PASS' if not bad else 'FAIL','mismatches':bad,
            'scope':'exactly the previously frozen input inventory; no assertion about unfrozen project files'}
    out.parent.mkdir(parents=True,exist_ok=True)
    with out.open('x') as stream:json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps(report));return bool(bad)

if __name__=='__main__':raise SystemExit(main())
