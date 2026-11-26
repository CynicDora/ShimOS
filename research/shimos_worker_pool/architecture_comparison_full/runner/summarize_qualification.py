#!/usr/bin/env python3
"""Read-only same-code full/low qualification recheck; writes exclusive results."""
import argparse
import hashlib
import json
from pathlib import Path
import verify_qualification as lifecycle
import verify_runtime as runtime

STUDY=Path(__file__).resolve().parent.parent

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def persist(path,result):
    if path.exists():
        previous=json.loads(path.read_text())
        if previous.get('verifier_sha256')!=result.get('verifier_sha256') or previous.get('status')!=result.get('status'):
            raise RuntimeError('refusing to reuse a prior verdict from another verifier or outcome: '+str(path))
    else:
        with path.open('x') as out:json.dump(result,out,ensure_ascii=False,indent=2);out.write('\n')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prefix',required=True);p.add_argument('--variant',required=True,choices=['full','low']);p.add_argument('--output',required=True,type=Path);p.add_argument('--suffix',default='recheck-v2');a=p.parse_args()
    if a.output.exists():p.error('refusing to overwrite matrix')
    rows=[]
    for group in lifecycle.GROUP_CASES:
        name=a.prefix+'-'+group;run=STUDY/'runs'/name
        if not (run/'result.json').is_file():raise RuntimeError('VM run not complete: '+name)
        q=lifecycle.analyze(name);r=runtime.analyze(name)
        if q['variant']!=a.variant or r['diagnostics']!=a.variant:raise RuntimeError('variant mismatch')
        qp=STUDY/'analysis'/f'{name}-qualification-{a.suffix}.json';rp=STUDY/'analysis'/f'{name}-runtime-{a.suffix}.json'
        persist(qp,q);persist(rp,r)
        rows.append(dict(run=name,lifecycle=q['status'],runtime=r['status'],attempts=len(q['attempts']),
            qualification_file=str(qp.relative_to(STUDY)),runtime_file=str(rp.relative_to(STUDY)),
            source_manifest_sha256=digest(run/'source-sha.json'),
            runtime_verifier_sha256=r['verifier_sha256'],lifecycle_verifier_sha256=q['verifier_sha256']))
        print(name,q['status'],r['status'],len(q['attempts']),flush=True)
    summary={'scope':'actual same-source diagnostics qualification, not a performance repetition set',
        'variant':a.variant,'vm_count':len(rows),'attempts':sum(r['attempts'] for r in rows),
        'all_pass':all(r['lifecycle']==r['runtime']=='PASS' for r in rows),'runs':rows,
        'original_failures_preserved':True,'summarizer_sha256':digest(Path(__file__))}
    with a.output.open('x') as out:json.dump(summary,out,ensure_ascii=False,indent=2);out.write('\n')
    return 0 if summary['all_pass'] else 1
if __name__=='__main__':raise SystemExit(main())
