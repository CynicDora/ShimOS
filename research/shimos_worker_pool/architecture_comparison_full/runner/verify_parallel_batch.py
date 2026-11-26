#!/usr/bin/env python3
"""Read-only per-session dispatch for finite concurrent/mixed batches and G0/C1.

Run only after measurement VMs have stopped. This hashes actual runtime/source
and decodes numerical arrays; it is not a low-impact live observer.
"""
import argparse
import importlib
import json
import traceback
from pathlib import Path
import verify_full_mechanism as full

S=full.S


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('runs',nargs='+')
    p.add_argument('--profile',choices=('qualification','boundary','performance'),required=True)
    p.add_argument('--source-review');p.add_argument('--out-dir',required=True);a=p.parse_args()
    out=S/a.out_dir;out.resolve().relative_to(S.resolve());out.mkdir(parents=True,exist_ok=False)
    result=[]
    for name in a.runs:
        batch=(S/'runs'/name).resolve(strict=True);batch.relative_to((S/'runs').resolve())
        sessions=sorted((batch/'sessions').iterdir()) if (batch/'sessions').is_dir() else [batch]
        for directory in sessions:
            if not directory.is_dir():continue
            relative=str(directory.relative_to(S/'runs'));module=None
            try:
                actual=json.loads((directory/'full-session.json').read_text())
                env=actual.get('extra_env',{});mode=env.get('FULL_MODE',actual.get('architecture_group'))
                if mode in ('G2_CONCURRENT','G3_CONCURRENT'):module=importlib.import_module('verify_concurrent')
                elif mode=='G2_MIXED':module=importlib.import_module('verify_mixed')
                elif mode=='G0' and actual.get('architecture_group')=='G0':
                    if env.get('FULL_CONCURRENCY','1')!='1':raise ValueError('G0 is a serial C1 reference, never unimplemented C2+')
                    module=full
                else:raise ValueError('batch dispatch does not admit mechanism '+str(mode))
                value=module.analyze(relative,a.profile,a.source_review)
            except Exception as error:
                value=dict(run=relative,status='BLOCKED',verifier_error=repr(error),traceback=traceback.format_exc())
            value['batch_dispatch_verifier']=Path(module.__file__).name if module else None
            value['batch_dispatch_verifier_sha256']=full.sha(Path(module.__file__)) if module else None
            target=out/(relative.replace('/','--')+'.json')
            with target.open('x') as f:json.dump(value,f,ensure_ascii=False,indent=2);f.write('\n')
            row={k:value.get(k) for k in ('run','status','mechanism_observations_status','mode','attempts','planned_requests','full_profile','pattern','hits','misses','verifier_sha256')}
            row.update(report=str(target.relative_to(S)),report_sha256=full.sha(target),
                       failed=len(value.get('failed',[])),missing=len(value.get('missing',[])))
            result.append(row);print(json.dumps(row),flush=True)
    counts={k:sum(x['status']==k for x in result) for k in ('PASS','FAIL','BLOCKED')}
    report=dict(status='FAIL' if counts['FAIL'] else 'BLOCKED' if counts['BLOCKED'] else 'PASS',
                profile=a.profile,source_review=a.source_review,session_count=len(result),
                attempt_count=sum(x.get('attempts') or 0 for x in result),counts=counts,sessions=result,
                orchestrator_sha256=full.sha(Path(__file__)),
                scope='Full workload/finite fault qualification. Resource-collection-only release verification is separate.')
    with (out/'summary.json').open('x') as f:json.dump(report,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps({k:report[k] for k in ('status','session_count','attempt_count','counts')}))
    return 0 if report['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
