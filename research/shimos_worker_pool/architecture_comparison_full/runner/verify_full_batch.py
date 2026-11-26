#!/usr/bin/env python3
"""Exclusive, read-only batch orchestration of the independent full verifier.

Run after the private VM has finished. This reads and hashes actual artifacts,
including runtime files and numerical outputs; it must not overlap formal VM
timing unless that host disturbance is separately recorded.
"""
import argparse
import importlib
import json
import traceback
from pathlib import Path
import verify_full_mechanism as verifier

S=verifier.S
def save(path,value):
    with path.open('x') as f:json.dump(value,f,ensure_ascii=False,indent=2);f.write('\n')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('batches',nargs='+');p.add_argument('--profile',choices=('qualification','boundary','performance'),required=True)
    p.add_argument('--source-review');p.add_argument('--out-dir',required=True)
    p.add_argument('--verifier-module',choices=('verify_full_mechanism','verify_full_mechanism_observer_v2'),default='verify_full_mechanism')
    a=p.parse_args()
    global verifier
    verifier=importlib.import_module(a.verifier_module)
    out=S/a.out_dir;out.resolve().relative_to(S.resolve());out.mkdir(parents=True,exist_ok=False)
    rows=[]
    for name in a.batches:
        root=(S/'runs'/name).resolve(strict=True);root.relative_to((S/'runs').resolve())
        sessions=sorted((root/'sessions').iterdir()) if (root/'sessions').is_dir() else [root]
        for session in sessions:
            if not session.is_dir():continue
            run=str(session.relative_to(S/'runs'));target=out/(run.replace('/','--')+'.json')
            try:value=verifier.analyze(run,a.profile,a.source_review)
            except Exception as error:value=dict(run=run,status='BLOCKED',verifier_error=repr(error),traceback=traceback.format_exc(),verifier_sha256=verifier.sha(Path(verifier.__file__)))
            save(target,value)
            row={k:value.get(k) for k in ['run','status','mechanism_observations_status','mode','full_profile','level','attempts','domains','cases','verifier_sha256']}
            row.update(report=str(target.relative_to(S)),report_sha256=verifier.sha(target),failed=len(value.get('failed',[])),missing=len(value.get('missing',[])))
            rows.append(row);print(json.dumps(row),flush=True)
    result=dict(profile=a.profile,source_review=a.source_review,verifier_sha256=verifier.sha(Path(verifier.__file__)),
                orchestrator_sha256=verifier.sha(Path(__file__)),sessions=rows,session_count=len(rows),attempt_count=sum(r.get('attempts') or 0 for r in rows),
                counts={k:sum(r['status']==k for r in rows) for k in ['PASS','FAIL','BLOCKED']},
                status='FAIL' if any(r['status']=='FAIL' for r in rows) else 'BLOCKED' if any(r['status']=='BLOCKED' for r in rows) else 'PASS')
    save(out/'summary.json',result)
    print(json.dumps(dict(status=result['status'],sessions=len(rows),attempts=result['attempt_count'],counts=result['counts'],summary=str(out/'summary.json'))))
    return 0 if result['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
