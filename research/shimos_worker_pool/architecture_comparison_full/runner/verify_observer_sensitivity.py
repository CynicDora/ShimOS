#!/usr/bin/env python3
"""Read-only observation scope: explicit sampler-off is NOT_OBSERVED, not zero."""
import argparse
import json
from pathlib import Path
import verify_observer_v2 as base

S=base.S
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('batch');p.add_argument('--out',required=True);a=p.parse_args()
    root=(S/'runs'/a.batch).resolve(strict=True);root.relative_to((S/'runs').resolve());rows=[]
    for path in sorted((root/'sessions').iterdir()):
        if not path.is_dir():continue
        f=json.loads((path/'full-session.json').read_text());c=json.loads((path/'review-config.json').read_text())
        declared=f.get('configuration',{}).get('resource_sample_ms',c.get('resource_sample_ms'))
        if declared!=0:
            row=base.inspect(path);row['observation_status']='OBSERVED' if row['status']=='PASS' else 'OBSERVATION_INCOMPLETE'
        else:
            process=json.loads((path/'resource-observer-status.json').read_text())
            checks=[{'name':'off deliberately registered and actual runner agrees','value':c.get('resource_sample_ms')==0},
                    {'name':'disabled observer has no claimed process or cleanup','value':process=={'status':'DISABLED_PAIRED_DIAGNOSTIC','product_cleanup_used':False}},
                    {'name':'no fabricated resource stream','value':not (path/'resource-observer.jsonl').exists()}]
            row={'run':str(path.relative_to(S/'runs')),'status':'PASS' if all(x['value'] is True for x in checks) else 'FAIL',
                 'observation_status':'NOT_OBSERVED_DISABLED','checks':checks,
                 'evidence_sha256':{str((path/n).relative_to(S)):base.sha(path/n) for n in ('full-session.json','review-config.json','resource-observer-status.json')},
                 'scope':'Only intentional observation-off contract validated. No resource sample or template PSS observed; no zero-cost/zero-memory inference; independent lifecycle/numerical proof is separate.'}
        row['timing']=c.get('timing');row['requested_sampling_ms']=declared;rows.append(row)
    result={'status':'FAIL' if any(x['status']=='FAIL' for x in rows) else 'BLOCKED' if any(x['status']=='BLOCKED' for x in rows) else 'PASS',
            'verifier_sha256':base.sha(Path(__file__)),'dependency_verifier_sha256':base.sha(Path(base.__file__)),
            'sessions':rows,'counts':{k:sum(x['status']==k for x in rows) for k in ('PASS','FAIL','BLOCKED')},
            'observed_sessions':sum(x['observation_status']=='OBSERVED' for x in rows),
            'not_observed_disabled_sessions':sum(x['observation_status']=='NOT_OBSERVED_DISABLED' for x in rows)}
    out=S/a.out;out.resolve().relative_to(S.resolve());out.parent.mkdir(parents=True,exist_ok=True)
    with out.open('x') as h:json.dump(result,h,ensure_ascii=False,indent=2);h.write('\n')
    print(json.dumps({k:v for k,v in result.items() if k!='sessions'}))
    return 0 if result['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
