#!/usr/bin/env python3
"""Sequential private-VM qualification; never start a second VM concurrently.

The driver checks export and expected session completion, not full qualification.
Independent verify_round1.py must still inspect actual per-attempt evidence.
"""
import argparse, datetime, hashlib, json, subprocess, sys, time
from pathlib import Path

STUDY=Path(__file__).resolve().parents[1]
PLAN={
 'G0':['control','budgets','cancels','failures','receipts','cancel_queued','controller_death','controller_during_entry','session_deadline'],
 'G1':['control','budgets','controller_death','session_deadline'],
 'G2':['control','cancels','receipts','failures','controller_death','session_deadline'],
}

def inventory():
    return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((STUDY/'prototype').iterdir()) if p.is_file()}

def main():
    p=argparse.ArgumentParser();p.add_argument('prefix');p.add_argument('--groups',default='G0,G1,G2')
    p.add_argument('--extra',action='store_true')
    args=p.parse_args();plan={'G0':[], 'G1':['cancels','receipts','failures'],'G2':['budgets']} if args.extra else PLAN
    source=inventory();out=STUDY/'analysis'/(args.prefix+'-driver.json')
    assert not out.exists()
    ledger={'created':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source_sha256':source,'plan':plan,'runs':[],'complete':False}
    def save():out.write_text(json.dumps(ledger,indent=2)+'\n')
    save()
    for group in args.groups.split(','):
        for case in plan[group]:
            assert inventory()==source,'source changed during qualification; do not combine code versions'
            name=args.prefix+'-'+group.lower()+'-'+case
            command=[sys.executable,'-B',str(STUDY/'runner/vm.py'),name,'--group',group,'--case',case,'--np-level','blas','--np-audit','0','--trace','1','--timing','1','--session-deadline', '2' if case=='session_deadline' else '240']
            print(json.dumps({'event':'QUALIFICATION_BEGIN','name':name}),flush=True)
            begin=time.monotonic();result=subprocess.run(command,capture_output=True,text=True)
            run=STUDY/'runs'/name
            (run/'driver-stdout.txt').write_text(result.stdout);(run/'driver-stderr.txt').write_text(result.stderr)
            def load(file):
                path=run/file;return json.loads(path.read_text()) if path.exists() else {}
            h=load('supervisor.json');summary=load('summary.json');vm=load('result.json')
            fault=case in ('controller_death','controller_during_entry','session_deadline')
            checks={'vm_export_complete':vm.get('complete') is True,
                    'product_release':h.get('release_state')=='RELEASED' and not h.get('errors'),
                    'expected_controller_completion':(h.get('business_result')=='UNKNOWN' and h.get('controller_wait_status')==9) if fault else (summary.get('all_passed') is True and h.get('controller_wait_status')==0),
                    'no_observer_cleanup':h.get('observer_cleanup_used') is False,
                    'same_source':load('source-sha.json')==source}
            row={'name':name,'group':group,'case':case,'command':command,'driver_seconds':time.monotonic()-begin,'returncode':result.returncode,'export_checks':checks,'export_ready_for_independent_audit':all(checks.values())}
            ledger['runs'].append(row);save();print(json.dumps(row),flush=True)
            if not all(checks.values()):return 1
    ledger['complete']=True;save();return 0

if __name__=='__main__':raise SystemExit(main())
