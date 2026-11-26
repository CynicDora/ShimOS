#!/usr/bin/env python3
"""Sequential private-VM correctness matrix. No performance samples here."""
import argparse,subprocess,json,sys,datetime
from pathlib import Path
p=Path(__file__).resolve().parent;s=p.parent
GROUPS=['control','budgets','receipts','cancels','failures','controller_death','controller_during_entry','runtime']
COUNTERS=['counter_state_corruption','counter_fd_leak','counter_forgotten_drop','counter_late_ack','counter_post_ack_controller_death','counter_post_forget_zygote_death']
def main():
 a=argparse.ArgumentParser();a.add_argument('prefix');a.add_argument('--variant',required=True,choices=['baseline_instrumented','ping_merged']);a.add_argument('--counters',action='store_true');args=a.parse_args()
 out=s/'analysis'/args.prefix;out.mkdir(exist_ok=False)
 assert (s/'docs/variant-source-review-v2.json').exists()
 results=[]
 for group in COUNTERS if args.counters else GROUPS:
  name=args.prefix+'-'+group;row={'run':name,'case':group,'variant':args.variant}
  with (out/(group+'-driver.log')).open('x') as log:
   row['vm_rc']=subprocess.run([sys.executable,'-B',str(p/'vm.py'),name,'--variant',args.variant,'--case',group,'--warmup','0','--trace','1'],stdout=log,stderr=subprocess.STDOUT).returncode
   names=['verify_counterexamples.py'] if args.counters else ['verify_qualification.py','verify_runtime.py']
   for verifier in names:
    row[verifier]=subprocess.run([sys.executable,'-B',str(p/verifier),name],stdout=log,stderr=subprocess.STDOUT).returncode
  row['status']='PASS' if row['vm_rc']==0 and all(row[n]==0 for n in names) else 'FAIL'
  results.append(row);print(json.dumps(row),flush=True)
 (out/'matrix.json').write_text(json.dumps({'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'variant':args.variant,'counterexamples':args.counters,'runs':results},indent=2)+'\n')
 return 0 if all(r['status']=='PASS' for r in results) else 1
if __name__=='__main__':raise SystemExit(main())
