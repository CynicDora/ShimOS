#!/usr/bin/env python3
"""Fixed, serial same-guest block pairs; no concurrent benchmark VMs."""
import json,random,subprocess,sys,datetime
from pathlib import Path
s=Path(__file__).resolve().parents[1];p=s/'runner';out=s/'analysis/formal-measurements-01';out.mkdir(exist_ok=False)
orders=[['baseline_instrumented','ping_merged'],['ping_merged','baseline_instrumented'],['baseline_instrumented','ping_merged']]
random.Random(20261019).shuffle(orders)
plan={'seed':20261019,'design':'randomized counterbalanced session-block order within independently initialized VMs; 3 VMs share one physical host','warmup':5,'measured_requests_per_variant_vm':35,'orders':orders,'scope':'controlled mechanism, not real Agent','trace':False}
(out/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
results=[];pairs=[]
for index,order in enumerate(orders,1):
 name='formal-pair-01-'+str(index)
 argv=[sys.executable,'-B',str(p/'paired_vm.py'),name,'--order',','.join(order),'--requests','35','--warmup','5']
 with (out/(name+'-driver.log')).open('x') as f:rc=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT).returncode
 results.append({'run':name,'rc':rc,'order':order});print(json.dumps(results[-1]),flush=True)
 if rc:break
 cfg=json.loads((s/'runs'/name/'batch-config.json').read_text());mapping={x['variant']:x['session'] for x in cfg['sessions']}
 pairs.append({'pair_id':name,'baseline_session':mapping['baseline_instrumented'],'candidate_session':mapping['ping_merged']})
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n');(out/'pair-map.json').write_text(json.dumps({'pairs':pairs},indent=2)+'\n')
if len(results)!=3 or any(r['rc'] for r in results):raise SystemExit(1)
# Small on/off instrumentation control; not part of formal A/B samples.
for index,order in enumerate([['baseline_instrumented','ping_merged'],['ping_merged','baseline_instrumented']],1):
 name='overhead-pair-01-'+str(index)
 argv=[sys.executable,'-B',str(p/'paired_vm.py'),name,'--timing-overhead','--order',','.join(order),'--requests','8','--warmup','5']
 with (out/(name+'-driver.log')).open('x') as f:rc=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT).returncode
 print(json.dumps({'run':name,'rc':rc}),flush=True)
 if rc:raise SystemExit(rc)
