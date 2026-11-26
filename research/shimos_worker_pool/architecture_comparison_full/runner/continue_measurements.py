#!/usr/bin/env python3
"""Bounded continuation after one failed VM, retaining all failed evidence.

No core changes or timeout changes. Two extra paired VMs, then two small
instrumentation controls; never retry a run ID or replace a failed sample.
"""
import json, subprocess, sys
from pathlib import Path

s=Path(__file__).resolve().parents[1]
out=s/'analysis/formal-continuation-01';out.mkdir(exist_ok=False)
plan=[
 ('formal-pair-01-3',['baseline_instrumented','ping_merged'],35,False),
 ('formal-pair-02-1',['ping_merged','baseline_instrumented'],35,False),
 ('overhead-pair-01-1',['baseline_instrumented','ping_merged'],8,True),
 ('overhead-pair-01-2',['ping_merged','baseline_instrumented'],8,True),
]
(out/'plan.json').write_text(json.dumps({'reason':'formal-pair-01-2 DOMAIN_READY timeout; failed VM retained, cause unresolved; no source/security/timeouts changed','plan':plan,'warmup':5,'bound':'run each listed VM once, no automatic retries'},indent=2)+'\n')
results=[]
for name,order,n,overhead in plan:
 argv=[sys.executable,'-B',str(s/'runner/paired_vm.py'),name,'--order',','.join(order),'--requests',str(n),'--warmup','5']
 if overhead:argv+=['--timing-overhead']
 with (out/(name+'-driver.log')).open('x') as f:
  rc=subprocess.run(argv,stdout=f,stderr=subprocess.STDOUT).returncode
 results.append({'run':name,'rc':rc,'order':order,'requests':n,'overhead':overhead})
 (out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
 print(json.dumps(results[-1]),flush=True)
 # A failed VM has already been torn down by paired_vm; do not delete evidence.
 # Stop after two further failures to avoid chasing only successful sessions.
 if sum(r['rc']!=0 for r in results)>=2:break
