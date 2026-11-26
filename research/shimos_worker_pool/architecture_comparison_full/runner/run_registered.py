#!/usr/bin/env python3
"""Sequential registered VM blocks; never starts a second VM concurrently."""
import argparse,json,subprocess,sys,time
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('prefix');p.add_argument('matrices',nargs='+',type=Path)
p.add_argument('--review',required=True);p.add_argument('--prototype',required=True)
p.add_argument('--timeout',default='1200');a=p.parse_args()
root=Path(__file__).resolve().parents[1]
ledger=root/'analysis'/(a.prefix+'-execution.jsonl')
with ledger.open('x') as log:
    for i,m in enumerate(a.matrices,1):
        name=a.prefix+'-block-'+str(i)
        cmd=[sys.executable,'-B',str(root/'runner/full_vm.py'),name,'--matrix',str(m),
             '--source-review',a.review,'--prototype-dir',a.prototype,'--np-level','blas',
             '--trace','0','--timeout',a.timeout]
        record=dict(name=name,matrix=str(m),argv=cmd,start_ns=time.monotonic_ns())
        with (root/'analysis'/(name+'-driver.log')).open('x') as out:
            ret=subprocess.run(cmd,cwd=root,stdout=out,stderr=subprocess.STDOUT)
        record.update(returncode=ret.returncode,end_ns=time.monotonic_ns())
        log.write(json.dumps(record)+'\n');log.flush();print(json.dumps(record),flush=True)
        if ret.returncode:raise SystemExit(ret.returncode)
