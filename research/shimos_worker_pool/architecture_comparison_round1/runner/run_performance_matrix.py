#!/usr/bin/env python3
"""Small predeclared paired series; serial VM runs, all failures retained."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
S=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser();p.add_argument('prefix');a=p.parse_args();out=S/'analysis'/a.prefix;out.mkdir(exist_ok=False)
 schedule=[(n,r,('cold,hot' if r==1 else 'hot,cold')) for n in (1,10,50,100) for r in (1,2)]
 (out/'predeclared.json').write_text(json.dumps({'schedule':schedule,'source_review_sha256':hashlib.sha256((S/'docs/variant-source-review-v2.json').read_bytes()).hexdigest(),'performance_scope':'fixed serial NumPy blas recipe; not online Agent; no free warmup','same_physical_host':True,'controller_supervisor_timeouts_unchanged':True},indent=2)+'\n')
 rows=[]
 for n,r,order in schedule:
  name=f'{a.prefix}-n{n}-r{r}';cmd=[sys.executable,'-B',str(S/'runner/paired_vm.py'),name,'--requests',str(n),'--warmup','0','--order',order,'--np-level','blas','--np-audit','0','--timing','1','--trace','0','--source-review','docs/variant-source-review-v2.json']
  with (out/(name+'-driver.log')).open('x') as f: rc=subprocess.run(cmd,cwd=S,stdout=f,stderr=subprocess.STDOUT).returncode
  row={'run':name,'N':n,'repeat':r,'order':order,'command':cmd,'driver_rc':rc};rows.append(row)
  (out/'matrix.json').write_text(json.dumps(rows,indent=2)+'\n');print(json.dumps(row),flush=True)
 return int(any(x['driver_rc'] for x in rows))
if __name__=='__main__':raise SystemExit(main())
