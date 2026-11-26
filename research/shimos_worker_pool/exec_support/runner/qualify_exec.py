#!/usr/bin/env python3
"""Sequential private-VM qualification; immutable run names and source lock."""
import argparse,hashlib,json,subprocess,sys,time
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('prefix');args=p.parse_args()
    study=Path(__file__).resolve().parents[1]
    lock={str(f.relative_to(study)):hashlib.sha256(f.read_bytes()).hexdigest()
          for directory in ('prototype','tools') for f in sorted((study/directory).rglob('*'))
          if f.is_file() and '__pycache__' not in f.parts}
    lockpath=study/'frozen'/(args.prefix+'-source-sha.json')
    with lockpath.open('x') as out:json.dump(lock,out,indent=2)
    results=[]
    suites=['level1','level2','level3','level4','lifecycle','budgets','controller_death','output_boundary','warm_control']
    for suite in suites:
        assert all(hashlib.sha256((study/f).read_bytes()).hexdigest()==sha for f,sha in lock.items()),'source changed during qualification'
        name=args.prefix+'-'+suite
        command=[sys.executable,'-B',str(study/'runner/vm.py'),name,'--variant','low','--warmup','0','--trace','1','--timing','1','--syscall-trace']
        if suite!='warm_control':command+=['--tool-suite',suite]
        begin=time.monotonic();proc=subprocess.run(command)
        result={'suite':suite,'run':name,'command':command,'driver_rc':proc.returncode,'wall_s':time.monotonic()-begin}
        results.append(result);print(json.dumps(result),flush=True)
        target=study/'analysis'/(args.prefix+'-execution-ledger.json')
        target.write_text(json.dumps({'source_lock':str(lockpath),'runs':results},indent=2)+'\n')
    return int(any(r['driver_rc'] for r in results))

if __name__=='__main__':raise SystemExit(main())
