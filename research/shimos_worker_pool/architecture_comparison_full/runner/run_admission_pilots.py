#!/usr/bin/env python3
"""Run only the finite, preregistration-blocking diagnostic pilots in series."""
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def main():
    output = ROOT / 'analysis/admission-pilots-driver.json'
    assert not output.exists(), 'never overwrite an existing pilot ledger'
    sources = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
               for p in sorted((ROOT / 'prototype').iterdir()) if p.is_file()}
    plans = [
        ('pilot-long-n100-01', ['--order','G1,G2','--requests','100']),
        ('sensitivity-timing-01', ['--order','G0,G1,G2','--requests','2','--timing-sequence','1,0']),
        ('sensitivity-timing-02', ['--order','G2,G1,G0','--requests','2','--timing-sequence','0,1']),
        ('sensitivity-observer-01', ['--order','G0,G1,G2','--requests','2','--resource-sequence','100,0']),
        ('sensitivity-observer-02', ['--order','G2,G1,G0','--requests','2','--resource-sequence','0,100']),
    ]
    ledger = {'source_sha256':sources,'plans':plans,'rows':[],'complete':False}
    def save(): output.write_text(json.dumps(ledger,indent=2)+'\n')
    save()
    for name, options in plans:
        current = {p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in sorted((ROOT / 'prototype').iterdir()) if p.is_file()}
        assert current == sources, 'product source changed during diagnostics'
        cmd = [sys.executable,'-B',str(ROOT/'runner/paired_vm.py'),name,'--pilot',
               '--np-level','blas','--np-audit','0','--trace','0','--timing','1',
               '--session-deadline','240','--resource-sample-ms','100',*options]
        print(json.dumps({'event':'PILOT_BEGIN','name':name}),flush=True)
        begin = time.monotonic()
        p = subprocess.run(cmd,capture_output=True,text=True)
        run = ROOT/'runs'/name
        run.mkdir(parents=True,exist_ok=True)
        (run/'driver-stdout.txt').write_text(p.stdout)
        (run/'driver-stderr.txt').write_text(p.stderr)
        result = json.loads((run/'result.json').read_text()) if (run/'result.json').exists() else {}
        row = {'name':name,'command':cmd,'returncode':p.returncode,
               'complete':result.get('complete') is True,'host_driver_seconds':time.monotonic()-begin}
        ledger['rows'].append(row);save()
        print(json.dumps({'event':'PILOT_EXPORTED',**row}),flush=True)
        if p.returncode or not row['complete']:
            return 1
    ledger['complete']=True;save()
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
