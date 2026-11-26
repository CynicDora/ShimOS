#!/usr/bin/env python3
"""Execute only the preregistered matrix, sequentially; no result selection."""
import hashlib, json, subprocess, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    plan_path=ROOT/'frozen/formal-plan.json';plan=json.loads(plan_path.read_text())
    output=ROOT/'analysis/formal-driver.json';assert not output.exists()
    ledger={'plan_sha256':sha(plan_path),'rows':[],'complete':False}
    def save():output.write_text(json.dumps(ledger,indent=2)+'\n')
    save()
    for block in plan['blocks']:
        # Do not silently compete with an unrelated private VM. Never terminate it.
        active_vms=[]
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():continue
            try:command=(proc/'cmdline').read_bytes().split(b'\0')[0].decode(errors='replace')
            except (FileNotFoundError,PermissionError,ProcessLookupError):continue
            if Path(command).name.startswith('qemu-system-'):active_vms.append(int(proc.name))
        if active_vms:
            ledger['blocked_before']=dict(block=block,reason='another VM is active',pids=active_vms);save()
            raise RuntimeError('do not launch another formal VM',active_vms)
        current={p.name:sha(p) for p in sorted((ROOT/'prototype').iterdir()) if p.is_file()}
        assert current==plan['source_sha256'],'source changed after preregistration'
        for name,expected in plan['runner_sha256'].items():
            assert sha(ROOT/'runner'/name)==expected,('runner changed after preregistration',name)
        assert sha(ROOT/plan['review_path'])==plan['review_sha256'],'source review changed'
        cmd=[sys.executable,'-B',str(ROOT/'runner/paired_vm.py'),block['name'],'--order',','.join(block['order']),
             '--requests',str(block['N']),'--np-level','blas','--np-audit','0','--warmup','0','--timing','1','--trace','0',
             '--session-deadline','240','--resource-sample-ms','100','--source-review',plan['review_path']]
        print(json.dumps({'event':'FORMAL_BEGIN',**block}),flush=True)
        begin=time.monotonic();p=subprocess.run(cmd,capture_output=True,text=True)
        run=ROOT/'runs'/block['name']
        (run/'driver-stdout.txt').write_text(p.stdout);(run/'driver-stderr.txt').write_text(p.stderr)
        result=json.loads((run/'result.json').read_text()) if (run/'result.json').exists() else {}
        row={**block,'command':cmd,'returncode':p.returncode,'complete':result.get('complete') is True,'host_driver_seconds':time.monotonic()-begin}
        ledger['rows'].append(row);save();print(json.dumps({'event':'FORMAL_EXPORTED',**row}),flush=True)
        # A failed block is retained. Do not reset resources inside that VM;
        # later preregistered blocks use new VMs and remain in the matrix.
    ledger['complete']=True;save();return 0
if __name__=='__main__':raise SystemExit(main())
