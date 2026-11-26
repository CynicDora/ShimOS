#!/usr/bin/env python3
"""Declared sequential diagnostics/regression, then small cost samples.

Never substitute these runs for the complete qualification matrix. Requires
the independent final matrix to have passed before any cost session starts.
"""
import json,subprocess,sys,time
from pathlib import Path

def main():
    study=Path(__file__).resolve().parents[1]
    assert (study/'analysis/qualification-matrix.json').is_file()
    # Manual independent audit is also recorded in the matrix; each cost
    # request still executes its correctness checks and is audited offline.
    jobs=[
      ('syscall-shell-01',['--tool-suite','shell_pipeline','--raw-syscalls','--timing','0']),
      ('syscall-gcc-01',['--tool-suite','gcc_success','--raw-syscalls','--timing','0']),
      ('syscall-unittest-01',['--tool-suite','unittest_pass','--raw-syscalls','--timing','0']),
      ('warm-controller-death-01',['--case','controller_death','--syscall-trace']),
      ('cost-tools-on-01',['--tool-suite','cost','--repeats','3','--trace','0','--resource-samples','0','--timing','1']),
      ('cost-tools-off-01',['--tool-suite','cost','--repeats','3','--trace','0','--resource-samples','0','--timing','0']),
    ]
    out=study/'analysis/followup-execution-ledger.json'
    if out.exists():raise SystemExit('ledger exists; choose a new script/run set')
    ledger=[]
    for name,flags in jobs:
        command=[sys.executable,'-B',str(study/'runner/vm.py'),name,'--variant','low','--warmup','0',*flags]
        start=time.monotonic();p=subprocess.run(command)
        record={'run':name,'command':command,'driver_rc':p.returncode,'wall_s':time.monotonic()-start}
        ledger.append(record);out.write_text(json.dumps(ledger,indent=2)+'\n');print(json.dumps(record),flush=True)
        if p.returncode:raise SystemExit('Follow-up failed; inspect preserved record before continuing')

if __name__=='__main__':main()
