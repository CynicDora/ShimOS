#!/usr/bin/env python3
"""Serial independent VM correctness runs; never a performance benchmark."""
import argparse,json,subprocess,sys,hashlib
from pathlib import Path
p=Path(__file__).resolve().parent
parser=argparse.ArgumentParser();parser.add_argument('prefix');a=parser.parse_args()
cases=['control','budgets','receipts','cancels','failures','controller_death','controller_during_entry']
record=[]
for case in cases:
    name=a.prefix+'-'+case.replace('_','-')
    print('RUN',name,flush=True)
    vm=subprocess.run([sys.executable,'-B',str(p/'vm.py'),name,'--case',case])
    check=subprocess.run([sys.executable,'-B',str(p/'verify.py'),name])
    record.append({'run':name,'case':case,'vm_returncode':vm.returncode,'verification_returncode':check.returncode})
with (p.parent/'analysis'/(a.prefix+'-qualification.json')).open('x') as f:
    json.dump({'correctness_only':True,'runs':record,'source_sha':{q.name:hashlib.sha256(q.read_bytes()).hexdigest() for q in p.iterdir() if q.is_file()}},f,indent=2);f.write('\n')
raise SystemExit(0 if all(r['vm_returncode']==r['verification_returncode']==0 for r in record) else 1)
