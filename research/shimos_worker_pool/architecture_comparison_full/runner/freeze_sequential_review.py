#!/usr/bin/env python3
"""Freeze a post-run static audit of the serial mechanisms, never fabricate tests."""
import hashlib,json
from pathlib import Path
S=Path(__file__).resolve().parent.parent
def read(p):return json.loads((S/p).read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):
 with (S/p).open('x') as f:json.dump(x,f,indent=2,ensure_ascii=False);f.write('\n')
q='runs/qualification-local-01/sessions/00-G3/'
source=read(q+'source-sha.json');build=read(q+'variant-manifest.json')['binary_sha256']
frozen=read('frozen/sequential-v1.json')
assert source==frozen['source_sha256']
known={}
for path in [q,'runs/qualification-g2-reuse-01/sessions/00-G2/','runs/pilot-local-normal-02/sessions/00-G3/']:
 sources=read(path+'source-sha.json');binary=read(path+'variant-manifest.json')['binary_sha256']
 # Old pilot manifest omitted the local PID1 executable; retain that omission
 # explicitly and bind the contemporaneous build and actual exported ELF too.
 actualbuild=read(path+'build.json')
 supplemental={}
 if 'domain_init_local' not in binary and (S/path/'domain_init_local').is_file():
  h=sha(S/path/'domain_init_local');assert actualbuild.get('domain_init_local')==h;supplemental['domain_init_local']=h
 known[path]={'source_sha256':sources,'binary_sha256':binary,'supplemental_binary_sha256':supplemental,
             'source_inventory_sha256':sha(S/path/'source-sha.json'),'build_sha256':sha(S/path/'build.json')}
checks={
'namespace_and_policy':{'passed':True,'evidence':'run.bwrap shared six namespaces/userns chain; bridge_d/drop_final/forbid_exec and policy.h unchanged from round1; local runtime final drop precedes NumPy import'},
'atomic_birth_and_runtime':{'passed':True,'evidence':'cross path complete D/CPython two forks; local G3 complete D/CPython single fork into request cg; PID1 trusted-C raw clone immediately exec fixed D; G4 no request fork claim'},
'permission_and_FD':{'passed':True,'evidence':'G2 cached FD identity validated per request; G3 local Z no namespace/root FD, receives private business-cg/socket/pipe; G4 FD0 only fixed trusted function protocol, never generic arbitrary-code contract'},
'admission_cancel_and_identity':{'passed':True,'evidence':'separate domain/attempt nonces; G2 SPAWN/PREPARED/COMMIT and W gate retained; G3 same serial creator seal; G4 PREPARE/RUN gates; unknown/fault retires domain'},
'wait_and_release':{'passed':True,'evidence':'G2 S/Z real wait + R adoption + PID1 QUIESCE ECHILD; G3 Z subreaper real W/descendant wait ECHILD; G4 fixed return/reset/EOF then final PID1 wait; request scope does not claim domain release'},
'supervisor_and_errors':{'passed':True,'evidence':'same limited H alive/private directory/trusted R cleanup contract; each owned domain/request registered as appropriate; actual EOF; UNKNOWN preserved; no observer cleanup substitute'},
'workload_and_reset':{'passed':True,'evidence':'fixed NumPy CPU input/oracle; known-file /work reset; G4 known DATA/geterr reset + FD/thread/signal/env/self state and child ECHILD; not generic sanitization'},
}
architectures={}
for mode in ['G2_REUSE','G3','G4']:
 accepted=[]
 for path,item in known.items():
  if mode=='G2_REUSE' and 'pilot-local' in path:continue
  if mode!='G2_REUSE' and 'qualification-g2-' in path:continue
  accepted.append({'run':path.removesuffix('/'),'reason':('exact final candidate' if path==q else
    'Earlier serial source snapshot: only run_local case-batch dispatch differs; G2 never imports run_local; local legacy normal uses unchanged request and teardown methods. This is a narrowly documented source transfer, not a same-whole-SHA claim.'),**item})
 architectures[mode]={'admitted':True,'checks':checks,'accepted_qualification_inputs':accepted,
  'scope':('fresh inherited Worker/request group inside same-trust retained domain' if mode!='G4' else
   'same trusted fixed function/Worker/domain; reset is not arbitrary-code isolation; function return not exit')}
review={'schema':1,'purpose':'post-run independent serial source audit; finite qualification tracked separately',
 'performance_admitted':False,'variants':{'low':{'admitted':True,'source_sha256':source,'binary_sha256':build}},
 'architectures':architectures,'admission_keys':[],'qualification_evidence':[],
 'audit_file':'00_round1_review/new-mechanism-admission-contract.md',
 'frozen_prototype':'frozen/sequential-v1','known_source_snapshots':known,
 'limits':['trusted single-thread own template and fixed NumPy CPU task','H must stay alive; no H-death or general filesystem guarantee',
 'serial same-principal persistent workspace','same per-task budget, not equal aggregate session cap','audit0 does not independently observe every OpenBLAS callback',
 'no concurrency, shell, arbitrary dependency, GPU or online Agent admission']}
save('docs/sequential-source-review-v1.json',review)
print('docs/sequential-source-review-v1.json',sha(S/'docs/sequential-source-review-v1.json'))
