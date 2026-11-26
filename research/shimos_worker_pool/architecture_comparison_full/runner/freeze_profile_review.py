#!/usr/bin/env python3
"""Post-run source closure audit; does not convert numerical evidence to claims."""
from pathlib import Path
import json,hashlib,copy
S=Path(__file__).resolve().parent.parent
def load(p):return json.loads((S/p).read_text())
def sha(p):return hashlib.sha256((S/p).read_bytes()).hexdigest()
r=load('docs/sequential-source-review-v1.json');r['purpose']='Source admission for serial profile validation; no concurrency or extra tool support'
base=r['variants']['low']['source_sha256']
for group in ['G0','G1','G2']:
 checks=copy.deepcopy(r['architectures']['G2_REUSE']['checks'])
 checks['wait_and_release']['evidence']='Unchanged fresh-domain original run/run_g0 source lifecycle: actual PID1/S/Z/R wait, seal/EOF/domain-empty/H retirement; original round1 fixed source audit applies only unchanged closure'
 if group=='G0':
  checks['atomic_birth_and_runtime']['evidence']='Existing G0 trusted C PID1 raw clone3 immediately exec fixed candidate D cold Python; full runtime initialized fresh, not an inherited Python bypass'
 r['architectures'][group]={'admitted':True,'checks':checks,'accepted_qualification_inputs':[],
  'scope':'fresh domain per request; fixed trusted NumPy task; group '+group+' retained exact original lifecycle path, expanded closed input profile only'}
for batch in ['qualification-profiles-01','qualification-boundaries-01']:
 for p in sorted((S/'runs'/batch/'sessions').iterdir()):
  full=json.loads((p/'full-session.json').read_text());mode=full['extra_env'].get('FULL_MODE',full['architecture_group']);source=json.loads((p/'source-sha.json').read_text())
  differences={k for k in set(base)|set(source) if base.get(k)!=source.get(k)}
  assert differences<={'run_concurrent.py','concurrent_router.py'},(p,differences)
  item={'run':str(p.relative_to(S)),'reason':'Exact unchanged serial executable closure; the only whole-bundle differences are dormant concurrent_router.py/run_concurrent.py, never imported by these declared serial modes.',
   'source_sha256':source,'binary_sha256':json.loads((p/'variant-manifest.json').read_text())['binary_sha256'],
   'supplemental_binary_sha256':{},'source_inventory_sha256':sha(p.relative_to(S)/'source-sha.json'),'build_sha256':sha(p.relative_to(S)/'build.json'),
   'dormant_source_differences':sorted(differences)}
  r['architectures'][mode]['accepted_qualification_inputs'].append(item)
r['performance_admitted']=False;r['admission_keys']=[];r['qualification_evidence']=[]
r['limits'].append('Profile/boundary runs tracing off: actual numerical/security/runtime/wait validation, not new kernel ancestry traces')
with (S/'docs/profile-source-review-v1.json').open('x') as f:json.dump(r,f,indent=2,ensure_ascii=False);f.write('\n')
print('docs/profile-source-review-v1.json',sha('docs/profile-source-review-v1.json'))
