#!/usr/bin/env python3
"""Finite source transfer for sampler/readback only; no run is admitted here."""
import ast
import copy
import hashlib
import json
from pathlib import Path
S=Path(__file__).resolve().parent.parent
def load(p):return json.loads((S/p).read_text())
def sha(p):return hashlib.sha256((S/p).read_bytes()).hexdigest()
a=load('frozen/sequential-v1.json');b=load('frozen/sequential-v2.json')
for version,manifest in [('v1',a),('v2',b)]:
 actual={p.name:sha(p.relative_to(S)) for p in (S/'frozen'/('sequential-'+version)).iterdir() if p.is_file()}
 assert actual==manifest['source_sha256'],version
assert set(a['source_sha256'])==set(b['source_sha256'])
changed=[k for k in a['source_sha256'] if a['source_sha256'][k]!=b['source_sha256'][k]]
assert set(changed)=={'run.py','resource_sampler.py'}
for file in changed:ast.parse((S/'frozen/sequential-v2'/file).read_text())
first=(S/'frozen/sequential-v1/resource_sampler.py').read_text()
second=(S/'frozen/sequential-v2/resource_sampler.py').read_text()
expected=first.replace("('control','transition','business')","('control','template','transition','business')")
expected=expected.replace('owned root/client/template/d-*/{control,transition,business}; no arbitrary nested cgroups',
 'owned root/client/template/d-*/{control,template,transition,business}; template includes local Z or persistent Worker; no arbitrary nested cgroups')
assert expected==second
first=(S/'frozen/sequential-v1/run.py').read_text();second=(S/'frozen/sequential-v2/run.py').read_text()
start=second.index('    # Read back actual installed limits; no limit or execution policy changes.\n')
end=second.index("    trace=Path('/sys/kernel/tracing');",start)
assert second[:start]+second[end:]==first
assert not any(x in second for x in ['G2_CONCURRENT','G3_CONCURRENT','G2_MIXED'])
r=load('docs/profile-source-review-v1.json')
r['purpose']='Static source audit of serial v2: only read-only fixture observation changed; runtime qualification and observer pilot tracked separately'
r['variants']['low']['source_sha256']=b['source_sha256']
r['performance_admitted']=False;r['admission_keys']=[];r['qualification_evidence']=[]
r['frozen_prototype']='frozen/sequential-v2'
r['observation_change']={'base':'frozen/sequential-v1','source_manifest_sha256':sha('frozen/sequential-v2.json'),
 'changed_files':changed,'patch':'frozen/sequential-v2-readonly-observer.patch','patch_sha256':sha('frozen/sequential-v2-readonly-observer.patch'),
 'product_execution_closure_unchanged':True,'compiled_C_sources_unchanged':True,
 'actual_binaries_still_require_run_export_comparison':True,
 'pilot_status':'PENDING','source_checks':['exact all-source SHA inventories',
 'sampler adds only template leaf to fixed census','run.py only inserts read-only actual-limit JSON before H start',
 'no concurrent/mixed dispatch','no gate/wait/policy/budget/clock boundary changes']}
for item in r['architectures'].values():
 item['checks']['observer_change']={'passed':True,'evidence':'Exact v1/v2 textual comparison; sampler remains outside product cgroup and never kills or removes product resources; limit readback occurs before fixture_session_start. New observer overhead needs actual pilot.'}
 item['scope']+='; v2 changes only independent observer coverage and actual-budget readback'
r['limits'] += ['v1 process PSS omitted local template; v2 cannot retroactively repair v1 evidence',
 'additional /proc reads may perturb v2; do not assume zero overhead',
 'No runtime or performance PASS from this static source audit alone']
out=S/'docs/sequential-v2-source-review.json'
with out.open('x') as f:json.dump(r,f,indent=2,ensure_ascii=False);f.write('\n')
print(out.relative_to(S),sha(out.relative_to(S)))
