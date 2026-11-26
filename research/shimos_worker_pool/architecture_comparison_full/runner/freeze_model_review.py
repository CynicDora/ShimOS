#!/usr/bin/env python3
"""Register finite serial model configurations; never claim they already ran."""
import copy
import hashlib
import json
from pathlib import Path

S=Path(__file__).resolve().parent.parent
def load(p):return json.loads((S/p).read_text())
def sha(p):return hashlib.sha256((S/p).read_bytes()).hexdigest()

basepath='docs/sequential-performance-review-v2.json'
base=load(basepath)
assert base['performance_admitted'] is True and base['frozen_prototype']=='frozen/sequential-v2'
review=copy.deepcopy(base)
review['purpose']='Finite model training/held-out parameter admission on qualified serial v2 mechanism; unrun combinations remain unverified observations'
review['basis_review']={'path':basepath,'sha256':sha(basepath)}
matrices=[];configs=[]
expected={('G2',n,d,k) for n,d,k in [(1,1,1),(10,1,10),(25,1,25),(32,4,8),(32,8,4)]}
expected|={('G3',n,d,k) for n,d,k in [(1,1,1),(10,1,10),(25,1,25),(32,4,8),(32,8,4)]}
for block in (1,2,3):
    p=f'07_cost_model/heldout-block-{block}.json';items=load(p)
    assert len(items)==10 and {(x['group'],x['requests'],int(x['env']['FULL_DOMAINS']),int(x['env']['FULL_PER_DOMAIN'])) for x in items}==expected
    for x in items:
        env=x['env'];d=int(env['FULL_DOMAINS']);k=int(env['FULL_PER_DOMAIN']);n=x['requests']
        assert d*k==n and x['block']==block
        assert env['FULL_MODE']==('G2_REUSE' if x['group']=='G2' else 'G3')
        assert env['FULL_PROFILE']=='legacy' and env['NP_LEVEL']=='blas' and env['RELIABILITY_CASE']=='performance'
        assert env['FULL_COST_MODE']=='stages' and x['admission_key']==x['group']+'-density-legacy'
        assert x['label']==(f'model-train-D{d}-K{k}' if d==1 else f'model-heldout-D{d}-K{k}')
    configs.extend(items);matrices.append({'path':p,'sha256':sha(p)})
review['formal_preregistration']=matrices
for key,contract in review['admission_contracts'].items():
    contract.pop('tasks',None)
    contract['allowed_request_counts']=[1,10,25,32]
    contract['domain_count_request_pairs']=[[1,1],[1,10],[1,25],[4,8],[8,4]]
    contract['parameter_admission_basis']='Same previously qualified serial per-request and retained-domain loop, exact v2 source and policy. These numerical combinations are registered for measurement, not claimed previously executed or stress-qualified.'
review['model_split']={
    'status':'REGISTERED_NOT_YET_OBSERVED',
    'training_extra':{'D':1,'N':[1,10,25]},
    'training_other':'Only admitted v2 density blocks at N=50, exact legacy task; no v1 PSS repair or stage2 profiles mixed in',
    'held_out':[{'N':32,'D':4,'K':8},{'N':32,'D':8,'K':4}],
    'held_out_not_used_to_fit':True,
    'model_contract':{'path':'07_cost_model/model-contract.md','sha256':sha('07_cost_model/model-contract.md')},
    'scope':'Same trusted serial function; D/K counting alone proves no new safety guarantee. Every actual run still requires all requested attempts, real waits, gates, EOF, template/FD checks, resource release and independent numeric verification. Any timeout/OOM/incomplete sequence remains a failed/incomplete observation.'}
review['scope_notes'] += [
    'New model combinations are explicit parameter extrapolations of the qualified serial mechanism, not new completed qualification samples.',
    'Held-out means withheld configuration, not an independent physical machine; fitting/VM holdout is described separately.',
    'Only the exact 30 registered configurations are admitted here; no concurrent/mixed/pressure admission.']
out='docs/model-performance-review-v2.json'
with (S/out).open('x') as f:json.dump(review,f,ensure_ascii=False,indent=2);f.write('\n')
print(out,sha(out),len(configs),'registered sessions; not yet observed')
