#!/usr/bin/env python3
"""Finite v2 serial admission: prior execution qualification + actual v2 pilot."""
import copy
import hashlib
import json
from pathlib import Path
S=Path(__file__).resolve().parent.parent
def load(p):return json.loads((S/p).read_text())
def sha(p):return hashlib.sha256((S/p).read_bytes()).hexdigest()
def save(p,x):
 with (S/p).open('x') as f:json.dump(x,f,ensure_ascii=False,indent=2);f.write('\n')
base=load('docs/sequential-v2-source-review.json')
summary_paths=['analysis/qualification-sequential-final-02/summary.json',
 'analysis/qualification-profile-final-01/summary.json','analysis/qualification-observer-v2-final-02/summary.json']
evidence=[];coverage={};summary_refs=[]
for path in summary_paths:
 summary=load(path);rows=summary.get('sessions',summary.get('runs',summary.get('results',[])))
 assert rows and all(r['status']=='PASS' for r in rows),(path,summary.keys())
 summary_refs.append({'path':path,'sha256':sha(path),'sessions':len(rows),
                      'attempts':sum(r.get('attempts',0) for r in rows),'scope':summary.get('profile',summary.get('scope'))})
 for row in rows:
  report=row.get('report',row.get('output',row.get('path')));assert report,(path,row)
  expected=row.get('report_sha256',row.get('sha256'));assert sha(report)==expected,(report,expected)
  value=load(report);assert value['status']=='PASS'
  ref={'path':report,'sha256':expected,'run':value['run'],'verification_profile':value.get('verification_profile'),
       'source_transfer':'v1 unchanged product closure, or exact v2 read-only observer candidate; no whole-SHA equivalence claimed'}
  evidence.append(ref)
  key=(value.get('mode'),value.get('full_profile'))
  if value.get('numeric') and any(n.get('numeric_status')=='PASS' for n in value['numeric']):
   coverage.setdefault(key,[]).append(ref)
observer='analysis/qualification-observer-v2-01-observation.json';assert load(observer)['status']=='PASS'
for stage,directory,old_review,output in [
 ('density','01_cross_vs_local','docs/sequential-performance-review-v1.json','docs/sequential-performance-review-v2.json'),
 ('persistent','02_local_vs_persistent','docs/persistent-performance-review-v1.json','docs/persistent-performance-review-v2.json'),
 ('profiles','03_initialization_cow',None,'docs/profile-performance-review-v2.json')]:
 r=copy.deepcopy(base);r['performance_admitted']=True;r['purpose']='Finite serial v2 '+stage+' performance admission; exact registered matrices only'
 r['qualification_evidence']=evidence;r['qualification_summaries']=summary_refs
 r['observer_pilot']={'path':observer,'sha256':sha(observer),'status':'PASS','samples':'12 sessions; 42 attempts lifecycle/numerical; 12 observer coverage checks',
 'scope':'timing1 full native/Python ordering; timing0 only separate native and Python ordering, cross-class order NOT_OBSERVED; no observed policy or wait change'}
 r['observation_change']['pilot_status']='PASS_WITH_DECLARED_OBSERVATION_LIMITS'
 matrices=[];allitems=[]
 for block in (1,2,3):
  path=f'{directory}/formal-block-{block}.json';items=load(path);assert isinstance(items,list) and items
  matrices.append({'path':path,'sha256':sha(path)});allitems+=items
 r['formal_preregistration']=matrices
 if old_review:
  original=load(old_review);r['admission_contracts']=copy.deepcopy(original['admission_contracts'])
 else:r['admission_contracts']={}
 for item in allitems:
  env=item['env'];mode=env.get('FULL_MODE') or item['group'];profile=env.get('FULL_PROFILE','legacy');key=item['admission_key']
  assert (mode,profile) in coverage,(mode,profile,'no actual numerical qualification')
  if stage=='profiles':
   assert mode in ('G0','G1','G2','G3')
   if mode=='G3':assert int(env['FULL_DOMAINS'])==item['requests'] and int(env['FULL_PER_DOMAIN'])==1,'G3 must use same fresh-domain-per-request contract'
   r['admission_contracts'][key]={'mode':mode,'profile':profile,'numpy_level':env['NP_LEVEL'],
    'serial':True,'normal_only':True,'domain_contract':'fresh independent domain per request; D=N, K=1',
    'no_arbitrary_code':True,'actual_numeric_qualification':coverage[(mode,profile)]}
  else:
   contract=r['admission_contracts'][key]
   assert contract['mode']==mode and contract['profile']==profile and contract['numpy_level']==env['NP_LEVEL']
   contract['actual_numeric_qualification']=coverage[(mode,profile)]
 r['admission_keys']=sorted({x['admission_key'] for x in allitems})
 r['numpy_admission_scope']={'architectures':sorted({x['group'] for x in allitems}),
  'levels':sorted({x['env']['NP_LEVEL'] for x in allitems}),'baselines':['cold','hot'],'cases':['normal'],'audit_modes':['0']}
 r['scope_notes']=['Actual v2 sources differ only in read-only sampling coverage and pre-H limit readback; prior finite lifecycle qualification is explicitly transferred.',
  'v1 numerical/fault proof + v2 exact observer pilot does not equal repeating all old faults under v2.',
  'Only fixed trusted single-thread NumPy task and original H alive contract; no concurrency, arbitrary reuse, or H-OOM guarantee.',
  'Observer uses approximately 2–6% of one CPU in this pilot; no zero-disturbance claim; formal timing1 and common sampler configuration required.',
  'v1 local PSS incomplete; v1 is retained as historical observation-limited data, never patched using v2.',
  'G4 completion is fixed function return/reset/EOF, not process exit; only full-session releases are directly compared.',
  'Stage3 matrices were corrected before execution so G3 also uses a fresh domain per request; exact current matrix SHA is bound.']
 save(output,r);print(output,sha(output),len(r['admission_keys']),'keys',len(allitems),'registered sessions')
