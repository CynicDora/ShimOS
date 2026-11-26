#!/usr/bin/env python3
"""Admit only a fully inspected, single-candidate qualification matrix.

Does not run experiments. Freezes a NEW review; never edits the initial source
review, manifests, rejected reports or raw evidence.
"""
import argparse,copy,datetime,json
from pathlib import Path
import verify_round1 as v

def main():
 p=argparse.ArgumentParser();p.add_argument('--matrix',required=True,type=Path)
 p.add_argument('--out',default='docs/performance-source-review.json',type=Path);a=p.parse_args()
 path=a.matrix if a.matrix.is_absolute() else v.S/a.matrix
 matrix=json.loads(path.read_text());assert matrix.get('status')=='PASS' and matrix.get('same_source_all_runs') is True
 assert matrix.get('scope')=='FINAL_FIXED_VERSION_MATRIX' and matrix.get('verifier_sha256')==v.sha(Path(v.__file__))
 old=v.S/'docs/variant-source-review.json';review=copy.deepcopy(json.loads(old.read_text()))
 refs=[];actual={g:set() for g in ('G0','G1','G2')};counts={g:0 for g in actual}
 for item in matrix['runs']:
  report=v.S/item['report'];data=json.loads(report.read_text());g=data['architecture_group']
  assert v.sha(report)==item['sha256'] and data['status']=='PASS' and data['verification_profile']=='qualification'
  assert data['verifier_sha256']==v.sha(Path(v.__file__))
  assert data['dependency_verifier_sha256']=={p.name:v.sha(p) for p in
      (Path(v.npcheck.__file__),Path(v.perfcheck.__file__),Path(v.lifecycle.__file__),Path(v.runtimecheck.__file__))}
  assert data['source_sha256']==review['variants']['low']['source_sha256']
  assert data['binary_sha256']==review['variants']['low']['binary_sha256']
  assert data.get('evidence_sha256_study_relative')
  for name,digest in data['evidence_sha256_study_relative'].items():assert v.sha(v.npcheck.within_run(v.S,name))==digest
  refs.append({'path':str(report.relative_to(v.S)),'sha256':v.sha(report),'architecture_group':g,
               'purpose':'actual_limited_architecture_qualification','cases':data['cases']})
  actual[g].update(data['cases']);counts[g]+=data['attempts']
 for g,seen in actual.items():
  required={'normal','nonzero','cancel_before_business','double_cancel','timeout','pid1_death','controller_death','session_deadline','result_loss_side_effect'}
  required|={'second_budget'} if g=='G0' else {'pid_budget','second_budget','zygote_death'}
  assert required<=seen,(g,'missing actual required case',required-seen)
  review['architectures'][g]['scope']='Performance allowed only for fixed trusted single-thread NumPy blas recipe, serial normal requests, original final security and H-alive/trusted-R ordinary-private-directory contract. No general third-party or full production qualification.'
  review['architectures'][g]['observed_qualification_cases']=sorted(seen)
  review['architectures'][g]['observed_qualification_attempts']=counts[g]
 review.update(review_version=2,date=datetime.datetime.now(datetime.timezone.utc).isoformat(),
               review_type='static-source-plus-actual-limited-qualification-performance-admission',performance_admitted=True,
               previous_review={'path':str(old.relative_to(v.S)),'sha256':v.sha(old)},
               qualification_matrix={'path':str(path.relative_to(v.S)),'sha256':v.sha(path)},qualification_evidence=refs)
 review['numpy_admission_scope']['qualification_evidence']=refs
 review['shared_contract']['resource_budget_scope']='Equal per-task/control/business cgroup limits; no common whole-session hard cap. Template and H/R outside task scopes are fully accounted, not free.'
 review['shared_contract']['whole_session_equal_hard_budget']=False
 review['qualification_limits']=['Limited per-architecture regression, not a claim of re-running every historical A/B case.',
    'Audit-off NumPy callbacks are unobserved in this round; fixed package and original dependency admission remain source constraints.',
    'Actual cross-domain runtime hooks/TID/robust-registration checkpoints are checked; no new robust-owner-death injection in this matrix.',
    'Source review before performance is mandatory. Some early qualification runs use explicit post-run static review of identical pre-frozen candidate bytes.',
    'Trace-off performance requires its own current-run wait/EOF/FD/safety/numerical evidence; qualified fault samples are not timing repetitions.']
 out=a.out if a.out.is_absolute() else v.S/a.out;out.resolve().relative_to(v.S.resolve())
 with out.open('x') as f:json.dump(review,f,ensure_ascii=False,indent=2);f.write('\n')
 print(json.dumps({'review':str(out),'sha256':v.sha(out),'groups':counts},ensure_ascii=False))
if __name__=='__main__':main()
