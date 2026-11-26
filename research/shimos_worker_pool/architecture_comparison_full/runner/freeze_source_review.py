#!/usr/bin/env python3
"""Freeze already-reviewed round1 source and actual build, never run a guest."""
import argparse,hashlib,json,datetime
from pathlib import Path
S=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
AUDIT={
 'common_ipc_fd_semantics':'common.py unchanged; run.py:48 bwrap and namespace/FD validation; run_g0.py domain validates nonce, SCM_CREDENTIALS, namespace ancestry and root refs',
 'domain_pid1_exit_and_export':'domain_init.c unchanged; new domain_init_g0.c export_domain/reap_ready/main serial START/CANCEL and STOP after seal+ECHILD',
 'bridge_d_fork_and_namespace_security':'bridge_d.c/native.c/policy.h/bridge.c unchanged from frozen NumPy; candidate-04 runtime exactly retained; G0 trusted C cold exec is a separate non-inherited path',
 'supervisor_failure_and_reaping':'supervisor.py only shared configurable session deadline changed; real wait/read EOF/reclaim unchanged under trusted-R ordinary-private-workspace/H-alive contract',
 'controller_gate_and_release':'run.py original gates/wait/EOF/H; run_g0.py distinct private gate and PID1 real wait, conservative UNKNOWN if result unavailable; resource observer cannot clean product',
 'zygote_gate_revoke_and_forget':'zygote.py original gates/seal/real waits/template checks unchanged, except explicit test_descendant=False normal-payload choice; G0 no fabricated Zygote',
 'timing_errno_signal_and_fd_preservation':'cost.py bounded stdout buffering and diagnostics; same FD and observation contracts, errors invalidate measurement; separate read-only resource_sampler starts only after H fork',
}
def main():
 p=argparse.ArgumentParser();p.add_argument('--build-run',required=True);p.add_argument('--out',default='docs/variant-source-review.json');a=p.parse_args()
 run=(S/'runs'/a.build_run).resolve();run.relative_to((S/'runs').resolve())
 source=load(run/'source-sha.json');manifest=load(run/'variant-manifest.json');build=load(run/'build.json')
 for n,h in source.items():
  assert sha(run/'prototype'/n)==sha(S/'prototype'/n)==h,('source changed since actual build',n)
 binaries=manifest['binary_sha256'];assert set(binaries)=={'bridge.so','native.so','domain_init','bridge_d.so','libab_probe.so','numpy_atfork_audit.so','domain_init_g0'}
 for n,h in binaries.items():assert sha(run/n)==build[n]==h,('binary mismatch',n)
 old=load(S.parent/'numpy_admission/docs/variant-source-review-v2.json')['variants']['low']
 note=S/'docs/source-admission-review.md';assert note.is_file()
 base={'admitted':True,'scope':'Static private-VM source admission only; not actual qualification or performance. Fixed trusted NumPy CPU recipe; serial requests; H alive; trusted R/private ordinary directories.',
       'source_sha256':source,'binary_sha256':binaries,'diagnostics':'low',
       'bridge_d_original_sha256':old['bridge_d_original_sha256'],
       'bridge_d_original_binary_sha256':old['bridge_d_original_binary_sha256'],
       'review_notes':{'path':str(note.relative_to(S)),'sha256':sha(note)},
       'checks':{n:{'passed':True,'evidence':v} for n,v in AUDIT.items()}}
 groups={
  'G0':{'cold_child_exec':'domain_init_g0.c:start_worker uses atomic business cgroup clone then fixed candidate D loader; no Python interpreter state cloned',
        'seal_wait_permission':'domain_init_g0.c:main/reap_ready; run_g0.py:domain; g0_worker.py:run business gate and final policy',
        'runtime_and_target_identity':'run_g0.py checks namespace export/SCM peer/business membership/mapped runtime; W validates common 17 plus fresh runtime/no preload'},
  'G1':{'fresh_template_each_request':'run.py:run cold branch start_z/stop_z each request; W-cold initialization in unchanged numpy_workload.py',
        'original_cross_domain_fork_contract':'unchanged bridge_d.c and runtime candidate-04; original Z/S/W authority/wait/gates preserved'},
  'G2':{'prepared_template_reuse':'run.py and zygote.py retain one initialized trusted Z; post-request fingerprint, FD and NumPy template validation',
        'original_cross_domain_fork_contract':'unchanged bridge_d.c and runtime candidate-04; original Z/S/W authority/wait/gates preserved'}}
 review={'review_version':1,'date':datetime.datetime.now(datetime.timezone.utc).isoformat(),
         'review_type':'static-source-admission-not-runtime-qualification','binary_reference':str((run/'build.json').relative_to(S)),
         'variants':{'low':base},
         'architectures':{g:{'admitted':True,'scope':base['scope'],'checks':{k:{'passed':True,'evidence':v} for k,v in checks.items()}} for g,checks in groups.items()},
         'shared_contract':{'session_deadline_seconds':240,'qualification_test_descendant':True,'performance_test_descendant':False,
                            'H_scope':'old NumPy H alive; trusted R; private ordinary workspace; no exec_support_followup guarantees'},
         'numpy_admission_scope':{'architectures':['G0','G1','G2'],'levels':['blas'],'baselines':['cold','hot'],'cases':['normal'],
                                  'audit_modes':['0'],'qualification_evidence':[]},'qualification_evidence':[],'performance_admitted':False}
 out=S/a.out;out.resolve().relative_to(S.resolve())
 with out.open('x') as f:json.dump(review,f,ensure_ascii=False,indent=2);f.write('\n')
 print(json.dumps({'path':str(out),'sha256':sha(out),'performance_admitted':False}))
if __name__=='__main__':main()
