#!/usr/bin/env python3
"""Admit timing only with pinned qualified sources plus every request's facts.
Not an alternative to the full fault qualification; no new namespace proof from
trace-disabled timing runs. It references that separately completed matrix.
"""
import argparse,hashlib,json,traceback
from pathlib import Path
S=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def artifact(name,default='analysis'):
 p=Path(name)
 p=p if p.is_absolute() else (S/p if p.parts and p.parts[0] in ('analysis','docs','runs') else S/default/p)
 p=p.resolve();assert p.is_relative_to(S.resolve()),'evidence path escaped study'
 return p
def evidence_unchanged(report,run):
 values=report.get('evidence_sha256',{})
 return bool(values) and all(not Path(n).is_absolute() and '..' not in Path(n).parts
      and (run/n).is_file() and sha(run/n)==h for n,h in values.items())
def qualification_binding(q,variant,sources,binaries,runtime,check):
 refs=[];names=[];attempts=0;groups=[]
 for item in q.get('runs',[]):
  name=item['run'];assert Path(name).name==name
  run=S/'runs'/name;names.append(name)
  lp=artifact(item.get('qualification_file',name+'-qualification-recheck-v2.json'))
  # The former checker skipped some post-forget paths. It is preserved, but
  # cannot admit performance measurements as a completed corrected matrix.
  check(name+':uses corrected qualification',lp.name.endswith('-qualification-recheck-v2.json'),str(lp))
  rp=artifact(item.get('runtime_file',name+'-runtime.json'))
  lifecycle=load(lp);rt=load(rp);manifest=load(run/'variant-manifest.json')
  frozen=load(run/'source-sha.json');config=load(run/'review-config.json');groups.append(config['case'])
  review_path=artifact(manifest.get('source_review_path','docs/variant-source-review.json'))
  entry=load(review_path)['variants'][variant]
  check(name+':actual lifecycle/runtime PASS',lifecycle.get('status')==rt.get('status')=='PASS'
        and lifecycle.get('variant')==manifest.get('variant')==variant)
  check(name+':qualification review pinned',manifest.get('source_review_sha256')==sha(review_path))
  check(name+':exact qualified sources',frozen==manifest.get('source_sha256')==entry.get('source_sha256')==sources
        and all(sha(run/'prototype'/n)==h for n,h in frozen.items()))
  check(name+':exact qualified binaries',manifest.get('binary_sha256')==entry.get('binary_sha256')==binaries
        and all(sha(run/n)==h for n,h in binaries.items()))
  check(name+':same candidate runtime',load(run/'candidate-runtime-sha.json')==runtime)
  check(name+':qualification original evidence unchanged',evidence_unchanged(lifecycle,run)
        and evidence_unchanged(rt,run))
  attempts+=len(lifecycle.get('attempts',[]))
  refs.append({'run':name,'qualification_file':str(lp.relative_to(S)), 'qualification_sha256':sha(lp),
               'runtime_file':str(rp.relative_to(S)), 'runtime_sha256':sha(rp),
               'source_review_path':str(review_path.relative_to(S)), 'source_review_sha256':sha(review_path)})
 expected={'control','runtime','budgets','receipts','cancels','failures','controller_death','controller_during_entry'}
 check('completed corrected eight-VM 29-attempt fault matrix',len(names)==len(set(names))==8
       and set(groups)==expected and attempts==29,{'groups':groups,'actual_attempts':attempts})
 return refs
def counterexample_binding(variant,sources,binaries,check):
 if variant!='ping_merged':return []
 matrix=S/'analysis/counterexample-recheck-v2-matrix.json';data=load(matrix);refs=[];cases=[]
 for item in data.get('runs',[]):
  name=item['run'];assert Path(name).name==name
  path=S/'analysis'/(name+'-counterexample-recheck-v2.json');report=load(path);run=S/'runs'/name
  manifest=load(run/'variant-manifest.json');config=load(run/'review-config.json');cases.append(config['case'])
  review_path=artifact(manifest.get('source_review_path','docs/variant-source-review.json'))
  entry=load(review_path)['variants'][variant]
  check(name+':counterexample actual PASS and same implementation',report.get('status')=='PASS'
        and manifest.get('variant')==variant and manifest.get('source_sha256')==sources
        and manifest.get('binary_sha256')==binaries and evidence_unchanged(report,run))
  check(name+':counterexample reviewed source and binary bytes',sha(review_path)==manifest.get('source_review_sha256')
        and entry.get('source_sha256')==sources and entry.get('binary_sha256')==binaries
        and all(sha(run/'prototype'/n)==h for n,h in sources.items())
        and all(sha(run/n)==h for n,h in binaries.items()))
  refs.append({'run':name,'report':str(path.relative_to(S)),'sha256':sha(path)})
 expected={'counter_state_corruption','counter_fd_leak','counter_forgotten_drop','counter_late_ack',
           'counter_post_ack_controller_death','counter_post_forget_zygote_death'}
 check('six corrected merged-finalization counterexamples',len(cases)==6 and set(cases)==expected)
 return refs
def analyze(p,qualification):
 checks=[]
 def check(n,v,detail=None):checks.append({'name':n,'passed':bool(v),'detail':detail})
 config=load(p/'review-config.json');v=load(p/'variant-manifest.json');sources=load(p/'source-sha.json')
 rp=v.get('source_review_path','docs/variant-source-review.json');assert rp.startswith('docs/') and '..' not in Path(rp).parts
 review=load(S/rp);a=review['variants'][v['variant']]
 check('source review pinned',v['source_review_sha256']==sha(S/rp))
 check('review admits matching variant',a.get('admitted') is True and config.get('variant')==v['variant'])
 if (p/'source-review.json').exists():check('frozen review copy matches',sha(p/'source-review.json')==v['source_review_sha256'])
 check('source exact',sources==v['source_sha256']==a['source_sha256'] and all(sha(p/'prototype'/n)==h for n,h in sources.items()))
 check('compiled exact',v['binary_sha256']==a['binary_sha256'] and all(sha(p/n)==h for n,h in v['binary_sha256'].items()))
 runtime=load(p/'candidate-runtime-sha.json')
 check('candidate runtime installed and pinned',runtime==load(p/'candidate-runtime-install.json')['verified_sha256'])
 q=load(qualification)
 qrefs=qualification_binding(q,v['variant'],sources,v['binary_sha256'],runtime,check)
 crefs=counterexample_binding(v['variant'],sources,v['binary_sha256'],check)
 res=load(p/'result.json');sup=load(p/'supervisor.json');ext=load(p/'external-final-release.json');summary=load(p/'summary.json')
 check('VM/session complete',res['complete'] and not res['timeout'] and res['qemu_rc']==0)
 check('trace disabled',config['trace']=='0' and load(p/'trace-config.json')['tracing_on'].strip()=='0')
 check('H resources and true wait',sup['release_state']=='RELEASED' and sup['echild'] and sup['controller_wait_status']==0 and not sup['errors'] and not sup['protocol_errors'])
 check('H explicit release and no remaining objects',sup.get('resources_removed') is True
       and not sup.get('remaining_cgroups') and not sup.get('remaining_workspaces') and sup.get('observer_cleanup_used') is False)
 check('H actual Controller wait record',any(w.get('pid')==sup.get('controller_pid') and w.get('wait_status')==0
       and w.get('role')=='controller' for w in sup.get('wait_records',[])))
 check('H FD exact',sup['fd_before']==sup['fd_after'])
 check('fixture release no observer cleanup',ext['delegation_removed'] and ext['supervisor_wait_status']==0 and not ext['observer_killed_processes'] and not ext['observer_removed_product_resources'])
 check('summary',summary['all_passed'] and summary['controller_echild'] and len(summary['rows'])==int(config['requests'])+int(config['warmup']))
 nonces=[r['nonce'] for r in summary['rows']];hrows=sup.get('attempts',[])
 check('unique exact H/request attempt inventory',len(nonces)==len(set(nonces)) and len(hrows)==len(nonces)
       and {r.get('nonce') for r in hrows}==set(nonces))
 for observer_file in ('observer-after.json','observer-later.json'):
  obs=load(p/observer_file);cg=obs.get('cgroups',{})
  check(observer_file+':no product processes/workspaces',not obs.get('uid65534_processes') and not obs.get('workspaces'))
  check(observer_file+':only empty fixture/client cgroups',set(cg)=={'/sys/fs/cgroup/cdz','/sys/fs/cgroup/cdz/client'}
        and all(not r.get('cgroup.procs','missing').strip() and not r.get('cgroup.threads','missing').strip()
                and r.get('pids.current','').strip()=='0' and 'populated 0' in r.get('cgroup.events','') for r in cg.values()))
 session_config=load(p/'guest-session-config.json') if (p/'guest-session-config.json').exists() else {}
 expected_session=session_config.get('session',config.get('cost_session',config.get('session')))
 check('exact expected session identity recorded',isinstance(expected_session,str) and expected_session not in ('','unset'))
 if config.get('same_vm_pair'):
  execution=load(p/'session-execution.json');state=execution.get('after_product',{})
  check('paired fixture actual post-session product state',execution.get('complete') is True and execution.get('returncode')==0
        and execution.get('session')==expected_session and execution.get('variant')==v['variant']
        and state.get('state_root_is_private_directory') is True and state.get('cgroup_exists') is False
        and not state.get('uid65534_processes') and not state.get('workspaces') and not state.get('other_state_entries')
        and execution.get('observer_cleanup_performed') is False)
  check('paired timing level consistently recorded',str(config.get('timing'))==str(v.get('timing'))
        ==str(session_config.get('timing'))==str(execution.get('timing')))
 logs=[]
 for f in p.glob('zygote-*.log'):
  for line in f.read_text(errors='replace').splitlines():
   try:logs.append(json.loads(line))
   except ValueError:pass
 expected='PONG' if v['variant']=='baseline_instrumented' else 'FORGOTTEN'
 for row in summary['rows']:
  n=row['nonce'];r=load(p/('attempt-'+n+'.json'));post=r.get('zygote_post',{})
  check(n+':complete result',r['case']=='normal' and r['response_committed'] and r['qualification']=='PASS' and r['outcome']=='SUCCEEDED' and r['business']=='KNOWN' and r['result']['exit_code']==0)
  check(n+':domain release',r['domain_empty'] and r['resources_removed'] and r['resources']=='RELEASED' and r['output_eof'] and r['admission'].startswith('SEALED') and r['drained']['echild'])
  check(n+':real status',r['s_state']==r['w_state']=='REAPED' and r['s_wait']==r['monitor_wait']==0 and r['w_wait']['wait_status']==0)
  check(n+':actual S and W waits',any(x.get('event')=='ACTUAL_TRANSITION_WAIT' and x.get('nonce')==n and x['pid']==r['s_pid'] and x['wait_status']==0 for x in logs) and any(x.get('event')=='ACTUAL_WORKER_WAIT' and x.get('nonce')==n and x['worker_host_pid']==r['w_pid'] and x['wait_status']==0 for x in logs))
  check(n+':19 business checks',len(r['worker']['checks'])==19 and all(r['worker']['checks'].values()))
  check(n+':FD and template',r['controller_fd_before']==r['controller_fd_after'] and post['event']==expected and post['nonce']==n and post['session']==expected_session and post['active_attempts']==0 and post['state_unchanged'] and post['identity']['pid']==r['zygote_pid'] and set(post['identity']['fds'])=={'0','1','2','3'})
  h=[x for x in hrows if x.get('nonce')==n]
  check(n+':H exact retirement',len(h)==1 and h[0].get('registered') is True and h[0].get('retired') is True
        and h[0].get('resources_removed') is True and h[0].get('output_eof') is True
        and h[0].get('outcome')==h[0].get('business_result')=='SUCCEEDED')
  if v['variant']=='ping_merged':check(n+':late existing pidfd liveness checked',r.get('zygote_pidfd_alive_at_validation') is True)
 return {'run':str(p),'variant':v['variant'],'status':'PASS' if all(c['passed'] for c in checks) else 'FAIL','checks':checks,'failures':[c for c in checks if not c['passed']], 'qualification_reference':str(qualification),'qualification_sha256':sha(qualification),'qualified_run_bindings':qrefs,'counterexample_bindings':crefs,'verifier_sha256':sha(Path(__file__)),'resource_sampling':'Detailed CPU/PSS may be N/A with timing=0; absence is not a safety failure.','scope':'timing admission; separately pinned full fault matrix, trusted serial mechanism only'}
def main():
 a=argparse.ArgumentParser();a.add_argument('runs',nargs='+',type=Path);a.add_argument('--qualification',required=True,type=Path);a.add_argument('--out',required=True,type=Path);x=a.parse_args();out=[]
 for p in x.runs:
  try:out.append(analyze(p,x.qualification))
  except (OSError,ValueError,KeyError,TypeError,AssertionError):
   out.append({'run':str(p),'status':'FAIL','failures':[{'name':'evidence incomplete, invalid or inconsistent','passed':False,'detail':traceback.format_exc()}],'verifier_sha256':sha(Path(__file__))})
 with x.out.open('x') as f:json.dump({'runs':out},f,indent=2);f.write('\n')
 print(json.dumps([{'run':r['run'],'status':r['status'],'failures':r['failures']} for r in out]));return int(any(r['status']!='PASS' for r in out))
if __name__=='__main__':raise SystemExit(main())
