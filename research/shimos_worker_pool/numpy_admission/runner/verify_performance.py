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
  lp=artifact(item['qualification_file']);rp=artifact(item['runtime_file'])
  lifecycle=load(lp);rt=load(rp);manifest=load(run/'variant-manifest.json')
  frozen=load(run/'source-sha.json');config=load(run/'review-config.json');groups.append(config['case'])
  review_path=artifact(manifest.get('source_review_path','docs/variant-source-review.json'))
  entry=load(review_path)['variants'][variant]
  check(name+':actual lifecycle/runtime PASS',lifecycle.get('status')==rt.get('status')=='PASS'
        and lifecycle.get('variant')==manifest.get('variant')==variant
        and lifecycle.get('diagnostics')==rt.get('diagnostics')==config.get('diagnostics')==variant)
  check(name+':current independent verifier identity',lifecycle.get('verifier_sha256')==sha(S/'runner/verify_qualification.py')
        and rt.get('verifier_sha256')==sha(S/'runner/verify_runtime.py'))
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
 check('same-mode eight-VM 29-attempt fault matrix',variant in ('full','low') and len(names)==len(set(names))==8
       and set(groups)==expected and attempts==29,{'groups':groups,'actual_attempts':attempts})
 return refs
def counterexample_binding(variant,sources,binaries,check):
 if variant in ('full','low'):return []  # Both retain the original PING protocol.
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

def runtime_request(row,logs,diagnostics,timing,check):
 """Actual normal-request facts, separate from traced fault qualification.

 No callback is synthesized from an expected list. Buffered native/Python
 records are deduplicated by nonce, process and recorded execution timestamp.
 No intermediate management FD proof is inferred in low mode.
 """
 nonce=row['nonce'];prefix=nonce+':runtime:'
 own=[x for x in logs if x.get('nonce')==nonce]
 snaps=[x for x in own if x.get('event')=='AB_RUNTIME_SNAPSHOT']
 stages={x.get('stage'):x for x in snaps}
 required={'Z_before_first_fork','Z_after_first_parent','S_after_first_fork','S_early_drop',
           'S_before_second_fork','S_after_second_parent','W_after_second_fork','W_gated','W_business'}
 check(prefix+'nine actual runtime checkpoints',required<=set(stages) and len(stages)==len(snaps))
 if not required<=set(stages):return
 for stage,snap in stages.items():
  native=snap.get('native',{});label=prefix+stage+':'
  check(label+'explicit mode and current attempt',snap.get('diagnostics')==diagnostics and snap.get('nonce')==nonce)
  check(label+'real runtime checks',set(snap.get('checks',{}))=={'native_owner','tid_matches','thread_clock','robust_registered','tls_cookie'}
        and all(snap['checks'].values()) and native.get('pid')==native.get('tid')==native.get('native_owner')
        and native.get('cpuclock_rc')==0 and native.get('cpuclock_tid')==native.get('tid')
        and native.get('robust_rc')==0 and native.get('robust_head',0)>0
        and native.get('tls_cookie')==0x51a7c0de and native.get('native_counts')==snap.get('python_counts'))
  if stage.startswith('W_') or stage in {'S_early_drop','S_before_second_fork','S_after_second_parent'}:
   check(label+'final authority still dropped',native.get('capget_rc')==0
         and all(native.get(k)==0 for k in ('cap_eff','cap_prm','cap_inh','cap_bnd','cap_amb'))
         and native.get('nnp')==1 and native.get('seccomp')==2)
  if diagnostics=='low':
   fds=snap.get('fds',{})
   check(label+'RP FD gap explicitly recorded',fds.get('complete') is False and fds.get('entries')==[]
         and fds.get('method')=='not_observed_low_diagnostics')
   check(label+'native callback buffer intact',native.get('native_callback_order_dropped')==0
         and native.get('native_callback_log_enabled') is False)
 check(prefix+'W FD boundary independently observed',set(row['worker']['identity']['fds'])=={'0','1','2'}
       and row['worker']['checks']['fd_allowlist'] is True and row['worker']['runtime']==stages['W_business'])
 for before,after,branch in [('Z_before_first_fork','Z_after_first_parent','parent'),
                            ('Z_before_first_fork','S_after_first_fork','child'),
                            ('S_before_second_fork','S_after_second_parent','parent'),
                            ('S_before_second_fork','W_after_second_fork','child')]:
  base=stages[before]['native']['native_counts']
  desired={k:v+int(k.startswith('prepare') or k.startswith(branch)) for k,v in base.items()}
  check(prefix+'counter transition '+before+' -> '+after,stages[after]['native']['native_counts']==desired)
 parent=['python:prepare2','python:prepare1','native:prepare2','native:prepare1',
         'native:parent1','native:parent2','python:parent1','python:parent2']
 child=['native:child1','native:child2','python:child1','python:child2']
 if diagnostics=='full':
  callbacks=[x for x in own if x.get('event') in ('AB_NATIVE_FORK_CALLBACK','AB_PYTHON_FORK_CALLBACK')]
 else:
  unique={}
  for snap in snaps:
   for field,container,kind in [('native_callback_events',snap['native'],'AB_NATIVE_FORK_CALLBACK'),
                                ('python_callback_events',snap,'AB_PYTHON_FORK_CALLBACK')]:
    entries=container.get(field);check(prefix+snap['stage']+':'+field+' present',isinstance(entries,list))
    for x in entries or []:
     if x.get('pid')!=snap['native']['pid']:continue
     check(prefix+'buffer attempt binding',x.get('nonce',nonce)==nonce)
     key=(kind,x.get('pid'),x.get('name'),x.get('monotonic_ns'))
     detail=dict(x,event=kind,nonce=nonce)
     if key in unique:check(prefix+'duplicate buffered observation agrees',unique[key]==detail)
     unique[key]=detail
  callbacks=sorted(unique.values(),key=lambda x:x.get('monotonic_ns',0))
 roles={'Z':stages['Z_before_first_fork']['native']['pid'],
        'S':stages['S_after_first_fork']['native']['pid'],
        'W':stages['W_after_second_fork']['native']['pid']}
 check(prefix+'runtime role identity',roles['Z']==row['zygote_pid'] and roles['S']==row['s_pid']
       and roles['W']==row['worker']['identity']['pid'])
 for role,pid in roles.items():
  records=[x for x in callbacks if x.get('pid')==pid]
  if role=='W':records=[x for x in records if x.get('name','').startswith('child')]
  expected=parent if role=='Z' else child+parent if role=='S' else child
  actual=[('native:' if x['event']=='AB_NATIVE_FORK_CALLBACK' else 'python:')+x['name'] for x in records]
  if str(timing)=='1' or diagnostics=='full':
   check(prefix+role+' actual two-cross-domain-fork callback order',actual==expected,{'actual':actual,'expected':expected})
  else:
   check(prefix+role+' timing-off callback inventory (order not observed)',sorted(actual)==sorted(expected))
  for x in records:
   second=role=='W' or (role=='S' and x.get('name','').startswith(('prepare','parent')))
   if second:
    check(prefix+role+':callback authority:'+x['name'],x.get('capget_rc')==0 and x.get('cap_eff')==x.get('cap_prm')==0
          and x.get('nnp')==1 and x.get('seccomp')==2)

def analyze(p,qualification):
 checks=[]
 def check(n,v,detail=None):checks.append({'name':n,'passed':bool(v),'detail':detail})
 config=load(p/'review-config.json');v=load(p/'variant-manifest.json');sources=load(p/'source-sha.json')
 rp=v.get('source_review_path','docs/variant-source-review.json');assert rp.startswith('docs/') and '..' not in Path(rp).parts
 review=load(S/rp);a=review['variants'][v['variant']]
 check('source review pinned',v['source_review_sha256']==sha(S/rp))
 check('review admits matching variant',a.get('admitted') is True and config.get('variant')==v['variant'])
 scope=review.get('numpy_admission_scope',{})
 check('NumPy configuration has explicit reviewed performance scope',review.get('performance_admitted') is True
       and config.get('numpy_level') in scope.get('levels',[]) and config.get('numpy_baseline') in scope.get('baselines',[])
       and config.get('numpy_case') in scope.get('cases',[]) and str(config.get('numpy_audit')) in scope.get('audit_modes',[])
       and bool(scope.get('qualification_evidence')))
 check('explicit full/low mode',v['variant'] in ('full','low') and config.get('diagnostics')==v.get('diagnostics')==v['variant'])
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
 for f in list(p.glob('zygote-*.log'))+list(p.glob('*-output.log')):
  for line in f.read_text(errors='replace').splitlines():
   try:logs.append(json.loads(line))
   except ValueError:pass
 expected='PONG'
 for row in summary['rows']:
  n=row['nonce'];r=load(p/('attempt-'+n+'.json'));post=r.get('zygote_post',{})
  check(n+':complete result',r['case']=='normal' and r['response_committed'] and r['qualification']=='PASS' and r['outcome']=='SUCCEEDED' and r['business']=='KNOWN' and r['result']['exit_code']==0)
  check(n+':domain release',r['domain_empty'] and r['resources_removed'] and r['resources']=='RELEASED' and r['output_eof'] and r['admission'].startswith('SEALED') and r['drained']['echild'])
  check(n+':real status',r['s_state']==r['w_state']=='REAPED' and r['s_wait']==r['monitor_wait']==0 and r['w_wait']['wait_status']==0)
  check(n+':actual S and W waits',any(x.get('event')=='ACTUAL_TRANSITION_WAIT' and x.get('nonce')==n and x['pid']==r['s_pid'] and x['wait_status']==0 for x in logs) and any(x.get('event')=='ACTUAL_WORKER_WAIT' and x.get('nonce')==n and x['worker_host_pid']==r['w_pid'] and x['wait_status']==0 for x in logs))
  check(n+':19 business checks',len(r['worker']['checks'])==19 and all(r['worker']['checks'].values()))
  ident=r['worker'].get('identity',{});status=ident.get('status',{})
  check(n+':actual final W namespace/authority/environment boundary',ident.get('uid')==ident.get('gid')==65534
        and ident.get('ns')==r.get('target_ns') and set(ident.get('ns',{}))=={'user','mnt','pid','net','ipc','uts'}
        and all(int(status.get(k,'-1'),16)==0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
        and status.get('NoNewPrivs')=='1' and status.get('Seccomp')=='2'
        and ident.get('cgroup','').strip()=='0::/cdz/d-'+n+'/business'
        and set(ident.get('fds',{}))=={'0','1','2'})
  check(n+':FD and template',r['controller_fd_before']==r['controller_fd_after'] and post['event']==expected and post['nonce']==n and post['session']==expected_session and post['active_attempts']==0 and post['state_unchanged'] and post['identity']['pid']==r['zygote_pid'] and set(post['identity']['fds'])=={'0','1','2','3'})
  h=[x for x in hrows if x.get('nonce')==n]
  check(n+':H exact retirement',len(h)==1 and h[0].get('registered') is True and h[0].get('retired') is True
        and h[0].get('resources_removed') is True and h[0].get('output_eof') is True
        and h[0].get('outcome')==h[0].get('business_result')=='SUCCEEDED')
  runtime_request(r,logs,v['variant'],config.get('timing','1'),check)
  check(n+':journal policy explicit',r.get('diagnostics')==v['variant'] and r.get('journal_writes',0)>0
        and (r.get('journal_updates_buffered',0)>0 if v['variant']=='low' else r.get('journal_updates_buffered')==0))
 if config.get('numpy_baseline')=='cold':
  actual_rows=[load(p/('attempt-'+n+'.json')) for n in nonces]
  zids=[r.get('zygote_pid') for r in actual_rows]
  check('cold request sequence uses fresh templates',len(zids)==len(set(zids)) and None not in zids)
  check('each cold template truly waited with zero exit',all(sum(w.get('pid')==z and w.get('wait_status')==0
        for w in summary.get('wait_records',[]))==1 for z in zids))
 evidence={str(f.relative_to(p)):sha(f) for f in sorted(p.rglob('*')) if f.is_file()
           and f.suffix in ('.json','.jsonl','.log','.txt','.py','.c','.h','.sh','.npz')}
 return {'run':str(p),'variant':v['variant'],'diagnostics':v['variant'],'status':'PASS' if all(c['passed'] for c in checks) else 'FAIL','checks':checks,'failures':[c for c in checks if not c['passed']], 'qualification_reference':str(qualification),'qualification_sha256':sha(qualification),'qualified_run_bindings':qrefs,'counterexample_bindings':crefs,'verifier_sha256':sha(Path(__file__)),'evidence_sha256':evidence,'resource_sampling':'Detailed CPU/PSS may be N/A with timing=0; absence is not a safety failure.','scope':'timing admission; separately pinned same-mode fault matrix and per-request runtime checks; low intermediate RP FD and extra ordinary business-fork callback details not observed. No trace-disabled namespace ancestry proof is inferred.'}
def main():
 a=argparse.ArgumentParser();a.add_argument('runs',nargs='+',type=Path);a.add_argument('--qualification',required=True,type=Path);a.add_argument('--out',required=True,type=Path);x=a.parse_args();out=[]
 for p in x.runs:
  try:out.append(analyze(p,x.qualification))
  except (OSError,ValueError,KeyError,TypeError,AssertionError):
   out.append({'run':str(p),'status':'FAIL','failures':[{'name':'evidence incomplete, invalid or inconsistent','passed':False,'detail':traceback.format_exc()}],'verifier_sha256':sha(Path(__file__))})
 with x.out.open('x') as f:json.dump({'runs':out},f,indent=2);f.write('\n')
 print(json.dumps([{'run':r['run'],'status':r['status'],'failures':r['failures']} for r in out]));return int(any(r['status']!='PASS' for r in out))
if __name__=='__main__':raise SystemExit(main())
