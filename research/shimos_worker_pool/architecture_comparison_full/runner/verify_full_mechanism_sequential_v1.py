#!/usr/bin/env python3
"""Independent, read-only admission for retained domains and local Workers.

No task is run, signalled or cleaned by this program. G4 fixed-function return
is deliberately not represented as an exit/wait, nor a request as a whole-domain
release. Missing observations are BLOCKED. A pilot can have valid mechanism
observations while overall admission stays BLOCKED pending exact source review.
"""
import argparse
import collections
import json
import re
import traceback
from pathlib import Path
import verify_numpy as npcheck
import verify_runtime as rp
import verify_round1 as old

S=Path(__file__).resolve().parent.parent
sha=npcheck.sha
NORMAL={'normal','nonzero','created_drop','reaped_drop'}
LOCAL_CHECKS={'marker','memory_state','state_origin','no_host_path','no_other_workspace','readonly','writable',
 'setns_denied','unshare_denied','chroot_denied','exec_denied','caps_zero','nnp_seccomp','fd_allowlist',
 'namespaces','cgroup','environment','cwd','root_identity'}


class Evidence(old.Evidence):
    section='mechanism'
    def check(self,name,value,detail=None):
        super().check(name,value,detail)
        self.checks[-1]['section']=self.section


def valid_nonce(x):return isinstance(x,str) and re.fullmatch('[0-9a-f]{32}',x) is not None

def zero(v):
    try:return int(v,16)==0 if isinstance(v,str) else v==0
    except (ValueError,TypeError):return False


def domains(rows):return {r.get('domain_nonce',r.get('persistent_domain_nonce')) for r in rows}


def load_rows(e):
    allrows={}
    for p in sorted(e.run.glob('attempt-*.json')):
        r=e.json(p)
        if r.get('nonce'):allrows[r['nonce']]=r
    finals=sorted(e.run.glob('[0-9]*-*.json'),key=lambda p:int(p.name.split('-')[0]))
    order=[]
    for p in finals:
        r=e.json(p)
        if r.get('nonce') and 'case' in r:
            e.check('one final record per attempt:'+r['nonce'],r['nonce'] not in order)
            allrows[r['nonce']]=r;order.append(r['nonce'])
    order += [n for n in allrows if n not in order]
    return [allrows[n] for n in order]


def source_binding(e,manifest,config,full,mode,review_arg,profile):
    e.section='source_admission'
    source=e.json(e.run/'source-sha.json');build=e.json(e.run/'build.json')
    bad=[]
    for f,h in source.items():
        try:
            if sha(npcheck.within_run(e.run/'prototype',f))!=h or build.get(f)!=h:bad.append(f)
        except (ValueError,OSError):bad.append(f)
    e.check('actual frozen source and build inventory',bool(source) and source==manifest.get('source_sha256') and not bad,bad)
    binary=manifest.get('binary_sha256',{})
    required={'bridge.so','native.so','domain_init','bridge_d.so','libab_probe.so','numpy_atfork_audit.so','domain_init_g0'}
    if mode in ('G3','G4'):required.add('domain_init_local')
    bbad=[]
    for f,h in binary.items():
        try:
            if sha(npcheck.within_run(e.run,f))!=h or build.get(f)!=h:bbad.append(f)
        except (ValueError,OSError):bbad.append(f)
    missing_required=required-set(binary)
    supplemental={}
    for f in missing_required:
        if (e.run/f).is_file() and build.get(f)==sha(e.run/f):supplemental[f]=build[f]
    e.check('all executed compiled components exported and build-bound',missing_required<=set(supplemental) and not bbad,
            {'manifest_missing':sorted(missing_required),'actual_build_bound_supplement':supplemental,'mismatch':bbad})
    runtime=e.json(e.run/'candidate-runtime-sha.json');installed=e.json(e.run/'candidate-runtime-install.json')
    frozen=e.json(S/'frozen/candidate-04-runtime-sha.json');rbad=[]
    for f,h in runtime.items():
        try:
            if sha(npcheck.within_run(e.run/'candidate-runtime',f))!=h:rbad.append(f)
        except (ValueError,OSError):rbad.append(f)
    e.check('fixed candidate D actual bytes installed unchanged',bool(runtime) and runtime==frozen
            and installed.get('verified_sha256')==runtime and not rbad,rbad)
    review={}
    if review_arg:
        path=Path(review_arg)
        if not path.is_absolute():path=S/path
        path=path.resolve(strict=True);path.relative_to(S.resolve())
        review=e.json(path)
        e.check('post-run review is exact static audit not claimed preregistered',True,
                {'path':str(path.relative_to(S)),'sha256':sha(path),'timing':'POST_RUN_STATIC_REVIEW'})
    else:
        path=e.run/'source-review.json';review=e.json(path)
        e.check('run frozen review hash exact',manifest.get('source_review_sha256')==sha(path) if path.is_file() else None)
    variant=review.get('variants',{}).get('low',{})
    e.check('source reviewer explicitly admitted exact mode',True if review.get('architectures',{}).get(mode,{}).get('admitted') is True else None)
    accepted=review.get('architectures',{}).get(mode,{}).get('accepted_qualification_inputs',[])
    def supplemental_matches(item):
        values=item.get('supplemental_binary_sha256',{})
        return all(values.get(k)==v for k,v in supplemental.items()) and all(
            (e.run/f).is_file() and build.get(f)==h and sha(e.run/f)==h for f,h in values.items())
    qualified_input=next((x for x in accepted if x.get('source_sha256')==source and x.get('binary_sha256')==binary
                          and supplemental_matches(x)),None)
    exact=variant.get('admitted') is True and variant.get('source_sha256')==source and variant.get('binary_sha256')==binary and not supplemental
    reviewed_input=exact or (profile=='qualification' and qualified_input is not None)
    e.check('source reviewer binds all actual source and compiled bytes',True if reviewed_input else None,
            {'exact_final_candidate':exact,'qualification_transfer':qualified_input.get('reason') if qualified_input else None})
    if profile=='performance':
        key=full.get('configuration',{}).get('admission_key')
        e.check('formal exact configuration key admitted',review.get('performance_admitted') is True
                and key is not None and key in review.get('admission_keys',[]),key)
        e.check('formal has actual same-source qualification references',True if review.get('qualification_evidence') else None)
        e.check('formal not an unqualified pilot',config.get('pilot') is False)
    e.section='mechanism'
    return review,source,binary


def configurations(e,config,manifest,full):
    env=full.get('extra_env',{})
    conf=full.get('configuration',{})
    mode=env.get('FULL_MODE',config.get('architecture_group'))
    e.check('explicit supported mechanism',mode in ('G0','G1','G2','G2_REUSE','G3','G4'))
    e.check('same actual architecture declared in all records',config.get('architecture_group')==manifest.get('architecture_group')==full.get('architecture_group')==conf.get('group'))
    e.check('fixed low diagnostic mode',config.get('variant')==manifest.get('variant')==config.get('diagnostics')==manifest.get('diagnostics')=='low')
    e.check('single-thread package budget recorded',config.get('numpy_thread_environment')==npcheck.THREAD_ENV)
    expected_baseline='hot' if config.get('architecture_group') in ('G2','G3','G4') else 'cold'
    e.check('baseline semantic label',config.get('numpy_baseline')==manifest.get('numpy_baseline')==expected_baseline)
    # full-session stores the exact actual overrides; old review-config may
    # describe runner defaults. Neither is silently rewritten by this checker.
    token=env.get('FULL_PROFILE','legacy');level=env.get('NP_LEVEL',config.get('numpy_level'))
    actual_case=env.get('RELIABILITY_CASE','performance')
    desc=env.get('ARCH_TEST_DESCENDANT','0')=='1'
    e.check('actual workload configuration captured',bool(conf) and conf.get('env',{})==env
            and full.get('requests')==conf.get('requests'))
    e.check('actual template level is supported',level in ('base','import','data','blas'))
    if token!='legacy':
        parts=token.split(':')
        e.check('closed profile syntax matches preheat level',len(parts)==5 and parts[0]=='v1' and parts[1]==level
                and parts[2] in ('8','32','64','128') and parts[3] in ('readonly','element','sparse','many','full')
                and parts[4] in ('light','medium','heavy'))
    return mode,env,token,level,actual_case,desc


def session_release(e,rows,sup,ext,summary,logs,full,mode):
    e.check('H normal surviving-owner release',sup.get('release_state')=='RELEASED' and sup.get('resources_removed') is True
            and sup.get('remaining_cgroups')==[] and sup.get('remaining_workspaces')==[] and sup.get('errors')==[]
            and sup.get('protocol_errors')==[] and sup.get('echild') is True)
    e.check('H actual FD objects restored',sup.get('fd_before') is not None and sup.get('fd_before')==sup.get('fd_after'))
    waits=[x for x in logs if x.get('event')=='SUPERVISOR_REAL_WAIT']
    e.check('H actual wait for R',any(x.get('pid')==sup.get('controller_pid') and x.get('wait_status')==sup.get('controller_wait_status') for x in waits))
    for r in sup.get('wait_records',[]):
        e.check('H adopted wait backed by actual record:'+str(r.get('pid')),any(x.get('pid')==r.get('pid') and x.get('wait_status')==r.get('wait_status') for x in waits))
    e.check('no external observer product cleanup',sup.get('observer_cleanup_used') is False
            and ext.get('observer_killed_processes') is False and ext.get('observer_removed_product_resources') is False
            and ext.get('supervisor_wait_status')==0 and ext.get('delegation_removed') is True)
    for f in ('observer-after.json','observer-later.json'):
        d=e.json(e.run/f);cg=d.get('cgroups',{})
        e.check(f+':no private products remain',d.get('uid65534_processes')=={} and d.get('workspaces')=={}
                and set(cg)=={'/sys/fs/cgroup/cdz','/sys/fs/cgroup/cdz/client'} and all(
                not v.get('cgroup.procs','missing').strip() and not v.get('cgroup.threads','missing').strip()
                and v.get('pids.current','').strip()=='0' and 'populated 0' in v.get('cgroup.events','') for v in cg.values()))
    if summary:
        e.check('R real final ECHILD, success only after cleanup',summary.get('all_passed') is True
                and summary.get('controller_echild') is True and sup.get('done_received') is True
                and sup.get('controller_wait_status')==0 and sup.get('failure_reason') is None)
    else:
        case=full.get('extra_env',{}).get('RELIABILITY_CASE')
        e.check('missing summary only deliberate R/deadline fault',case in ('controller_death','controller_during_entry','session_deadline'))
        e.check('H recovery result UNKNOWN, never invented',sup.get('done_received') is False and sup.get('business_result')=='UNKNOWN'
                and isinstance(sup.get('recovery_started_ns'),int) and bool(waits))
    registered={x.get('nonce'):x for x in sup.get('attempts',[])}
    e.check('all H registration identities unique',len(registered)==len(sup.get('attempts',[]))
            and all(valid_nonce(n) for n in registered))
    domain_ids=domains(rows)-{None}
    expected={r['nonce'] for r in rows}|domain_ids if mode in ('G2_REUSE','G3') else domain_ids if mode=='G4' else {r['nonce'] for r in rows}
    if summary:e.check('H exact request/domain ownership inventory',set(registered)==expected,{'actual':sorted(registered),'expected':sorted(expected)})
    for row in rows:
        n=row['nonce'];h=registered.get(n if mode!='G4' else row.get('domain_nonce'),{})
        e.check(n+':H owns required cleanup scope',h.get('registered') is True)
        if row.get('business')=='UNKNOWN':e.check(n+':unknown not promoted to result',row.get('result') is None and row.get('outcome') not in ('SUCCEEDED','NONZERO'))
        if row.get('response_committed'):
            e.check(n+':real output EOF and R FD restoration',row.get('output_eof') is True
                    and row.get('controller_fd_before') is not None and row.get('controller_fd_before')-(1 if mode in ('G3','G4') and row.get('case')=='control_eof' else 0)==row.get('controller_fd_after'))
            if mode!='G4':
                e.check(n+':per-request actual domain resources released',row.get('resources')=='RELEASED'
                        and row.get('resources_removed') is True and row.get('domain_empty') is True
                        and str(row.get('admission','')).startswith('SEALED'))
                e.check(n+':H request retirement follows actual EOF',h.get('retired') is True and h.get('resources_removed') is True
                        and h.get('output_eof') is True and h.get('outcome')==row.get('outcome'))
                roles={'task','business'}|({'transition'} if mode=='G2_REUSE' else set())
                e.check(n+':all actual request cgroups zero',roles<=set(row.get('stats',{})) and all(
                        'populated 0' in row['stats'][r].get('cgroup.events','') and row['stats'][r].get('pids.current','').strip()=='0' for r in roles))
        else:e.check(n+':H recovery confirmed unknown and resources',h.get('business_result')=='UNKNOWN'
                and h.get('resources_removed') is True and h.get('output_eof') is True)
    return registered


def identity(e,ident,ns,label,fdset=None):
    status=ident.get('status',{})
    e.check(label+':six actual target namespaces',ident.get('ns')==ns and set(ns or {})=={'user','mnt','pid','net','ipc','uts'})
    e.check(label+':all final credentials and security',ident.get('uid')==ident.get('gid')==65534
            and all(zero(status.get(k)) for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
            and status.get('NoNewPrivs')=='1' and status.get('Seccomp')=='2')
    if fdset is not None:e.check(label+':actual business FD set',set(ident.get('fds',{}))==fdset)


def runtime_snapshot(e,snap,label,generation):
    if not snap:e.check(label+':runtime observed',None);return
    n=snap.get('native',{})
    derived={'native_owner':n.get('native_owner_matches') is True and n.get('native_owner')==n.get('pid'),
     'tid_matches':n.get('cpuclock_rc')==0 and n.get('cpuclock_tid')==n.get('tid'),
     'thread_clock':n.get('clock_gettime_rc')==0,
     'robust_registered':n.get('robust_rc')==0 and isinstance(n.get('robust_head'),int) and n['robust_head']>0,
     'tls_cookie':n.get('tls_cookie')==0x51a7c0de}
    e.check(label+':actual libc TID TLS robust checks',snap.get('checks')==derived and all(derived.values()))
    e.check(label+':actual generation and single thread',n.get('pid')==n.get('tid') and n.get('generation')==generation)
    e.check(label+':native Python callback counters consistent',set(n.get('native_counts',{}))==rp.COUNTS
            and n.get('native_counts')==snap.get('python_counts'))
    e.check(label+':runtime capability and policy boundary',n.get('capget_rc')==0 and all(n.get(k)==0 for k in
            ('cap_eff','cap_prm','cap_inh','cap_bnd','cap_amb')) and n.get('nnp')==1 and n.get('seccomp')==2)
    e.check(label+':callback instrumentation no overflow',n.get('native_callback_order_dropped')==0)


def local_runtime(e,row,logs,mode):
    n=row['nonce'];own=[x for x in logs if x.get('nonce')==n]
    snapshots=old.unique([x for x in own if x.get('event')=='AB_RUNTIME_SNAPSHOT'])
    for x in ((row.get('worker') or {}).get('runtime',{}),(row.get('gated') or {}).get('runtime',{})):
        if x:snapshots=old.unique(snapshots+[x])
    stages={x.get('stage'):x for x in snapshots}
    generation=0 if mode=='G4' else 1
    for stage in (('LOCAL_PERSISTENT_gated','LOCAL_W_business') if mode=='G4' else ('LOCAL_W_gated','LOCAL_W_business')):
        if row.get('worker') or (row.get('gated') and stage.endswith('gated')):
            runtime_snapshot(e,stages.get(stage),n+':'+stage,generation)
    if mode=='G4':return
    if row.get('worker'):
        e.check(n+':local parent before/after complete fork snapshots',{'LOCAL_Z_before_fork','LOCAL_Z_after_fork'}<=set(stages))
    callbacks={}
    for snap in snapshots:
        native=snap.get('native',{})
        for kind,records in [('native',native.get('native_callback_events',[])),('python',snap.get('python_callback_events',[]))]:
            for x in records:
                if x.get('pid')!=native.get('pid'):continue
                key=(kind,x.get('pid'),x.get('name'),x.get('monotonic_ns'))
                callbacks[key]=dict(x,kind=kind)
    for x in callbacks.values():
        e.check(n+':local callback executes after final drop:'+str((x.get('kind'),x.get('name'),x.get('pid'))),
                x.get('capget_rc')==0 and zero(x.get('cap_eff')) and zero(x.get('cap_prm'))
                and x.get('nnp')==1 and x.get('seccomp')==2 and isinstance(x.get('monotonic_ns'),int) and x['monotonic_ns']>0)
    before=stages.get('LOCAL_Z_before_fork',{});after=stages.get('LOCAL_Z_after_fork',{})
    parent=after.get('native',{}).get('pid');child=stages.get('LOCAL_W_gated',{}).get('native',{}).get('pid')
    for pid,expected,label in [(parent,rp.PARENT,'parent'),(child,rp.CHILD,'child')]:
        if pid is None:continue
        actual=[x['kind']+':'+x['name'] for x in sorted(callbacks.values(),key=lambda v:v.get('monotonic_ns',0)) if x.get('pid')==pid]
        e.check(n+':complete local fork callback order '+label,actual==expected,{'actual':actual,'expected':expected})
    if before and after:
        a=before['native']['native_counts'];b=after['native']['native_counts']
        e.check(n+':actual one full local parent wrapper',all(b[k]-a[k]==(1 if k.startswith(('prepare','parent')) else 0) for k in rp.COUNTS))


def local_domain_evidence(e,rows,logs,summary,mode,registered):
    ready={};released={}
    for p in sorted(e.run.glob('local-domain-*-ready.json')):
        r=e.json(p);ready[r.get('domain_nonce')]=r
    for p in sorted(e.run.glob('local-domain-*-released.json')):
        r=e.json(p);released[r.get('domain_nonce')]=r
    if summary:e.check('all intended local domains really released',set(ready)==set(released)==domains(rows))
    for n,r in ready.items():
        state=r.get('ready',{})
        e.check(n+':local ready and actual inherited FD export identity',state.get('nonce')==n and state.get('domain_nonce')==n
                and state.get('group')==mode and state.get('final_security_installed') is True
                and bool(r.get('mapping_checks')) and all(r.get('mapping_checks',{}).values()))
        identity(e,state.get('identity',{}),r.get('target_ns'),n+':prepared runtime')
        runtime_snapshot(e,state.get('runtime'),n+':prepared runtime',0)
        d=released.get(n,{})
        if d:
            e.check(n+':final real whole-domain release',d.get('resources')=='RELEASED' and d.get('resources_removed') is True
                    and d.get('domain_empty') is True and d.get('output_eof') is True
                    and all('populated 0' in x.get('cgroup.events','') and x.get('pids.current','').strip()=='0' for x in d.get('stats',{}).values()))
            e.check(n+':H final domain RETIRE',registered.get(n,{}).get('retired') is True
                    and registered.get(n,{}).get('resources_removed') is True and registered.get(n,{}).get('output_eof') is True)
            if not d.get('dead'):
                drained=d.get('drained',{})
                e.check(n+':real PID1 DRAINED/ECHILD and monitor exit',drained.get('event')=='DRAINED'
                        and drained.get('nonce')==n and drained.get('echild') is True and d.get('monitor_wait')==0)
                actual=[x for x in logs if x.get('event')=='PID1_LOCAL_WAIT' and x.get('nonce')==n]
                e.check(n+':PID1 actually waited retained runtime',any(x.get('pid_local')==state.get('identity',{}).get('pid')
                        and x.get('wait_status')==0 for x in actual),actual)
    for row in rows:
        n=row['nonce'];dn=row.get('domain_nonce');d=ready.get(dn,{})
        e.check(n+':request distinct from bound domain identity',valid_nonce(dn) and dn!=n and bool(d))
        if mode=='G3':
            e.check(n+':local single fork, no invented external transition',row.get('s_state')=='NOT_APPLICABLE' and row.get('s_pid') is None
                    and row.get('zygote_pid')==d.get('runtime_host') and row.get('domain_scope')=='PERSISTENT_HELD')
        w=row.get('worker')
        if w:
            ident=w.get('identity',{})
            identity(e,ident,row.get('target_ns'),n+':business',{'0','1','2'})
            e.check(n+':19 actual boundary checks match fixed contract',set(w.get('checks',{}))==LOCAL_CHECKS and all(v is True for v in w.get('checks',{}).values()))
            e.check(n+':business marker/domain/attempt identity',w.get('nonce')==n and w.get('domain_nonce')==dn)
            expected_cg='0::/cdz/d-'+(n if mode=='G3' else dn)+('/business' if mode=='G3' else '/template')
            e.check(n+':actual cgroup resource attribution',ident.get('cgroup','').strip()==expected_cg,ident.get('cgroup'))
            if mode=='G4':
                e.check(n+':FD0 explicit private protocol, not generic untrusted input',str(ident.get('fds',{}).get('0','')).startswith('socket:'))
        if mode=='G3' and row.get('w_wait'):
            raw=row['w_wait'];actual=[x for x in logs if x.get('event')=='LOCAL_Z_ACTUAL_WAIT' and x.get('nonce')==n]
            e.check(n+':true Z wait backs request result',raw.get('source')=='LOCAL_Z_REAL_WAIT' and len(actual)==1
                    and actual[0].get('wait_status')==raw.get('wait_status') and actual[0].get('exit_code')==raw.get('exit_code'))
        if mode=='G3' and row.get('w_pid'):
            bound=[x for x in logs if x.get('event')=='LOCAL_WORKER_BIND' and x.get('nonce')==n]
            births=[x for x in logs if x.get('event')=='LOCAL_Z_ACTUAL_CLONE' and x.get('nonce')==n]
            e.check(n+':actual SCM host identity and atomic cgroup birth',len(bound)==len(births)==1
                    and bound[0].get('host_pid')==row['w_pid'] and bound[0].get('credentials')==[row['w_pid'],65534,65534]
                    and str(row['w_pid']) in bound[0].get('business_members',[])
                    and births[0].get('clone_into_cgroup') is True
                    and births[0].get('worker_local_pid')==bound[0].get('worker_local_pid')
                    and bound[0].get('parent_local')==d.get('ready',{}).get('identity',{}).get('pid'))
        post=row.get('template_after')
        if mode=='G3' and post:
            base=d.get('ready',{})
            e.check(n+':actual local template restored before reuse',post.get('nonce')==n and post.get('domain_nonce')==dn
                    and post.get('state_unchanged') is True and post.get('fingerprint')==base.get('fingerprint')
                    and post.get('snapshot')==base.get('snapshot') and post.get('active_requests')==0
                    and post.get('wait_echild') is True and row.get('zygote_wait_echild') is True)
            actual=[x for x in logs if x.get('event')=='LOCAL_Z_DESCENDANT_WAIT' and x.get('nonce')==n]
            for q in row.get('descendants_reaped',[]):
                e.check(n+':adopted descendant true wait:'+str(q.get('pid_local')),any(x.get('pid_local')==q.get('pid_local') and x.get('wait_status')==q.get('wait_status') for x in actual))
        if mode=='G4':
            e.check(n+':persistent Worker never invents request process wait',row.get('s_state')=='NOT_APPLICABLE'
                    and row.get('w_wait') is None and row.get('w_pid')==d.get('runtime_host'))
            binds=[x for x in logs if x.get('event')=='LOCAL_WORKER_BIND' and x.get('nonce')==n]
            if row.get('gated'):
                e.check(n+':persistent request actual existing Worker identity',len(binds)==1 and binds[0].get('reused') is True
                        and binds[0].get('host_pid')==row.get('w_pid') and binds[0].get('credentials')==[row.get('w_pid'),65534,65534]
                        and str(row.get('w_pid')) in binds[0].get('business_members',[]))
            if row.get('outcome') in ('SUCCEEDED','NONZERO_RETURN'):
                r=row.get('reset') or {};post=row.get('persistent_after') or {};ret=row.get('result') or {}
                e.check(n+':return code explicitly not process exit',ret.get('process_exit') is False
                        and ret.get('source')=='PERSISTENT_FUNCTION_RETURN' and 'exit_code' not in ret)
                e.check(n+':successful request retains real Worker and domain',row.get('resources')=='RETAINED_WORKER_AND_DOMAIN'
                        and row.get('resources_removed') is False and row.get('domain_empty') is False and row.get('w_state')=='RETAINED')
                e.check(n+':actual complete fixed-state reset before reusable ACK',r.get('process_before')==r.get('process_after')
                        and bool(r.get('process_before')) and r.get('own_state_unchanged') is True and r.get('wait_echild') is True
                        and r.get('numpy',{}).get('after')==r.get('numpy',{}).get('expected')
                        and r.get('numpy',{}).get('checks',{}).get('fixed_state_restored') is True
                        and post.get('reset')==r and post.get('sealed') is True and post.get('active_requests')==0
                        and post.get('worker_retained') is True and post.get('nonce')==n and post.get('domain_nonce')==dn)
                reset_records=[x for x in logs if x.get('event')=='PERSISTENT_RESET_CONFIRMED' and x.get('nonce')==n]
                e.check(n+':reset ACK backed by actual business-side record',any(x.get('reset')==r for x in reset_records))
            if row.get('resources')=='PENDING_FINAL_DOMAIN_WAIT':
                final=released.get(dn,{})
                e.check(n+':uncertain Worker retired and actually released only at domain endpoint',row.get('business')=='UNKNOWN'
                        and row.get('result') is None and final.get('dead') is True and final.get('resources')=='RELEASED'
                        and final.get('domain_empty') is True and final.get('output_eof') is True)
            if row.get('case') in ('cancel_queued','double_cancel') and row.get('response_committed'):
                late=row.get('late_cancel_rejected') or {}
                e.check(n+':forgotten attempt late cancel really rejected',late.get('event')=='STALE_REJECTED'
                        and late.get('nonce')==n and late.get('domain_nonce')==dn and late.get('forgotten') is True)
        local_runtime(e,row,logs,mode)
    return ready,released


def trace_evidence(e,rows,logs,sup,ready,mode,profile):
    if profile=='performance':
        config=e.json(e.run/'trace-config.json')
        e.check('formal samples not syscall/process traced',str(config.get('tracing_on','')).strip()=='0')
        return
    p=e.run/'process-trace.txt'
    if not p.is_file():e.check('actual qualification process trace',None);return
    e.record(p);text=p.read_text(errors='replace');stats=e.json(e.run/'trace-stats.json')
    e.check('trace CPU loss counters recorded',bool(stats))
    for cpu,raw in stats.items():
        counts=dict(re.findall(r'^(overrun|commit overrun|dropped events): (\d+)$',raw,re.M))
        e.check('no trace loss:'+cpu,len(counts)==3 and all(int(x)==0 for x in counts.values()))
    parents={};execs=collections.defaultdict(list);exits=set()
    for line in text.splitlines():
        if 'sched_process_fork:' in line:
            m=re.search(r' pid=(\d+) child_comm=.* child_pid=(\d+)',line)
            if m:
                e.check('no PID reuse ambiguity:'+m[2],int(m[2]) not in parents);parents[int(m[2])]=int(m[1])
        elif 'sched_process_exec:' in line:
            m=re.search(r'filename=(.*?) pid=(\d+)',line)
            if m:execs[int(m[2])].append(m[1])
        elif 'sched_process_exit:' in line:
            m=re.search(r' pid=(\d+)',line)
            if m:exits.add(int(m[1]))
    e.check('actual H→R parent relation',parents.get(sup.get('controller_pid'))==sup.get('pid'))
    for n,d in ready.items():
        pid=d.get('runtime_host')
        e.check(n+':actual PID1→local runtime and fixed D exec',parents.get(pid)==d.get('pid1_host')
                and execs.get(pid)==['/opt/shimos-glibc/lib/ld-linux-x86-64.so.2'])
    for r in rows:
        n=r['nonce'];w=r.get('w_pid')
        if mode=='G3' and w:
            e.check(n+':actual single local Z→W birth without Python exec',parents.get(w)==r.get('zygote_pid') and not execs.get(w))
        elif mode=='G2_REUSE' and w:
            e.check(n+':actual inherited Z→S→W birth without exec',parents.get(r.get('s_pid'))==r.get('zygote_pid')
                    and parents.get(w)==r.get('s_pid') and not execs.get(w) and not execs.get(r.get('s_pid')))
        if w and r.get('resources')=='RELEASED' and mode!='G4':e.check(n+':Worker actual kernel exit',w in exits)
    if mode=='G4':
        for n,d in ready.items():e.check(n+':persistent W actually exits at final domain release',d.get('runtime_host') in exits)


def numeric(e,rows,logs,package,token,level,mode,ready):
    ref=e.json(e.run/'numpy-reference.json');cmd=e.json(e.run/'numpy-reference-command.json');path=e.run/'numpy-reference.npz'
    e.check('independent fixed D cold reference',ref.get('event')=='NP_COLD_REFERENCE' and ref.get('numpy')=='2.2.6'
            and ref.get('rtol')==npcheck.RTOL and ref.get('atol')==npcheck.ATOL
            and cmd.get('argv',[None])[0]=='/opt/shimos-glibc/lib/ld-linux-x86-64.so.2' and cmd.get('performance_sample') is False)
    if path.is_file():e.record(path);e.check('cold raw oracle SHA',sha(path)==ref.get('sha256'))
    else:e.check('cold raw oracle retained',None)
    if token!='legacy':e.check('exact cold reference profile',ref.get('profile',{}).get('token')==token)
    results=old.unique([x for x in logs if x.get('event')=='NP_RESULT']);observed=[]
    e.check('one actual NumPy result per nonce',len(results)==len({x.get('nonce') for x in results}) and {x.get('nonce') for x in results}<={r['nonce'] for r in rows})
    for r in rows:
        n=r['nonce'];items=[x for x in results if x.get('nonce')==n];v=items[0] if len(items)==1 else None
        ob={'nonce':n,'case':r.get('case'),'numeric_status':'NOT_OBSERVED'}
        if r.get('business')=='NOT_EXECUTED':
            e.check(n+':unexecuted really has no numeric result',not items and not r.get('worker') and not r.get('numpy_output'))
            ob['numeric_status']='NOT_EXECUTED'
        elif r.get('case') in NORMAL:e.check(n+':normal numerical task actually observed',True if v else None)
        if not v:observed.append(ob);continue
        before,after=v.get('before',{}),v.get('after',{})
        for label,snap in [('before',before),('after',after)]:
            npcheck.snapshot_check(e,snap,n+':numpy:'+label,package,audit_required=False)
            e.check(n+':NumPy final strict security:'+label,zero(snap.get('security',{}).get('capabilities',{}).get('CapBnd'))
                    and snap.get('security',{}).get('seccomp')==2 and set(snap.get('fds',{}))=={'0','1','2'}
                    and snap.get('environment')=={'PATH':'/usr/bin:/bin'})
        npcheck.pair_state_check(e,before,after,n+':NumPy runtime')
        expected={'numerical','single_thread','fds_restored','signals_unchanged','env_unchanged','inherited','expected_failure'}
        if token!='legacy':expected|={'profile_binding','data_readonly_after'}
        e.check(n+':complete actual NumPy assertions',set(v.get('checks',{}))==expected and all(x is True for x in v.get('checks',{}).values()))
        if token!='legacy':
            e.check(n+':same profile and final task regardless preload',v.get('profile')==ref.get('profile')
                    and v.get('level')==level and v.get('completed_level')=='blas')
            if mode in ('G2_REUSE','G2','G3'):
                e.check(n+':actual staged inherited state',v.get('reuse_model')=='fork' and v.get('inherited_template_state') is True
                        and v.get('inherited_numpy')==(level!='base') and v.get('inherited_data')==(level in ('data','blas'))
                        and v.get('template_level')==level)
            elif mode=='G4':
                e.check(n+':persistent state not misrepresented as fork',v.get('reuse_model')=='persistent'
                        and v.get('inherited_template_state') is False and v.get('inherited_numpy') is False
                        and v.get('inherited_data') is False)
            else:e.check(n+':cold work not misrepresented as inherited',v.get('reuse_model')=='cold'
                    and v.get('inherited_template_state') is False and v.get('inherited_numpy') is False and v.get('inherited_data') is False)
        else:
            e.check(n+':legacy fixed inherited initialization',v.get('level')==level
                    and v.get('baseline')==('cold' if mode in ('G0','G1') else 'hot')
                    and (mode=='G4' or v.get('inherited_preload')==(mode not in ('G0','G1'))))
        output=r.get('numpy_output',{})
        if output.get('file') and path.is_file():
            try:
                actual=npcheck.within_run(e.run,output['file']);e.record(actual);comparison=npcheck.compare_npz(actual,path)
                e.check(n+':actual numerical raw result SHA',sha(actual)==output.get('sha256')==v.get('output_sha256'))
                e.check(n+':entire output independently decoded/allclose',comparison['passed'],comparison)
                e.check(n+':same reference actually used',v.get('reference_sha256')==sha(path))
                ob['numeric_status']='PASS' if comparison['passed'] else 'FAIL'
            except (OSError,ValueError) as error:e.check(n+':raw result readable',False,repr(error))
        elif r.get('case') in NORMAL:e.check(n+':normal raw numeric output retained',None)
        else:ob['numeric_status']='UNKNOWN_RAW_OUTPUT_NOT_PRESERVED'
        if mode=='G4' and r.get('outcome') in ('SUCCEEDED','NONZERO_RETURN'):
            resets=old.unique([x for x in logs if x.get('event')=='NP_RESET' and x.get('nonce')==n])
            e.check(n+':persistent NumPy state actually reset',len(resets)==1 and resets[0].get('after')==resets[0].get('expected')==v.get('initial_fingerprint')
                    and resets[0].get('checks',{}).get('fixed_state_restored') is True)
        observed.append(ob)
    return observed


def g2_reuse(e,rows,logs,summary,registered):
    ds=e.json(e.run/'persistent-domains.json',optional=True)
    if summary:e.check('persistent domain inventory present',True if isinstance(ds,list) and ds else None)
    ds={x.get('nonce'):x for x in ds} if isinstance(ds,list) else {}
    if summary:e.check('all retained domains released at session boundary',set(ds)==domains(rows))
    for n,d in ds.items():
        e.check(n+':whole-domain final EOF/release',d.get('output_eof') is True and d.get('resources_removed') is True
                and d.get('output_channel_role')=='real monitor/PID1 output' and 'populated 0' in d.get('stats',{}).get('cgroup.events',''))
        e.check(n+':H domain cleanup retired',registered.get(n,{}).get('retired') is True and registered.get(n,{}).get('output_eof') is True)
    for r in rows:
        n=r['nonce'];dn=r.get('persistent_domain_nonce')
        e.check(n+':request and domain release scopes separated',r.get('release_scope')=='REQUEST_GROUP' and valid_nonce(dn) and dn!=n)
        old.worker_boundary(e,r,'G2')
        if r.get('domain_retained'):
            qs=[x for x in logs if x.get('event')=='QUIESCENT' and x.get('nonce')==n]
            e.check(n+':real surviving PID1 quiescence after request',len(qs)==1 and qs[0].get('echild') is True)
        if r.get('worker'):
            e.check(n+':inherited template identity',r['worker'].get('inherited')==r.get('expected_state'))
        waited=r.get('w_wait')
        if waited:
            if waited.get('event')=='ADOPTED_WORKER_WAIT':
                actual=[x for x in logs if x.get('event')=='CONTROLLER_WAIT' and x.get('pid')==r.get('w_pid')]
            else:actual=[x for x in logs if x.get('nonce')==n and x.get('event')=='ACTUAL_WORKER_WAIT']
            e.check(n+':actual permitted waiter backs Worker status',any(x.get('wait_status')==waited.get('wait_status') for x in actual),actual)
        elif r.get('response_committed') and r.get('worker'):
            e.check(n+':lost result remains explicitly unknown after scoped reclaim',r.get('business')=='UNKNOWN'
                    and r.get('result') is None and r.get('w_state')=='RECLAIMED_STATUS_UNKNOWN'
                    and r.get('s_state')=='REAPED' and r.get('output_eof') is True and r.get('domain_empty') is True)
        if r.get('s_wait') is not None:
            actual=[x for x in logs if (x.get('event')=='ACTUAL_TRANSITION_WAIT' and x.get('nonce')==n)
                    or (x.get('event')=='CONTROLLER_WAIT' and x.get('pid')==r.get('s_pid'))]
            e.check(n+':actual permitted waiter backs S status',any(x.get('wait_status')==r['s_wait'] for x in actual),actual)
        post=r.get('zygote_post')
        if post:e.check(n+':external template checks retained',post.get('nonce')==n and post.get('state_unchanged') is True
                and post.get('active_attempts')==0 and set(post.get('identity',{}).get('fds',{}))=={'0','1','2','3'})


def fault_evidence(e,rows,logs,mode):
    for r in rows:
        n=r['nonce'];case=r.get('case');own=[x for x in logs if x.get('nonce')==n]
        if case in NORMAL:
            if r.get('response_committed'):e.check(n+':known normal/nonzero business result',r.get('business')=='KNOWN'
                    and r.get('outcome')==(('NONZERO_RETURN' if mode=='G4' else 'NONZERO') if case=='nonzero' else 'SUCCEEDED')
                    and (r.get('result') or {}).get('exit_code',(r.get('result') or {}).get('return_code'))==(7 if case=='nonzero' else 0))
        elif case in ('cancel_queued','cancel_before_business','double_cancel'):
            if case!='double_cancel' or mode!='G2_REUSE':
                e.check(n+':cancel before business did not execute',r.get('business')=='NOT_EXECUTED'
                        and r.get('business_permit') is False and r.get('side_effect') is None and not r.get('worker'))
            else:e.check(n+':cross-domain repeated cancel actual postbusiness scope',r.get('business_permit') is True
                    and r.get('outcome')=='CANCELLED')
            if case=='double_cancel':
                messages=r.get('events',[])
                acks=[x for x in messages if x.get('event')=='CANCEL_ACK']
                extra=r.get('terminal_duplicate_ack')
                e.check(n+':duplicate seal actual acknowledgements',len(acks)>=2 or (extra or {}).get('sealed') is True,
                        {'acks':len(acks),'terminal':extra})
            if case=='cancel_queued':e.check(n+':late actual start refused',r.get('late_commit_rejected') is True or r.get('late_start_rejected') is True)
        elif case in ('pid_budget','second_budget'):
            e.check(n+':real budget rejection definitely unexecuted',r.get('business')=='NOT_EXECUTED' and r.get('business_permit') is False
                    and r.get('outcome')=='RESOURCE_REJECTED' and not r.get('worker') and r.get('side_effect') is None
                    and (r.get('worker_errno')==11 or r.get('spawn_errno')==11 or r.get('transition_errno')==11))
        elif case=='timeout':e.check(n+':timeout after actual business, not a silent success',bool(r.get('worker')) and r.get('outcome') in ('TIMED_OUT','TIMEOUT'))
        elif case=='result_loss_side_effect':e.check(n+':real effect with lost result remains UNKNOWN',r.get('side_effect')=='2650100'
                and r.get('business')=='UNKNOWN' and r.get('result') is None and r.get('outcome')=='RESULT_UNKNOWN')
        elif case in ('reset_failure','fd_leak'):
            e.check(n+':persistent corruption rejected, not reusable success',r.get('outcome') not in ('SUCCEEDED','NONZERO')
                    and r.get('result') is None and r.get('business')=='UNKNOWN')
        if case not in NORMAL and r.get('response_committed'):e.check(n+':failure never emits successful response',r.get('outcome') not in ('SUCCEEDED','NONZERO'))


def analyze(name,profile,review):
    run=(S/'runs'/name).resolve(strict=True);run.relative_to((S/'runs').resolve())
    e=Evidence(run);config=e.json(run/'review-config.json');manifest=e.json(run/'variant-manifest.json');full=e.json(run/'full-session.json')
    mode,env,token,level,case,desc=configurations(e,config,manifest,full)
    reviewed,sources,binaries=source_binding(e,manifest,config,full,mode,review,profile)
    result=e.json(run/'result.json');execution=e.json(run/'session-execution.json');sup=e.json(run/'supervisor.json')
    ext=e.json(run/'external-final-release.json');summary=e.json(run/'summary.json',optional=True)
    e.check('actual VM session completed without observer rescue',result.get('complete') is True and result.get('timeout') is False
            and result.get('qemu_rc')==0 and execution.get('complete') is True and execution.get('observer_cleanup_performed') is False)
    rows=load_rows(e)
    e.check('actual request inventory nonempty unique',bool(rows) and all(valid_nonce(r.get('nonce')) for r in rows)
            and len({r['nonce'] for r in rows})==len(rows))
    caseplan=e.json(run/'local-case-plan.json',optional=True)
    if caseplan:
        batches=caseplan.get('batches',caseplan.get('domains',[]))
        if isinstance(batches,list) and all(isinstance(x,list) for x in batches):expected=[c for b in batches for c in b]
        else:expected=caseplan.get('cases')
        e.check('explicit local domain case plan matches actual attempts',expected==[r.get('case') for r in rows],caseplan)
    elif case=='performance':
        e.check('exact intended complete sequence, not successful prefix',len(rows)==full.get('requests')
                and all(r.get('case')=='normal' and r.get('outcome')=='SUCCEEDED' for r in rows))
    else:
        suites={'control':['normal','normal','nonzero'],'budgets':['second_budget','normal'],
                'cancels':['cancel_queued','cancel_before_business','double_cancel','timeout','normal'],
                'receipts':['created_drop','reaped_drop','result_loss_side_effect','normal']}
        expected=suites.get(case,case.split(','))
        e.check('intended qualification cases actually reached',[r.get('case') for r in rows]==expected)
    logs=e.records(sorted(set(list(run.glob('*.log'))+[run/'events.jsonl',run/'supervisor-events.jsonl'])))
    registered=session_release(e,rows,sup,ext,summary,logs,full,mode)
    ready={}
    if mode in ('G3','G4'):ready,_=local_domain_evidence(e,rows,logs,summary,mode,registered)
    elif mode=='G2_REUSE':g2_reuse(e,rows,logs,summary,registered)
    else:e.check('fresh mechanisms must be independently handled before admission',None,mode)
    fault_evidence(e,rows,logs,mode);trace_evidence(e,rows,logs,sup,ready,mode,profile)
    package,_=npcheck.package_evidence(e)
    observed=numeric(e,rows,logs,package,token,level,mode,ready)
    failures=[x for x in e.checks if x['value'] is False];missing=[x for x in e.checks if x['value'] is None]
    mechanism=[x for x in e.checks if x.get('section')!='source_admission']
    def status(checks):return 'FAIL' if any(x['value'] is False for x in checks) else 'BLOCKED' if any(x['value'] is None for x in checks) else 'PASS'
    return dict(run=name,status=status(e.checks),mechanism_observations_status=status(mechanism),verification_profile=profile,
        mode=mode,full_profile=token,level=level,cases=[r.get('case') for r in rows],attempts=len(rows),domains=len(domains(rows)-{None}),
        source_sha256=sources,binary_sha256=binaries,numeric=observed,checks=e.checks,failed=failures,missing=missing,
        verifier_sha256=sha(Path(__file__)),dependency_verifier_sha256={Path(m.__file__).name:sha(Path(m.__file__)) for m in (npcheck,rp,old)},
        evidence_sha256_study_relative=e.evidence,
        scope=['Fixed trusted single-thread NumPy CPU task; no generic state reset',
          'H alive/trusted R/private ordinary directories; no stronger H-failure claim',
          'Per-request release is not persistent-domain release; G4 function return is not process exit',
          'Native NumPy callbacks audit0 NOT_OBSERVED; runtime probe callbacks checked when applicable'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run');p.add_argument('--profile',choices=('qualification','performance'),default='qualification')
    p.add_argument('--source-review',help='explicit post-run exact source review; never changes frozen manifest')
    p.add_argument('--out',required=True,help='new study-relative JSON, exclusive create')
    a=p.parse_args()
    try:r=analyze(a.run,a.profile,a.source_review)
    except Exception as error:r=dict(run=a.run,status='BLOCKED',verifier_error=repr(error),traceback=traceback.format_exc(),verifier_sha256=sha(Path(__file__)))
    out=Path(a.out)
    if not out.is_absolute():out=S/out
    out.resolve().relative_to(S.resolve());out.parent.mkdir(parents=True,exist_ok=True)
    with out.open('x') as f:json.dump(r,f,indent=2,ensure_ascii=False);f.write('\n')
    print(json.dumps({'run':a.run,'status':r['status'],'mechanism':r.get('mechanism_observations_status'),
        'checks':len(r.get('checks',[])),'failed':len(r.get('failed',[])),'missing':len(r.get('missing',[])),'output':str(out)}))
    return 0 if r['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
