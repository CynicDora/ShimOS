#!/usr/bin/env python3
"""Independent fixed-profile, one-slot cache observation/admission.

No VM execution or product cleanup. A cache miss here is exact-key policy,
not proof of incompatible dependencies or of optimal placement.
"""
import argparse
import json
import traceback
from pathlib import Path
import verify_full_mechanism as fullcheck
import verify_round1 as old
import verify_numpy as npcheck

S=Path(__file__).resolve().parent.parent
sha=npcheck.sha

def overall(checks):
    return 'FAIL' if any(x['value'] is False for x in checks) else 'BLOCKED' if any(x['value'] is None for x in checks) else 'PASS'

def analyze(name,profile,review):
    run=(S/'runs'/name).resolve(strict=True);run.relative_to((S/'runs').resolve())
    e=fullcheck.Evidence(run)
    config=e.json(run/'review-config.json');manifest=e.json(run/'variant-manifest.json');actual=e.json(run/'full-session.json')
    env=actual.get('extra_env',{});mode=env.get('FULL_MODE')
    e.check('explicit mixed one-slot mechanism',mode=='G2_MIXED' and actual.get('architecture_group')==config.get('architecture_group')==manifest.get('architecture_group')=='G2')
    e.check('actual full configuration immutable',actual.get('configuration',{}).get('env')==env
            and actual.get('configuration',{}).get('requests')==actual.get('requests'))
    e.check('fixed low diagnostics hot template single-thread inputs',config.get('variant')==config.get('diagnostics')==manifest.get('variant')=='low'
            and config.get('numpy_baseline')==manifest.get('numpy_baseline')=='hot'
            and config.get('numpy_thread_environment')==npcheck.THREAD_ENV and int(env.get('COST_WARMUP','0'))==0)
    _,sources,binaries=fullcheck.source_binding(e,manifest,config,actual,mode,review,profile)
    result=e.json(run/'result.json');execution=e.json(run/'session-execution.json')
    sup=e.json(run/'supervisor.json');ext=e.json(run/'external-final-release.json');summary=e.json(run/'summary.json',optional=True)
    e.check('actual collector and session completed without observer cleanup',result.get('complete') is True and result.get('timeout') is False
            and result.get('qemu_rc')==0 and execution.get('complete') is True and execution.get('observer_cleanup_performed') is False)
    rows=fullcheck.load_rows(e)
    e.check('complete actual finite request sequence',len(rows)==actual.get('requests') and bool(rows)
            and len({x.get('nonce') for x in rows})==len(rows)
            and all(fullcheck.valid_nonce(x.get('nonce')) and x.get('case')=='normal' and x.get('outcome')=='SUCCEEDED' for x in rows))
    logs=e.records(sorted(set(list(run.glob('*.log'))+[run/'events.jsonl',run/'supervisor-events.jsonl'])))
    old.common_release(e,rows,sup,ext,summary,logs,config)
    plan=e.json(run/'mixed-case-plan.json');ledger=e.json(run/'mixed-cache-ledger.json');references=e.json(run/'mixed-reference-manifest.json')
    sequence=plan.get('sequence',[]);profiles=plan.get('profiles',[]);entries=ledger.get('requests',[])
    if sources.get('run_mixed.py')=='76276e483ff4a59fb67f1a3012f278db44e6139e3a6c4ffe1223b43e9490a553':
        directories=references.get('fixture_directory_checks',[])
        parent='/state/cross-domain/src/mixed-templates'
        expected_paths=[parent,parent+'/p0',parent+'/p1']
        e.check('fixture repair records exact three private directories',len(directories)==3
                and [x.get('path') for x in directories]==expected_paths
                and all(isinstance(x.get('dev'),int) and x['dev']>=0 and isinstance(x.get('inode'),int) and x['inode']>0
                        and x.get('owner_before') in (0,65534) for x in directories))
        e.check('fixture repair never reuses previous oracle results or cleans product',references.get('oracle_recomputed_each_session') is True
                and references.get('oracle_file_umask')=='0022' and references.get('product_resource_cleanup') is False)
        first=actual.get('index')==0
        e.check('actual first preparation or later checked fixture reentry',all(x.get('existed') is (not first) for x in directories)
                and all(x.get('members_before')==([] if first else (['p0','p1'] if i==0 else ['input','numpy-reference.json','numpy-reference.npz']))
                        for i,x in enumerate(directories)))
        hstarted=[x for x in logs if x.get('event')=='SUPERVISOR_STARTED']
        e.check('one actual H start anchors pre-session oracle preparation',len(hstarted)==1)
        for i in range(2):
            raw=e.records([run/f'mixed-reference-{i}.log'])
            cold=old.unique([x for x in raw if x.get('event')=='NP_COLD_REFERENCE'])
            meta=e.json(run/f'mixed-reference-{i}-numpy-reference.json')
            sec=meta.get('snapshot',{}).get('security',{})
            e.check('profile '+str(i)+':oracle output independently matches this session metadata',len(cold)==1
                    and old.clean(cold[0])==meta)
            e.check('profile '+str(i)+':actual fresh low-privilege oracle before H starts',
                    len(hstarted)==1 and 0<meta.get('started_ns',0)<=meta.get('finished_ns',-1)
                    <=meta.get('snapshot',{}).get('monotonic_ns',-2)<hstarted[0].get('monotonic_ns',-3)
                    and sec.get('uid')==sec.get('euid')==sec.get('gid')==sec.get('egid')==65534 and sec.get('nnp')==1
                    and fullcheck.zero(sec.get('capabilities',{}).get('CapEff'))
                    and fullcheck.zero(sec.get('capabilities',{}).get('CapPrm')))
    e.check('actual one-slot plan and request count',plan.get('mode')=='G2_MIXED' and plan.get('capacity')==ledger.get('capacity')==ledger.get('simultaneous_templates')==1
            and len(sequence)==len(rows)==len(entries) and set(sequence)=={0,1}
            and len(profiles)==2 and profiles[0].get('token')!=profiles[1].get('token'))
    business=[{k:v for k,v in p.items() if k not in ('token','preload')} for p in profiles]
    e.check('two profiles have exactly same final business semantics',len(business)==2 and business[0]==business[1])
    configured=json.loads(env.get('FULL_MIX_PROFILES_JSON','["v1:import:8:readonly:light","v1:blas:8:readonly:light"]'))
    e.check('actual profiles equal declared fixed keys',[p.get('token') for p in profiles]==configured)
    pattern=env.get('FULL_MIX_PATTERN','alternating');n=actual.get('requests',0)
    if env.get('FULL_MIX_SEQUENCE_JSON'):expected=json.loads(env['FULL_MIX_SEQUENCE_JSON']);pattern='explicit'
    elif pattern=='grouped':expected=[0]*((n+1)//2)+[1]*(n//2)
    elif pattern=='alternating':expected=[i%2 for i in range(n)]
    elif pattern=='skewed':expected=[1 if i%8==7 else 0 for i in range(n)]
    else:expected=None
    e.check('actual sequence equals declared pattern',sequence==expected and plan.get('pattern')==pattern)
    hits=sum(i>0 and sequence[i-1]==p for i,p in enumerate(sequence));misses=len(sequence)-hits
    e.check('cache arithmetic exact; not a predicted observed result',ledger.get('hits')==summary.get('cache_hits')==hits
            and ledger.get('misses')==summary.get('cache_misses')==ledger.get('initialized_templates')==misses
            and ledger.get('final_template_removed') is True and summary.get('execution_mode')==mode and summary.get('cache_capacity')==1)
    ready=sorted(old.unique([x for x in logs if x.get('event')=='ZYGOTE_READY']),key=lambda x:x.get('monotonic_ns',0))
    stops=old.unique([x for x in logs if x.get('event')=='ZYGOTE_STOP'])
    waits=old.unique([x for x in logs if x.get('event')=='CONTROLLER_WAIT'])
    e.check('one actual template initialization and stop per miss',len(ready)==len(stops)==misses)
    e.check('each clean template has distinct inherited object identity in one session',
            len({json.dumps(x.get('state'),sort_keys=True) for x in ready})==len(ready)
            and len({x.get('session') for x in ready})==1 and all(x.get('threads')==1 for x in ready))
    package,_=npcheck.package_evidence(e)
    numeric=[];active_ready=None;miss_index=-1
    for index,row in enumerate(rows):
        nonce=row['nonce'];record=entries[index] if index<len(entries) else {};wanted=sequence[index] if index<len(sequence) else None
        item=row.get('mixed_template_cache',{})
        hit=index>0 and wanted==sequence[index-1]
        e.check(nonce+':same actual per-request cache record',item==record and record.get('index')==index and record.get('nonce')==nonce
                and record.get('profile_index')==wanted and record.get('profile')==(profiles[wanted] if wanted in (0,1) else None)
                and record.get('hit')==hit and record.get('includes_eviction_and_initialization')==(not hit)
                and record.get('capacity')==1 and record.get('current_pid')==row.get('zygote_pid'))
        if not hit:
            miss_index+=1;new_ready=ready[miss_index] if miss_index<len(ready) else {}
            e.check(nonce+':miss pays actual creation before request completion',record.get('start_ns',0)<=new_ready.get('monotonic_ns',-1)<=record.get('complete_ns',-2)
                    and new_ready.get('identity',{}).get('pid')==record.get('current_pid'))
            if active_ready:
                prev=active_ready.get('identity',{}).get('pid')
                e.check(nonce+':prior template truly waited before replacement ready',any(x.get('pid')==prev and x.get('wait_status')==0
                        and record.get('start_ns',0)<=x.get('monotonic_ns',-1)<new_ready.get('monotonic_ns',-2) for x in waits))
            active_ready=new_ready
        else:
            e.check(nonce+':hit retains actual previous live template',record.get('previous_pid')==record.get('current_pid')
                    and active_ready is not None and active_ready.get('identity',{}).get('pid')==record.get('current_pid'))
        old.worker_boundary(e,row,'G2')
        rd=row.get('domain_ready_record',{})
        e.check(nonce+':own fresh target references validated',row.get('fd_metadata_validated') is True and rd.get('event')=='DOMAIN_READY'
                and rd.get('nonce')==nonce and rd.get('pid')==1 and rd.get('uid')==65534)
        e.check(nonce+':exact chosen inherited state',bool(active_ready) and row.get('expected_state')==active_ready.get('state')
                and (row.get('worker') or {}).get('inherited')==row.get('expected_state'))
        old.perfcheck.runtime_request(row,[old.clean(x) for x in old.unique(logs)],'low',str(config.get('timing','1')),e.check)
        post=row.get('zygote_post',{})
        e.check(nonce+':same strict per-request template check',post.get('event')=='PONG' and post.get('state_unchanged') is True
                and post.get('nonce')==nonce and post.get('session')==(active_ready or {}).get('session') and post.get('active_attempts')==0
                and set(post.get('identity',{}).get('fds',{}))==set((active_ready or {}).get('identity',{}).get('fds',{})))
        argv=row.get('argv',[]);source=record.get('source')
        e.check(nonce+':target uses correct immutable profile oracle',source=='/state/cross-domain/src/mixed-templates/p'+str(wanted)
                and any(argv[i:i+3]==['--ro-bind',source,'/src'] for i in range(max(0,len(argv)-2))))
    for i,definition in enumerate(profiles):
        matching=[x for x in references.get('profiles',[]) if x.get('index')==i]
        e.check('profile '+str(i)+':independent reference manifest',len(matching)==1 and references.get('numerical_task_same') is True
                and references.get('privileged_numpy_import') is False and references.get('performance_sample') is False)
        if not matching:continue
        ref=matching[0];metadata=e.json(run/f'mixed-reference-{i}-numpy-reference.json')
        e.check('profile '+str(i)+':actual cold oracle at final low privilege',ref.get('uid')==65534 and ref.get('nnp')==1
                and ref.get('profile')==definition and ref.get('metadata')==metadata and ref.get('reference_sha256')==metadata.get('sha256'))
        subset=[r for r in rows if r.get('mixed_template_cache',{}).get('profile_index')==i];nonces={r['nonce'] for r in subset}
        subsetlogs=[x for x in logs if x.get('event')!='NP_RESULT' or x.get('nonce') in nonces]
        numeric += fullcheck.numeric(e,subset,subsetlogs,package,definition['token'],definition['preload'],'G2',{},
            reference={'metadata':metadata,'command':{'argv':ref.get('argv',[]),'performance_sample':False},'npz':f'mixed-reference-{i}-numpy-reference.npz'})
    if profile=='boundary':
        trace=e.json(run/'trace-config.json');e.check('kernel trace explicitly not observed',str(config.get('trace'))=='0' and str(trace.get('tracing_on','')).strip()=='0')
    else:old.actual_trace(e,config,rows,sup,'G2',profile)
    for r in ready:
        pid=r.get('identity',{}).get('pid')
        e.check('template '+str(pid)+':actual terminal STOP and true wait',any(x.get('state')==r.get('state') and x.get('state_unchanged') is True for x in stops)
                and any(x.get('pid')==pid and x.get('wait_status')==0 for x in waits))
    return dict(run=name,status=overall(e.checks),verification_profile=profile,mode=mode,attempts=len(rows),pattern=pattern,
        hits=hits,misses=misses,numeric=numeric,checks=e.checks,failed=[x for x in e.checks if x['value'] is False],missing=[x for x in e.checks if x['value'] is None],
        verifier_sha256=sha(Path(__file__)),dependency_verifier_sha256={Path(m.__file__).name:sha(Path(m.__file__)) for m in (fullcheck,npcheck,old)},
        source_sha256=sources,binary_sha256=binaries,evidence_sha256_study_relative=e.evidence,
        scope=['Fixed exact-key one-slot sensitivity; not incompatible-dependency proof or adaptive scheduling',
               'Two independent fixed-profile numerical oracles; miss includes STOP/wait/new initialization',
               'H must survive; every request and final template physically released before full-session completion'])

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run');p.add_argument('--profile',choices=('qualification','boundary','performance'),default='qualification')
    p.add_argument('--source-review');p.add_argument('--out',required=True);a=p.parse_args()
    try:value=analyze(a.run,a.profile,a.source_review)
    except Exception as error:value=dict(run=a.run,status='BLOCKED',verifier_error=repr(error),traceback=traceback.format_exc(),verifier_sha256=sha(Path(__file__)))
    out=Path(a.out);out=out if out.is_absolute() else S/out;out.resolve().relative_to(S.resolve());out.parent.mkdir(parents=True,exist_ok=True)
    with out.open('x') as f:json.dump(value,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(dict(run=a.run,status=value['status'],failed=len(value.get('failed',[])),missing=len(value.get('missing',[])),out=str(out))))
    return 0 if value['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
