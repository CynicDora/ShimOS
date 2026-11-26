#!/usr/bin/env python3
"""Read-only common ledger; qualification is a separate operation."""
import argparse,csv,json,statistics
from pathlib import Path
from analyze_resource_sampler import analyze_resources

ANALYSIS_SCHEMA='full-ledger-v2-call-commit-domain-role'
CONCURRENT_MODES=('G2_CONCURRENT','G3_CONCURRENT')

def elapsed(a,b):
    # Negative or missing observations are not a duration and never become 0.
    return (b-a)/1e9 if type(a) is int and type(b) is int and 0<a<=b else None

def one_point(events,issues,label):
    values={e.get('ns') for e in events if type(e.get('ns')) is int and e['ns']>0
            and e.get('clock')=='CLOCK_MONOTONIC'}
    if len(values)==1:return next(iter(values))
    issues.append(dict(problem='MISSING_POINT' if not values else 'AMBIGUOUS_POINT',point=label,values=sorted(values)))
    return None

def observed_domains(summary,journals,costs):
    """IDs from received domain records; never multiply declared D/K into facts."""
    ids=set();sources=set()
    for r in summary.get('domains',summary.get('persistent_domains',[])) or []:
        n=r.get('domain_nonce') or r.get('nonce')
        if n:ids.add(n);sources.add('summary_domain_records')
    for r in journals.values():
        n=r.get('domain_nonce') or r.get('persistent_domain_nonce') or r.get('domain_ready_record',{}).get('nonce')
        if n:ids.add(n);sources.add('attempt_domain_identity')
    for e in costs:
        if e.get('name')=='domain_fd_received':n=e.get('pid1_record',{}).get('nonce')
        elif e.get('name')=='retained_domain_ready':n=e.get('domain_nonce')
        elif e.get('name')=='persistent_domain_ready':n=e.get('nonce')
        else:continue
        if n:ids.add(n);sources.add('COST_domain_ready')
    return dict(ids=sorted(ids),count=len(ids) if ids else None,sources=sorted(sources),
                scope='observed target-domain identities; partial failure data is a lower bound, not configured D')

def request_timing(costs,nonce,record,index,mode):
    """Keep call, resources, logical commit and post-journal ready distinct.

    Serial numpy_call_begin may carry the PREVIOUS request's context nonce.
    Its explicit call_index is the correct binding; never use stale nonce alone.
    """
    issues=[];own=[e for e in costs if e.get('nonce')==nonce and e.get('role')=='R']
    starts=[e for e in own if e.get('name') in ('request_begin','local_request_begin')]
    request=one_point(starts,issues,'request_begin')
    repeats={e.get('repeat') for e in starts if type(e.get('repeat')) is int}
    if len(repeats)==1:
        observed_index=next(iter(repeats))
        if index is not None and index!=observed_index:
            issues.append(dict(problem='SUMMARY_VS_OBSERVED_INDEX_MISMATCH',summary=index,observed=observed_index))
        index=observed_index
    elif len(repeats)>1:
        issues.append(dict(problem='AMBIGUOUS_REQUEST_INDEX',values=sorted(repeats)));index=None
    call_events=[e for e in costs if e.get('role')=='R' and e.get('name')=='numpy_call_begin'
                 and index is not None and e.get('call_index')==index]
    complete_events=[e for e in costs if e.get('role')=='R' and e.get('name')=='numpy_call_complete'
                     and index is not None and e.get('call_index')==index]
    if mode in CONCURRENT_MODES:
        # This path binds nonce before its call boundary. Require that fact.
        wrong=[e for e in call_events+complete_events if e.get('nonce')!=nonce]
        if wrong:issues.append(dict(problem='CONCURRENT_CALL_NONCE_MISMATCH',count=len(wrong)))
        call_events=[e for e in call_events if e.get('nonce')==nonce]
        complete_events=[e for e in complete_events if e.get('nonce')==nonce]
    call=one_point(call_events,issues,'numpy_call_begin')
    complete=one_point(complete_events,issues,'numpy_call_complete')
    ready=one_point([e for e in own if e.get('name')=='response_ready'],issues,'response_ready')
    # A local/request_complete event or cgroup release is NOT a response ACK.
    committed=record.get('response_committed') is True
    commit=record.get('response_commit_ns') if committed else None
    resource=record.get('execution_resources_complete_ns')
    if type(commit) is not int or commit<=0:commit=None
    if type(resource) is not int or resource<=0:resource=None
    if ready is not None and not committed:
        issues.append(dict(problem='READY_EVENT_WITHOUT_COMMITTED_RESPONSE'));ready=None
    if mode in CONCURRENT_MODES and committed and commit is None:
        issues.append(dict(problem='CONCURRENT_COMMIT_TIMESTAMP_NOT_OBSERVED'))
    points=[(k,v) for k,v in [('call',call),('request',request),('resource',resource),('commit',commit),('ready',ready),('call_complete',complete)] if v is not None]
    monotonic=all(a[1]<=b[1] for a,b in zip(points,points[1:]))
    if not monotonic:issues.append(dict(problem='REQUEST_BOUNDARY_ORDER_INVALID',points=points))
    def duration(a,b):return elapsed(a,b) if monotonic else None
    if mode in ('G3','G4','G2_REUSE'):
        scope='call starts inside already prepared persistent domain; domain/template setup and final teardown charged in full_s'
        domain_in_call=False
    elif mode=='G3_CONCURRENT':
        scope='call includes fresh domain/local-template preparation and final sequence integrity wait'
        domain_in_call=True
    elif mode=='G2_CONCURRENT':
        scope='call includes fresh domain and final sequence integrity wait; external Z setup/stop charged in full_s'
        domain_in_call=True
    elif mode=='G2_MIXED':
        scope='call includes cache hit or actual eviction/initialization plus fresh domain; final template stop charged in full_s'
        domain_in_call=True
    else:
        scope='call includes fresh domain and any Z startup on this call; call_complete additionally includes cold-Z stop when applicable'
        domain_in_call=True
    return dict(call_index=index,call_begin_ns=call,request_begin_ns=request,
      execution_resources_complete_ns=resource,response_commit_ns=commit,response_ready_event_ns=ready,
      call_complete_ns=complete,response_committed=committed,call_scope=scope,domain_setup_in_call=domain_in_call,
      response_s=duration(call,ready),begin_ns=call,end_ns=ready,
      response_boundary='numpy_call_begin -> response_ready COST after result journaling; missing never replaced by resource completion',
      call_to_response_ready_s=duration(call,ready),call_to_response_commit_s=duration(call,commit),
      call_to_resources_complete_s=duration(call,resource),resources_to_commit_s=duration(resource,commit),
      commit_to_ready_event_s=duration(commit,ready),request_setup_to_ready_s=duration(request,ready),
      call_to_request_s=duration(call,request),call_complete_s=duration(call,complete),
      timing_issues=issues)

def explain_resource_roles(resources,base):
    """Interpret copied sampler's fixed cgroup-leaf labels without changing raw data."""
    group=base.get('group')
    for name in ('resource_processes','resource_role_summary','resource_role_growth'):
        for row in resources.get(name,[]):
            observed=row.get('role');row['role_observed']=observed
            if group=='G4' and observed=='Z':
                row['role']='W_PERSISTENT'
                row['role_interpretation']='G4 template cgroup contains the retained application Worker; not a fork template Z'
            elif group=='G4' and observed=='W':
                row['role']='W_PER_REQUEST'
                row['role_interpretation']='G4 has no separate per-request W; persistent process is W_PERSISTENT'
                if row.get('valid_sample_count')==0:row['status']='NOT_APPLICABLE'
            else:
                row['role_interpretation']='sampler owned-cgroup leaf role; DOMAIN_CONTROL combines bwrap/monitor/PID1'
            if group=='G0' and observed in ('Z','S') and row.get('valid_sample_count')==0:
                row['status']='NOT_APPLICABLE'

def read(p):
    return json.loads(p.read_text()) if p.exists() else {}
def kv(s):
    return {x[0]:int(x[1]) for l in s.splitlines() for x in [l.split()] if len(x)==2}
def csvout(p,rows):
    if not rows:return
    keys=sorted(set().union(*(r.keys() for r in rows)))
    with p.open('w') as f:
        w=csv.DictWriter(f,keys);w.writeheader()
        for r in rows:w.writerow({k:json.dumps(v,ensure_ascii=False) if isinstance(v,(dict,list)) else v for k,v in r.items()})
def scan(d):
    costs=[];np=[];seen=set()
    for p in sorted(d.glob('*.log')):
        with p.open(errors='replace') as stream:
            for line in stream:
                try:r=json.loads(line[line.index('{'):])
                except (ValueError,TypeError):continue
                if not isinstance(r,dict):continue
                if r.get('event')!='COST' and not r.get('event','').startswith('NP_'):continue
                key=json.dumps(r,sort_keys=True)
                if key in seen:continue
                seen.add(key);r['_source']=p.name
                (costs if r.get('event')=='COST' else np).append(r)
    return costs,np
def one(d):
    cfg=read(d/'full-session.json');decl=cfg.get('configuration',{});env=cfg.get('extra_env',{})
    costs,np=scan(d);summary=read(d/'summary.json');H=read(d/'supervisor.json')
    summary_rows=summary.get('rows',[])
    journals={r.get('nonce'):r for r in summary_rows if r.get('nonce')}
    indices={r.get('nonce'):i for i,r in enumerate(summary_rows) if r.get('nonce')}
    for p in sorted(d.glob('attempt-*.json')):
        r=read(p)
        if r.get('nonce'):journals[r['nonce']]={**journals.get(r['nonce'],{}),**r}
    def ts(name,nonce=None):
        v=[x['ns'] for x in costs if x.get('name')==name and (nonce is None or x.get('nonce')==nonce)]
        return min(v) if v else None
    start=ts('fixture_session_start');end=ts('session_supervisor_waited')
    ledger=read(d/'session-resource-ledger.json').get('session_parent',{})
    base={'analysis_schema':ANALYSIS_SCHEMA,'run':d.parent.parent.name,'session':d.name,'path':str(d),'group':cfg.get('architecture_group'),
      'label':decl.get('label'), 'admission_key':decl.get('admission_key'),'block':decl.get('block'),
      'N':cfg.get('requests'),'D':env.get('FULL_DOMAINS'),'K':env.get('FULL_PER_DOMAIN'),
      'C':env.get('FULL_CONCURRENCY','1'),'profile':env.get('FULL_PROFILE','legacy'),
      'memory_budget_MiB':env.get('FULL_MEMORY_MIB'),'mode':env.get('FULL_MODE'),
      'qualification_run':cfg.get('qualification',False)}
    domain_counts=observed_domains(summary,journals,costs)
    base.update(D_declared=base['D'],K_declared=base['K'],N_declared=base['N'],profile_declared=base['profile'],
                D=domain_counts['count'],D_sources=domain_counts['sources'],D_observation_scope=domain_counts['scope'],
                Q=len(journals),Q_committed=sum(r.get('response_committed') is True for r in journals.values()),
                K=len(journals)/domain_counts['count'] if domain_counts['count'] else None,
                K_scope='observed attempts / observed ready domains; mean, not configured per-domain guarantee',
                count_scope='N is configured demand; Q is observed attempts incl failed/uncommitted; D may be lower bound on interrupted sessions')
    mixed=read(d/'mixed-cache-ledger.json');mixplan=read(d/'mixed-case-plan.json')
    if base['mode']=='G2_MIXED':
        configured_profiles=json.loads(env.get('FULL_MIX_PROFILES_JSON','[]'))
        profiles=[x.get('token') for x in mixplan.get('profiles',[]) if isinstance(x,dict)] or configured_profiles
        base.update(profile='MIXED:'+json.dumps(profiles,separators=(',',':')),mixed_profiles=profiles,
                    mixed_pattern=mixplan.get('pattern',env.get('FULL_MIX_PATTERN')),
                    mixed_routing='one clean-template slot, fixed schedule; no adaptive scheduler')
    usage=kv(ledger.get('cpu.stat','')).get('usage_usec')
    row={**base,'full_s':elapsed(start,end),'fixture_tail_s':elapsed(end,ts('fixture_release')),
      'cpu_s':usage/1e6 if usage is not None else None,
      'root_memory_peak_MiB':int(ledger['memory.peak'])/2**20 if 'memory.peak' in ledger else None,
      'memory_events':kv(ledger.get('memory.events','')),'summary_all_passed':summary.get('all_passed'),
      'actual_rows':len(summary.get('rows',[])),'H_released':H.get('release_state')=='RELEASED',
      'H_echild':H.get('echild'),'controller_wait':H.get('controller_wait_status'),
      'controller_failure':read(d/'controller-failure.json') or None,
      'observed_outcomes':{out:sum(r.get('outcome')==out for r in summary.get('rows',[])) for out in {r.get('outcome') for r in summary.get('rows',[])}},
      'net_physical_memory_saving':'Unknown; PSS samples and memcg charges are distinct'}
    if base['mode']=='G2_MIXED':
        row.update(mixed_cache_hits=mixed.get('hits'),mixed_cache_misses=mixed.get('misses'),
                   mixed_initialized_templates=mixed.get('initialized_templates'),
                   mixed_cache_capacity=mixed.get('capacity'),mixed_simultaneous_templates=mixed.get('simultaneous_templates'),
                   mixed_ledger_requests=len(mixed['requests']) if isinstance(mixed.get('requests'),list) else None,
                   mixed_cache_count_source='mixed-cache-ledger.json' if mixed else 'NOT_OBSERVED',
                   mixed_final_template_removed=mixed.get('final_template_removed'))
    resource_result=analyze_resources(d,base,start,end,[])
    resources=resource_result['tables'];issues=resource_result['issues']
    explain_resource_roles(resources,base)
    for m in resources['resource_integrals']:
        row[m['metric']+'_integral']=m['integral_trapezoid'];row[m['metric']+'_coverage']=m['covered_fraction']
    row['resource_analysis_issues']=issues
    req=[];stage=[];cow=[];init=[]
    for nonce,r in journals.items():
        cache=r.get('mixed_template_cache',{})
        index=cache.get('index',indices.get(nonce))
        timing=request_timing(costs,nonce,r,index,base['mode'])
        req.append({**base,'nonce':nonce,'outcome':r.get('outcome'),'resources':r.get('resources'),
          'domain_nonce':r.get('domain_nonce') or r.get('persistent_domain_nonce') or r.get('domain_ready_record',{}).get('nonce'),
          'qualification':r.get('qualification'),**timing,
          'request_profile':cache.get('profile',{}).get('token',base['profile']),
          'mixed_cache_hit':cache.get('hit'),'mixed_profile_index':cache.get('profile_index'),
          'mixed_template_pid':cache.get('current_pid'),
          'mixed_call_ledger_s':elapsed(cache.get('start_ns'),cache.get('complete_ns')),
          'mixed_ledger_scope':'fixed mixed record includes actual eviction/init before domain; separate from inner request interval' if cache else None})
    for e in costs:
        if e.get('kind') in ('span','c_span'):
            stage.append({**base,'nonce':e.get('nonce'),'role':e.get('role'),'pid':e.get('pid'),
              'kind':e.get('kind'),
              'name':e.get('name'),'wall_ns':e.get('end_ns',0)-e.get('start_ns',0) if e.get('end_ns') is not None and e.get('start_ns') is not None else None,
              'start_ns':e.get('start_ns'),'end_ns':e.get('end_ns'),'source':e['_source']})
    for e in np:
        dest=init if e.get('event') in ('NP_INIT_STAGE','NP_INITIALIZE','NP_ADMISSION') else cow
        dest.append({**base,**e})
    return row,req,stage,cow,init,resources
def main():
    a=argparse.ArgumentParser();a.add_argument('runs',nargs='+',type=Path);a.add_argument('--output',required=True,type=Path);args=a.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    tables={k:[] for k in ('sessions','requests','stages','numpy_records','initialization')}
    for run in args.runs:
        for d in sorted((run/'sessions').iterdir()):
            if not (d/'full-session.json').exists():continue
            row,req,stage,cow,init,res=one(d)
            for k,v in [('sessions',[row]),('requests',req),('stages',stage),('numpy_records',cow),('initialization',init)]:tables[k].extend(v)
            for k,v in res.items():tables.setdefault(k,[]).extend(v)
    for name,rows in tables.items():csvout(args.output/(name+'.csv'),rows)
    (args.output/'sessions.json').write_text(json.dumps(tables['sessions'],indent=2,ensure_ascii=False)+'\n')
    print(json.dumps({'sessions':len(tables['sessions']),'requests':len(tables['requests']),'output':str(args.output)}))
if __name__=='__main__':main()
