#!/usr/bin/env python3
"""Offline only. Preserve raw failures; no business execution or PID guessing."""
import argparse,csv,hashlib,json,math,statistics
from pathlib import Path
from collections import Counter,defaultdict

def load(p,default=None):
    return json.loads(p.read_text()) if p.exists() else default
def fields(s):
    return {a:float(b) for a,b in (l.split() for l in (s or '').splitlines())}
def value(x,key):
    try:
        v=float(x[key]);return v if math.isfinite(v) else None
    except (KeyError,ValueError,TypeError):return None
def seconds(x,key):
    v=value(x,key);return v/1e9 if v is not None else None
def delta(a,b,key='usage_usec'):
    aa=fields((a or {}).get('cpu.stat',''));bb=fields((b or {}).get('cpu.stat',''))
    return (bb[key]-aa[key])/1e6 if key in aa and key in bb else None
def counter_change(before,after,field):
    a=fields((before or {}).get(field,''));b=fields((after or {}).get(field,''))
    return {'before':a,'after':b,'delta':{k:b[k]-a[k] for k in a.keys() & b.keys()},
            'counter_regressed':any(b[k]<a[k] for k in a.keys() & b.keys()),
            'missing_fields':sorted(a.keys() ^ b.keys())}
def stats(xs):
    xs=sorted(x for x in xs if x is not None)
    def quant(p):
        i=(len(xs)-1)*p;lo=int(i);return xs[lo]+(xs[min(lo+1,len(xs)-1)]-xs[lo])*(i-lo)
    return {'n':len(xs),'median':statistics.median(xs),'min':xs[0],'max':xs[-1],'p90_descriptive':quant(.9)} if xs else {'n':0}
def rows(p):
    if not p.exists():return []
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
def csvout(path,data):
    keys=list(dict.fromkeys(k for x in data for k in x));
    with path.open('w') as f:
        w=csv.DictWriter(f,fieldnames=keys);w.writeheader()
        for row in data:w.writerow({k:json.dumps(v,ensure_ascii=False) if isinstance(v,(dict,list)) else v for k,v in row.items()})
def memory(samples,start,end,hz=None):
    # cgroup files are read after the sequential /proc scan. No exact per-file
    # timestamp exists: use scan-end proxy and retain its uncertainty explicitly.
    ss=sorted([r for r in samples if start<=r['t_ns'] and r['t_ns']+r.get('sample_ns',0)<=end],key=lambda r:r['t_ns'])
    ts=[r['t_ns']+r.get('sample_ns',0) for r in ss];wall=end-start
    span=ts[-1]-ts[0] if len(ts)>=2 else 0
    result={'sample_count':len(ss),'observed_span_s':span/1e9,
            'wall_coverage_fraction':span/wall if wall>0 else None,
            'sample_duration_ms':stats([r.get('sample_ns',0)/1e6 for r in ss]),
            'sample_interval_ms':stats([(b-a)/1e6 for a,b in zip(ts,ts[1:])]),
            'first_sample_offset_s':(ts[0]-start)/1e9 if ts else None,
            'last_sample_tail_s':(end-ts[-1])/1e9 if ts else None,
            'whole_platform_physical_memory':'UNKNOWN',
            'whole_platform_memcg_memory_available':bool(ss) and all('memory.current' in r.get('root',{}) for r in ss),
            'timestamp_scope':'scan end proxy; actual cgroup reads and process samples occur sequentially within sample_ns; no host/guest subtraction',
            'meaning':'memcg charge and sampled PSS/RSS are separate; role RSS sums are mapping totals, never physical memory; no extrapolation across window endpoints'}
    for group in ['business','control']:
        vals=[value(r.get(group,{}),'memory.current') for r in ss]
        valid=[(a,b,t1,t2) for a,b,t1,t2 in zip(vals,vals[1:],ts,ts[1:]) if a is not None and b is not None and t2>t1]
        area=sum((a+b)/2*(t2-t1)/1e9 for a,b,t1,t2 in valid)/1024**2 if valid else None
        valid_ns=sum(t2-t1 for _,_,t1,t2 in valid)
        result[group+'_memory_current_sample_max_MiB']=max(v for v in vals if v is not None)/1024**2 if any(v is not None for v in vals) else None
        result[group+'_memory_time_MiBs_observed_window']=area
        result[group+'_memory_integral_coverage']={'valid_samples':sum(v is not None for v in vals),'missing_samples':sum(v is None for v in vals),'valid_adjacent_intervals':len(valid),'valid_interval_s':valid_ns/1e9,'fraction_of_window':valid_ns/wall if wall>0 else None,'integration':'trapezoids only between adjacent valid samples; gaps/endpoints not zero-filled or extrapolated; long intervals remain interpolation uncertainty'}
    series=defaultdict(list);seen=set();cpu_by_identity=defaultdict(list)
    for r,when in zip(ss,ts):
        sums=defaultdict(float)
        for p in r.get('processes',[]):
            cg=p.get('cgroup','');comm=p.get('comm','')
            role='business' if '/challenge/business/' in cg else 'control' if '/challenge/control/' in cg else 'daemon_runtime' if any(x in comm for x in ['dockerd','containerd','runc']) else 'observer_driver'
            ident=(p['pid'],p['start_ticks']);seen.add(ident)
            for metric in ['Pss','Private_Dirty','Rss']:
                v=value(p,metric)
                if v is not None:sums[role+'_'+metric]+=v
            cpu_by_identity[ident].append((when,role,p['utime_ticks']+p['stime_ticks']))
        for k,v in sums.items():series[k].append(v/1024)
    result['sampled_distinct_process_identities']=len(seen)
    result['role_sampled_max_MiB']={k:max(v) for k,v in series.items()}
    cpu=defaultdict(float);changed=0;regressed=0
    for ident,values in cpu_by_identity.items():
        for left,right in zip(values,values[1:]):
            if right[2]<left[2]:regressed+=1;continue
            if left[1]!=right[1]:changed+=1;continue
            cpu[left[1]]+=right[2]-left[2]
    result['sampled_CPU_observed_tick_deltas']=dict(cpu)
    result['sampled_CPU_observed_delta_s']={k:v/hz for k,v in cpu.items()} if hz and hz>0 else None
    result['sampled_CPU_clock_ticks_per_s']=hz
    result['sampled_CPU_clock_source']='actual guest driver-start SC_CLK_TCK' if hz else 'UNKNOWN; do not assume host or HZ100'
    result['sampled_CPU_role_change_intervals_omitted']=changed;result['sampled_CPU_counter_regressions']=regressed
    result['sampled_CPU_caveat']='Same PID+start_ticks adjacent sampled deltas only; role labels from cgroup/comm, not a complete CPU ledger. Misses short lifetimes/endpoints and unobserved migrations; never add to root CPU or call daemon sample pure overhead.'
    result['sampled_process_coverage_fraction']='UNKNOWN until independent trace identity audit'
    return result

def overlap(intervals,start,end):
    events=defaultdict(Counter);invalid=[]
    for begin,finish,sid in intervals:
        if begin is None or finish is None or finish<begin:
            invalid.append({'start':begin,'end':finish,'session':sid});continue
        begin=max(begin,start);finish=min(finish,end)
        if finish<=begin:continue
        events[begin][sid]+=1;events[finish][sid]-=1
    active=Counter();last=start;area=0;peak=0;by_count=defaultdict(int)
    for t,changes in sorted(events.items()):
        n=sum(v>0 for v in active.values());by_count[n]+=t-last
        if n>=2:area+=t-last
        active.update(changes);peak=max(peak,sum(v>0 for v in active.values()));last=t
    by_count[sum(v>0 for v in active.values())]+=max(0,end-last)
    return {'max_distinct_sessions':peak,'overlap_at_least2_s':area/1e9,
            'wall_s_by_active_session_count':{str(k):v/1e9 for k,v in sorted(by_count.items())},
            'intervals_supplied':len(intervals),'invalid_intervals':invalid,
            'kind':'recorded wall intervals clipped to batch; not simultaneous CPU execution; missing intervals not inferred'}

def accepted_completed(row):
    """Observation acceptance only; never upgrades the executor fault contract."""
    return (row.get('executor_status')=='COMPLETED' and row.get('product_released') is True
            and row.get('targeted_outcome')=='PASS'
            and not row.get('session_observer_assisted')
            and not row.get('session_deadline_requested')
            and not row.get('batch_cancel_requested')
            and not row.get('controller_outer_timeout')
            and row.get('agent_status')=='Submitted'
            and row.get('action_contract_normal') is True
            and row.get('action_log_complete') is True)

def action_contract(action_rows,receipt_actions,*,log_present,final_receipt_present):
    """A final PASS does not erase a recovered action timeout or missing result.

    This checks saved normal API records, not hidden kernel state. Nonzero
    business returncodes and B1 foreground PENDING are not generic errors.
    """
    issues=[];counts=Counter();ids=[]
    for i,row in enumerate(action_rows,1):
        if not isinstance(row,dict):
            counts['action_unknown_result_count']+=1
            issues.append({'index':i,'reason':['MALFORMED_ACTION_ROW']});continue
        ids.append(row.get('action_id'))
        failure=row.get('failure_result')if isinstance(row.get('failure_result'),dict)else{}
        states=[row,failure];et=row.get('exception_type');err=row.get('error')
        exceptional=bool(et or err)
        timeout=et in {'TimeoutExpired','TimeoutError','ActionTimeout','ExecutionTimeoutError'}or any(s.get('timed_out')is True or s.get('outcome')=='TIMEOUT'for s in states)
        cancelled=any(s.get('cancelled')is True or s.get('cancel_sent')is True or s.get('outcome')=='CANCELLED'for s in states)
        limited=any(s.get('output_limit_exceeded')is True or s.get('outcome')=='OUTPUT_LIMIT'for s in states)
        known_return=isinstance(row.get('returncode'),int)and not isinstance(row.get('returncode'),bool)
        known_output=isinstance(row.get('output'),str)
        missing=[]
        if not known_return:missing.append('integer returncode')
        if not known_output:missing.append('string output')
        unknown=any(s.get('outcome')in {'UNKNOWN','INCOMPLETE'}for s in states)or(bool(missing)and not exceptional)
        marks={'action_exception_count':exceptional,'action_timeout_count':timeout,
               'action_cancelled_count':cancelled,'action_output_limit_count':limited,
               'action_unknown_result_count':unknown}
        for key,flag in marks.items():counts[key]+=int(flag)
        if known_return and row['returncode']!=0:counts['action_nonzero_return_count']+=1
        reasons=[key.removesuffix('_count')for key,flag in marks.items()if flag]
        if reasons:
            issues.append({'index':i,'action_id':row.get('action_id'),'reason':reasons,
                           'exception_type':et,'error':err,'missing_normal_result_fields':missing,
                           'failure_state':{k:failure[k]for k in ['outcome','timed_out','cancelled','cancel_sent','output_limit_exceeded','returncode','output_eof','group_release_state']if k in failure}})
    complete=(log_present and final_receipt_present and isinstance(receipt_actions,list)
              and bool(action_rows)and action_rows==receipt_actions
              and len(ids)==len(action_rows)and all(isinstance(x,str)and x for x in ids)
              and len(set(ids))==len(ids))
    if not final_receipt_present:log_state='UNKNOWN_NO_FINAL_RECEIPT'
    elif not log_present:log_state='UNKNOWN_NO_ACTION_LOG'
    elif not isinstance(receipt_actions,list):log_state='UNKNOWN_NO_FINAL_ACTION_LIST'
    elif not action_rows:log_state='UNKNOWN_EMPTY_ACTION_LOG'
    elif not complete:log_state='INCONSISTENT_ACTION_LOG_OR_IDENTITIES'
    else:log_state='RECORDED_ACTION_LOG_MATCHES_FINAL_RECEIPT'
    keys=['action_exception_count','action_timeout_count','action_cancelled_count',
          'action_output_limit_count','action_unknown_result_count','action_nonzero_return_count']
    return {**{k:counts[k]for k in keys},'action_contract_normal':not issues and complete,
            'action_log_complete':complete,'action_log_status':log_state,
            'action_result_issues':issues,
            'action_contract_scope':'Saved normal API result subset only. Does not certify complete fault handling, kernel EOF, all planned model steps, or independent process wait. Nonzero business exits and normal foreground PENDING remain allowed.'}

def assistance_evidence(sd,assists):
    related=[x for x in assists if x.get('session')==sd.name or x.get('session_id')==sd.name]
    cw=load(sd/'controller-wait.json',{})
    return {'session_observer_assisted':(sd/'observer-assistance.json').exists() or bool(related),
            'session_assistance_reasons':related,
            'session_deadline_requested':(sd/'session-deadline-request.json').exists(),
            'batch_cancel_requested':(sd/'batch-cancel-request.json').exists(),
            'controller_outer_timeout':cw.get('outer_timeout',False)}

def psi(text):
    out={}
    for line in (text or '').splitlines():
        words=line.split()
        if words:out[words[0]]={k:float(v) for k,v in (p.split('=',1) for p in words[1:] if '=' in p)}
    return out

def host_context(run):
    before=load(run/'host-before.json',{});after=load(run/'host-after.json',{});ss=rows(run/'host-pressure.jsonl')
    result={'host_kernel':before.get('kernel'),'start_utc':before.get('utc'),'end_utc':after.get('utc'),
            'sample_count':len(ss),'scope':'same physical host context only; not independent hardware replication or a guest bottleneck attribution; never subtract host and guest clocks',
            'monitor_span_s':(ss[-1]['host_monotonic_ns']-ss[0]['host_monotonic_ns'])/1e9 if len(ss)>=2 else None,'pressure':{}}
    for name in ['cpu','memory','io']:
        b=psi(before.get('pressure',{}).get(name));e=psi(after.get('pressure',{}).get(name));p={}
        for kind in sorted(b.keys()|e.keys()):
            x=b.get(kind,{});y=e.get(kind,{});d=y.get('total',0)-x.get('total',0) if 'total'in x and 'total'in y else None
            p[kind]={'host_total_stall_delta_s':d/1e6 if d is not None else None,'counter_regressed':d is not None and d<0,
                     'sampled_avg10_percent':stats([psi(r.get('pressure',{}).get(name)).get(kind,{}).get('avg10') for r in ss]),
                     'boundary_before':x,'boundary_after':y}
        result['pressure'][name]=p
    return result

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--study',type=Path,default=Path(__file__).resolve().parents[1]);ap.add_argument('--out',type=Path,required=True);a=ap.parse_args()
    a.out.mkdir(parents=True,exist_ok=False);inputs=[];batches=[];sessions=[];alltasks=[];runs=[]
    def inp(p):
        if p.exists():inputs.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
    inp(Path(__file__))
    for run in sorted((a.study/'runs').iterdir()):
        if not run.is_dir():continue
        cfg=load(run/'pilot-config.json',{});rr=load(run/'result.json',{});release=load(run/'guest-release.json',{})if rr else{}
        row={'run_id':run.name,'kind':cfg.get('kind'),'complete':bool(rr),'vm_wall_s':rr.get('wall_s'),'guest_shutdown_success':rr.get('guest_success'),'resources_released':release.get('released'),'observer_assistance_count':release.get('observer_assistance_count'),
             'driver_failure':load(run/'driver-failure.json',{}).get('error')if rr else None,'is_product_qualification':False}
        runs.append(row)
        if not rr:
            row['analysis_status']='IN_PROGRESS_NOT_ANALYZED';inp(run/'pilot-config.json');continue
        ds=load(run/'driver-start.json',{});hz=value(ds,'clock_ticks_per_s')
        cpu=delta(ds.get('root'),release.get('root_final'))
        row.update(analysis_status='COMPLETED_VM_RECORD',driver_start_to_release_root_CPU_s=cpu,
                   driver_start_to_release_wall_s=(release['t_ns']-ds['t_ns'])/1e9 if 't_ns'in ds and 't_ns'in release else None,
                   driver_CPU_scope='actual guest markers include fixture preparation, business, evidence, scoring and final cleanup; exclude guest boot before marker and shutdown/host QEMU overhead after marker; unavailable markers stay UNKNOWN',
                   driver_CPU_counter_regressed=cpu is not None and cpu<0,host_context=host_context(run))
        for p in [run/'pilot-config.json',run/'result.json',run/'guest-release.json',run/'driver-start.json',run/'fixtures-result.json',run/'batch-result.json',run/'resource-samples.jsonl',run/'host-before.json',run/'host-after.json',run/'host-pressure.jsonl']:inp(p)
        batch=load(run/'batch-result.json')
        if batch:
            sample=rows(run/'resource-samples.jsonl');mem=memory(sample,batch['start_ns'],batch['end_ns'],hz)
            root=delta(batch['root_before'],batch['root_after']);business=delta(batch['business_before'],batch['business_after']);control=delta(batch['control_before'],batch['control_after'])
            br={'run_id':run.name,'block':cfg['block'],'C':cfg['concurrency'],'task_denominator':batch['denominator'],'batch_wall_s':batch['wall_ns']/1e9,
                'root_CPU_s':root,'business_CPU_s':business,'control_CPU_s':control,'root_other_CPU_s':root-business-control if None not in [root,business,control] else None,
                'root_other_meaning':'root minus two sibling cgroups; daemon+runtime+observer+driver+other guest, not all pure overhead; boundaries read sequentially, not an atomic role ledger',
                'CPU_counters_regressed':any(x is not None and x<0 for x in [root,business,control]),
                'root_other_negative':None not in [root,business,control] and root-business-control<0,
                'CPU_scope':'guest root inclusive; business/control are subsets, do NOT add them again to root; counters read sequentially just after start/end markers',
                'business_throttled_s':delta(batch['business_before'],batch['business_after'],'throttled_usec'),
                'business_throttle_scope':'kernel accumulated throttled_usec, not request queue time or directly additive wall latency',
                'business_mem_peak_lifetime_before_MiB':value(batch['business_before'],'memory.peak')/1024**2 if value(batch['business_before'],'memory.peak') is not None else None,
                'business_mem_peak_lifetime_after_MiB':value(batch['business_after'],'memory.peak')/1024**2 if value(batch['business_after'],'memory.peak') is not None else None,
                'business_mem_peak_scope':'lifetime since cgroup creation; unchanged peak may predate batch; do not subtract peaks or call it an exact batch peak',
                'business_memory_event_counters':counter_change(batch['business_before'],batch['business_after'],'memory.events'),
                'business_pids_event_counters':counter_change(batch['business_before'],batch['business_after'],'pids.events'),
                'observer_assists':len(batch['assists']),'full_fault_qualified':False,'strict_B0_B1_ranking':False,**mem}
            tasks=[];tool_intervals=[];domain_intervals=[];admit_intervals=[];missing_action_intervals=[]
            for e in batch['sessions']:
                row={'run_id':run.name,'block':cfg['block'],'C':cfg['concurrency'],'task_id':e['task_id'],'session_id':e.get('session_id'),'executor_status':e['status'],'arrival_ns':e['arrival_ns'],
                     'admitted_ns':e.get('admitted_ns'),'product_released':e.get('product_released',False),'queue_s':(e['admitted_ns']-e['arrival_ns'])/1e9 if e.get('admitted_ns') else None}
                sd=run/'sessions'/str(e.get('session_id'));sr=load(sd/'session-result.json',{});vr=load(sd/'validation/result.json',{})
                action_rows=rows(sd/'actions.jsonl');action_source='actions.jsonl'
                if not(sd/'actions.jsonl').exists():action_rows=sr.get('actions',[]);action_source='session-result fallback'
                inp(sd/'actions.jsonl')
                if not sr:missing_action_intervals.append({'session_id':e.get('session_id'),'reason':'no final receipt; completed action log rows retained, in-flight action tail UNKNOWN'})
                for ar in action_rows:
                    if ar.get('start_ns') and ar.get('end_ns'):tool_intervals.append((ar['start_ns'],ar['end_ns'],e.get('session_id')))
                if sr.get('domain_ready_ns') and sr.get('controller_end_ns'):domain_intervals.append((sr['domain_ready_ns'],sr['controller_end_ns'],e.get('session_id')))
                if e.get('admitted_ns') and e.get('controller_reaped_ns'):admit_intervals.append((e['admitted_ns'],e['controller_reaped_ns'],e.get('session_id')))
                row.update(**assistance_evidence(sd,batch.get('assists',[])))
                for name in ['observer-assistance.json','session-deadline-request.json','batch-cancel-request.json']:inp(sd/name)
                row.update(targeted_outcome=vr.get('outcome') or 'BLOCKED',targeted_business_acceptance=vr.get('targeted_business_acceptance',False),score_receipt_present=bool(vr),
                           session_s=seconds(sr,'full_session_ns'),response_s=(e['controller_reaped_ns']-e['arrival_ns'])/1e9 if e.get('controller_reaped_ns') else None,
                           action_count=len(action_rows),action_count_scope='recorded completed/exception actions; no final receipt means actual count may be higher',action_source=action_source,
                           final_receipt_present=bool(sr),agent_status=sr.get('agent_status'),exception=sr.get('exception'),
                           domain_setup_s=seconds(sr,'domain_setup_ns'),tool_s=seconds(sr,'tool_cumulative_ns'),
                           evidence_export_s=seconds(sr,'evidence_export_ns'),cleanup_s=seconds(sr,'cleanup_ns'))
                row.update(action_contract(action_rows,sr.get('actions'),log_present=(sd/'actions.jsonl').exists(),final_receipt_present=bool(sr)))
                row['accepted_completed_observation']=accepted_completed(row)
                row['accepted_is_not_full_fault_qualification']=True
                tasks.append(row);alltasks.append(row)
            br['tool_wall_overlap']=overlap(tool_intervals,batch['start_ns'],batch['end_ns']);br['ready_to_controller_end_overlap']=overlap(domain_intervals,batch['start_ns'],batch['end_ns'])
            br['tool_overlap_missing_tail_evidence']=missing_action_intervals
            br['admit_to_controller_wait_overlap']=overlap(admit_intervals,batch['start_ns'],batch['end_ns'])
            br['admission_overlap_scope']='ledger admit through parent wait, includes workspace preparation; observer safety cleanup after wait can extend occupied slot, so not exact slot-release or live-domain proof'
            br['outcomes']=dict(Counter(t['targeted_outcome'] for t in tasks));br['executor_outcomes']=dict(Counter(t['executor_status'] for t in tasks))
            br['completed_released_sessions']=sum(t['executor_status']=='COMPLETED' and t['product_released'] for t in tasks)
            br['targeted_score_PASS_count']=sum(t['targeted_outcome']=='PASS' for t in tasks)
            br['targeted_score_PASS_count_per_batch_s']=br['targeted_score_PASS_count']/br['batch_wall_s']
            br['accepted_completed_count']=sum(t['accepted_completed_observation']for t in tasks)
            br['accepted_completed_throughput_s']=br['accepted_completed_count']/br['batch_wall_s']
            br['action_result_counts']={k:sum(t[k]for t in tasks)for k in ['action_exception_count','action_timeout_count','action_cancelled_count','action_output_limit_count','action_unknown_result_count','action_nonzero_return_count']}
            br['sessions_without_complete_action_log']=sum(not t['action_log_complete']for t in tasks)
            br['sessions_outside_normal_action_subset']=sum(not t['action_contract_normal']for t in tasks)
            br['accepted_is_not_full_fault_qualification']=True
            br['targeted_throughput_scope']='targeted score alone does not certify execution/release; acceptance requires COMPLETED + product release + targeted PASS + Submitted + consistent complete action log + normal action API results + no Session observer/deadline/batch-cancel/outer-timeout assistance. Normal nonzero business exits are allowed. Scoring time outside batch, not a full product fault guarantee.'
            observed_active=[len(r.get('active_sessions',[])) for r in sample if batch['start_ns']<=r['t_ns']<=batch['end_ns']]
            br['sampled_peak_running_sessions']=max(observed_active)if observed_active else None
            br['sampled_peak_scope']='sampled driver running list, begins after workspace copy and ends at finish; may miss short sessions, not exact actual concurrency or CPU use'
            for k in ['queue_s','session_s','response_s','domain_setup_s','tool_s','evidence_export_s','cleanup_s']:br[k+'_distribution']=stats([t[k] for t in tasks])
            batches.append(br)
        for sd in sorted((run/'sessions').glob('*')) if (run/'sessions').exists() else []:
            sr=load(sd/'session-result.json',{});config=load(sd/'config.json',{});wait=load(sd/'controller-wait.json',{});vr=load(sd/'validation/result.json',{})
            for p in [sd/'session-result.json',sd/'config.json',sd/'controller-wait.json',sd/'validation/result.json']:inp(p)
            sessions.append({'run_id':run.name,'session_id':sd.name,'case':config.get('case'),'variant':config.get('variant'),'task_id':config.get('task_id'),
                'cohort':load(sd/'cohort.json',{}).get('cohort'),'status':sr.get('status','UNKNOWN_NO_FINAL_RECEIPT'),
                'controller_returncode':wait.get('returncode'),'real_wait_controller':wait.get('real_wait_controller'),'released':sr.get('product_released',False),
                'observer_assisted':(sd/'observer-assistance.json').exists(),'targeted_outcome':vr.get('outcome')or'BLOCKED',
                'full_session_s':seconds(sr,'full_session_ns'),'tool_s':seconds(sr,'tool_cumulative_ns'),
                'cleanup_s':seconds(sr,'cleanup_ns'),'evidence_export_s':seconds(sr,'evidence_export_ns'),'action_count_recorded':len(rows(sd/'actions.jsonl'))if(sd/'actions.jsonl').exists()else len(sr.get('actions',[])),
                'final_receipt_present':bool(sr),'action_count_scope':'recorded finished/exception actions only; missing final receipt leaves execution tail UNKNOWN'})
            inp(sd/'actions.jsonl');inp(sd/'cohort.json')
    result={'schema':'shimos.next.workload-accounting.v4','analyzer_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'scope':'offline reproducible analysis; same-host blocks, controlled arrivals; not strict executor ranking','runs':runs,'batches':batches,'all_task_denominator_rows':len(alltasks),'tasks':alltasks,'sessions':sessions}
    (a.out/'summary.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    for name,data in [('runs',runs),('batches',batches),('tasks',alltasks),('sessions',sessions),('input-sha',inputs)]:csvout(a.out/(name+'.csv'),data)
    (a.out/'input-sha.json').write_text(json.dumps(inputs,indent=2)+'\n')
    if batches:
        try:
            import matplotlib;matplotlib.use('Agg');import matplotlib.pyplot as plt
            fig,axes=plt.subplots(1,3,figsize=(13,3.5))
            for block in sorted({b['block'] for b in batches}):
                bs=sorted([b for b in batches if b['block']==block],key=lambda x:x['C'])
                for ax,metric,title in zip(axes,['batch_wall_s','root_CPU_s','business_memory_time_MiBs_observed_window'],['Batch makespan (s)','Guest root CPU (s)','Business charge integral (MiB s)']):
                    ax.plot([b['C'] for b in bs],[b[metric] for b in bs],marker='o',label='VM block '+str(block));ax.set_title(title);ax.set_xlabel('FIFO concurrency');ax.set_xticks([1,2,4]);ax.grid(alpha=.3)
            axes[0].legend();fig.suptitle('B0_INIT only: 13-task denominator, synthetic burst, same-host observations');fig.tight_layout();fig.savefig(a.out/'multisession-costs.png',dpi=160);plt.close(fig)
        except ImportError as e:(a.out/'plot-blocked.json').write_text(json.dumps({'error':str(e)}))
    print(json.dumps({'runs':len(runs),'batches':len(batches),'sessions':len(sessions),'task_rows':len(alltasks)}))
if __name__=='__main__':main()
