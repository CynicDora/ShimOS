#!/usr/bin/env python3
"""Read-only NumPy admission/cost ledger. Does not grant execution qualification.

All duration arithmetic is within one guest CLOCK_MONOTONIC domain. Full
sessions retain preload, repeated cold Z creation and final H cleanup. CPU,
PSS, RSS, cgroup charges and pagemap flags remain different measurements.
"""
import argparse
from collections import defaultdict
import csv
import hashlib
import itertools
import json
import math
from pathlib import Path
import shutil
import statistics


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def percentile(values, q):
    values=sorted(values)
    if not values:return None
    at=(len(values)-1)*q; left=int(at); right=math.ceil(at)
    return values[left]+(values[right]-values[left])*(at-left)


def number(value):
    try:return int(value)
    except (ValueError,TypeError):return None


def keyvalues(text):
    out={}
    if isinstance(text,str):
        for line in text.splitlines():
            fields=line.split()
            if len(fields)==2:out[fields[0]]=number(fields[1])
    return out


def overlap_union(intervals, lower, upper):
    if lower is None or upper is None:return None
    end=None;total=0
    for start,stop in sorted((max(a,lower),min(b,upper)) for a,b in intervals):
        if stop<=start:continue
        if end is None or start>=end:total+=stop-start;end=stop
        elif stop>end:total+=stop-end;end=stop
    return total


def write_csv(path, rows):
    fields=sorted({key for row in rows for key in row})
    with path.open('x',newline='') as stream:
        writer=csv.DictWriter(stream,fields);writer.writeheader()
        for row in rows:
            writer.writerow({key:json.dumps(value,ensure_ascii=False,sort_keys=True) if isinstance(value,(dict,list)) else value
                             for key,value in row.items()})


def analyze(directory):
    directory=directory.resolve();issues=[];sources={}
    def read(name,required=True):
        path=directory/name
        if not path.is_file():
            if required:issues.append({'file':name,'problem':'MISSING'})
            return {}
        sources[name]=sha(path)
        try:return json.loads(path.read_text())
        except (ValueError,OSError) as exc:
            issues.append({'file':name,'problem':repr(exc)});return {}
    config=read('review-config.json');summary=read('summary.json');result=read('result.json')
    supervisor=read('supervisor.json');external=read('external-final-release.json')
    manifest=read('variant-manifest.json');reference=read('numpy-reference.json',False)
    costs=[];numpy=[];h_events=[];r_events=[];seen=set();identities={};duplicate_count=0
    main_log=directory/'guest-output.log'
    if not main_log.exists():main_log=directory/'serial.log'
    paths=[main_log,*sorted(directory.glob('zygote-*.log')),
           *sorted(p for p in directory.glob('*-output.log') if p.name!='guest-output.log'),
           directory/'supervisor-events.jsonl',directory/'events.jsonl']
    for path in dict.fromkeys(paths):
        if not path.is_file():continue
        sources[path.name]=sha(path)
        for line,raw in enumerate(path.read_text(errors='replace').splitlines(),1):
            begin=raw.find('{')
            if begin<0:continue
            try:item=json.loads(raw[begin:])
            except ValueError:
                if any(token in raw for token in ('"COST"','"NP_RESULT"','"NP_ADMISSION"','"NP_Z_CHECK"')):
                    issues.append({'file':path.name,'line':line,'problem':'MALFORMED_TARGET_JSON'})
                continue
            if not isinstance(item,dict):continue
            event=item.get('event','')
            if event!='COST' and not event.startswith('NP_') and path.name not in ('supervisor-events.jsonl','events.jsonl'):continue
            encoded=json.dumps(item,sort_keys=True,separators=(',',':'))
            if encoded in seen:duplicate_count+=1;continue
            seen.add(encoded)
            item={**item,'_source':path.name+':'+str(line),'_source_file':path.name,'_raw_bytes':len(raw.encode())+1}
            if event=='COST':
                identity=tuple(item.get(key) for key in ('session','role','pid','nonce','seq'))
                if identity in identities:issues.append({'problem':'CONFLICTING_COST_IDENTITY','identity':identity})
                identities[identity]=encoded;costs.append(item)
                if item.get('clock')!='CLOCK_MONOTONIC':issues.append({'problem':'UNEXPECTED_CLOCK','source':item['_source']})
                if item.get('kind')=='measurement_error' or any(item.get('metadata',{}).get(k) for k in ('dropped','overflow','clock_errors')):
                    issues.append({'problem':'MEASUREMENT_ERROR','source':item['_source']})
            elif event.startswith('NP_'):numpy.append(item)
            elif path.name=='supervisor-events.jsonl':h_events.append(item)
            else:r_events.append(item)
    costs.sort(key=lambda row:row.get('ns',0));numpy.sort(key=lambda row:row.get('monotonic_ns',0))
    sessions={row.get('session') for row in costs}
    if len(sessions)!=1:issues.append({'problem':'MIXED_OR_MISSING_SESSION','sessions':sorted(str(x) for x in sessions)})
    session=next(iter(sessions)) if len(sessions)==1 else directory.name
    # Final reports may be absent after an H deadline/failure. Keep actual
    # observed requests and journals instead of pretending the session ran N=0.
    attempts={}
    for pattern in ('attempt-*.json','[0-9]*-*.json'):
        for path in sorted(directory.glob(pattern)):
            data=read(path.name,False)
            if isinstance(data,dict) and data.get('nonce'):attempts[data['nonce']]={**data,'_receipt':path.name}
    request_begins={row['nonce'] for row in costs if row.get('name')=='request_begin' and row.get('nonce')}
    for nonce in request_begins:
        attempts.setdefault(nonce,{'nonce':nonce,'_receipt':None,'outcome':'UNKNOWN_NO_RECEIPT'})
    observed_attempts=set(attempts)|{row['nonce'] for row in summary.get('rows',[]) if row.get('nonce')}
    base={'run':str(directory),'session':session,'pair':config.get('same_vm_pair'),
          'baseline':config.get('numpy_baseline'),'level':config.get('numpy_level'),
          'np_case':config.get('numpy_case'),'audit':str(config.get('numpy_audit','unknown')),
          'case':config.get('case'),'diagnostics':config.get('diagnostics'),
          'timing':str(config.get('timing','unknown')),'declared_N':config.get('requests'),
          'warmup':config.get('warmup'),'actual_attempts':len(observed_attempts),
          'observed_request_begin_count':len(request_begins),
          'completed_attempt_receipts':sum(r.get('qualification')=='PASS' for r in attempts.values()),
          'declared_summary_attempts':len(summary['rows']) if 'rows' in summary else None}
    tables={name:[] for name in ('sessions','requests','initialization','worker','memory','zygote_growth','zygote_growth_summary','zygote_memory_time','zygote_flush_tail','cow','cpu','cpu_ledger','cgroup','metrics','paired')}
    z_memory_samples=[]
    def pick(name,role=None,nonce=None,pid=None):
        rows=[row for row in costs if row.get('name')==name and (role is None or row.get('role')==role)
              and (nonce is None or row.get('nonce')==nonce) and (pid is None or row.get('pid')==pid)]
        return rows[0] if rows else None
    def timestamp(name,role=None,nonce=None,pid=None):
        row=pick(name,role,nonce,pid);return row.get('ns') if row else None
    def htimestamp(event,role=None):
        rows=[r for r in h_events if r.get('event')==event and (role is None or r.get('role')==role)]
        return rows[0].get('monotonic_ns') if rows else None
    def difference(start,end):
        return end-start if isinstance(start,int) and isinstance(end,int) else None
    def z_wait(pid):
        waited=[r.get('end_ns',r['ns']) for r in costs if r.get('role')=='R' and r.get('name')=='waitpid_poll' and r.get('waited_pid')==pid]
        if waited:return min(waited),'R_COST_true_wait'
        rows=[r for r in summary.get('wait_records',[]) if r.get('pid')==pid and isinstance(r.get('time_ns'),int)]
        if rows:return min(r['time_ns'] for r in rows),'R_summary_true_wait'
        rows=[r for r in r_events if r.get('event')=='CONTROLLER_WAIT' and r.get('pid')==pid]
        if rows:return min(r.get('time_ns',r['monotonic_ns']) for r in rows),'R_event_true_wait'
        rows=[r for r in h_events if r.get('event')=='SUPERVISOR_REAL_WAIT' and r.get('pid')==pid]
        return (min(r['monotonic_ns'] for r in rows),'H_adopted_true_wait') if rows else (None,'NOT_OBSERVED')
    def metric(name,value,unit,scope,**fields):
        if fields.get('nonce') is not None and fields['nonce'] in attempts:
            fields.setdefault('outcome',attempts[fields['nonce']].get('outcome'))
            fields.setdefault('request_case',attempts[fields['nonce']].get('case'))
        tables['metrics'].append({**base,'metric':name,'value':value,'unit':unit,'scope':scope,
                                  'observed':value is not None,**fields})
        return value
    def memory(sample,phase,role,nonce=None,**fields):
        values=sample.get('KiB',{}) if isinstance(sample,dict) else {}
        record={**base,'nonce':nonce,'phase':phase,'role':role,'pid':sample.get('pid'),
                'monotonic_ns':sample.get('monotonic_ns'),'rss_KiB':values.get('Rss'),
                'pss_KiB':values.get('Pss'),'private_dirty_KiB':values.get('Private_Dirty'),
                'shared_dirty_KiB':values.get('Shared_Dirty'),'anonymous_KiB':values.get('Anonymous'),
                'error':sample.get('error'),'status':'OBSERVED' if values else 'NOT_OBSERVED',
                'scope':'one non-atomic smaps_rollup sample; not peak or physical memory sum',**fields}
        if phase=='worker_gated' and role in ('Z','S','W'):
            record['initialization_state']='inherited_NumPy_preload' if base['baseline']=='hot' else 'Python_only_before_W_NumPy_import'
            record['memory_comparison_limit']='cold/hot gated samples are different initialization stages; do not infer physical-memory savings from their difference'
        elif role=='W' and phase in ('numpy_business_before','numpy_business_after'):
            record['initialization_state']='NumPy_initialized'
            record['memory_comparison_limit']='matched W initialization stage, but W-only PSS excludes additional resident Z/S; not whole-system net memory saving'
        tables['memory'].append(record)
        for key in ('rss_KiB','pss_KiB','private_dirty_KiB','shared_dirty_KiB'):
            metric(phase+'_'+key,record[key],'KiB',record['scope'],role=role,nonce=nonce)
        return record

    first=timestamp('fixture_session_start');hstart=timestamp('supervisor_enter','H')
    hwaitr=htimestamp('SUPERVISOR_REAL_WAIT','controller')
    hreleased=timestamp('supervisor_released','H') or htimestamp('SUPERVISOR_FINISHED')
    wait_h=timestamp('session_supervisor_waited');final=timestamp('fixture_release')
    allsleep=[(r['start_ns'],r['end_ns']) for r in costs if r.get('name')=='artificial_descendant_sleep'
              and isinstance(r.get('start_ns'),int) and isinstance(r.get('end_ns'),int)]
    full=metric('full_sequence_fixture_start_to_true_wait_H_ns',difference(first,wait_h),'ns',
                'new H/R/Z, initial hot preload or every cold Z start, all requests, final H process exit and true wait; excludes build/reference/VM boot')
    metric('H_start_to_true_wait_R_ns',difference(hstart,hwaitr),'ns','H start through actual adopted/controller wait; not entire H cleanup')
    metric('H_start_to_H_release_evidence_ns',difference(hstart,hreleased),'ns','includes H product cleanup verification; excludes final diagnostic flush')
    metric('H_start_to_fixture_true_wait_H_ns',difference(hstart,wait_h),'ns','full H process lifetime and parent wait observation')
    metric('full_sequence_to_final_delegation_release_ns',difference(first,final),'ns','includes external observer checks, intentional 100ms observer delay and fixture delegation removal')
    metric('fixture_post_H_wait_tail_ns',difference(wait_h,final),'ns','observer/trace/delegation fixture tail, not product execution architecture')
    sleep_overlap=metric('full_sequence_artificial_descendant_sleep_overlap_ns',overlap_union(allsleep,first,wait_h),'ns','union of actual sleep intervals intersected with full sequence; overlaps other work')
    metric('full_sequence_minus_observed_sleep_overlap_ns',full-sleep_overlap if full is not None and sleep_overlap is not None else None,'ns',
           'diagnostic residual only, NOT a prediction of removing sleeps; unadjusted sequence is primary')
    metric('reference_process_wall_ns',difference(reference.get('started_ns'),reference.get('finished_ns')),'ns','separate fresh-D correctness reference, excluded from product sequence')
    h_attempts=supervisor.get('attempts',[])
    tables['sessions'].append({**base,'complete':result.get('complete'),'summary_passed':summary.get('all_passed'),
        'H_release_state':supervisor.get('release_state'),'H_echild':supervisor.get('echild'),
        'H_controller_wait_status':supervisor.get('controller_wait_status'),
        'H_failure_reason':supervisor.get('failure_reason'),'H_resources_removed':supervisor.get('resources_removed'),
        'H_errors':supervisor.get('errors'),'H_protocol_errors':supervisor.get('protocol_errors'),
        'H_fds_restored':supervisor.get('fd_before')==supervisor.get('fd_after') if 'fd_before' in supervisor and 'fd_after' in supervisor else None,
        'H_attempts':len(h_attempts),'H_registered':sum(a.get('registered') is True for a in h_attempts),
        'H_retired':sum(a.get('retired') is True for a in h_attempts),'H_output_eof':sum(a.get('output_eof') is True for a in h_attempts),
        'H_attempt_resources_removed':sum(a.get('resources_removed') is True for a in h_attempts),
        'H_remaining_cgroups':supervisor.get('remaining_cgroups'),'H_remaining_workspaces':supervisor.get('remaining_workspaces'),
        'H_observer_cleanup_used':supervisor.get('observer_cleanup_used'),
        'H_true_wait_R_event_ns':hwaitr,'fixture_true_wait_H_event_ns':wait_h,
        'fixture_wait_H_status':external.get('supervisor_wait_status'),'delegation_removed':external.get('delegation_removed'),
        'observer_killed':external.get('observer_killed_processes'),'observer_removed':external.get('observer_removed_product_resources'),
        'host_timeout_intervention':result.get('host_timeout_intervention_used'),
        'full_sequence_ns':full,'H_release_evidence_ns':difference(first,hreleased),
        'final_delegation_release_ns':difference(first,final),'artificial_sleep_overlap_ns':sleep_overlap,
        'qualification':'NOT_DECIDED_BY_COST_ANALYZER','source_manifest':manifest.get('numpy_package_manifest_sha256')})

    def index_hint(row):
        receipt=row.get('_receipt') or '';prefix=receipt.split('-',1)[0]
        if prefix.isdigit():return int(prefix)
        event=pick('request_begin','R',row['nonce'])
        return event.get('repeat') if event else None
    ordered=sorted(attempts.values(),key=lambda r:(index_hint(r) is None,index_hint(r) if index_hint(r) is not None else timestamp('request_begin','R',r['nonce']) or 0))
    source_nonce={}
    for r in ordered:
        if r['_receipt'] and not r['_receipt'].startswith('attempt-'):
            source_nonce[r['_receipt'].removesuffix('.json')+'-output.log']=r['nonce']
    results_by_nonce={r['nonce']:r for r in numpy if r.get('event')=='NP_RESULT' and r.get('nonce')}
    for row in ordered:
        index=index_hint(row)
        nonce=row['nonce'];start=timestamp('request_begin','R',nonce);end=timestamp('response_ready','R',nonce)
        duration=difference(start,end);subsleep=overlap_union(allsleep,start,end)
        call_start=next((r['ns'] for r in costs if index is not None and r.get('name')=='numpy_call_begin' and r.get('call_index')==index),None)
        call_end=next((r['ns'] for r in costs if index is not None and r.get('name')=='numpy_call_complete' and r.get('call_index')==index),None)
        record={**base,'nonce':nonce,'index':index,'request_case':row.get('case'),
            'outcome':row.get('outcome'),'business':row.get('business'),'resources':row.get('resources'),
            'qualification_receipt':row.get('qualification'),'receipt':row['_receipt'],
            'domain_request_to_response_ns':duration,'numpy_call_ns':difference(call_start,call_end),
            'request_to_resource_delete_ns':difference(start,timestamp('resources_deleted','R',nonce)),
            'artificial_sleep_overlap_ns':subsleep,'test_sleep_requested_ns':sum(r.get('requested_ns',0) for r in costs if r.get('name')=='artificial_descendant_sleep' and r.get('nonce')==nonce),
            'domain_minus_sleep_overlap_ns':duration-subsleep if duration is not None and subsleep is not None else None,
            'zygote_pid':row.get('zygote_pid'),'warmup_request':index<int(config.get('warmup',0)) if index is not None else None,
            'wait_W_status':row.get('w_wait'),'wait_S_status':row.get('s_wait'),
            'monitor_wait_status':row.get('monitor_wait'),'domain_empty':row.get('domain_empty'),
            'PID1_DRAINED_observed':bool(row.get('drained')),
            'output_eof':row.get('output_eof'),'resources_removed':row.get('resources_removed'),
            'call_to_W_business_gate_ns':difference(call_start,timestamp('worker_gated','R',nonce)),
            'call_to_business_enter_ns':difference(call_start,timestamp('business_enter','W',nonce)),
            'domain_create_ns':difference(timestamp('domain_build_begin','R',nonce),timestamp('domain_ready','R',nonce)),
            'quiescent_to_resources_deleted_ns':difference(timestamp('domain_quiescent','R',nonce),timestamp('resources_deleted','R',nonce)),
            'gate_semantics':'W is authorized/gated but cold W has not imported NumPy; this is not NumPy-ready',
            'call_begin_ns':call_start,'request_begin_ns':start,'response_ready_ns':end,'call_complete_ns':call_end}
        for stage in ('cgroup_delete','workspace_delete','controller_close_attempt_fds'):
            span=pick(stage,'R',nonce)
            record[stage+'_ns']=difference(span.get('start_ns'),span.get('end_ns')) if span else None
        tables['requests'].append(record)
        for name in ('domain_request_to_response_ns','numpy_call_ns','request_to_resource_delete_ns','artificial_sleep_overlap_ns'):
            metric(name,record[name],'ns','request interval; numpy_call additionally includes cold Z start/stop or first hot Z start; final hot stop is session-only',nonce=nonce,index=index,outcome=row.get('outcome'))
        spans=[('domain_build_ns','domain_build_begin','domain_ready'),
               ('request_to_W_gate_ns','request_begin','worker_gated'),
               ('request_to_business_enter_ns','request_begin','business_enter'),
               ('business_end_to_domain_quiescent_ns','business_end','domain_quiescent'),
               ('domain_quiescent_to_response_ns','domain_quiescent','response_ready')]
        for name,left,right in spans:
            metric(name,difference(timestamp(left,None,nonce),timestamp(right,None,nonce)),'ns','event wall interval; component intervals can overlap',nonce=nonce,index=index)
        samples=row.get('numpy_memory_gated',{}).get('samples',{})
        for role in ('Z','S','W','R'):
            observed=memory(samples.get(role,{}),'worker_gated',role,nonce,index=index)
            if role=='Z':z_memory_samples.append({**observed,'zygote_pid':row.get('zygote_pid'),'source':row['_receipt']})
        for group,data in row.get('stats',{}).items():
            cpu=keyvalues(data.get('cpu.stat'));events=keyvalues(data.get('memory.events'))
            tables['cgroup'].append({**base,'nonce':nonce,'index':index,'group':group,
                'cpu_usage_us':cpu.get('usage_usec'),'cpu_user_us':cpu.get('user_usec'),'cpu_system_us':cpu.get('system_usec'),
                'throttled_us':cpu.get('throttled_usec'),'nr_throttled':cpu.get('nr_throttled'),
                'memory_current_bytes':number(data.get('memory.current')),'memory_peak_charged_bytes':number(data.get('memory.peak')),
                'pids_current':number(data.get('pids.current')),'memory_oom':events.get('oom'),'memory_oom_kill':events.get('oom_kill'),
                'scope':'hierarchical task includes child groups; do not add parent+children or role/waited-child CPU; charged memory is not PSS'})
        np_result=results_by_nonce.get(nonce)
        if np_result:
            record['call_to_NumPy_compute_ready_ns']=difference(call_start,np_result.get('compute_begin_ns'))
            record['request_to_NumPy_compute_ready_ns']=difference(start,np_result.get('compute_begin_ns'))
            record['NumPy_ready_semantics']='actual outputs() start after initialization, security/qualification checks and NumPy before-snapshot/fingerprint; not pure import completion'
            metric('call_to_NumPy_compute_ready_ns',record['call_to_NumPy_compute_ready_ns'],'ns',record['NumPy_ready_semantics'],nonce=nonce,index=index)
            before=np_result.get('before',{});after=np_result.get('after',{})
            wr={**base,'nonce':nonce,'index':index,'source':np_result['_source'],
                'total_numpy_business_ns':difference(np_result.get('call_start_ns'),np_result.get('done_ns')),
                'compute_ns':difference(np_result.get('compute_begin_ns'),np_result.get('compute_end_ns')),
                'before_compute_ns':difference(np_result.get('call_start_ns'),np_result.get('compute_begin_ns')),
                'after_compute_validation_and_output_ns':difference(np_result.get('compute_end_ns'),np_result.get('done_ns')),
                'self_cpu_ns':np_result.get('cpu_ns'),'inherited_preload':np_result.get('inherited_preload'),
                'initialized_in_W':np_result.get('initialized_in_this_worker'),
                'fd_before':len(before['fds']) if isinstance(before.get('fds'),dict) else None,
                'fd_after':len(after['fds']) if isinstance(after.get('fds'),dict) else None,
                'threads_before':len(before['threads']) if isinstance(before.get('threads'),list) else None,
                'threads_after':len(after['threads']) if isinstance(after.get('threads'),list) else None}
            tables['worker'].append(wr)
            for name in ('total_numpy_business_ns','compute_ns','before_compute_ns','after_compute_validation_and_output_ns','self_cpu_ns'):
                metric('W_'+name,wr[name],'ns','NumPy workload, observations and validation included except compute_ns; cold before_compute includes initialize',nonce=nonce,index=index)
            memory(before.get('memory',{}),'numpy_business_before','W',nonce,index=index)
            memory(after.get('memory',{}),'numpy_business_after','W',nonce,index=index)
            tables['cow'].append({**base,'nonce':nonce,'index':index,
                'requested_cow_write_bytes':np_result.get('requested_cow_write_bytes'),
                'pages_before':np_result.get('pages_before'),'pages_after':np_result.get('pages_after'),
                'fingerprint_before':np_result.get('initial_fingerprint'),'fingerprint_after':np_result.get('after_cow_fingerprint'),
                'scope':'requested write bytes are not copied bytes; exclusive/soft-dirty/present flags are not exact COW counts; no clear_refs',
                'source':np_result['_source']})
        else:
            issues.append({'problem':'NP_RESULT_NOT_OBSERVED','nonce':nonce,'outcome':row.get('outcome'),
                           'expected_when_business_not_executed':row.get('business')=='NOT_EXECUTED',
                           'not_a_lifecycle_failure_verdict':True})

    for row in numpy:
        if row.get('event')=='NP_ADMISSION':
            nonce=row.get('nonce') or source_nonce.get(row['_source_file'])
            location=row.get('location');role='Z' if location=='Z' or str(location).startswith('Z') else 'W'
            item={**base,'nonce':nonce,'role':role,'location':location,'pid_namespace_local':row.get('pid_namespace_local'),
                'source':row['_source'],'start_ns':row.get('start_ns'),'complete_ns':row.get('complete_ns'),
                'initialization_wall_ns':difference(row.get('start_ns'),row.get('complete_ns')),
                'through_import_observation_ns':difference(row.get('start_ns'),row.get('import_ready_ns')),
                'data_or_blas_preparation_ns':difference(row.get('import_ready_ns'),row.get('initialized_ns')),
                'post_initialization_observation_ns':difference(row.get('initialized_ns'),row.get('complete_ns')),
                'self_cpu_ns':row.get('cpu_ns'),'checks':row.get('checks'),
                'scope':'full initialize includes before/after diagnostics and state fingerprint; import interval is not pure import syscall cost'}
            tables['initialization'].append(item)
            for name in ('initialization_wall_ns','through_import_observation_ns','data_or_blas_preparation_ns','post_initialization_observation_ns','self_cpu_ns'):
                metric('NP_'+name,item[name],'ns',item['scope'],role=role,nonce=nonce)
            for side in ('before','after'):
                sample=memory(row.get(side,{}).get('memory',{}),'preload_'+side,role,nonce)
                if role=='Z':z_memory_samples.append({**sample,'zygote_pid':row.get('pid_namespace_local'),'source':row['_source']})
        if row.get('event')=='NP_Z_CHECK':
            snap=row.get('snapshot',{});mem=memory(snap.get('memory',{}),'Z_post_request_check','Z',row.get('nonce'))
            z_memory_samples.append({**mem,'zygote_pid':row.get('pid_namespace_local'),'source':row['_source']})
            tables['zygote_growth'].append({**base,'nonce':row.get('nonce'),'source':row['_source'],
                'zygote_pid':row.get('pid_namespace_local'),'monotonic_ns':row.get('monotonic_ns'),
                'pss_KiB':mem['pss_KiB'],'rss_KiB':mem['rss_KiB'],'private_dirty_KiB':mem['private_dirty_KiB'],
                'fd_count':len(snap['fds']) if isinstance(snap.get('fds'),dict) else None,
                'fd_objects':snap.get('fds'),'thread_count':len(snap['threads']) if isinstance(snap.get('threads'),list) else None,
                'stable':row.get('stable'),'fingerprint':row.get('fingerprint'),
                'scope':'boundary samples with growing diagnostics/buffers and cache effects; growth alone is not a leak'})
    for row in costs:
        if row.get('kind')=='memory' and row.get('role') in ('H','R'):
            values={k:number(str(v).split()[0]) for k,v in row.get('values',{}).items() if str(v).endswith('kB')}
            memory({'pid':row.get('sampled_pid'),'monotonic_ns':row.get('ns'),'KiB':values,
                    'error':row.get('error')},row.get('name'),'H' if row['role']=='H' else 'R',row.get('nonce'))
        if row.get('name')=='zygote_ready_memory' and row.get('kind')=='memory':
            values={k:number(str(v).split()[0]) for k,v in row.get('values',{}).items() if str(v).endswith('kB')}
            sample=memory({'pid':row.get('sampled_pid'),'monotonic_ns':row.get('ns'),'KiB':values,
                           'error':row.get('error')},'Z_ready_from_R','Z',row.get('nonce'))
            z_memory_samples.append({**sample,'zygote_pid':number(row.get('sampled_pid')),'source':row['_source']})
    trajectories=defaultdict(list)
    for sample in z_memory_samples:
        if sample.get('zygote_pid') is not None:trajectories[sample['zygote_pid']].append(sample)
    for pid,samples in trajectories.items():
        observed=sorted((s for s in samples if isinstance(s.get('pss_KiB'),(int,float)) and isinstance(s.get('monotonic_ns'),int)),key=lambda s:s['monotonic_ns'])
        unique={sample['monotonic_ns']:sample for sample in observed};observed=list(unique.values())
        trapezoid=left_hold=right_hold=None
        if len(observed)>=2:
            trapezoid=left_hold=right_hold=0.0
            for left,right in zip(observed,observed[1:]):
                seconds=(right['monotonic_ns']-left['monotonic_ns'])/1e9
                left_hold+=left['pss_KiB']*seconds;right_hold+=right['pss_KiB']*seconds
                trapezoid+=(left['pss_KiB']+right['pss_KiB'])*0.5*seconds
        ready_for_pid=[r for r in costs if r.get('name')=='zygote_ready_memory' and number(r.get('sampled_pid'))==pid]
        ready_ns=ready_for_pid[0]['ns'] if ready_for_pid else None
        creation=[r['ns'] for r in costs if r.get('name')=='zygote_create_begin' and ready_ns is not None and r['ns']<=ready_ns]
        requested=max(creation) if creation else None
        true_wait,wait_owner=z_wait(pid)
        sampled_ns=observed[-1]['monotonic_ns']-observed[0]['monotonic_ns'] if len(observed)>=2 else None
        lifetime_ns=difference(requested,true_wait)
        valid_count=sum(isinstance(s.get('pss_KiB'),(int,float)) and isinstance(s.get('monotonic_ns'),int) for s in samples)
        tables['zygote_memory_time'].append({**base,'zygote_pid':pid,'available_samples':len(observed),
            'unavailable_samples':len(samples)-valid_count,'duplicate_timestamp_samples':valid_count-len(observed),'sampled_span_ns':sampled_ns,
            'lifecycle_requested_to_true_wait_ns':lifetime_ns,
            'true_wait_evidence':wait_owner,
            'sample_span_fraction_of_lifecycle':sampled_ns/lifetime_ns if sampled_ns is not None and lifetime_ns else None,
            'first_sample_ns':observed[0]['monotonic_ns'] if observed else None,
            'last_sample_ns':observed[-1]['monotonic_ns'] if observed else None,
            'PSS_KiB_seconds_trapezoid_estimate':trapezoid,
            'PSS_KiB_seconds_left_hold_sensitivity':left_hold,'PSS_KiB_seconds_right_hold_sensitivity':right_hold,
            'samples':[{key:s.get(key) for key in ('phase','monotonic_ns','pss_KiB','rss_KiB','source','nonce')} for s in observed],
            'scope':'discrete Z-only PSS integral between observed endpoints; no extrapolation before/after; left/right are interpolation sensitivity, not rigorous bounds; excludes S/W/H/R'})
    integrals=[row['PSS_KiB_seconds_trapezoid_estimate'] for row in tables['zygote_memory_time']]
    metric('all_Z_PSS_time_observed_spans_estimate',sum(integrals) if integrals and all(v is not None for v in integrals) else None,
           'KiB*s','sum of Z-only sparse observed-span trapezoid estimates; uncovered initialization/exit edges and other roles excluded')
    all_z_pids=set(trajectories)|{r['pid'] for r in costs if r.get('role')=='Z'}
    for pid in sorted(all_z_pids):
        records=[r for r in costs if r.get('role')=='Z' and r.get('pid')==pid]
        checks=[r for r in numpy if r.get('event')=='NP_Z_CHECK' and r.get('pid_namespace_local')==pid]
        last_check=max((r['monotonic_ns'] for r in checks),default=None)
        last_record=max((r['ns'] for r in records),default=None)
        waited,owner=z_wait(pid)
        tables['zygote_flush_tail'].append({**base,'zygote_pid':pid,'COST_records_logged':len(records),
            'COST_raw_log_bytes':sum(r['_raw_bytes'] for r in records),
            'last_NP_Z_CHECK_ns':last_check,'last_COST_sample_ns':last_record,'true_wait_ns':waited,
            'true_wait_evidence':owner,'last_template_check_to_true_wait_ns':difference(last_check,waited),
            'last_COST_sample_to_true_wait_ns':difference(last_record,waited),
            'scope':'tail includes protocol finish, FD close, diagnostic flush, exit, scheduling and parent wait; not isolated flush CPU; logged bytes do not equal Python ROWS heap size'})
    growth_by_pid=defaultdict(list)
    for row in tables['zygote_growth']:growth_by_pid[row['zygote_pid']].append(row)
    for pid,rows in growth_by_pid.items():
        rows.sort(key=lambda r:r.get('monotonic_ns',0));first,last=rows[0],rows[-1]
        delta=lambda key:last[key]-first[key] if isinstance(first.get(key),(int,float)) and isinstance(last.get(key),(int,float)) else None
        tables['zygote_growth_summary'].append({**base,'zygote_pid':pid,'observed_checks':len(rows),
            'observed_distinct_attempts':len({r['nonce'] for r in rows if r['nonce']}),
            'first_ns':first.get('monotonic_ns'),'last_ns':last.get('monotonic_ns'),
            'first_pss_KiB':first.get('pss_KiB'),'last_pss_KiB':last.get('pss_KiB'),'pss_delta_KiB':delta('pss_KiB'),
            'first_rss_KiB':first.get('rss_KiB'),'last_rss_KiB':last.get('rss_KiB'),'rss_delta_KiB':delta('rss_KiB'),
            'first_fd_count':first.get('fd_count'),'last_fd_count':last.get('fd_count'),'fd_delta':delta('fd_count'),
            'scope':'first observed post-request check to last check for this real Z; not pre-initialization-to-final, and not proof of leak or stability'})
    for role,startname,endname in [('H','supervisor_initial_usage','supervisor_final_usage'),
                                   ('R','controller_initial_usage','process_exit_usage')]:
        a=pick(startname,role);b=pick(endname,role)
        if role=='R' and b is None:b=pick('controller_final_usage',role)
        cpu=None if not a or not b else sum(b.get(k,0)-a.get(k,0) for k in ('cpu_user_ns','cpu_system_ns'))
        tables['cpu'].append({**base,'role':role,'self_cpu_ns':cpu,'start_event':startname,'end_event':b.get('name') if b else None,
            'waited_children_cpu_ns':None if not a or not b else sum(b.get(k,0)-a.get(k,0) for k in ('waited_children_user_ns','waited_children_system_ns')),
            'maxrss_KiB':b.get('maxrss_kib') if b else None,'scope':'self CPU interval; waited children separate, final diagnostic flush may follow sample'})
        metric(role+'_session_self_cpu_ns',cpu,'ns','role self interval; not added to cgroup or waited-child CPU')
    z_pids=sorted({r['pid'] for r in costs if r.get('role')=='Z' and r.get('name')=='zygote_ready_usage'})
    for pid in z_pids:
        ready=pick('zygote_ready_usage','Z',pid=pid);end=pick('zygote_final_usage','Z',pid=pid)
        cumulative=lambda row:sum(row.get(k,0) for k in ('cpu_user_ns','cpu_system_ns')) if row else None
        startup=cumulative(ready);final_cpu=cumulative(end)
        tables['cpu'].append({**base,'role':'Z','pid':pid,'startup_to_ready_self_cpu_ns':startup,
            'birth_to_final_sample_self_cpu_ns':final_cpu,
            'ready_to_final_self_cpu_ns':final_cpu-startup if final_cpu is not None and startup is not None else None,
            'maxrss_KiB':end.get('maxrss_kib') if end else None,
            'scope':'per real Z process cumulative CPU; cold has one Z per request; do not combine child CPU'})
    z_final=[r['birth_to_final_sample_self_cpu_ns'] for r in tables['cpu'] if r['role']=='Z']
    metric('all_Z_birth_to_final_sample_self_cpu_ns',sum(z_final) if z_final and all(v is not None for v in z_final) else None,'ns','sum self CPU across separate real Z processes; includes startup, excludes post-sample flush and children')
    role_cpu={r['role']:r['self_cpu_ns'] for r in tables['cpu'] if r['role'] in ('H','R')}
    task_cpu=[r['cpu_usage_us'] for r in tables['cgroup'] if r['group']=='task']
    z_sum=sum(z_final) if z_final and all(v is not None for v in z_final) else None
    task_sum=sum(task_cpu)*1000 if task_cpu and all(v is not None for v in task_cpu) else None
    components=[role_cpu.get('H'),role_cpu.get('R'),z_sum,task_sum]
    tables['cpu_ledger'].append({**base,'H_observed_self_cpu_ns':role_cpu.get('H'),'R_observed_self_cpu_ns':role_cpu.get('R'),
        'Z_observed_self_cpu_ns':z_sum,'domain_task_cgroup_cpu_ns':task_sum,
        'nonoverlapping_observed_cpu_subtotal_ns':sum(components) if all(v is not None for v in components) else None,
        'task_cgroups_sampled':len(task_cpu),'Z_processes_final_cpu_sampled':sum(v is not None for v in z_final),
        'full_sequence_complete':result.get('complete'),
        'scope':'partial measured subtotal only: H/R self samples + each template Z self sample + one hierarchical task cgroup per domain. Z remains template sibling cgroup; S/W/control are inside task. Never add waited-child CPU or task child cgroups. Excludes H/R initialization before first sample, role final flush after sample, fixture/reference, and any interrupted unsampled process/domain; not exact total request CPU.'})
    return {'base':base,'tables':tables,'issues':issues,'source_sha256':sources,'duplicate_log_records':duplicate_count,
            'cost_records':len(costs),'numpy_records':len(numpy),'qualification':'NOT_DECIDED_BY_COST_ANALYZER'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs',nargs='+',type=Path)
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args();directories=[]
    for path in args.runs:
        nested=sorted((path/'sessions').glob('*')) if (path/'sessions').is_dir() else []
        directories.extend([p for p in nested if p.is_dir()] if nested else [path])
    directories=list(dict.fromkeys(p.resolve() for p in directories))
    assert all(p.is_dir() for p in directories),'missing input run'
    args.out.mkdir(parents=True,exist_ok=False)
    analyses=[analyze(path) for path in directories];combined=defaultdict(list)
    for item in analyses:
        for name,rows in item['tables'].items():combined[name].extend(rows)
    for pair,rows in itertools.groupby(sorted((r for r in combined['sessions'] if r.get('pair')),key=lambda r:r['pair']),key=lambda r:r['pair']):
        rows=list(rows);variants={r['baseline']:r for r in rows}
        if set(variants)=={'cold','hot'} and len(rows)==2:
            a,b=variants['cold'],variants['hot']
            comparable=all(a.get(k)==b.get(k) for k in ('level','np_case','audit','actual_attempts','warmup','timing','diagnostics'))
            observed=a.get('full_sequence_ns') is not None and b.get('full_sequence_ns') is not None
            combined['paired'].append({'pair':pair,'cold_run':a['run'],'hot_run':b['run'],'level':a['level'],'audit':a['audit'],
                'actual_attempts':a['actual_attempts'],'same_configuration':comparable,
                'cold_full_sequence_ns':a.get('full_sequence_ns'),'hot_full_sequence_ns':b.get('full_sequence_ns'),
                'cold_minus_hot_ns':a['full_sequence_ns']-b['full_sequence_ns'] if comparable and observed else None,
                'both_complete':a.get('complete') is True and b.get('complete') is True,
                'independent_qualification':'must be supplied separately; no automatic performance admission',
                'scope':'same VM complete H/R/Z sequences; natural caches and explicit order; includes initialization/final cleanup'})
    grouped=defaultdict(list)
    for row in combined['metrics']:
        key=tuple(row.get(k) for k in ('pair','session','baseline','level','audit','case','request_case','outcome','actual_attempts','metric','unit','role'))
        grouped[key].append(row['value'])
    stats=[]
    keys=('pair','session','baseline','level','audit','case','request_case','outcome','actual_attempts','metric','unit','role')
    for key,values in grouped.items():
        valid=[v for v in values if isinstance(v,(int,float))]
        stats.append({**dict(zip(keys,key)),'n':len(valid),'missing':len(values)-len(valid),
            'median':statistics.median(valid) if valid else None,'p90':percentile(valid,.9),
            'minimum':min(valid) if valid else None,'maximum':max(valid) if valid else None,
            'tail_claim':'descriptive interpolation only; no production tail guarantee'})
    combined['statistics']=stats
    for name,rows in combined.items():write_csv(args.out/(name+'.csv'),rows)
    payload={'runs':analyses,'tables':dict(combined),'limitations':[
        'Cost analysis never grants lifecycle, NumPy/fork, security or performance qualification.',
        'All time differences are within one guest; host/VM boot times are not subtracted from guest timestamps.',
        'Full unadjusted sequence and H true wait are primary; final delegation endpoint additionally includes the 100ms observer fixture.',
        'The 40ms test-descendant sleep remains charged; overlap-subtracted residuals are not counterfactual predictions.',
        'Initialization and W workload durations include admission diagnostics, snapshots, hashing and output validation.',
        'Hot first preload and final Z stop are session costs; cold creates/stops a new Z for every call.',
        'PSS/RSS are sampled, not peaks; no physical-memory claim from RSS summation; cgroup charges and process CPU are not additive.',
        'Cold gated W has not imported NumPy while hot gated W inherited it. Gated PSS is not a matched initialization-stage comparison.',
        'W NP_RESULT before/after samples have completed NumPy initialization in both paths, but W-only PSS excludes resident Z/S and cannot show system net savings.',
        'Z PSS-time uses sparse trapezoidal interpolation only inside observed endpoints; no extrapolation; it is not an exact memory-time integral or whole-system physical-memory cost.',
        'Pagemap exclusive/soft-dirty/present flags and requested write sizes do not measure exact COW-copy bytes.',
        'Z growth can include buffered evidence, allocator and cache state; these short sequences cannot establish long-term leak freedom.',
        'Failures, missing timestamps and unknown results are retained, never filled from another session.' ]}
    (args.out/'numpy-cost.json').write_text(json.dumps(payload,ensure_ascii=False,indent=2)+'\n')
    shutil.copy2(Path(__file__),args.out/'analyze_numpy_cost.py')
    (args.out/'analyzer-sha256.txt').write_text(sha(Path(__file__))+'  analyze_numpy_cost.py\n')
    print(json.dumps({'out':str(args.out),'sessions':len(analyses),'attempts':len(combined['requests']),
                      'issues':sum(len(x['issues']) for x in analyses),'qualification':'NOT_DECIDED_BY_COST_ANALYZER'}))


if __name__=='__main__':main()
