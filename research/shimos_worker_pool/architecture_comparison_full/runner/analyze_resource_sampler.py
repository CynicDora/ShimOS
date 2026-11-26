"""Read-only resource-sampler interpretation; never execution qualification."""
import hashlib
import json
import statistics


def integer(value):
    try:return int(value)
    except (ValueError,TypeError):return None


def keyed(value):
    if not isinstance(value,str):return {}
    return {parts[0]:integer(parts[1]) for line in value.splitlines()
            for parts in [line.split()] if len(parts)==2}


def analyze_resources(directory,base,full_start,full_end,numpy_windows):
    tables={name:[] for name in ('resource_batches','resource_processes','resource_cgroup_samples',
                                'resource_integrals','resource_observer','session_resource_ledger','template_resource_ledger',
                                'resource_role_summary','resource_role_growth')}
    sources={};issues=[]
    def load(name):
        path=directory/name
        if not path.is_file():return None
        sources[name]=hashlib.sha256(path.read_bytes()).hexdigest()
        return json.loads(path.read_text())
    def value_phase(start,end):
        matches=[n for n,left,right in numpy_windows if left<=start and end<=right]
        return ('numpy_initialized_business',matches[0]) if len(matches)==1 else ('unmatched_or_cross_phase',None)
    path=directory/'resource-observer.jsonl';start_event=None;stop_event=None
    if path.is_file():
        sources[path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
        for lineno,line in enumerate(path.open(),1):
            try:event=json.loads(line)
            except ValueError:
                issues.append({'file':path.name,'line':lineno,'problem':'MALFORMED_RESOURCE_JSON'});continue
            if event.get('clock')!='CLOCK_MONOTONIC':issues.append({'file':path.name,'line':lineno,'problem':'RESOURCE_CLOCK_MISMATCH'})
            if event.get('event')=='RESOURCE_OBSERVER_START':start_event=event;continue
            if event.get('event')=='RESOURCE_OBSERVER_STOP':stop_event=event;continue
            if event.get('event')!='RESOURCE_BATCH':continue
            left=event['start_ns'];right=event['end_ns'];phase,nonce=value_phase(left,right)
            records=event.get('processes',[])
            complete=event.get('membership_census_stable') is True and all(r.get('observed') is True for r in records)
            pss=[r.get('memory_KiB',{}).get('Pss') for r in records]
            observed=complete and all(isinstance(v,int) for v in pss)
            tables['resource_batches'].append({**base,'sequence':event['sequence'],'start_ns':left,'end_ns':right,
                'midpoint_ns':(left+right)//2,'sampling_span_ns':right-left,'phase':phase,'nonce':nonce,
                'enumerated_processes':len(records),'valid_identity_processes':sum(r.get('observed') is True for r in records),
                'membership_census_stable':event.get('membership_census_stable'),'all_process_samples_observed':observed,
                'batch_sum_pss_KiB':sum(pss) if observed else None,'errors':event.get('errors'),
                'scope':'sum only identity/membership-stable batch, sequential not atomic PSS; missing/changing member invalidates batch sum'})
            for row in records:
                memory=row.get('memory_KiB',{});before=row.get('identity_before',{});after=row.get('identity_after',{})
                tables['resource_processes'].append({**base,'sequence':event['sequence'],'phase':phase,'nonce':nonce,
                    'pid':row['pid'],'start_ticks':before.get('start_ticks'),'role':row['role'],
                    'start_ns':row['start_ns'],'end_ns':row['end_ns'],'sample_midpoint_ns':(row['start_ns']+row['end_ns'])//2,
                    'observed':row.get('observed'),'error':row.get('error'),'cgroup':row.get('cgroup_observed'),
                    'identity_stable':row.get('identity_stable'),'membership_stable':row.get('membership_stable'),
                    'pss_KiB':memory.get('Pss') if row.get('observed') else None,
                    'rss_KiB':memory.get('Rss') if row.get('observed') else None,
                    'private_dirty_KiB':memory.get('Private_Dirty') if row.get('observed') else None,
                    'shared_dirty_KiB':memory.get('Shared_Dirty') if row.get('observed') else None,
                    'fd_count':row.get('fd_count'),'cpu_user_ticks':after.get('user_ticks'),
                    'cpu_system_ticks':after.get('system_ticks'),'threads':after.get('threads')})
            root=start_event.get('cgroup_root') if start_event else None
            for row in event.get('cgroups',[]):
                cpu=keyed(row.get('cpu.stat'));events=keyed(row.get('cgroup.events'))
                tables['resource_cgroup_samples'].append({**base,'sequence':event['sequence'],'path':row['path'],
                    'is_product_root':row['path']==root,'start_ns':row['start_ns'],'end_ns':row['end_ns'],
                    'midpoint_ns':(row['start_ns']+row['end_ns'])//2,'memory_current_bytes':integer(row.get('memory.current')),
                    'memory_peak_bytes':integer(row.get('memory.peak')),'cpu_usage_us':cpu.get('usage_usec'),
                    'pids_current':integer(row.get('pids.current')),'pids_peak':integer(row.get('pids.peak')),
                    'populated':events.get('populated'),'scope':'hierarchical accounting; never sum parent and children'})
        if start_event is None or stop_event is None:issues.append({'file':path.name,'problem':'RESOURCE_OBSERVER_ENDPOINT_MISSING'})
        status=load('resource-observer-status.json')
        tables['resource_observer'].append({**base,'start':start_event,'stop':stop_event,'status':status,
            'observer_cpu_ns':stop_event.get('observer_self_cpu_ns') if stop_event else None,
            'observer_wall_ns':stop_event.get('observer_wall_ns') if stop_event else None,
            'samples':stop_event.get('samples') if stop_event else None,
            'skipped_intervals':stop_event.get('skipped_intervals') if stop_event else None,
            'sampling_wall_ns':stop_event.get('total_sampling_wall_ns') if stop_event else None})
    else:
        status=load('resource-observer-status.json')
        if status and status.get('status')=='DISABLED_PAIRED_DIAGNOSTIC':
            tables['resource_observer'].append({**base,'start':None,'stop':None,'status':status,
                'observer_cpu_ns':None,'observer_wall_ns':None,'samples':None,'skipped_intervals':None,
                'sampling_wall_ns':None,'scope':'explicitly disabled; memory observations are N/A, not zero'})
        else:issues.append({'file':path.name,'problem':'RESOURCE_OBSERVER_NOT_OBSERVED'})
    full=full_end-full_start if isinstance(full_start,int) and isinstance(full_end,int) else None
    def integrate(label,rows,value,unit):
        rows=sorted(rows,key=lambda r:r['midpoint_ns']);integral=left_hold=right_hold=0.;covered=0;gaps=[];pairs=0
        for left,right in zip(rows,rows[1:]):
            a=left.get(value);b=right.get(value);dt=right['midpoint_ns']-left['midpoint_ns']
            if isinstance(a,(int,float)) and isinstance(b,(int,float)) and dt>0 and right['sequence']==left['sequence']+1:
                lower=max(left['midpoint_ns'],full_start) if isinstance(full_start,int) else left['midpoint_ns']
                upper=min(right['midpoint_ns'],full_end) if isinstance(full_end,int) else right['midpoint_ns']
                if upper<=lower:continue
                # Clip the already observed segment to the primary sequence.
                # Do not charge the observer's final post-H-wait batch to H.
                aa=a+(b-a)*(lower-left['midpoint_ns'])/dt
                bb=a+(b-a)*(upper-left['midpoint_ns'])/dt
                duration=upper-lower
                integral+=(aa+bb)*.5*duration/1e9;left_hold+=a*duration/1e9;right_hold+=b*duration/1e9;covered+=duration;pairs+=1;gaps.append(dt)
        valid=[r[value] for r in rows if isinstance(r.get(value),(int,float))]
        tables['resource_integrals'].append({**base,'metric':label,'unit':unit+'*s','samples':len(rows),'valid_samples':len(valid),
            'integral_trapezoid':integral if pairs else None,'left_hold_sensitivity':left_hold if pairs else None,
            'right_hold_sensitivity':right_hold if pairs else None,'covered_ns':covered,'full_session_ns':full,
            'covered_fraction':covered/full if full else None,'largest_included_sample_gap_ns':max(gaps) if gaps else None,
            'sampled_max':max(valid) if valid else None,
            'scope':'adjacent valid observed batches clipped to fixture_start..true_wait_H; linear interpolation only within observed segments, no extrapolation or crossing missing batches; not rigorous bounds or continuous peak'})
    integrate('product_root_charged_memory_time',[r for r in tables['resource_cgroup_samples'] if r['is_product_root']],
              'memory_current_bytes','bytes')
    integrate('product_batch_PSS_time',tables['resource_batches'],'batch_sum_pss_KiB','KiB')
    ledger=load('session-resource-ledger.json')
    if ledger:
        for group in ('session_parent','H_R_client'):
            row=ledger.get(group,{});cpu=keyed(row.get('cpu.stat'));events=keyed(row.get('memory.events'))
            tables['session_resource_ledger'].append({**base,'group':group,'at_ns':ledger.get('at_ns'),
                'cpu_usage_us':cpu.get('usage_usec'),'cpu_user_us':cpu.get('user_usec'),'cpu_system_us':cpu.get('system_usec'),
                'memory_peak_bytes':integer(row.get('memory.peak')),'memory_current_bytes':integer(row.get('memory.current')),
                'memory_oom':events.get('oom'),'memory_oom_kill':events.get('oom_kill'),
                'pids_current':integer(row.get('pids.current')),'accounting':ledger.get('accounting'),'scope':ledger.get('scope')})
    else:issues.append({'file':'session-resource-ledger.json','problem':'FINAL_PRODUCT_LEDGER_NOT_OBSERVED'})
    for path in sorted(directory.glob('template-resource-*.json')):
        row=load(path.name);tables['template_resource_ledger'].append({**base,'file':path.name,'raw':row})
    roles=('H','R','Z','S','W','DOMAIN_CONTROL')
    for role in roles:
        candidates=[r for r in tables['resource_processes'] if r['role']==role and
                    (not isinstance(full_start,int) or r['start_ns']>=full_start) and
                    (not isinstance(full_end,int) or r['end_ns']<=full_end)]
        for phase in ('all_observed_primary_sequence','numpy_initialized_business'):
            selected=[r for r in candidates if phase=='all_observed_primary_sequence' or r['phase']==phase]
            valid=[r for r in selected if r['observed'] is True]
            row={**base,'role':role,'phase':phase,'sample_count':len(selected),'valid_sample_count':len(valid),
                 'distinct_process_identities':len({(r['pid'],r['start_ticks']) for r in valid}),
                 'status':'OBSERVED' if valid else 'NOT_APPLICABLE' if base.get('architecture_group')=='G0' and role in ('Z','S') else 'NOT_OBSERVED',
                 'scope':'individual identity-stable process samples wholly inside primary sequence, pooled within role; sampled extrema are not peaks and roles are not summed; phase coverage may differ by architecture'}
            for key in ('pss_KiB','rss_KiB','private_dirty_KiB','shared_dirty_KiB','fd_count'):
                values=[r[key] for r in valid if isinstance(r.get(key),(int,float))]
                row[key+'_median']=statistics.median(values) if values else None
                row[key+'_min']=min(values) if values else None
                row[key+'_max']=max(values) if values else None
            tables['resource_role_summary'].append(row)
        identities=sorted({(r['pid'],r['start_ticks']) for r in candidates if r['observed'] is True})
        for pid,start_ticks in identities:
            points=sorted((r for r in candidates if r['observed'] is True and
                           (r['pid'],r['start_ticks'])==(pid,start_ticks)),key=lambda r:r['sample_midpoint_ns'])
            first,last=points[0],points[-1]
            row={**base,'role':role,'pid':pid,'start_ticks':start_ticks,'samples':len(points),
                 'first_sample_ns':first['sample_midpoint_ns'],'last_sample_ns':last['sample_midpoint_ns'],
                 'observed_span_ns':last['sample_midpoint_ns']-first['sample_midpoint_ns'],
                 'scope':'within one actual PID/starttime; sparse first-to-last observed change, not birth-to-exit or a leak verdict; R rows and qualification evidence may intentionally accumulate with N'}
            for key in ('pss_KiB','rss_KiB','private_dirty_KiB','fd_count'):
                row['first_'+key]=first.get(key);row['last_'+key]=last.get(key)
                row['delta_'+key]=last[key]-first[key] if len(points)>=2 and all(isinstance(x.get(key),(int,float)) for x in (first,last)) else None
                present=[r[key] for r in points if isinstance(r.get(key),(int,float))]
                row['sampled_max_'+key]=max(present) if present else None
            tables['resource_role_growth'].append(row)
    return {'tables':tables,'source_sha256':sources,'issues':issues}
