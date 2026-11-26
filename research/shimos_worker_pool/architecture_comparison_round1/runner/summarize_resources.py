#!/usr/bin/env python3
"""Read-only, same-guest component/resource ledger; never qualifies execution.

Keep hierarchical cgroup CPU, waited-child CPU and role self CPU separate.
RSS/PSS are boundary observations, memory.peak is cgroup charged memory, and
ru_maxrss is the process lifetime high-water mark; none is interchangeable.
"""
import argparse
import csv
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def quantile(values, q):
    values=sorted(values)
    if not values:return None
    pos=(len(values)-1)*q;lo=int(pos);hi=math.ceil(pos)
    return values[lo]+(values[hi]-values[lo])*(pos-lo)


def read_json(path,issues,required=True):
    if not path.is_file():
        if required:issues.append({'file':str(path),'problem':'missing'})
        return {}
    try:return json.loads(path.read_text())
    except (OSError,ValueError) as exc:
        issues.append({'file':str(path),'problem':repr(exc)});return {}


def read_lines(path,issues):
    result=[]
    if not path.is_file():return result
    for line,text in enumerate(path.read_text(errors='replace').splitlines(),1):
        try:row=json.loads(text)
        except ValueError:
            if text.startswith('{'):issues.append({'file':str(path),'line':line,'problem':'unparseable JSON line'})
            continue
        if isinstance(row,dict):result.append(dict(row,_source_file=path.name,_source_line=line))
    return result


def proc_kib(value):
    if not isinstance(value,str):return None
    parts=value.split()
    return int(parts[0]) if len(parts)==2 and parts[1]=='kB' and parts[0].isdigit() else None


def kv_values(value):
    if not isinstance(value,str):return {}
    result={}
    for line in value.splitlines():
        parts=line.split()
        if len(parts)==2:
            try:result[parts[0]]=int(parts[1])
            except ValueError:result[parts[0]]=parts[1]
    return result


def int_value(value):
    try:return int(value)
    except (ValueError,TypeError):return None


def analyze(directory):
    directory=directory.resolve();issues=[];sources={}
    def read(name,required=True):
        path=directory/name
        if path.is_file():sources[name]=sha(path)
        return read_json(path,issues,required)
    config=read('review-config.json');manifest=read('variant-manifest.json')
    summary=read('summary.json');supervisor=read('supervisor.json');result=read('result.json')
    external=read('external-final-release.json');session_config=read('guest-session-config.json',False)
    session=session_config.get('session') or config.get('session') or config.get('cost_session')
    mode=config.get('diagnostics',config.get('variant','unknown'))
    logs=[];seen={}
    # serial.log mirrors guest-output.log; do not read both. If only serial
    # survived a failure, retain it and explicitly identify the source.
    guest_log=directory/'guest-output.log'
    if not guest_log.is_file():guest_log=directory/'serial.log'
    paths=[guest_log,*sorted(directory.glob('zygote-*.log')),
           *sorted(p for p in directory.glob('*-output.log') if p.name!='guest-output.log')]
    for path in dict.fromkeys(paths):
        if not path.is_file():continue
        sources[path.name]=sha(path)
        for row in read_lines(path,issues):
            if row.get('event')!='COST':continue
            key=(row.get('session'),row.get('role'),row.get('nonce'),row.get('pid'),row.get('seq'))
            clean={k:v for k,v in row.items() if not k.startswith('_')}
            if key in seen:
                if seen[key]!=clean:issues.append({'problem':'conflicting COST identity','identity':key})
                continue
            seen[key]=clean;logs.append(row)
    sessions={r.get('session') for r in logs}
    if session is None and len(sessions)==1:session=next(iter(sessions))
    if len(sessions)!=1 or sessions!={session}:issues.append({'problem':'mixed or missing guest session identity','sessions':sorted(str(s) for s in sessions),'expected':session})
    if any(r.get('clock')!='CLOCK_MONOTONIC' for r in logs):issues.append({'problem':'unexpected COST clock'})
    timing_errors=[r for r in logs if r.get('kind')=='measurement_error' or
                   (r.get('kind')=='measurement_metadata' and any(r.get('metadata',{}).get(k) for k in ('dropped','overflow','clock_errors')))]
    if timing_errors:issues.append({'problem':'measurement errors/incomplete exports','count':len(timing_errors)})
    logs.sort(key=lambda r:r.get('ns',0))
    hpath=directory/'supervisor-events.jsonl';h_events=read_lines(hpath,issues)
    if hpath.is_file():sources[hpath.name]=sha(hpath)
    base={'session':session,'diagnostics':mode,'run':str(directory),'case':config.get('case'),
          'timing':str(config.get('timing','unknown'))}
    intervals=[];cpu=[];memory=[];cgroups=[];waits=[];requests=[]

    def pick(name,role=None,nonce=None):
        rows=[r for r in logs if r.get('name')==name and (role is None or r.get('role')==role)
              and (nonce is None or r.get('nonce')==nonce)]
        return rows[0] if rows else None
    def phase(name,role=None):
        row=pick(name,role)
        return {'ns':row['ns'],'source':row['_source_file']+':'+str(row['_source_line']),
                'event':name} if row else None
    def hphase(name,controller_only=False):
        rows=[r for r in h_events if r.get('event')==name and
              (not controller_only or (r.get('role')=='controller' and r.get('pid')==supervisor.get('controller_pid')))]
        row=rows[0] if rows else None
        return {'ns':row['monotonic_ns'],'source':row['_source_file']+':'+str(row['_source_line']),
                'event':name} if row and isinstance(row.get('monotonic_ns'),int) else None
    def interval(name,start,end,scope,nonce=None):
        item={**base,'name':name,'nonce':nonce,'scope':scope,'start':start,'end':end,
              'duration_ns':end['ns']-start['ns'] if start and end else None,
              'clock':'same guest CLOCK_MONOTONIC','status':'observed' if start and end else 'not_observed'}
        if item['duration_ns'] is not None and item['duration_ns']<0:item['status']='opposite_order_observed'
        intervals.append(item);return item

    interval('fixture_to_H_enter',phase('fixture_session_start'),phase('supervisor_enter','H'),'cold: includes H fork and credential setup; excludes VM boot/build')
    interval('H_enter_to_R_first_point',phase('supervisor_enter','H'),phase('controller_forked','R'),'cold: H setup + R creation; not pure fork')
    interval('R_enter_to_Z_create',phase('session_begin','R'),phase('zygote_create_begin','R'),'cold: R initialization and diagnostics')
    interval('Z_create_to_ready_received',phase('zygote_create_begin','R'),phase('zygote_ready_received','R'),'cold: loader/interpreter/import/probes, readiness and validation')
    interval('Z_python_enter_to_ready_local',phase('zygote_python_enter','Z'),phase('zygote_ready','Z'),'cold: excludes Python startup before this module point')
    interval('cold_H_R_Z_ready',phase('fixture_session_start'),phase('zygote_ready_received','R'),'cold H/R/Z mechanism only; not VM boot or runtime installation')
    interval('session_HRZ_complete',phase('fixture_session_start'),phase('session_supervisor_waited'),'entire session through true wait H; includes final diagnostic flush')
    eof=hphase('CONTROLLER_CHANNEL_EOF');rwait=hphase('SUPERVISOR_REAL_WAIT',True)
    released=phase('supervisor_released','H') or hphase('SUPERVISOR_FINISHED')
    interval('H_R_channel_EOF_to_true_wait_R',eof,rwait,'H completion tail; EOF and process death are distinct')
    interval('H_true_wait_R_to_release_evidence',rwait,released,'H final resource checks, fsync and release evidence; excludes H cost flush')
    interval('H_recovery_start_to_release',hphase('SUPERVISOR_RECOVERY_START'),released,'abnormal path only; no inference for successful session')
    interval('H_release_evidence_to_fixture_wait_H',released,phase('session_supervisor_waited'),'H final memory/diagnostic flush and exit + parent true wait')

    def usage_difference(role,start,end,name,nonce=None):
        fields=('cpu_user_ns','cpu_system_ns','nvcsw','nivcsw')
        item={**base,'name':name,'role':role,'nonce':nonce,
              'start_event':start.get('name') if start else None,'end_event':end.get('name') if end else None,
              'start_ns':start.get('ns') if start else None,'end_ns':end.get('ns') if end else None,
              'status':'observed' if start and end else 'not_observed',
              'scope':'role self getrusage; does not include waited children or final unobserved flush'}
        for field in fields:item[field]=end.get(field,0)-start.get(field,0) if start and end else None
        item['self_cpu_ns']=item['cpu_user_ns']+item['cpu_system_ns'] if start and end else None
        item['end_process_lifetime_maxrss_kib']=end.get('maxrss_kib') if end else None
        # Kept separately for inspection; not added to self or cgroup totals.
        item['waited_children_cpu_user_delta_ns']=end.get('waited_children_user_ns',0)-start.get('waited_children_user_ns',0) if start and end else None
        item['waited_children_cpu_system_delta_ns']=end.get('waited_children_system_ns',0)-start.get('waited_children_system_ns',0) if start and end else None
        if any(item[k] is not None and item[k]<0 for k in fields):
            item['status']='invalid_negative_counter_delta';issues.append({'problem':'negative CPU/counter delta','record':item})
        cpu.append(item);return item

    for role,start_name,end_name in [('H','supervisor_initial_usage','supervisor_final_usage'),
                                     ('R','controller_initial_usage','process_exit_usage'),
                                     ('Z','zygote_ready_usage','zygote_final_usage')]:
        usage_difference(role,pick(start_name,role),pick(end_name,role),role+'_session_self_cpu')
    zready=pick('zygote_ready_usage','Z')
    cpu.append({**base,'name':'Z_ready_cumulative_startup_cpu','role':'Z','nonce':None,
                'status':'observed' if zready else 'not_observed',
                'cpu_user_ns':zready.get('cpu_user_ns') if zready else None,
                'cpu_system_ns':zready.get('cpu_system_ns') if zready else None,
                'self_cpu_ns':zready.get('cpu_user_ns',0)+zready.get('cpu_system_ns',0) if zready else None,
                'scope':'cumulative self CPU since Z process birth including loader/interpreter; not an interval subtraction'})
    request_files=sorted(directory.glob('attempt-*.json'))
    declared={r.get('nonce') for r in summary.get('rows',[])}
    for path in request_files:
        sources[path.name]=sha(path);row=read_json(path,issues);nonce=row.get('nonce');start=pick('request_begin','R',nonce);end=pick('response_ready','R',nonce)
        info={**base,'nonce':nonce,'request_case':row.get('case'),'repeat':start.get('repeat') if start else None,
              'warmup':start.get('warmup') if start else None,'outcome':row.get('outcome'),'resources':row.get('resources'),
              'response_committed':row.get('response_committed',False),'declared_in_summary':nonce in declared,
              'journal_writes':row.get('journal_writes'),'journal_updates_buffered':row.get('journal_updates_buffered')}
        requests.append(info)
        interval('request_response_ready',{'ns':start['ns'],'event':'request_begin','source':start['_source_file']} if start else None,
                 {'ns':end['ns'],'event':'response_ready','source':end['_source_file']} if end else None,
                 'R request to complete response evidence; not H/Z final release',nonce)
        item=usage_difference('R',pick('request_cpu_begin','R',nonce),pick('request_cpu_end','R',nonce),'R_request_self_cpu',nonce)
        item.update(repeat=info['repeat'],warmup=info['warmup'],outcome=info['outcome'])
        for group,data in row.get('stats',{}).items():
            stat=kv_values(data.get('cpu.stat'));memory_events=kv_values(data.get('memory.events'))
            cgroups.append({**base,'nonce':nonce,'repeat':info['repeat'],'warmup':info['warmup'],'outcome':info['outcome'],
               'group':group,'cpu_usage_usec':stat.get('usage_usec'),'cpu_user_usec':stat.get('user_usec'),
               'cpu_system_usec':stat.get('system_usec'),'nr_throttled':stat.get('nr_throttled'),
               'throttled_usec':stat.get('throttled_usec'),'memory_current_bytes':int_value(data.get('memory.current')),
               'memory_peak_charged_bytes':int_value(data.get('memory.peak')),'memory_oom':memory_events.get('oom'),
               'memory_oom_kill':memory_events.get('oom_kill'),'pids_current':int_value(data.get('pids.current')),
               'pids_events':kv_values(data.get('pids.events')),'cgroup_events':kv_values(data.get('cgroup.events')),
               'scope':'task is hierarchical parent; control/transition/business are subdivisions, never add parent and children; charged memory is not PSS'})
    for row in logs:
        if row.get('kind')=='memory':
            values=row.get('values',{});memory.append({**base,'nonce':row.get('nonce'),'name':row.get('name'),
                'collector_role':row.get('role'),'collector_pid':row.get('pid'),'sampled_pid':row.get('sampled_pid'),
                'ns':row.get('ns'),'rss_kib':proc_kib(values.get('Rss')),'pss_kib':proc_kib(values.get('Pss')),
                'private_clean_kib':proc_kib(values.get('Private_Clean')),'private_dirty_kib':proc_kib(values.get('Private_Dirty')),
                'shared_clean_kib':proc_kib(values.get('Shared_Clean')),'shared_dirty_kib':proc_kib(values.get('Shared_Dirty')),
                'error':row.get('error'),'scope':'one smaps_rollup boundary sample, neither peak nor memory-time integral'})
        if row.get('kind')=='aggregate' and row.get('name')=='waitpid_poll':
            relation='not_a_H_tail_record'
            if row.get('role')=='H' and eof and rwait and rwait['ns']>=eof['ns']:
                first,last=row.get('first_observed_ns'),row.get('last_observed_ns')
                relation=('inside' if first>=eof['ns'] and last<=rwait['ns'] else
                          'outside' if last<eof['ns'] or first>rwait['ns'] else 'overlaps_unresolved')
            waits.append({**base,'role':row.get('role'),'nonce':row.get('nonce'),'result':row.get('result'),
                **{k:row.get(k) for k in ('count','total_wall_ns','total_thread_cpu_ns','min_wall_ns','max_wall_ns','first_observed_ns','last_observed_ns')},
                'H_EOF_to_R_wait_relation':relation,
                'scope':'sum of actual individual calls, not a continuous span; overlapping aggregate cannot locate exact tail CPU/count'})
    return {'metadata':{**base,'source_sha256':sources,'core_source_sha256':manifest.get('source_sha256'),
                       'binary_sha256':manifest.get('binary_sha256'),'verifier_sha256':sha(Path(__file__)),
                       'formal_qualification':'not performed by this summarizer; bind separate admission report',
                       'complete':result.get('complete'),'timeout':result.get('timeout'),'qemu_rc':result.get('qemu_rc'),
                       'H_release_state':supervisor.get('release_state'),'H_failure_reason':supervisor.get('failure_reason'),
                       'fixture_delegation_removed':external.get('delegation_removed'),'measurement_errors':len(timing_errors)},
            'issues':issues,'requests':requests,'intervals':intervals,'role_cpu':cpu,
            'memory_samples':memory,'cgroup_samples':cgroups,'empty_wait_aggregates':waits}


def write_csv(path,rows):
    fields=list(dict.fromkeys(k for row in rows for k in row))
    with path.open('x',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader()
        for row in rows:writer.writerow({k:json.dumps(v,ensure_ascii=False,separators=(',',':')) if isinstance(v,(dict,list)) else v for k,v in row.items()})


def summarize(analyses):
    """Distributions of available observations, never qualification-filtered.

    Warmup, outcome and VM session remain explicit strata. A missing field is
    counted, not replaced by zero or quietly removed as an allegedly slow run.
    """
    groups=defaultdict(list)
    metrics={
        'intervals':('duration_ns',),
        'role_cpu':('self_cpu_ns','cpu_user_ns','cpu_system_ns','nvcsw','nivcsw'),
        'memory_samples':('rss_kib','pss_kib','private_dirty_kib'),
        'cgroup_samples':('cpu_usage_usec','cpu_user_usec','cpu_system_usec','memory_peak_charged_bytes','nr_throttled','throttled_usec'),
    }
    for item in analyses:
        request_map={r.get('nonce'):r for r in item.get('requests',[])}
        for category,fields in metrics.items():
            for row in item.get(category,[]):
                req=request_map.get(row.get('nonce'),{})
                for field in fields:
                    key=(row.get('diagnostics'),row.get('session'),category,row.get('name',row.get('group')),
                         req.get('request_case'),req.get('warmup'),req.get('outcome'),field)
                    groups[key].append(row.get(field))
    result=[]
    for key,items in sorted(groups.items(),key=lambda pair:repr(pair[0])):
        values=[x for x in items if isinstance(x,(int,float))]
        result.append(dict(zip(('diagnostics','session','category','component','request_case','warmup','outcome','metric'),key),
                           observations=len(items),measured=len(values),not_observed=len(items)-len(values),
                           median=quantile(values,.5),p90=quantile(values,.9),
                           minimum=min(values) if values else None,maximum=max(values) if values else None,
                           scope='available observations, no qualification or success filtering'))
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs',nargs='+',type=Path);parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    (args.out/'summarize_resources.py').write_bytes(Path(__file__).read_bytes())
    analyses=[]
    for path in args.runs:
        try:analyses.append(analyze(path))
        except Exception as exc:
            # Keep a failed or incomplete session visible; do not replace it by
            # the successful subset or report it as zero-cost execution.
            import traceback
            analyses.append({'metadata':{'run':str(path),'complete':False},'issues':[{'problem':repr(exc),'traceback':traceback.format_exc()}]})
    result={'schema':1,'sessions':analyses,'limitations':[
        'Only same-guest monotonic timestamps are subtracted. Separate VMs are independent clock domains.',
        'No source qualification or performance ranking is inferred by this read-only ledger.',
        'Self CPU, waited-child CPU and hierarchical cgroup CPU are separate overlapping accounting systems.',
        'H/R/Z final self CPU snapshots exclude some final measurement flush; final wall through wait(H) includes it.',
        'PSS/RSS are sparse boundary samples; cgroup memory.peak is charged memory, not physical shared footprint.',
        'Empty-wait aggregate totals are not contiguous time spans; exact tail attribution may be unavailable.',
        'The 40ms test descendant remains a synthetic workload delay, not intrinsic sandbox overhead.',
        'Missing or failed sessions are retained and not assigned zero cost.']}
    (args.out/'resource-ledger.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    for name in ('requests','intervals','role_cpu','memory_samples','cgroup_samples','empty_wait_aggregates'):
        write_csv(args.out/(name+'.csv'),[row for item in analyses for row in item.get(name,[])])
    statistics=summarize(analyses)
    (args.out/'resource-statistics.json').write_text(json.dumps(statistics,ensure_ascii=False,indent=2)+'\n')
    write_csv(args.out/'resource-statistics.csv',statistics)
    lines=['# 架构资源账本','',
           '本文件只整理实际样本，不代替资格验收。CPU、cgroup 记账和 PSS 不互相相加。','',
           '| 会话 | 模式 | H 释放 | 请求数 | 观测问题 |','|---|---|---|---:|---:|']
    for item in analyses:
        meta=item['metadata'];lines.append('| '+str(meta.get('session',meta.get('run')))+' | '+str(meta.get('diagnostics','N/A'))+' | '+str(meta.get('H_release_state','N/A'))+' | '+str(len(item.get('requests',[])))+' | '+str(len(item['issues']))+' |')
    lines+=['','## 同 guest 的 H 尾段','',
            '| 会话 | EOF → wait R（ms） | wait R → H释放证据（ms） | H 空wait次数 | H 空wait CPU（ms） |','|---|---:|---:|---:|---:|']
    def ms(v):return 'N/A' if v is None else f'{v/1e6:.3f}'
    for item in analyses:
        by={r['name']:r['duration_ns'] for r in item.get('intervals',[]) if r.get('nonce') is None}
        waits=[r for r in item.get('empty_wait_aggregates',[]) if r.get('role')=='H']
        lines.append('| '+str(item['metadata'].get('session'))+' | '+ms(by.get('H_R_channel_EOF_to_true_wait_R'))+' | '+ms(by.get('H_true_wait_R_to_release_evidence'))+' | '+(str(sum(r['count'] for r in waits)) if waits else 'N/A')+' | '+ms(sum(r['total_thread_cpu_ns'] for r in waits) if waits else None)+' |')
    lines+=['','空 wait 统计为整个 H 会话的实际空调用，不是全部发生于 EOF 尾段。跨越尾段边界的聚合不能恢复精确的尾段 CPU，CSV 中标为 overlaps_unresolved。','',
            '原始索引、哈希、未观测字段和逐请求数据见 resource-ledger.json 与各 CSV。']
    (args.out/'README.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({'out':str(args.out),'sessions':len(analyses),'issues':sum(len(x['issues']) for x in analyses)},ensure_ascii=False))


if __name__=='__main__':main()
