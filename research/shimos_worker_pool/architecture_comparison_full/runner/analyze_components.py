#!/usr/bin/env python3
"""Offline architecture component analysis; preserves missing/failed samples.

No workload execution. Uses the same-guest CLOCK_MONOTONIC event domain only.
Component wall intervals are descriptive coverage, not additive critical-path
contributions or hypothetical speedups. CPU is only reported where measured.
"""
import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path

from analyze_cost import collect, records, analyze_run, describe, union_ns


def component(name, role):
    if name.startswith('runtime_snapshot') or name.startswith('worker_qualification'):
        return 'qualification_diagnostics'
    if name.startswith('native_callback_sample'):
        return 'qualification_callback_security_sample'
    if name.startswith('native_callback_log') or name.startswith('python_callback'):
        return 'qualification_callback_and_recording'
    if name.startswith('timing_'):
        return 'measurement_probe'
    if name in ('evidence_json_write','controller_journal','controller_event_write',
                'lifecycle_evidence_write','worker_ready_evidence_write','output_evidence_write'):
        return 'evidence_and_recovery_recording'
    if name.startswith('supervisor_'):
        return 'supervisor_H'
    if name.startswith('controller_message') or name=='controller_poll':
        return 'controller_R'
    if name.startswith('rpc_'):
        return 'blocking_RPC_envelope'
    if name.startswith('ipc_'):
        return 'IPC_encoding_transport_decode'
    if name.startswith('native_prepare') or name.startswith('native_parent') or name.startswith('native_child') or name.startswith('native_callback'):
        return 'native_atfork_callbacks'
    if name.startswith('fork_'):
        return 'fork_bridge_wrapper'
    if name.startswith('enter_'):
        return 'namespace_root_cwd'
    if name.startswith('drop_') or name=='worker_forbid_exec':
        return 'capabilities_NNP_seccomp'
    if name.startswith('close_') or name=='controller_close_attempt_fds':
        return 'necessary_FD_close'
    if name.startswith('wait'):
        return 'real_wait_calls'
    if name in ('cgroup_delete','workspace_delete'):
        return 'resource_delete'
    if name=='artificial_descendant_sleep':
        return 'controlled_40ms_test_delay'
    if name=='controlled_payload_compute_write':
        return 'controlled_payload'
    if 'gate' in name or name in ('worker_setsid','zygote_message_service','zygote_poll'):
        return 'gate_and_message_service'
    if name.startswith('PID1_'):
        return 'domain_PID1'
    if name.startswith('bwrap_') or name in ('domain_reference_validation','native_launcher_spawn','domain_cgroup_workspace_prepare'):
        return 'domain_creation_and_identity'
    return 'unclassified_observed_span'


def csv_new(path, rows):
    fields=list(dict.fromkeys(k for r in rows for k in r))
    with path.open('x') as out:
        writer=csv.DictWriter(out,fieldnames=fields);writer.writeheader()
        for row in rows:
            writer.writerow({k:json.dumps(v,ensure_ascii=False,separators=(',',':')) if isinstance(v,(dict,list)) else v for k,v in row.items()})


def max_cpu_sum(spans):
    """Same-role nonnested measured CPU only, not system/cgroup total."""
    candidates=[s for s in spans if isinstance(s.get('thread_cpu_ms'),(int,float))]
    maximal=[]
    for s in candidates:
        if any(o is not s and o['start_ns']<=s['start_ns'] and o['end_ns']>=s['end_ns']
               and (o['start_ns']<s['start_ns'] or o['end_ns']>s['end_ns']) for o in candidates):
            continue
        maximal.append(s)
    for i,s in enumerate(maximal):
        for o in maximal[i+1:]:
            if max(s['start_ns'],o['start_ns'])<min(s['end_ns'],o['end_ns']):
                return None,'overlapping maximal CPU samples'
    return (sum(s['thread_cpu_ms'] for s in maximal) if maximal else None,
            'measured same-thread CPU only; nested same-component samples excluded')


def analyze(run):
    raw,duplicates,malformed,sources=collect(run)
    raw.sort(key=lambda e:e['ns'])
    base=analyze_run(run,None,None)
    receipts=records(run)
    index={(r['session'],r['nonce']):r for r in base['requests']}
    spans=[];missing=[];derived=[];aggregates=[]
    for e in raw:
        if e.get('kind')=='aggregate':
            r=index.get((e.get('session'),e.get('nonce')),{})
            aggregates.append(dict(run=str(run),session=e.get('session'),nonce=e.get('nonce'),variant=e.get('variant'),
                measurement_mode=r.get('measurement_mode','session_or_unclassified'),sample_class=r.get('sample_class','session'),
                case=r.get('case'),role=e.get('role'),pid=e.get('pid'),name=e.get('name'),result=e.get('result'),
                count=e.get('count'),wall_ms=e.get('total_wall_ns')/1e6 if isinstance(e.get('total_wall_ns'),int) else None,
                thread_cpu_ms=e.get('total_thread_cpu_ns')/1e6 if isinstance(e.get('total_thread_cpu_ns'),int) else None,
                minimum_ns=e.get('min_wall_ns'),maximum_ns=e.get('max_wall_ns'),
                first_observed_ns=e.get('first_observed_ns'),last_observed_ns=e.get('last_observed_ns'),
                notes='sum of discrete empty/ECHILD polls, NOT a continuous interval or critical-path union'))
            continue
        if e.get('kind') not in ('span','c_span'):continue
        a,b=e.get('start_ns'),e.get('end_ns')
        valid=(e.get('clock')=='CLOCK_MONOTONIC' and isinstance(a,int) and isinstance(b,int)
               and a>0 and b>=a and e.get('clock_valid',True))
        if not valid:
            missing.append({'origin':e.get('_origin'),'reason':'invalid component span','event':e});continue
        r=index.get((e.get('session'),e.get('nonce')),{})
        row=dict(run=str(run),session=e.get('session'),variant=e.get('variant'),diagnostics=e.get('diagnostics'),
                 measurement_mode=r.get('measurement_mode','session_or_unclassified'),nonce=e.get('nonce'),
                 sample_class=r.get('sample_class','session'),case=r.get('case'),role=e.get('role'),pid=e.get('pid'),
                 component=component(str(e.get('name')),e.get('role')),name=e.get('name'),branch=e.get('branch','local'),
                 message=e.get('message'),start_ns=a,end_ns=b,wall_ms=(b-a)/1e6,
                 thread_cpu_ms=e.get('thread_cpu_ns')/1e6 if isinstance(e.get('thread_cpu_ns'),int) else None,
                 cpu_clock=e.get('cpu_clock'),timing_eligible=r.get('timing_eligible'),
                 receipt=r.get('receipt'),source=e.get('_origin'))
        spans.append(row)
    for key,r in index.items():
        own=[e for e in raw if (e.get('session'),e.get('nonce'))==key]
        phase=collections.defaultdict(list)
        for e in own:
            if e.get('kind')=='phase':phase[e['name']].append(e)
        def point(name,role=None):
            found=[e for e in phase[name] if role is None or e.get('role')==role]
            return found[0]['ns'] if len(found)==1 else None
        receipt=receipts.get(key[1],{})
        ready=receipt.get('domain_ready_record',{})
        if not ready:
            candidates=[e.get('pid1_record') for e in phase['domain_fd_received'] if e.get('pid1_record')]
            ready=candidates[0] if len(candidates)==1 else {}
        drained=receipt.get('drained',{})
        t=ready.get('timing',{});d=drained.get('timing',{})
        if ready and (t.get('clock')!='CLOCK_MONOTONIC' or ready.get('timing_error')!=0):
            missing.append({'nonce':key[1],'reason':'PID1 ready timing missing or invalid','record':ready})
        def add(name,a,b,role,notes):
            item=dict(run=str(run),session=key[0],variant=r['variant'],diagnostics=r['variant'],
                      measurement_mode=r['measurement_mode'],nonce=key[1],sample_class=r['sample_class'],
                      case=r['case'],role=role,name=name,component=component(name,role),
                      start_ns=a,end_ns=b,wall_ms=(b-a)/1e6 if isinstance(a,int) and isinstance(b,int) and a>0 and b>=a else None,
                      timing_eligible=r['timing_eligible'],notes=notes)
            derived.append(item)
        add('domain_cgroup_workspace_prepare',point('domain_build_begin','R'),point('bwrap_spawn_begin','R'),'R','cgroup creation, budgets, workspace and sockets; not namespace setup')
        add('bwrap_spawn_to_PID1_C_main',point('bwrap_spawn_begin','R'),t.get('entry_ns'),'R+bwrap+PID1','includes launcher, exec loader, scheduling and all bwrap setup; no exclusive syscall attribution')
        for name,a,b in [('PID1_main_to_ready','entry_ns','ready_ns'),('PID1_dumpable','policy_begin_ns','dumpable_done_ns'),
                         ('PID1_NNP','dumpable_done_ns','nnp_done_ns'),('PID1_seccomp','nnp_done_ns','policy_end_ns'),
                         ('PID1_export_objects','export_begin_ns','export_end_ns'),('PID1_nonce_marker','marker_begin_ns','marker_end_ns')]:
            add(name,t.get(a),t.get(b),'PID1','existing message carries local same-guest timestamps; nested total not additive')
        for name,a,b in [('PID1_READY_sendmsg','ready_send_begin_ns','ready_send_end_ns'),
                         ('PID1_close_export_FDs','ready_send_end_ns','exports_closed_ns'),
                         ('PID1_STOP_to_DRAINED_record','stop_received_ns','drained_record_ns')]:
            add(name,d.get(a),d.get(b),'PID1','available only when final DRAINED message was received')
        add('PID1_ready_to_R_received',t.get('ready_ns'),point('domain_fd_received','R'),'PID1+R','JSON/sendmsg/scheduling/receiver completion; not pure IPC CPU')
        add('request_to_business_enter',point('request_begin','R'),point('business_enter','W'),'critical_boundary','permission gate passed and Python business entered; includes qualification code after entry separately')
        add('W_branch_to_business_gate',point('worker_branch_enter','W'),point('worker_business_gate_ready','W'),'W','includes required setup and RP diagnostic before gate; not full first-fork creation')
        add('W_business_end_to_S_wait_return',point('business_end','W'),point('worker_waited','S'),'W+S','includes exit and buffered telemetry flush plus S scheduling; not pure wait syscall')
        add('W_business_end_to_output_EOF',point('business_end','W'),point('output_eof','R'),'W+descendant+R','includes inherited output holders and controlled 40ms sleep; not fixed sandbox overhead')
        add('S_wait_W_to_Z_wait_S',point('worker_waited','S'),point('transition_waited','Z'),'S+Z','S report/exit/timing flush and Z polling/scheduling')
        if d.get('wait_total_wall_ns') is not None:
            derived.append(dict(run=str(run),session=key[0],variant=r['variant'],diagnostics=r['variant'],measurement_mode=r['measurement_mode'],nonce=key[1],sample_class=r['sample_class'],case=r['case'],role='PID1',name='PID1_sum_wait_syscalls',component='real_wait_calls',wall_ms=d['wait_total_wall_ns']/1e6,wait_calls=d.get('wait_calls'),timing_eligible=r['timing_eligible'],notes='sum of disjoint PID1 waitpid calls; not time spent waiting for descendants, not CPU'))
    session_boundaries=[]
    for session in sorted({e.get('session') for e in raw},key=str):
        own=[e for e in raw if e.get('session')==session]
        def endpoint(name,role):
            rows=[e for e in own if e.get('kind')=='phase' and e.get('name')==name and e.get('role')==role]
            return rows[0]['ns'] if len(rows)==1 else None
        def sess(name,left,right,notes):
            x,y=endpoint(*left),endpoint(*right)
            session_boundaries.append(dict(run=str(run),session=session,variant=own[0].get('variant'),name=name,
                start_ns=x,end_ns=y,wall_ms=(y-x)/1e6 if isinstance(x,int) and isinstance(y,int) and y>=x else None,
                notes=notes,measurement_mode='traced_diagnostic' if base['tracing_enabled'] else 'untraced'))
        sess('cold_fixture_to_R_started',('fixture_session_start','fixture'),('session_begin','R'),'includes H creation, R creation and trusted imports; no build or VM boot')
        sess('cold_H_enter_to_R_started',('supervisor_enter','H'),('session_begin','R'),'H setup/fork and R scheduler/constructor entry; overlaps H parent branch')
        sess('cold_Z_create_to_Z_ready',('zygote_create_begin','R'),('zygote_ready','Z'),'new template cgroup, loader/Python, self-owned initialization and mandatory probe installation')
        sess('cold_Z_create_to_R_READY_received',('zygote_create_begin','R'),('zygote_ready_received','R'),'includes receiver validation/mapping evidence before this marker')
        sess('cold_fixture_to_R_Z_READY_received',('fixture_session_start','fixture'),('zygote_ready_received','R'),'cold H/R/Z phase before first domain; no later warm request creation')
        sess('session_R_end_to_H_waited',('session_end','R'),('session_supervisor_waited','fixture'),'includes process evidence flush, actual H wait and H final fsync/release')
        sess('H_abnormal_recovery_to_release',('supervisor_recovery_begin','H'),('supervisor_released','H'),'only actual abnormal recovery; N/A on normal sessions, before H buffered cost flush')
        sess('session_product_through_H_wait',('fixture_session_start','fixture'),('session_supervisor_waited','fixture'),'includes all requests and final resource cleanup; excludes final root observer sleep')
    per_request=[]
    groups=collections.defaultdict(list)
    for s in spans:
        groups[(s['session'],s['nonce'],s['role'],s['pid'],s['component'])].append(s)
    for (session,nonce,role,pid,comp),items in groups.items():
        r=index.get((session,nonce),{})
        a,b=r.get('start_ns'),r.get('end_ns')
        clipped=[(max(x['start_ns'],a),min(x['end_ns'],b)) for x in items if a is not None and b is not None and x['start_ns']<b and x['end_ns']>a]
        cpu,note=max_cpu_sum(items)
        inside=[x for x in items if a is not None and b is not None and x['start_ns']>=a and x['end_ns']<=b]
        in_cpu,in_note=max_cpu_sum(inside)
        straddling=[x for x in items if a is not None and b is not None and x['start_ns']<b and x['end_ns']>a and not (x['start_ns']>=a and x['end_ns']<=b)]
        per_request.append(dict(run=str(run),session=session,nonce=nonce,variant=items[0]['variant'],measurement_mode=r.get('measurement_mode','session_or_unclassified'),sample_class=r.get('sample_class','session'),case=r.get('case'),role=role,pid=pid,component=comp,calls=len(items),wall_union_ms=union_ns([(x['start_ns'],x['end_ns']) for x in items])/1e6,within_request_union_ms=union_ns(clipped)/1e6,measured_thread_cpu_ms=cpu,cpu_note=note,within_request_measured_thread_cpu_ms=in_cpu,within_request_cpu_note=in_note,partly_outside_request_spans=len(straddling),timing_eligible=r.get('timing_eligible'),notes='same-process interval union only; different components/roles overlap and cannot be summed'))
    return dict(run=str(run),baseline_analysis=base,spans=spans,derived=derived,per_request=per_request,aggregates=aggregates,session_boundaries=session_boundaries,missing=missing,sources=sources,duplicates=duplicates)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('runs',nargs='+',type=Path);p.add_argument('--outdir',required=True,type=Path);a=p.parse_args()
    a.outdir.mkdir(parents=True,exist_ok=False)
    results=[analyze(run) for run in a.runs]
    spans=[s for r in results for s in r['spans']];derived=[s for r in results for s in r['derived']];per=[s for r in results for s in r['per_request']]
    aggregates=[s for r in results for s in r['aggregates']]
    groups=collections.defaultdict(list)
    # Raw failures and missing values remain in exports. Main normal summaries
    # use measured, receipt-qualified rows only and retain traced/untraced split.
    for s in spans+derived:
        if s.get('sample_class')=='measured' and s.get('timing_eligible') is True and isinstance(s.get('wall_ms'),(int,float)):
            groups[(s['variant'],s['measurement_mode'],s.get('case'),s['role'],s['name'],s.get('branch','local'),s.get('message'))].append(s)
    summary=[]
    for key,items in sorted(groups.items(),key=lambda item:tuple(str(v) for v in item[0])):
        summary.append(dict(zip(('variant','measurement_mode','case','role','name','branch','message'),key),wall_ms=describe(s['wall_ms'] for s in items),thread_cpu_ms=describe(s['thread_cpu_ms'] for s in items if isinstance(s.get('thread_cpu_ms'),(int,float))),sessions=sorted({s['session'] for s in items}),note='per-call distribution, not per-request sum; N/A CPU remains missing'))
    report=dict(scope='architecture component diagnostics; not proof of architecture optimality',clock='same guest CLOCK_MONOTONIC',analyzer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),component_distributions=summary,runs=results,limitations=['Per-role component wall unions are overlapping observations, not additive total latency.','Thread CPU exists only for Python instrumented spans; C/syscall wall is not kernel CPU.','Failure traces and missing events remain in raw exports; qualified normal distributions exclude them explicitly.','Controlled descendants sleep 40ms; this is a workload control, not ShimOS intrinsic cost.','Low mode retains mandatory runtime/security probes and is not a production zero-diagnostic executor.'])
    (a.outdir/'component-results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    csv_new(a.outdir/'mechanism-spans.csv',spans);csv_new(a.outdir/'derived-boundaries.csv',derived);csv_new(a.outdir/'per-request-components.csv',per);csv_new(a.outdir/'poll-aggregates.csv',aggregates);csv_new(a.outdir/'cold-and-session-boundaries.csv',[s for r in results for s in r['session_boundaries']])
    rows=['# 架构组件实测索引','', '单位 ms；同名机制分进程角色统计。嵌套/并行跨度不能相加。只有已完成、计时合格且非热身样本进入下表；全部失败与缺失记录保留在 JSON/CSV。','', '|模式|测量类型|角色|机制|n|wall median|wall p90|CPU median|','|---|---|---|---|---:|---:|---:|---:|']
    def fmt(v):return 'N/A' if v is None else f'{v:.3f}'
    for r in summary:
        rows.append('|'+ '|'.join(str(v) for v in [r['variant'],r['measurement_mode'],r['role'],r['name']+(':'+str(r['message']) if r['message'] else ''),r['wall_ms']['n'],fmt(r['wall_ms']['median']),fmt(r['wall_ms']['p90']),fmt(r['thread_cpu_ms']['median'])])+'|')
    (a.outdir/'component-summary.md').write_text('\n'.join(rows)+'\n')
    print(json.dumps({'outdir':str(a.outdir),'runs':len(results),'spans':len(spans),'derived':len(derived),'summary_groups':len(summary),'missing':sum(len(r['missing']) for r in results)},ensure_ascii=False))

if __name__=='__main__':main()
