#!/usr/bin/env python3
"""Read-only, small-n traced qualification cost extraction; no new workloads."""
import argparse
import csv
import hashlib
import json
from pathlib import Path

from analyze_cost import collect


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('components',type=Path)
    p.add_argument('--outdir',required=True,type=Path)
    args=p.parse_args();args.outdir.mkdir(parents=True,exist_ok=False)
    data=json.loads(args.components.read_text());rows=[]
    for result in data['runs']:
        run=Path(result['run']);base=result['baseline_analysis'];events,_,_,_=collect(run)
        ordinary=read_jsonl(run/'events.jsonl');super_events=read_jsonl(run/'supervisor-events.jsonl')
        supervisor=json.loads((run/'supervisor.json').read_text())
        for request in base['requests']:
            case=request['case'];nonce=request['nonce']
            if case=='normal':continue
            phase=[e for e in events if e.get('kind')=='phase' and e.get('nonce')==nonce]
            own=[e for e in ordinary if e.get('nonce')==nonce]
            def one(xs,key):
                return xs[0].get(key) if len(xs)==1 else None
            def point(name):return one([e for e in phase if e.get('name')==name],'ns')
            name=('CANCEL_REQUEST' if case in ('cancel_queued','cancel_before_business','cancel_during_entry','double_cancel','timeout','revoke_ack_loss')
                  else 'SPAWN_REJECTED' if case=='pid_budget' else 'WORKER_REJECTED' if case=='second_budget'
                  else 'WORKER_WAITED' if case=='nonzero' else 'FAULT')
            trigger=one([e for e in own if e.get('event')==name],'monotonic_ns')
            def delta(a,b):return (b-a)/1e6 if isinstance(a,int) and isinstance(b,int) and b>=a else None
            h_begin=one([e for e in events if e.get('kind')=='phase' and e.get('name')=='supervisor_recovery_begin'],'ns')
            h_end=one([e for e in events if e.get('kind')=='phase' and e.get('name')=='supervisor_released'],'ns')
            h_empty=one([e for e in super_events if e.get('event')=='SUPERVISOR_QUIESCENCE'],'monotonic_ns')
            abnormal=case.startswith('controller_')
            row=dict(run=str(run),variant=request['variant'],case=case,nonce=nonce,measurement_mode=base['result_scope'],
                ordinary_result=request['outcome'],ordinary_business=request['business'],ordinary_resources=request['resources'],
                supervisor_business=supervisor['business_result'],supervisor_release=supervisor['release_state'],
                no_observer_cleanup=not supervisor['observer_cleanup_used'],trigger=name,trigger_ns=trigger,
                response_ready_ms=request['response_ready_ms'],trigger_to_domain_quiescent_ms=delta(trigger,point('domain_quiescent')),
                trigger_to_resources_deleted_ms=delta(trigger,point('resources_deleted')),
                trigger_to_response_ready_ms=delta(trigger,point('response_ready')),
                fault_to_H_quiescent_ms=delta(trigger,h_empty) if abnormal else None,
                fault_to_H_released_ms=delta(trigger,h_end) if abnormal else None,
                H_recovery_to_release_ms=delta(h_begin,h_end) if abnormal else None,
                timing_errors=base['errors'],complete_request_timing=request['timing_eligible'],
                notes='Only one/two traced observations per case/mode, not performance quantiles. CANCEL_REQUEST is logged after seal/journal/send, not cancellation API entry. H release is a session endpoint and is shown only for Controller-death cases. Dead R has no response-ready; its stale PENDING journal is not final H resource state.')
            rows.append(row)
    report=dict(scope='Traced qualification diagnostics only; independent product correctness remains in qualification-*-final.json',
        analyzer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),input_sha256=hashlib.sha256(args.components.read_bytes()).hexdigest(),
        measurements=rows,limitations=['Malformed COST serial lines are retained; affected request intervals are not admitted to timing comparison.',
            'R death can lose its buffered COST records; do not invent response timestamps. Actual H fault/recovery evidence is independent.',
            'A missing trigger or interval is N/A, not zero. No observer cleanup is counted as product completion.'])
    (args.outdir/'failure-costs.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    with (args.outdir/'failure-costs.csv').open('x') as out:
        w=csv.DictWriter(out,fieldnames=list(rows[0]));w.writeheader()
        for row in rows:w.writerow({k:json.dumps(v,ensure_ascii=False) if isinstance(v,list) else v for k,v in row.items()})
    def fmt(value):return 'N/A' if value is None else f'{value:.3f}'
    md=['# 失败、取消和 H 接管：小样本诊断','','全部来自打开 tracing 的资格运行；每种情况/模式通常只有 1 次，nonzero 有 2 次，不作性能排名或尾延迟推断。每行对应一次尝试，全部结果、缺失与错误保留在同目录 JSON/CSV。','',
        '`CANCEL_REQUEST` 在 seal、日志和发送之后记录，因此下面取消到回收仅为该明确事件之后的跨度，不能称为完整取消 API 延迟。非零退出从 R 收到 WORKER_WAITED 开始，预算失败从 R 收到拒绝消息开始。','',
        '|模式|场景|业务结果|H 最终资源|触发→域静止 ms|触发→资源删除 ms|请求→响应 ms|计时准入|',
        '|---|---|---|---|---:|---:|---:|---|']
    for r in rows:
        if r['case'].startswith('controller_'):continue
        admitted=r['complete_request_timing'] and not r['timing_errors']
        md.append('|'+ '|'.join([r['variant'],r['case'],str(r['ordinary_result'])+'/'+str(r['ordinary_business']),r['supervisor_release'],
            fmt(r['trigger_to_domain_quiescent_ms']) if admitted else 'N/A',fmt(r['trigger_to_resources_deleted_ms']) if admitted else 'N/A',
            fmt(r['response_ready_ms']) if admitted else 'N/A','实际小样本' if admitted else 'BLOCKED：COST 记录不完整'])+'|')
    md+=['','## Controller 死亡：H 的独立接管证据','','R 进程死亡导致其缓冲计时无法导出；不得补造完整请求时间。以下使用已落盘 FAULT 与 H 同 guest 单调时钟事件。H 的最终 UNKNOWN/RELEASED 为真实状态，不把 R 最后一个 PENDING 文件当成泄漏，也不将 UNKNOWN 改成成功。','',
        '|模式|场景|H业务/资源|fault→H quiescent ms|fault→H released ms|H recovery→release ms|',
        '|---|---|---|---:|---:|---:|']
    for r in rows:
        if not r['case'].startswith('controller_'):continue
        md.append('|'+ '|'.join([r['variant'],r['case'],r['supervisor_business']+'/'+r['supervisor_release'],fmt(r['fault_to_H_quiescent_ms']),fmt(r['fault_to_H_released_ms']),fmt(r['H_recovery_to_release_ms'])])+'|')
    md+=['','所有条目均 observer_cleanup_used=false；最终 release、真实 wait、EOF 和目录/cgroup 删除分别由既有独立资格核验，不仅检查退出码。',
        '', '计时限制：low-control 的 serial.log 第 988 行及 low-cancels 的第 1494 行存在 COST 片段合行/不完整，完整原始事件仍保留。它们的生命周期与 runtime 资格通过，但本诊断不接受其请求成本为完整性能样本；原始可读数值在 JSON/CSV 留存，未删掉慢样本。']
    (args.outdir/'failure-costs.md').write_text('\n'.join(md)+'\n')
    print(json.dumps({'outdir':str(args.outdir),'attempt_rows':len(rows),'timing_errors_retained':sum(bool(r['timing_errors']) for r in rows)}))


if __name__=='__main__':main()
