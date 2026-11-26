#!/usr/bin/env python3
"""Summarize explicitly selected long/measurement-switch pilots; no admission."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import statistics


def csv_write(path, rows):
    columns=sorted({k for row in rows for k in row})
    with path.open('x',newline='') as stream:
        writer=csv.DictWriter(stream,columns);writer.writeheader();writer.writerows(rows)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('analysis',type=Path);parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    path=args.analysis/'numpy-cost.json';data=json.loads(path.read_text());t=data['tables']
    assert all(str(r.get('pair','')).startswith(('pilot-','sensitivity-')) for r in t['sessions']), 'diagnostic pilots only'
    args.out.mkdir(parents=True,exist_ok=False)
    sessions={r['run']:r for r in t['sessions']}
    def rows(name,run):return [r for r in t.get(name,[]) if r.get('run')==run]
    def first(name,run,predicate=lambda r:True):return next((r for r in rows(name,run) if predicate(r)),{})
    def metric(name,run):return first('metrics',run,lambda r:r.get('metric')==name).get('value')
    def maximum(values):
        values=[v for v in values if isinstance(v,(float,int))]
        return max(values) if values else None
    def minimum(values):
        values=[v for v in values if isinstance(v,(float,int))]
        return min(values) if values else None
    def scaled(value,unit):return value/unit if isinstance(value,(int,float)) else None
    summary=[]
    for run,s in sessions.items():
        calls=[r['numpy_call_ns'] for r in rows('requests',run) if isinstance(r.get('numpy_call_ns'),int)]
        flush=rows('stream_flushes',run);growth=rows('zygote_growth_summary',run)
        observer=first('resource_observer',run);root=first('session_resource_ledger',run,lambda r:r['group']=='session_parent')
        full=scaled(s.get('full_sequence_ns'),1e9);deadline=s.get('session_deadline_seconds')
        residual=deadline-full if isinstance(deadline,(int,float)) and full is not None else None
        summary.append({k:s.get(k) for k in ('run','pair','architecture_group','declared_N','actual_attempts','timing',
            'resource_sample_ms','complete','summary_passed','H_release_state','H_resources_removed','H_echild',
            'H_attempts','H_retired','H_output_eof','delegation_removed','host_timeout_intervention')} | {
            'full_sequence_s':full,'fixture_release_s':scaled(s.get('final_delegation_release_ns'),1e9),
            'fixture_post_H_wait_tail_ms':scaled(metric('fixture_post_H_wait_tail_ns',run),1e6),
            'shared_deadline_s':deadline,'deadline_minus_full_sequence_s':residual,
            'calls_observed':len(calls),'call_median_ms':scaled(statistics.median(calls) if calls else None,1e6),
            'call_max_ms':scaled(maximum(calls),1e6),'product_root_CPU_ms':scaled(root.get('cpu_usage_us'),1000),
            'product_root_memory_peak_MiB':scaled(root.get('memory_peak_bytes'),1024**2),
            'max_buffered_records':maximum(r.get('max_buffered_rows') for r in flush),
            'unconfirmed_records':maximum(r.get('unconfirmed_records') for r in flush),
            'Z_PSS_delta_min_KiB':minimum(r.get('pss_delta_KiB') for r in growth),
            'Z_PSS_delta_max_KiB':maximum(r.get('pss_delta_KiB') for r in growth),
            'Z_FD_delta_min':minimum(r.get('fd_delta') for r in growth),
            'Z_FD_delta_max':maximum(r.get('fd_delta') for r in growth),
            'observer_CPU_ms':scaled(observer.get('observer_cpu_ns'),1e6),
            'observer_CPU_over_observer_wall':observer['observer_cpu_ns']/observer['observer_wall_ns'] if observer.get('observer_wall_ns') else None,
            'observer_sampling_duty':observer['sampling_wall_ns']/observer['observer_wall_ns'] if observer.get('observer_wall_ns') else None,
            'observer_skipped_intervals':observer.get('skipped_intervals'),
            'scope':'pilot only; deadline headroom uses complete sequence, not prediction; Z deltas per actual Z, no cross-PID subtraction'})
    switches=[]
    for row in t.get('same_vm_switches',[]):
        setting=row['changed_setting']
        if setting not in ('timing','resource_sample_ms'):continue
        a=sessions[row['left_run']];b=sessions[row['right_run']]
        on,off=(a,b) if int(row['left_setting'])>0 else (b,a)
        full_on=on.get('full_sequence_ns');full_off=off.get('full_sequence_ns')
        valid=row.get('both_complete') is True and row.get('same_other_configuration') is True and all(isinstance(x,int) for x in (full_on,full_off))
        cpu_on=first('session_resource_ledger',on['run'],lambda r:r['group']=='session_parent').get('cpu_usage_us')
        cpu_off=first('session_resource_ledger',off['run'],lambda r:r['group']=='session_parent').get('cpu_usage_us')
        switches.append({k:row.get(k) for k in ('pair','architecture_group','changed_setting','declared_N','both_complete','same_other_configuration')} | {
            'actual_session_order':Path(row['left_run']).name+' → '+Path(row['right_run']).name,
            'on_run':on['run'],'off_run':off['run'],'on_setting':on.get(setting),'off_setting':off.get(setting),
            'on_wall_ms':scaled(full_on,1e6),'off_wall_ms':scaled(full_off,1e6),
            'on_minus_off_ms':(full_on-full_off)/1e6 if valid else None,
            'on_minus_off_fraction_of_off':(full_on-full_off)/full_off if valid and full_off else None,
            'on_product_CPU_ms':scaled(cpu_on,1000),'off_product_CPU_ms':scaled(cpu_off,1000),
            'on_minus_off_product_CPU_ms':(cpu_on-cpu_off)/1000 if valid and all(isinstance(x,int) for x in (cpu_on,cpu_off)) else None,
            'scope':'same-VM switch sensitivity; includes order/cache/scheduling variation; negative differences retained; not guaranteed causal saving'})
    csv_write(args.out/'pilot-sessions.csv',summary);csv_write(args.out/'measurement-switches.csv',switches)
    issues=[{'run':r['base']['run'],'issues':r['issues']} for r in data['runs'] if r['issues']]
    (args.out/'pilot-summary.json').write_text(json.dumps({'sessions':summary,'measurement_switches':switches,'issues':issues,
        'source':str(path.resolve()),'source_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
        'renderer_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'admission':'not decided here; use independently checked source and qualification'},indent=2,ensure_ascii=False)+'\n')
    def fmt(value,digits=2):return 'N/A' if value is None else f'{value:.{digits}f}'
    lines=['# 正式运行前诊断摘要','','这里只解释已选择 pilot，不混入正式架构性能结果。完整执行边界为创建 H 前至真实 wait(H)；夹具最终释放另列。','',
        '| VM / 组 | N / 实际 | 完整主时间 (s) | 共同期限余量 (s) | 最慢 call (ms) | 产品 CPU (ms) | 结果 / 回收 |',
        '|---|---:|---:|---:|---:|---:|---|']
    for r in summary:
        lines.append(f"| {r['pair']} / {r['architecture_group']} (t={r['timing']}, obs={r['resource_sample_ms']}ms) | {r['declared_N']} / {r['actual_attempts']} | {fmt(r['full_sequence_s'])} | {fmt(r['deadline_minus_full_sequence_s'])} | {fmt(r['call_max_ms'])} | {fmt(r['product_root_CPU_ms'])} | complete={r['complete']} / {r['H_release_state']} |")
    lines+=['','## 同 VM 开关对照','','正值表示开关开启更慢，负值原样保留。两个反向顺序 VM 只能提供扰动范围，不产生稳定尾分位或无条件因果加速结论。','',
        '| VM / 组 | 开关 | on−off (ms) | 相对 off | 产品 CPU 差 (ms) |',
        '|---|---|---:|---:|---:|']
    for r in switches:
        fraction=r['on_minus_off_fraction_of_off']
        lines.append(f"| {r['pair']} / {r['architecture_group']} | {r['changed_setting']} | {fmt(r['on_minus_off_ms'])} | {'N/A' if fraction is None else f'{fraction*100:.2f}%'} | {fmt(r['on_minus_off_product_CPU_ms'])} |")
    lines+=['','## 解释限制','','- 240 s 余量基于本次实际完整主时间；不能保证未来任意负载均不触发期限。',
        '- 有界缓冲、FD 恢复和最终资源回收需要独立资格核验，不能只根据耗时或零退出码判断。',
        '- 观察器 CPU 不在产品组内，仍可能改变产品 wall；不可从 wall 中直接减去该 CPU。',
        '- timing=0 只保留必要强制边界，未记录的内部阶段和 flush 成本为 N/A，不能补零。',
        '- N100 pilot 不替代正式三个 VM block，也不把其运行时间加入正式均值。','']
    (args.out/'pilot-diagnostics.md').write_text('\n'.join(lines))
    print(json.dumps({'out':str(args.out),'sessions':len(summary),'switch_pairs':len(switches),'runs_with_issues':len(issues)}))


if __name__=='__main__':main()
