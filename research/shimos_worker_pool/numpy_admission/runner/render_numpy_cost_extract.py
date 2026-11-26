#!/usr/bin/env python3
"""Render a concise, non-qualifying report from analyze_numpy_cost CSVs."""
import argparse
import csv
import json
from pathlib import Path
import statistics


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('analysis',type=Path)
    a=p.parse_args();base=a.analysis
    def rows(name):
        with (base/(name+'.csv')).open() as f:return list(csv.DictReader(f))
    tables={n:rows(n) for n in ('sessions','requests','initialization','worker','memory','cpu','cpu_ledger','cgroup','zygote_growth_summary','zygote_memory_time','zygote_flush_tail','cow')}
    def num(r,k):
        try:return float(r.get(k,''))
        except (ValueError,TypeError):return None
    def med(rs,k):
        vs=[num(r,k) for r in rs];vs=[v for v in vs if v is not None]
        return statistics.median(vs) if vs else None
    def fmt(v,div=1,places=1):return 'N/A' if v is None else f'{v/div:.{places}f}'
    def subset(name,s):return [r for r in tables[name] if r['run']==s['run']]
    def ident(s):return s['pair'].replace('paired-numpy-01-','').replace('paired-numpy-','')+'/'+s['baseline']
    text=[]
    def line(s=''):text.append(s)
    def table(headers,data):
        line('| '+' | '.join(headers)+' |');line('| '+' | '.join(['---']*len(headers))+' |')
        for row in data:line('| '+' | '.join(str(x) for x in row)+' |')
        line()
    line('# NumPy 成本原值摘录')
    line('由 analyze_numpy_cost 的 CSV 自动整理；本文件不授予安全、运行时或性能资格。每个方向只有两个同宿主 VM，timing0 只有一个敏感度 VM。')
    line()
    line('## 完整序列与独立资源释放事实')
    line('主终点为根夹具真实 wait(H) 返回，包含新 H/R/Z、初始化、全部请求和产品回收。最终 delegation release 另包含 100 ms observer 等夹具工作，不是纯产品延迟。部分请求失败和未执行不插值为 N=100。')
    line()
    table(['会话','timing','已登记/已RETIRE','完整N','主终点 ms','H release ms','最终夹具 release ms','H结果'],[
        [ident(s),s['timing'],s['H_registered']+'/'+s['H_retired'],s['complete'],fmt(num(s,'full_sequence_ns'),1e6),fmt(num(s,'H_release_evidence_ns'),1e6),fmt(num(s,'final_delegation_release_ns'),1e6),s['H_failure_reason'] or s['H_release_state'] or 'NOT_RUN'] for s in tables['sessions']])
    table(['会话','H真实wait R状态','H ECHILD','EOF/已登记','删除/已登记','FD恢复','H残留域/目录','observer补杀/删除'],[
        [ident(s),s['H_controller_wait_status'],s['H_echild'],s['H_output_eof']+'/'+s['H_registered'],s['H_attempt_resources_removed']+'/'+s['H_registered'],s['H_fds_restored'],s['H_remaining_cgroups']+'/'+s['H_remaining_workspaces'],s['observer_killed']+'/'+s['observer_removed']] for s in tables['sessions']])
    line('## 请求内耗时：仅完整序列，中位数 ms')
    line('call→gate 是业务许可门禁，cold 此时尚未 import NumPy；call→NumPy ready 是实际 outputs() 开始，已包含本轮 NumPy 前置观察/指纹检查。hot 首次初始化及最终 STOP 完整计入序列；中位数不能代表整段序列总成本。')
    line()
    complete=[s for s in tables['sessions'] if s['complete']=='True']
    table(['会话','建域','删cgroup','删workspace','call→gate','call→NumPy ready','domain→response','完整call'],[
        [ident(s),*[fmt(med(subset('requests',s),k),1e6,2) for k in ('domain_create_ns','cgroup_delete_ns','workspace_delete_ns','call_to_W_business_gate_ns','call_to_NumPy_compute_ready_ns','domain_request_to_response_ns','numpy_call_ns')]] for s in complete])
    line('## 初始化与业务')
    line('初始化包含准入快照/哈希；纯 outputs() 计算与验证输出分列。CPU 为进程自身，不包含子进程。')
    line()
    table(['会话','初始化次数','init wall ms','init CPU ms','W业务wall ms','outputs计算 ms'],[
        [ident(s),len(subset('initialization',s)),fmt(med(subset('initialization',s),'initialization_wall_ns'),1e6,2),fmt(med(subset('initialization',s),'self_cpu_ns'),1e6,2),fmt(med(subset('worker',s),'total_numpy_business_ns'),1e6,2),fmt(med(subset('worker',s),'compute_ns'),1e6,2)] for s in complete])
    line('## CPU：非重叠已采样小计，不是完整总 CPU')
    line('H/R 自身区间 + 所有真实 Z 的自身累计采样 + 每域 task cgroup（含 S/W/control）；不再加 waited-child 或 task 子组。缺少角色前后采样外的启动/flush，timing0 不补算；缺失或未完成序列不凑数。')
    line()
    table(['会话','H ms','R ms','Z总 ms','task cgroup总 ms','采样小计 ms'],[
        [ident(s),*[fmt(num(subset('cpu_ledger',s)[0],k),1e6) for k in ('H_observed_self_cpu_ns','R_observed_self_cpu_ns','Z_observed_self_cpu_ns','domain_task_cgroup_cpu_ns','nonoverlapping_observed_cpu_subtotal_ns')]] for s in complete if s['declared_N'] in ('50','100')])
    line('## 内存：各自采样，不相加声称物理节省')
    line('以下 PSS 为 MiB。gated 时 cold 尚未载入 NumPy、hot 已继承，阶段不匹配。W before/after 是双方都初始化后的匹配点，但仍排除额外驻留 Z/S。H/R 为初末样本；S/W/R 跨进程 smaps 权限不足时保留 N/A。')
    line()
    def memmed(s,role,phase,key='pss_KiB'):
        return med([r for r in subset('memory',s) if r['role']==role and r['phase']==phase],key)
    table(['会话','gate Z/S/W/R PSS','W匹配before/after PSS','Z末check PSS','H初/末 PSS','R初/末 PSS','task memory.peak max MiB'],[
        [ident(s),'/'.join(fmt(memmed(s,r,'worker_gated'),1024,2) for r in ('Z','S','W','R')),
         '/'.join(fmt(memmed(s,'W',phase),1024,2) for phase in ('numpy_business_before','numpy_business_after')),
         fmt(max([num(r,'last_pss_KiB') for r in subset('zygote_growth_summary',s) if num(r,'last_pss_KiB') is not None],default=None),1024,2),
         '/'.join(fmt(memmed(s,'H',phase),1024,2) for phase in ('supervisor_initial_memory','supervisor_final_memory')),
         '/'.join(fmt(memmed(s,'R',phase),1024,2) for phase in ('controller_initial_memory','controller_final_memory')),
         fmt(max([num(r,'memory_peak_charged_bytes') for r in subset('cgroup',s) if r['group']=='task' and num(r,'memory_peak_charged_bytes') is not None],default=None),1024**2,2)] for s in complete if s['declared_N'] in ('50','100')])
    line('## 热模板增长、稀疏内存时间与缓冲尾段')
    line('PSS-time 仅 Z、仅已观测端点之间的梯形近似；不补起止缺失段。日志字节不是 Python ROWS 堆大小；末条 COST→真实 wait(Z) 包含 flush、退出与调度，不能全部归为日志写入。')
    line()
    hot=[s for s in complete if s['baseline']=='hot']
    data=[]
    for s in hot:
        g=subset('zygote_growth_summary',s);mt=subset('zygote_memory_time',s);tail=subset('zygote_flush_tail',s)
        integral=sum(num(r,'PSS_KiB_seconds_trapezoid_estimate') or 0 for r in mt)
        coverage=med(mt,'sample_span_fraction_of_lifecycle')
        data.append([ident(s),s['timing'],fmt(med(g,'first_pss_KiB'),1024,2)+'→'+fmt(med(g,'last_pss_KiB'),1024,2),fmt(med(g,'pss_delta_KiB'),1,0),fmt(med(g,'fd_delta'),1,0),fmt(integral/1024),fmt(coverage,1,3),sum(int(r['COST_records_logged']) for r in tail),sum(int(r['COST_raw_log_bytes']) for r in tail),fmt(med(tail,'last_COST_sample_to_true_wait_ns'),1e6,2),fmt(med(tail,'last_template_check_to_true_wait_ns'),1e6,2)])
    table(['会话','timing','Z PSS MiB','增长KiB','FD增量','Z MiB·s估计','生命周期覆盖率','Z COST条数','原始COST字节','末COST→wait ms','末check→wait ms'],data)
    line('## COW 观察')
    line('正常负载只请求写 8 字节。page flags 的 exclusive/soft_dirty 不等于新复制页数；未 clear_refs。memory.peak 是 cgroup 记账峰值而非总物理内存，RSS 高水位只适用于对应进程；没有完整会话物理峰值或完整 COW 字节计数。')
    line()
    data=[]
    for s in complete:
        if s['declared_N'] not in ('50','100'):continue
        rs=subset('cow',s)
        fields=[]
        for side in ('pages_before','pages_after'):
            vals=[]
            for r in rs:
                parsed=json.loads(r[side]) if r.get(side) else {}
                if parsed.get('status')=='OBSERVED':vals.append(parsed)
            fields.extend([fmt(med(vals,'pages'),1,0),fmt(med(vals,'exclusive'),1,0),fmt(med(vals,'soft_dirty'),1,0)])
        data.append([ident(s),len(rs),*fields])
    table(['会话','已观测W','before页数','before独占','before软脏','after页数','after独占','after软脏'],data)
    line('## 原始列与限制')
    line('- 完整序列和回收：sessions.csv；逐请求身份、完整call、gate/NumPy-ready、建域和删除：requests.csv。')
    line('- 初始化、业务 CPU/wall：initialization.csv、worker.csv；不可重复计费的已观测小计：cpu_ledger.csv。')
    line('- PSS/RSS/Private_Dirty/Shared_Dirty 原值、时刻与错误：memory.csv；角色 maxrss：cpu.csv；域 memory.peak/current、CPU、OOM：cgroup.csv。')
    line('- Z 边界增长/FD集合：zygote_growth.csv 与 zygote_growth_summary.csv；Z 稀疏内存时间：zygote_memory_time.csv；末端与缓冲：zygote_flush_tail.csv。')
    line('- COW 请求量、page flags 和不可写模板指纹：cow.csv；不存在精确 COW-copy 字节测量。')
    line('- N100 截断请求必须保持 UNKNOWN；资源 RELEASED 不表示业务成功。timing0 对照只诊断测量扰动，不能据单次不同 VM 差额作因果性能结论。')
    out=base/'report-extract.md';out.open('x').write('\n'.join(text)+'\n')
    print(out)


if __name__=='__main__':main()
