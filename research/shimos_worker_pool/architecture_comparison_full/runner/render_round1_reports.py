#!/usr/bin/env python3
"""Render final round-one results from explicit cost and admission artifacts."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import statistics
from analysis_admission import load_admission, STUDY

GROUPS=('G0','G1','G2')
NS=(1,2,5,10,25,50,100)


def request_distribution(requests, admitted):
    """Descriptive pooled requests, never independent-session tail inference."""
    output=[]
    for n in NS:
        for group in GROUPS:
            selected=[r for r in requests if r['architecture_group']==group and
                      int(r['declared_N'])==n and admitted(r['run'])]
            runs=sorted({r['run'] for r in selected})
            complete=(len(runs)==3 and all(sorted(int(r['index']) for r in selected if r['run']==run)==list(range(n)) for run in runs))
            durations=[int(r['numpy_call_ns'])/1e6 for r in selected if r.get('numpy_call_ns')]
            first=[int(r['numpy_call_ns'])/1e6 for r in selected if r.get('numpy_call_ns') and int(r['index'])==0]
            subsequent=[int(r['numpy_call_ns'])/1e6 for r in selected if r.get('numpy_call_ns') and int(r['index'])>0]
            complete=complete and len(durations)==3*n
            ordered=sorted(durations)
            position=(len(ordered)-1)*.9 if ordered else 0
            lower=int(position);upper=min(lower+1,len(ordered)-1)
            q90=(ordered[lower]+(ordered[upper]-ordered[lower])*(position-lower)) if ordered else None
            output.append({'N':n,'architecture_group':group,'admitted_sessions':len(runs),
                'planned_sessions':3,'requests_observed':len(durations),'requests_planned':3*n,
                'matrix_complete':complete,'call_median_ms':statistics.median(durations) if durations and complete else None,
                'call_p90_ms':q90 if complete else None,'call_min_ms':min(durations) if durations else None,
                'call_max_ms':max(durations) if durations else None,'first_request_count':len(first),
                'first_request_median_ms':statistics.median(first) if len(first)==3 else None,
                'subsequent_request_count':len(subsequent),
                'subsequent_request_median_ms':statistics.median(subsequent) if subsequent and complete else None,
                'quantile_method':'linear interpolation at (n-1)*0.9; descriptive correlated requests, no population tail claim',
                'scope':'numpy_call_begin to numpy_call_complete; G1 includes per-call Z start/stop; G2 first call includes preload, final session close is charged only in full sequence'})
    return output


def request_distribution_section(rows, csv_link):
    def display(value):return 'N/A' if value is None else f'{value:.2f}'
    lines=['## 正式请求分布与首轮/后续调用','',
        '这里统计每个 N、每组的 3N 条完整 call，口径是 numpy_call_begin→numpy_call_complete。G1 每次都包含新 Z 创建与关闭；G2 第一条包含一次 Z 预热，后续条复用该 Z。G0/G1 的后续请求仍会重新初始化应用，不能一概称为热 Worker 请求。最终 Z/H 关闭不摊入某条 call，继续由前面的完整序列 T 和 T/N 全额计费。','',
        'median/p90/min/max 是这批相关请求的描述性统计；p90 采用排序后 (n−1)×0.9 位置的线性插值，不是生产尾延迟保证。首轮仅有每 VM 一条，共 3 条；后续共 3(N−1) 条，N=1 时为 N/A。请求共享同一会话，不把它们当成独立重复，也不代替三个 VM 的配对主结果。','',
        '| N | 组 | 请求数 | call median ms | p90 ms | min–max ms | 首请求 median ms | 后续 median ms |',
        '|---|---|---|---|---|---|---|---|']
    for r in rows:
        lines.append('| '+' | '.join([str(r['N']),r['architecture_group'],
            str(r['requests_observed'])+'/'+str(r['requests_planned']),display(r['call_median_ms']),
            display(r['call_p90_ms']),display(r['call_min_ms'])+'–'+display(r['call_max_ms']),
            display(r['first_request_median_ms']),display(r['subsequent_request_median_ms'])])+' |')
    lines+=['',f'未四舍五入数据、首轮/后续样本数及口径见 [request-distribution.csv]({csv_link})。','']
    return lines


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('analysis',type=Path);p.add_argument('--admission',type=Path,required=True)
    p.add_argument('--figures',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--host-environment',type=Path,default=STUDY/'analysis/formal-host-environment.json')
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    names=('sessions','paired','requests','initialization','worker','memory','zygote_growth_summary',
           'session_resource_ledger','resource_integrals','resource_observer','resource_role_summary','resource_role_growth',
           'component_cpu_balance','adjacent_partition','stream_flushes')
    tables={};sources={}
    for name in names:
        file=a.analysis/(name+'.csv');sources[file.name]=hashlib.sha256(file.read_bytes()).hexdigest()
        tables[name]=list(csv.DictReader(file.open()))
    sessions=tables['sessions'];by_run={r['run']:r for r in sessions}
    admission,binding=load_admission(a.admission,by_run)
    matrix=json.loads(a.admission.read_text());plan=json.loads((STUDY/matrix['plan']['path']).read_text())
    host=json.loads(a.host_environment.read_text())
    assert host['status']=='COMPLETE' and host['plan_sha256']==matrix['plan']['sha256']
    figures=json.loads((a.figures/'figure-manifest.json').read_text())
    assert figures.get('profile')=='formal' and figures.get('admission_binding',{}).get('sha256')==binding['sha256']
    issues=json.loads((a.analysis/'measurement-issues.json').read_text())
    bad_measurements=[r for r in issues['runs'] if r['issues']]
    if bad_measurements:raise ValueError({'measurement_issues_require_explicit_review':bad_measurements})
    def num(r,key):
        try:return float(r.get(key,''))
        except (ValueError,TypeError):return None
    def admitted(run):
        row=by_run.get(run,{})
        return admission.get(run,{}).get('status')=='PASS' and row.get('complete')=='True' and row.get('actual_attempts')==row.get('declared_N')
    def select(name,arch_group,n=None,**conditions):
        return [r for r in tables[name] if r.get('architecture_group')==arch_group and admitted(r['run']) and
                (n is None or int(r['declared_N'])==n) and all(r.get(k)==str(v) for k,v in conditions.items())]
    def fmt(v,digits=2):return 'N/A' if v is None else f'{v:.{digits}f}'
    def stats(values,scale=1):
        values=[v/scale for v in values if isinstance(v,(int,float))]
        return {'n':len(values),'mean':statistics.mean(values) if values else None,
                'median':statistics.median(values) if values else None,
                'min':min(values) if values else None,'max':max(values) if values else None}
    def spread(values,scale=1,digits=2,center='median'):
        s=stats(values,scale)
        return 'N/A' if not s['n'] else fmt(s[center],digits)+' ['+fmt(s['min'],digits)+', '+fmt(s['max'],digits)+']'
    def triple(values,scale=1,digits=2,center='median'):
        s=stats(values,scale)
        return spread(values,scale,digits,center) if s['n']==3 else f"矩阵/观察未完成（{s['n']}/3）"
    def values(rows,key):return [num(r,key) for r in rows]
    def link(path):return os.path.relpath(Path(path).resolve(),STUDY)
    def image(name):return '!['+name+']('+link(a.figures/(name+'.png'))+')'
    def markdown_table(headers,rows):
        return ['| '+' | '.join(headers)+' |','|'+'---|'*len(headers)]+['| '+' | '.join(map(str,row))+' |' for row in rows]
    raw=[];sequence=[];cpu=[];mem=[];paired=[]
    for n in NS:
        for group in GROUPS:
            selected=select('sessions',group,n);raw_values=[]
            for block in (1,2,3):
                row=next((r for r in sessions if r['pair']==f'round1-n{n}-b{block}' and r['architecture_group']==group),None)
                raw_ns=num(row,'full_sequence_ns') if row is not None else None
                raw_s=raw_ns/1e9 if raw_ns is not None else None
                raw_values.append('NOT_EXPORTED' if row is None else fmt(raw_s,3) if admitted(row['run']) else admission[row['run']]['status']+':'+fmt(raw_s,3))
            sequence.append([n,group,*raw_values,triple(values(selected,'full_sequence_ns'),1e9,3),
                             triple(values(selected,'full_sequence_ns'),n*1e6,2),str(len(selected))+'/3'])
            raw+=selected
            root=select('session_resource_ledger',group,n,group='session_parent')
            cpu.append([n,group,triple(values(root,'cpu_usage_us'),1e6,3),triple(values(root,'memory_peak_bytes'),1024**2,2)])
            charge=select('resource_integrals',group,n,metric='product_root_charged_memory_time')
            pss=select('resource_integrals',group,n,metric='product_batch_PSS_time')
            mem.append([n,group,triple(values(charge,'integral_trapezoid'),1024**2,2),
                        triple(values(charge,'covered_fraction'),.01,1),triple(values(pss,'integral_trapezoid'),1024,2),
                        triple(values(pss,'covered_fraction'),.01,1)])
        for left in ('G0','G1'):
            rows=[r for r in tables['paired'] if int(r['declared_N'])==n and r['left_group']==left and r['right_group']=='G2' and admitted(r['left_run']) and admitted(r['right_run'])]
            ds=values(rows,'left_minus_right_ns');paired.append([n,left+'−G2',triple(ds,1e9,3),sum(v is not None and v>0 for v in ds),str(len(ds))+'/3'])
    failures=[{'run':run,**row} for run,row in admission.items() if not admitted(run)]
    io_max=max(r['io_some_avg10_max_percent'] for r in host['rows'])
    memory_max=max(r['memory_some_avg10_max_percent'] for r in host['rows'])
    io_window=max(host['rows'],key=lambda r:r['io_some_total_delta_percent_of_host_window'])
    pressure_note=(f"**宿主并非一直安静。** 正式采集窗口的 IO PSI some avg10 最高 {io_max:.2f}%，memory some avg10 最高 {memory_max:.2f}%；"
                   f"{io_window['run']} 的 whole-VM 已观察窗口 IO some 累计 stall 比例为 {io_window['io_some_total_delta_percent_of_host_window']:.2f}%。"
                   f"见[独立宿主聚合]({link(a.host_environment)})。这些窗口包含三组、VM 启动和夹具，avg10 还可能包含此前活动，不能当成某个请求的等待时间或进行 host/guest 时间相减。"
                   "全部样本保留；本轮只报告这三个 block 的方向和范围，不能声称无 I/O 干扰的精确延迟或普遍稳定回本。")
    b=['# G0 / G1 / G2 完整序列性能结果','',
       f"本轮预登记 {plan['sessions']} 个会话、{plan['total_requests']} 次调用。最终独立准入矩阵状态 **{matrix['status']}**，会话计数 `{json.dumps(matrix['session_counts'],ensure_ascii=False)}`。成本数据本身不授予执行资格；报告与[最终准入矩阵]({link(a.admission)})逐项绑定，未准入/不完整样本保留但不进入性能均值。",'',
       pressure_note,'',
       '## 比较对象与固定条件','',
       '| 组 | 执行方式 | 初始化状态 |','|---|---|---|',
       '| G0 | Bubblewrap 域内直接启动新 Python W；无 Z/S | 每请求在 W 初始化 NumPy |',
       '| G1 | 每请求创建新 Z，再经 S 派生 W | Z 不预加载 NumPy，W 冷初始化 |',
       '| G2 | 一个预加载 Z 服务整段序列，每请求新建执行域 | W 继承 NumPy 准备态；最后关闭 Z |','',
       f"N={','.join(map(str,NS))}，每个 N 三个独立 VM block，同一 VM 内三组按预登记顺序轮换。全部 VM 在同一物理宿主，{plan.get('vcpus')} vCPU、{plan.get('memory_mib')} MiB，固定任务限额和共同 {plan.get('session_deadline_seconds')} s 会话期限；没有共同全会话硬内存配额，因此不宣称固定整机会话预算下的容量胜负。",'',
       '使用固定 NumPy CPU 工作负载和相同 D 运行时、安全与生命周期合同。无在线 Agent、无第三方任意代码、无调度器。正式人工后代等待为 0；资格中的 40 ms 测试等待不进入本表。正式 trace=0，fork/exec 内核轨迹依据来自已运行资格和同源绑定，不声称每个性能请求重新做了内核 exec 跟踪或故障注入。每会话相同的独立 oracle 和运行时部署在主边界外，也会预热文件缓存；没有执行 drop_caches。','',
       '## 完整序列时间','',
       '主时间是创建 H 前至真实 wait(H)，包含 H/R、全部请求、G1 每次 Z 创建/关闭、G2 初次准备/最终关闭以及产品回收。每次调用的平均成本是完整 T/N。以下列出三个 block 原值；汇总为三个 VM 中位数 [最小, 最大]，不是置信区间或生产尾分位。','']
    b+=markdown_table(['N','组','b1 (s)','b2 (s)','b3 (s)','完整 T (s)','T/N (ms)','准入会话'],sequence)
    b+=['',image('01-full-sequence'),'',image('02-average-task-cost'),'','## 同 VM 配对差值','',
        '正值代表 G2 在该已测完整序列较快。三个 block 是同宿主重复环境，不是三个硬件平台；请求之间相关，不将 300 次请求当成 300 个独立会话。','']
    b+=markdown_table(['N','差值','累计节省 (s)，中位数[范围]','正向配对','完整配对'],paired)
    be=json.loads((a.figures/'observed-break-even.json').read_text())
    b+=['',image('05-paired-savings'),'','在已测网格中，三个配对均为正的首个 N：'+ '；'.join(x['comparison']+'：'+str(x['first_tested_N_with_three_positive_pairs']) for x in be)+'。这不是连续阈值估计，也不是任意任务都会回本的保证。N=1 的 G2 对 G0 三次均更慢；N=2 的最小正差约 167 ms，仍小于此前诊断开关对照中出现的数百毫秒变异，不能据此把 2 次调用定为稳定回本阈值。','',
        '## 不重叠的会话分解','',
        '下列四段相邻并覆盖完整主时间；没有把 fork、IPC 等嵌套跨度再相加。G1 的重复 Z 创建/关闭属于请求序列；G2 最后关闭 Z 属于最终关闭。为保证各段可相加，这一小节及图 6 使用算术均值 [范围]；不能拿分段均值之和与前面完整时间中位数直接核对。','']
    stage_rows=[]
    for n in (1,100):
        for g in GROUPS:
            stage_rows.append([n,g]+[triple(values(select('adjacent_partition',g,n,stage=s),'wall_ns'),1e6,2,'mean') for s in ('session_prefix','G2_single_Z_preparation','request_sequence','final_close')])
    b+=markdown_table(['N','组','会话前缀 ms','G2 一次准备 ms','请求序列 ms','最终关闭 ms'],stage_rows)
    b+=['',image('06-adjacent-partition'),'','### 请求内部观察（N100）','',
        '以下为相关请求样本的描述性中位数；call 包含该调用的 Z 处理，domain response 仅含执行域阶段。NumPy compute-ready 是初始化及 before 检查后真正开始数值计算，和 W 门禁就绪不同。init 区间含依赖初始化、状态快照、指纹与准入验证，不是纯 import 时间；这些内部区间可能嵌套，不能相加还原总耗时。','']
    component_rows=[]
    for g in GROUPS:
        req=select('requests',g,100);init=select('initialization',g,100);work=select('worker',g,100)
        component_rows.append([g,str(len(req))+'/'+str(len(init))]+[fmt(stats(values(req,k),1e6)['median']) for k in ('numpy_call_ns','domain_create_ns','call_to_NumPy_compute_ready_ns','domain_request_to_response_ns','quiescent_to_resources_deleted_ns')]+[fmt(stats(values(init,'initialization_wall_ns'),1e6)['median']),fmt(stats(values(init,'self_cpu_ns'),1e6)['median']),fmt(stats(values(work,'compute_ns'),1e6)['median'])])
    b+=markdown_table(['组','请求/init样本数','完整 call ms','建域 ms','call→NumPy ready ms','domain response ms','静止→删除 ms','每次 init wall ms','每次 init CPU ms','纯数值段 ms'],component_rows)
    distribution=request_distribution(tables['requests'],admitted)
    b+=['']+request_distribution_section(distribution,link(a.out/'request-distribution.csv'))
    b+=['## 失败、测量扰动与适用范围','',
        f"最终未准入或不完整会话共 {len(failures)}；完整状态与报告链接见 [admission-summary.json]({link(a.out/'admission-summary.json')})。所有缺失、失败和反向样本保留，未按 N 插值。",'',
        'timing=1、100 ms 只读资源采样和有界 COST 流对三组固定一致。此前两组反向开关 pilot 显示数百毫秒 wall 变异主要落在同步 JSON 证据写入和 H 最终持久化，无法给出稳定探针校正系数。本轮不扣除这些成本、不删除慢样本。见[诊断归因](docs/admission-pilot-cost-decision.md)。','',
        '当前仍包含 runtime probe、NumPy 数值/状态检查和经 9p 导出的证据日志；结果不是无诊断最低成本执行器。主时间后另有 observer join、100 ms 外部观察等待和委派目录删除，完整 fixture release 在原始数据单列，不能当作架构固有开销。','',
        '这些结果回答固定 CPU 任务下的执行机制成本，不代表在线 Agent 加速，也不决定最终 ShimOS 架构。真实依赖兼容范围、长期保活、并发和资源压力仍需分别验证。','',
        '## 数据与复核','',f"- [完整 CSV/JSON]({link(a.analysis)})：sessions、requests、initialization、worker、adjacent_partition、paired。",
        f"- [图表与输入 SHA]({link(a.figures)})：六图均提供 PNG/SVG/PDF。",
        '- [分析口径](docs/analysis-and-figure-boundaries.md)：原始 clock、CPU、内存和资格边界。','']
    c=['# CPU、内存与观测覆盖','',
       '本报告使用与性能报告相同的正式准入会话。产品累计 CPU、内存记账和 PSS 分开，不把它们相加或混成同一资源收益。','',
       pressure_note,'',
       '没有采集宿主 /proc/stat，因此宿主 CPU busy 为 Unknown，不能把较小 CPU PSI 当成低 CPU 利用率。some/full 及 CPU/内存/I/O 压力会重叠，不相加。观察器和产品 CPU 均单列。','',
       '## 产品累计 CPU 与记账峰值','',
       '根 cgroup 的 CPU 已包含下属 client、template、task。表中只使用真实 wait(H) 后的根计数，不再加 waited-child 或下属组。memory.peak 是产品 cgroup 记账峰值，不是全系统物理内存；H fork 以前及加入产品组之前的根夹具 CPU 不在此账本内。汇总为三个 VM 中位数 [范围]。','']
    c+=markdown_table(['N','组','产品 CPU (s)','memory.peak (MiB)'],cpu)
    c+=['',image('03-product-cpu'),'','### N100 的 CPU 组成','',
        '冻结代码没有生成逐 Z 最终 template cgroup 文件。下表逐 VM 列原值，最后一列由 root−client−Σtask 得出，只能解释为固定布局下的 template 类别残差；不能称直接测得的逐 Z CPU，也不能再加回 root。G0 无 Z，微小残差可来自微秒计数舍入。','']
    balances=[]
    for g in GROUPS:
        selected=select('component_cpu_balance',g,100)
        for row in sorted(selected,key=lambda r:r['pair']):
            balances.append([row['pair'],g]+[fmt(num(row,k)/1e6,3) if num(row,k) is not None else 'N/A' for k in ('root_total_cpu_us','client_H_R_cpu_us','sum_final_task_cpu_us','remaining_template_category_cpu_us')])
    c+=markdown_table(['VM','组','root (s)','H/R client (s)','各 task 累计 (s)','template 推导残差 (s)'],balances)
    c+=['','## 已覆盖区间的内存时间积分','',
        '**这里只报告 observed-span integral，不是完整会话物理内存时间。** cgroup 记账量与近同步 PSS 分列；不补零、不向未覆盖端点外推、不跨缺失批次。每组同时列覆盖率。采样间的瞬态仍未知；memory.peak×缺段时长也不能修复梯形内部的误差。全系统净物理内存收益仍是 Unknown。','']
    c+=markdown_table(['N','组','charge MiB·s [范围]','覆盖 %','PSS MiB·s [范围]','覆盖 %'],mem)
    c+=['',image('04-memory-time'),'','## 相同初始化阶段及角色内存','',
        'W before 样本在三组均已初始化 NumPy，可用于同阶段观察；它不含额外 Z/S，因此 W 单独 PSS 较小不等于系统净省。下表为 N100 样本中位数及实测范围，不是峰值。','']
    wrows=[]
    for g in GROUPS:
        selected=select('memory',g,100,role='W',phase='numpy_business_before')
        pss=stats(values(selected,'pss_KiB'),1024);rss=stats(values(selected,'rss_KiB'),1024)
        wrows.append([g,pss['n'],fmt(pss['median'])+' ['+fmt(pss['min'])+', '+fmt(pss['max'])+']',fmt(rss['median'])+' ['+fmt(rss['min'])+', '+fmt(rss['max'])+']'])
    c+=markdown_table(['组','W 有效样本','PSS MiB','RSS MiB'],wrows)
    c+=['',f"H/R/Z/S/W 的独立身份、阶段、PSS/RSS/FD 读数及覆盖见 [resource_role_summary.csv]({link(a.analysis/'resource_role_summary.csv')}) 和 resource_processes.csv。G0 的 Z/S 为不存在而非测得零；不同 gated 样本的初始化程度不同，不直接比较。",'',
        '### 长驻角色的首末观察（N100）','',
        '按同一 PID/starttime 配对；最早观察可能已经执行了一部分工作，不是出生时基线。R 保留 self.rows 和原有 runtime/数值证据，本轮没有将整个控制面改成 O(1)。因此不能把 root peak 随 N 变化都归因于模板或 COW。','']
    role_growth=[]
    for g in GROUPS:
        for role in ('H','R','Z'):
            selected=select('resource_role_growth',g,100,role=role)
            role_growth.append([g,role,len(selected),spread(values(selected,'first_pss_KiB'),1024,2),
                                spread(values(selected,'last_pss_KiB'),1024,2),spread(values(selected,'delta_pss_KiB'),1024,2),
                                spread(values(selected,'delta_fd_count'),1,2)])
    c+=markdown_table(['组','角色','实际 PID 数','首个 PSS MiB','最后 PSS MiB','PSS变化 MiB','FD变化'],role_growth)
    c+=['',
        '上述外部首末观察可能分别落在初始化、子进程共享、子进程退出后的不同阶段。PSS 会随页面被多少进程共享而改变，因此 G2 Z 的首末 PSS 增加约 18 MiB 不能直接解释成模板新增了等量内存或发生泄漏。下一表的 Z 变化来自原有 NP_Z_CHECK 的相同请求边界：N100 的 G2 三个会话均仅增加 4 KiB，FD 变化为 0。两种观察回答不同问题，都保留原值。','',
        '## 记录缓冲、模板增长与观察器开销','']
    obsrows=[]
    for g in GROUPS:
        obs=select('resource_observer',g,100);growth=select('zygote_growth_summary',g,100);flush=select('stream_flushes',g,100)
        fractions=[num(r,'observer_cpu_ns')/num(r,'observer_wall_ns') for r in obs if num(r,'observer_wall_ns')]
        deltas=values(growth,'pss_delta_KiB');fds=values(growth,'fd_delta')
        obsrows.append([g,spread(values(obs,'observer_cpu_ns'),1e6,2),spread(fractions,.01,2),
                        spread(deltas,1,2),spread(fds,1,2),fmt(max([num(r,'max_buffered_rows') or 0 for r in flush],default=0),0)])
    c+=markdown_table(['组','observer CPU ms','observer CPU/wall %','每个真实 Z 的 PSS变化 KiB','Z FD变化','缓冲高水位'],obsrows)
    c+=['','observer 在产品 cgroup 外，只读、不负责清理；它仍可能影响调度和缓存，不能直接从产品 wall 中减去其 CPU。G1 每请求新 Z，逐 PID 变化不能串成长期模板增长。G2 一个 Z 的观察只覆盖本次 100 请求，不证明无限期无泄漏。','',
        '128 条是缓冲记录数上限，不是固定字节上限；每批字节数、实际同步 flush wall/CPU 和写入错误在 stream_flushes.csv。跨角色 flush 可能重叠，不能把它们的 wall 简单相加当作关键路径总开销。','',
        '有界 COST 输出解决了 Z 中这一类测量对象的累积，不证明 R 的请求汇总、其他 RP/NP 资格证据或整个系统内存都恒定。角色变化和根组峰值必须结合具体账本解释。','',
        'pagemap 的 present/exclusive/soft-dirty 与请求写入字节数都不是实际 COW 复制字节统计。本轮没有通过这些标志推导精确共享比例或 COW 写放大。','',
        '所有原始资源读数、缺失和受限观察均保留。请求级 CPU、waited-child CPU 和角色自身 CPU可用于解释，但根 cgroup 是累计产品 CPU 的唯一主账本。','']
    (STUDY/'benchmark-results.md').open('x').write('\n'.join(b))
    (STUDY/'cpu-memory-analysis.md').open('x').write('\n'.join(c))
    payload={'admission_binding':binding,'nonadmitted_or_incomplete':failures,'cost_source_sha256':sources,
             'host_environment_path':str(a.host_environment),'host_environment_sha256':hashlib.sha256(a.host_environment.read_bytes()).hexdigest(),
             'reporter_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'figure_manifest_sha256':hashlib.sha256((a.figures/'figure-manifest.json').read_bytes()).hexdigest(),
             'scope':'presentation bound to independent final reports; no new runtime or qualification'}
    (a.out/'admission-summary.json').write_text(json.dumps(payload,indent=2,ensure_ascii=False)+'\n')
    for name,headers,rows in [('sequence-summary',['N','group','b1_s','b2_s','b3_s','T_s_summary','T_per_N_ms','admitted_sessions'],sequence),
                              ('cpu-summary',['N','group','product_cpu_s','charged_peak_MiB'],cpu),
                              ('memory-time-summary',['N','group','charge_MiBs','charge_coverage_percent','PSS_MiBs','PSS_coverage_percent'],mem),
                              ('paired-summary',['N','comparison','saved_s','positive_pairs','complete_pairs'],paired)]:
        with (a.out/(name+'.csv')).open('x',newline='') as stream:writer=csv.writer(stream);writer.writerow(headers);writer.writerows(rows)
    with (a.out/'request-distribution.csv').open('x',newline='') as stream:
        writer=csv.DictWriter(stream,list(distribution[0]));writer.writeheader();writer.writerows(distribution)
    print(json.dumps({'documents':['benchmark-results.md','cpu-memory-analysis.md'],'bindings':str(a.out),'nonadmitted':len(failures)}))


if __name__=='__main__':main()
