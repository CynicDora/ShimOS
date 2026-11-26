#!/usr/bin/env python3
"""Render completed observation data, not a causal/strict executor ranking."""
import argparse,json,statistics
from pathlib import Path

def f(x,d=2):return 'UNKNOWN' if x is None else f'{x:.{d}f}'
def table(headers,rows):
    return '\n'.join(['|'+'|'.join(headers)+'|','|'+'|'.join(['---']*len(headers))+'|']+['|'+'|'.join(map(str,r))+'|'for r in rows])
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--analysis',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);a=ap.parse_args()
    assert not a.out.exists(),'preserve prior generated report; use new output'
    data=json.loads((a.analysis/'summary.json').read_text());batches=sorted(data['batches'],key=lambda b:(b['block'],b['C']))
    assert len(batches)==6 and {(b['block'],b['C'])for b in batches}=={(i,c)for i in [0,1]for c in [1,2,4]}
    study=a.analysis.parent.parent;runs={r['run_id']:r for r in data['runs']};parts=[]
    parts.append('# 多 Session 观测：真实任务内容、受控到达与完整成本\n\n本报告是 **B0_INIT 单执行器的发现型负载观测**。完整B0/B1故障与安全合同未共同通过，故没有运行严格双执行器排名。不是在线自主Agent，不是生产到达流，没有新的未见Holdout，也没有自然CLI的heap准入。当前数据不能证明某种ShimOS架构优越。')
    parts.append('## 实际运行与合同\n\n使用原Discovery的13个任务、原动作和固定两个block到达顺序；每个C各两个独立私有VM，同物理宿主，一次只运行一个。顺序为block0 C=1→2→4，block1 C=4→2→1。到达均为已登记的同刻burst，FIFO只控制同时准入数，不是新调度算法。各C均保留13任务分母。\n\nVM为4vCPU/4GiB。业务父组3CPU/2GiB/512PID，每Session1CPU/512MiB/128PID；Controller、Docker daemon及观察者在业务父预算之外。全guest CPU包含它们，父业务配额不是整个平台的硬预算。单任务180秒从admit开始，排队不占该期限；batch900秒从到达开始。动作30秒。外部期限/补清只算研究兜底，不把缺失故障保证变成PASS。')
    parts.append('## 六个完整批次\n\n'+table(['block / C','batch秒','COMPLETED+released','定向P / TF / B','同时满足正常验收','补清','root CPU秒','业务 / 控制 / 其他CPU秒'],[
        [f"{b['block']} / {b['C']}",f(b['batch_wall_s']),f"{b['completed_released_sessions']}/13",' / '.join(str(b['outcomes'].get(k,0))for k in ['PASS','TEST_FAILURE','BLOCKED']),f"{b['accepted_completed_count']}/13",b['observer_assists'],f(b['root_CPU_s']),'/'.join(f(b[k])for k in ['business_CPU_s','control_CPU_s','root_other_CPU_s'])]for b in batches]))
    parts.append('正常验收要求COMPLETED、released、Submitted、定向PASS，动作日志与最终回执完整一致且没有工具异常/超时/取消/输出限制/UNKNOWN，同时没有本Session的观察者/期限/取消兜底；普通非零业务退出可以属于原任务失败后修复序列，不自动排除。即使满足这些条件，仍不是完整故障资格。TF是独立定向测试失败，B是评分或环境证据不足，均保留；评分是batch之后的独立阶段，不是官方SWE-bench完整resolution rate。不能把13个执行器完成当作13项业务修复成功。')
    parts.append('逐动作异常、超时、取消、输出限制、未知结果及正常非零退出分别保存在JSON的action_result_counts和每任务action_result_issues；缺最终回执不推断未执行。接受条件修订有19个离线统计反例核验，见[动作结果审查](../analysis/action-result-contract-review.md)。')
    parts.append('## 并发、排队与变化范围\n\n'+table(['C','两block batch秒','两block rootCPU秒','两block业务MiB·s'],[[c,' / '.join(f(b['batch_wall_s'])for b in batches if b['C']==c),' / '.join(f(b['root_CPU_s'])for b in batches if b['C']==c),' / '.join(f(b['business_memory_time_MiBs_observed_window'],0)for b in batches if b['C']==c)]for c in [1,2,4]]))
    parts.append(table(['block / C','queue中位/最大秒','response中位/最大秒','Session中位/最大秒','实记tool重叠≥2秒','实记tool并存峰值'],[[f"{b['block']}/{b['C']}",'/'.join(f(b['queue_s_distribution'].get(k))for k in ['median','max']),'/'.join(f(b['response_s_distribution'].get(k))for k in ['median','max']),'/'.join(f(b['session_s_distribution'].get(k))for k in ['median','max']),f(b['tool_wall_overlap']['overlap_at_least2_s']),b['tool_wall_overlap']['max_distinct_sessions']]for b in batches]))
    for block in [0,1]:
        bs={b['C']:b for b in batches if b['block']==block}
        parts.append(f"block{block}的同任务序列C1−C2 batch差为{f(bs[1]['batch_wall_s']-bs[2]['batch_wall_s'])}秒，C2−C4为{f(bs[2]['batch_wall_s']-bs[4]['batch_wall_s'])}秒。这里只描述固定到达与预算下的差额，不把它当跨平台加速或新联合调度收益。")
    parts.append('queue来自预设burst和FIFO，不能推断生产到达频率或普遍排队。response=arrival→Controller真实wait，Session则从admit开始；response超过180秒不等于Session期限违约。tool区间重叠不等于同时使用CPU。每块内13个相关任务不是13次独立机器重复；只有两个同宿主VM块，不给生产p99或显著性宣称。')
    parts.append('## 执行阶段与研究采集\n\n'+table(['block / C','domain准备中位秒','工具累计中位秒','本地证据快照中位秒','cleanup中位秒','全部工具wall之和秒'],[[f"{b['block']}/{b['C']}",*[f(b[k+'_distribution'].get('median'))for k in ['domain_setup_s','tool_s','evidence_export_s','cleanup_s']],f(sum(t['tool_s']for t in data['tasks']if t['run_id']==b['run_id']and t['tool_s']is not None))]for b in batches]))
    parts.append('这些阶段可能嵌套，跨Session还会重叠，不能把中位数或工具wall求和当batch时间。domain准备含Docker控制与观测，不是纯namespace系统调用。工作区在每Session准入时复制一次，之后持久；没有每动作复制。\n\n本批次先在guest本地保全静止最终快照，再正常清理业务资源；评分和完整tar归档在batch之后，仍计入整VM时间。此前依赖第一块直接9p导出版本不能混在本表。必要输出/退出/资源检查保留，进程事件追踪与约100ms扫描也保留，因此不是无诊断的产品性能。')
    rows=[]
    for b in batches:
        run=study/'runs'/b['run_id'];fr=json.loads((run/'fixtures-result.json').read_text());rr=runs[b['run_id']]
        rows.append([f"{b['block']}/{b['C']}",f((fr['end_ns']-fr['start_ns'])/1e9),f(rr['vm_wall_s']),f(rr.get('driver_start_to_release_root_CPU_s')),f(b['sample_duration_ms'].get('median')),f(b.get('sampled_CPU_observed_delta_s',{}).get('observer_driver'))])
    parts.append(table(['block / C','fixture秒','整VM秒','driver起点→释放rootCPU秒','扫描中位ms','driver/observer采样CPU下界秒'],rows))
    parts.append('整VM时间包括准备、业务、追踪、独立评分、证据归档和关闭。guest driver CPU不含marker之前启动及之后关闭，也不含宿主QEMU CPU。root−business−control是daemon/runtime/driver/observer及其他活动残差，不能全部归为可消除的控制成本。采样CPU遗漏短进程与端点，扫描消耗不能直接从wall扣除；本轮没有独立无trace批次精确剥离观测开销。')
    parts.append('## 内存与资源预算\n\n'+table(['block / C','业务lifetime peak MiB','业务采样max MiB','业务积分MiB·s','父组throttled秒','memory事件delta','pids事件delta'],[[f"{b['block']}/{b['C']}",f(b['business_mem_peak_lifetime_after_MiB']),f(b['business_memory_current_sample_max_MiB']),f(b['business_memory_time_MiBs_observed_window'],0),f(b['business_throttled_s']),json.dumps(b['business_memory_event_counters']['delta'],ensure_ascii=False),json.dumps(b['business_pids_event_counters']['delta'],ensure_ascii=False)]for b in batches]))
    parts.append('memcg charge不是系统净物理内存；peak从该组创建起累计。PSS/RSS/Private_Dirty各角色顺序采样，角色峰值不可相加，全平台净物理内存为UNKNOWN。积分只覆盖两端有效的相邻样本，不向端点外推。throttled_usec不是可与wall相加的排队时间。每个指标的采样覆盖、最大间隔、缺失区间和角色CPU边界见JSON及[统计审查](../analysis/resource-accounting-review.md)。')
    tasks=sorted({t['task_id']for t in data['tasks']});columns=[(b['block'],b['C'])for b in batches];lookup={(t['task_id'],t['block'],t['C']):t for t in data['tasks']}
    parts.append('## 原13任务的结果账本\n\n'+table(['任务']+[f'{i}/C{c}'for i,c in columns],[[task]+[lookup[(task,i,c)]['targeted_outcome']for i,c in columns]for task in tasks]))
    parts.append('若存在任务间相同分数，不表示输出逐字相同；计时、文件metadata、随机测试输出均保留。所有原动作、补丁、定向结果及候选评分前后不变性可从逐Session证据复核。没有按成绩筛任务或只统计较快成功样本。')
    parts.append('## 进程与域身份的独立核验\n\n原始自然trace包含fork/exec/exit/wait，以PID出生代次与cgroup/namespace关联，不把进程消失当wait。域身份用container ID、PID1出生身份和存活区间；串行销毁后namespace inode可以重用。Docker共用guest初始userns也不等于同一PID/mount域。逐批独立核验、角色exec分布和并存namespace检查另见analysis/study-process-*及study-namespaces-*。\n\n本批仍不覆盖Controller SIGKILL的完整产品恢复；那是两个资格VM已经明确的缺口，不能由正常批次0补清倒推解决。')
    link='../analysis/'+a.analysis.name
    parts.append(f'## 复现与原始索引\n\n![六批成本分布]({link}/multisession-costs.png)\n\n[完整JSON]({link}/summary.json)、[每批CSV]({link}/batches.csv)、[78任务行]({link}/tasks.csv)、[全部Session]({link}/sessions.csv)、[输入SHA]({link}/input-sha.json)。各run的command.json、source-sha.json、pilot-plan.md、fixture、actions、trace、resource-samples和validation为原始证据。host PSI是同宿主背景，不能与guest时间相减。')
    parts.append(table(['run ID','原始账本'],[[b['run_id'],f"[batch](../runs/{b['run_id']}/batch-result.json) / [VM](../runs/{b['run_id']}/result.json)"]for b in batches]))
    parts.append('结论限于固定13个Python仓库任务的离线真实动作回放、合成burst、4vCPU/4GiB和当前诊断模式。没有自然跨任务heap命中，没有新缓存/路由机制对照，不能据此推断联合调度的独立收益或生产资源最优布局。不同架构路线的决策另见综合报告。')
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text('\n\n'.join(parts)+'\n');print(a.out)
if __name__=='__main__':main()
