#!/usr/bin/env python3
"""Generate the evidence report / compact SVG from derived data, no workload run."""
import json,collections,html,statistics
from pathlib import Path
P=Path(__file__).resolve().parents[3];R=P/'research/real_agent_workload';W=R/'workload_analysis'
s=json.loads((W/'summary.json').read_text());t=json.loads((W/'tasks.json').read_text());a=[json.loads(x) for x in (W/'actions.jsonl').read_text().splitlines()];m=json.loads((R/'trajectories/trajectory_manifest.json').read_text());main=[x for x in a if x['included_main']];pro=[x for x in main if x['execution_time_s'] is not None];timed=[x['execution_time_s'] for x in pro];timeouts=[x for x in pro if 'cancelled because it took more than' in x['observation']]
mainids={x['run_id'] for x in t if x['included_main']};repeats=list(__import__('csv').DictReader((W/'exact_repeats.csv').open()));changed=sum(x['run_id'] in mainids and bool(json.loads(x['intervening_edit_requests'])) for x in repeats)
retry=[]
for x in main:
    if x['returncode'] is not None and x['returncode']!=0:
        later=[y for y in main if y['run_id']==x['run_id'] and y['action_index']>x['action_index'] and y['command_sha256']==x['command_sha256']]
        if later:retry.append({'run_id':x['run_id'],'nonzero_action':x['action_index'],'returncode':x['returncode'],'later_same_command_action':later[0]['action_index'],'meaning':'Observed failed tool envelope then identical command; source state and causal retry intent unknown'})
(W/'nonzero_then_same_command.json').write_text(json.dumps(retry,indent=2)+'\n')
special={'pro_timed_actions':len(pro),'pro_tool_wall_sum_s':sum(timed),'under_1s':sum(v<1 for v in timed),'over_30s':sum(v>30 for v in timed),'explicit_450s_timeout_count':len(timeouts),'explicit_450s_timeout_wall_s':sum(x['execution_time_s'] for x in timeouts),'main_repeats_with_intervening_edit':changed,'nonzero_then_later_same_command':len(retry),'persistent_kernel_calls_main':sum('python_kernel' in x['categories'] for x in main),'no_task_wall_no_llm_timing':True}
(W/'derived-findings.json').write_text(json.dumps(special,indent=2)+'\n')
cats=[('file_read_search','Read/search'),('file_edit_request','Write/edit request'),('python_script_or_entry','Python entry'),('python_test','pytest/unittest'),('git','Git'),('javascript_typescript','JS/TS'),('other_language_build_test','Other language tools'),('wait_poll_candidate','Wait/poll candidate')]
svg=['<svg xmlns="http://www.w3.org/2000/svg" width="900" height="440" viewBox="0 0 900 440">','<rect width="900" height="440" fill="white"/>','<g font-family="sans-serif" font-size="15" fill="#263238">','<text x="24" y="28" font-size="19">Public corpus: observed tool-record categories</text>','<text x="24" y="52" font-size="12">122 runs, 5,288 tool actions; overlapping labels; NOT processes / heap reuse</text>']
for i,(k,label) in enumerate(cats):
    n=s['main_categories'].get(k,0);y=85+i*39;svg += [f'<text x="24" y="{y+17}">{label}</text>',f'<rect x="220" y="{y}" width="{n/3600*570:.1f}" height="23" fill="#337d9c"/>',f'<text x="{225+n/3600*570:.1f}" y="{y+17}">{n}</text>']
svg+=['<text x="24" y="425" font-size="12">Convenience/stratified sample; no population-frequency or performance claim.</text></g></svg>'];(W/'tool-categories.svg').write_text('\n'.join(svg)+'\n')
rows=[]
for g,short in [('SWE-bench test | SWE-agent','SWE-agent 20240620 / SWE-bench test'),('SWE-bench Verified | mini-SWE-agent','mini v1.0.0 / Verified'),('SWE-bench Pro V1 public (2025-10-13 run) | SWE-agent','SWE-agent 1.1.0 / Pro V1')]:
    v=s['groups'][g];d=v['action_distribution'];rows.append(f"| {short} | {v['runs']} | {v['business_tool_actions']} | {d['median']:.1f} | {d['min']}–{d['max']} |")
catrows='\n'.join(f"| {name} | {s['main_categories'].get(key,0)} | {100*s['main_categories'].get(key,0)/s['main_business_tool_actions']:.1f}% |" for key,name in [('file_read_search','文件读取/搜索'),('file_edit_request','编辑/写入请求'),('python_script_or_entry','Python 显式入口'),('python_test','pytest/unittest 等测试入口'),('git','Git'),('javascript_typescript','JS/TS 工具'),('other_language_build_test','Go 等其他语言工具'),('dependency_install','依赖安装'),('wait_poll_candidate','等待/轮询候选')])
body=f'''# 真实公开轨迹：工具重复很多，但可继承状态仍需系统证据

本轮获得 **122 条具有终止记录的官方来源轨迹**，对应 **108 个不同 task ID、23 个仓库**。其中40条来自历史冻结语料，新增82条；不是重新声称收集了122条新轨迹。主语料有5,316条原始记录，其中28条为预算退出或空终态记录，保留 **5,288 个工具动作**。每任务动作中位数33，均值43.34，范围7–214。

另保留10份OpenHands历史导出和40份Terminal-Bench 2.0第三方镜像，共172份manifest条目。前者缺可靠终态，后者全部存在未解析的Next.js RSC文本引用，**均不混入完整轨迹主统计**。本成果是离线真实运行记录分析，没有执行轨迹命令，也没有新增模型调用或测得ShimOS加速。

## 1. 取得了什么，如何抽样

| 官方来源与运行版本 | 运行数 | 工具动作 | 每运行中位数 | 范围 |
|---|---:|---:|---:|---:|
{chr(10).join(rows)}

SWE-agent旧30条全部保留；mini保留旧10条，先按可恢复仓库选择7个VM候选，再按固定SHA种子和仓库轮转补足70条；Pro从官方S3的730个可列出轨迹中，每11个仓库取2个SHA排序任务，下载前冻结名单。不按成功、长度、耗时、命令重复数筛选。最长214动作的Pro任务、预算退出、超时与错误退出都保留。

这不是总体随机样本。mini占主样本70/122，Python修复项目偏多；最多的单仓库SymPy为12/122。SWE-bench test和Verified不是独立Benchmark家族；本轮完整主语料覆盖SWE-bench与Pro两个家族，未达到三类完整任务来源。14个task ID出现在不同Agent运行中，已按run ID分开，不能当作122个独立issue。

来源、URL、commit、模型、逐文件SHA、采集时间、纳入/排除理由见[trajectory_manifest.csv](trajectory_manifest.csv)；下载前名单见[mini](trajectories/selection-mini.json)、[Pro](trajectories/selection-pro.json)、[Terminal镜像v2](trajectories/selection-terminal-v2.json)。原始文本仅用于本地研究，轨迹再分发许可未确认；框架代码许可不自动覆盖模型对话与仓库内容，未上传或对外发布这些资料。

mini实际来源由[官方experiments固定metadata](https://github.com/SWE-bench/experiments/blob/40f164d5b8f1d249bf95a6df8b74b577fd8e519d/evaluation/verified/20250726_mini-v1.0.0_claude-sonnet-4-20250514/metadata.yaml)指向S3。Pro使用[官方traj索引](https://github.com/scaleapi/SWE-bench_Pro-os/blob/66f92766bba642462d4bbe5479e83f91f9211862/traj/README.md)所列2025-10-13 Claude Sonnet4.5运行；本机匿名HTTPS确实取得listing和22个完整`.traj`，无需账户或付费调用。**它们是Pro V1运行，不能作为2026 V2的负载记录。** Pro源码版本只自报SWE-agent1.1.0，hash为unavailable；SWE-ReX1.2.2的hash为`f1a4e68ad4ae35053163e922361e913c87362adb`。

## 2. 工具在做什么

以下为“含此类语法证据的动作数”，一条pipeline/多命令动作可以属于多类。分母为5,288工具动作，类别不能相加成100%，更不能加成进程数。

| 类别 | 动作数 | 占动作比例 |
|---|---:|---:|
{catrows}

![工具类别，多标签计数](workload_analysis/tool-categories.svg)

另有11个文档/扩展构建入口，主样本没有识别出明确gcc/clang入口；不能因此断言Coding Agent没有C/C++负载。Terminal不完整镜像可见编译/网络/后台工具，但只能用来定位下一批有效样本。52个主语料动作无法可靠分类，保持unknown。长时间CPU密集与阻塞只能由运行数据判断，`sleep`、`tail`、`wait`名称只是候选。

脚本去除heredoc和编辑正文后识别命令入口；`str_replace_editor create x.py`的Python代码是写入内容，不能算已经启动Python。JS/Go源码任务也有Python重现脚本：**22份Pro配置全部要求使用`python <filename.py>`重现，并把仓库称作Python仓库**，包括JS/Go项目。因此其中202个Python入口还受到scaffold提示策略影响，不能解释为项目自然具有202次NumPy预热需求。[配置偏差证据](workload_analysis/pro-scaffold-bias.json)。

## 3. 重复、修改与失败

主语料有537个“第二次及以后”的精确重复动作，其中256个含Python入口；{changed}次重复之间有编辑/写入请求。识别出522个“测试或重现候选→编辑请求→下一测试或重现候选”片段。它们证明反复验证存在，但不能证明前后工作区相同，更不是安全缓存命中。

例如原mini pytest-7205先执行失败测试、修改`setuponly.py`、再运行相同命令并成功；新增SymPy20154在修改partitions实现后反复验证。完整命令、前驱索引、编辑区间保存在[精确重复](workload_analysis/exact_repeats.csv)和[修改/验证片段](workload_analysis/edit_probe_cycles.csv)。复制旧项目模块heap可能保留旧代码；共享稳定依赖与共享正在修改的项目状态应分别审查。

官方评测索引显示旧SWE-agent30条中8条resolved、22条未resolved；mini70条中41条resolved、29条未resolved。`Submitted`只表明提交，不等于修复成功。Pro另保存官方`_output.json`测试结果，但没有把“某些测试PASSED”自行升级为完整resolved判定。其终态为19普通提交、1错误后提交、1预算后提交、1超时后提交。mini观察到167个非零工具返回码，{len(retry)}个非零结果后又出现相同命令；它们不是167个失败任务，也不一定都是自动重试。

一条mini助手回答缺Bash代码块，执行器明确拒绝格式。该回答保留在[parser_failures.json](workload_analysis/parser_failures.json)，不计作已执行工具，也没有删去所在任务。静态解析资格见[validation.json](workload_analysis/validation.json)，它不等于任务执行正确性。

## 4. 时间证据：新增Pro工具wall，仍无完整Agent时钟

Pro有1,847个非空动作附`execution_time`，占主工具动作34.9%；全语料5,316原始记录中占34.7%。另22个空终态记录的默认0被保留为reported字段，但排除工具计时。旧SWE/mini公开轨迹没有可靠动作耗时，下载时间与S3 LastModified没有拿来补造执行时间。

Pro动作记录wall中位数 **0.399秒**，描述性p90 **1.625秒**，范围 **0.189–452.388秒**，合计 **4,472.675秒**。{sum(v<1 for v in timed)}/1,847（{100*sum(v<1 for v in timed)/len(timed):.1f}%）低于1秒，18个超过30秒。三个`git show/diff`动作分别约452秒，观察明确写450秒超时取消，合计 **{sum(x['execution_time_s'] for x in timeouts):.3f}秒（工具wall的{100*sum(x['execution_time_s'] for x in timeouts)/sum(timed):.1f}%）**。不能把这些长等待归为依赖初始化，也不能删除后算“干净性能”。

同版本源码中[handle_action](https://github.com/SWE-agent/SWE-agent/blob/3ea751c087f32b16e039a2233dd6eefecef325d5/sweagent/agent/agents.py#L935)的计时从guard/communicate之前开始，在运行/超时中断后结束；排除LLM query，也排除后续get_state与部分提交处理。因此这是工具包装wall，非CPU、纯业务或完整response-ready。Pro实际SWE-agent commit未锁定，该语义仅有同版本源码支持，不声称已验证历史字节一致。

本语料无完整task起止和LLM网络/推理时钟，无法给出“初始化占整个Agent百分之几”，也无法把工具间隔当纯思考时间。Terminal ATIF step timestamps和`duration`等待参数也不等于真实每命令起止；镜像的RSC缺失进一步阻止时序推断。[逐动作时间](workload_analysis/recorded_action_timing.csv)。

## 5. K_tool、K_proc、K_heap、K_template

| 单位 | 本语料能确认什么 | 不能确认什么 |
|---|---|---|
| 每任务Tool Action | 122完整运行，7–214，中位33 | 不等于每域动作数 |
| K_tool：同域动作 | Pro配置显示Modal部署和preexisting工作区；源码可说明通常一个任务环境 | 原始记录没有完整sandbox创建/销毁身份链，所以数值UNKNOWN |
| K_proc：同域业务进程 | 能找到Python、Node、Go等命令入口 | 无PID/starttime/fork/exec链，全部UNKNOWN |
| K_heap：兼容heap操作 | 重复命令和import文本是候选；主语料没有IPython tool调用 | 无解释器身份、加载模块及状态reset资格，UNKNOWN，不是0 |
| K_template：可信跨域模板 | 有稳定外部依赖候选 | 无固定依赖版本、权限、native线程/回调准入，UNKNOWN |

静态AST发现119次NumPy import提及，包含写入脚本或修改正文；不等于119次成功import，亦不等于项目已准入NumPy2.2.6配方。目录状态与同一工作区路径也不证明同一Shell/Python PID。没有任何公开记录能独立建立已准入跨域模板命中次数。[依赖候选](workload_analysis/dependency_candidates.csv)。

因此K=10/50不能从33次中位工具数直接成立。长寿命容器中的几十次`docker exec`可以已摊销建域，但新Python进程仍各自初始化；是否有值得保留的稳定模块，以及exec是否替换heap，必须用本轮VM进程观测回答。

## 6. Terminal与OpenHands缺口如实保留

Terminal镜像来自公开[v0.1 release](https://github.com/Jiacheng-Zhu-AIML/terminal_bench_trajectories/releases/tag/v0.1)，按任务SHA选20个Terminus2/GPT5.2与20个Claude Code/Opus4.5试次，成功和失败reward均保留。40份全部包含未解析`$xx`引用，可能缺任务正文、推理或工具输出；原官方trial URL本次返回重定向后页面而非trajectory。故不能称40条完整Agent轨迹、不能用requested wait当时长，也不将其用于可靠动作结果比较。

初次镜像目录拼写导致仅选20份，随后读取实际目录修正；一次89任务断言发现实际镜像仅88个任务目录。两个获取/校验失败都留存，不补造缺失任务。见[开发失败记录](sources/trajectory_corpus/acquisition-development-failures.json)。OpenHands旧10份有297个tool calls但缺终止证据；与公开评测的resolved关联仍不补造轨迹终态。

## 7. 可执行任务候选与复现

旧mini Flask5014、pytest7205/7324、SymPy22080已有准备材料。本次新增预登记7个任务：requests5414/6028、SymPy19954/20154/20590/21379/21847。原始轨迹位于`trajectories/raw/mini/`，任务定义和base commit位于`trajectories/task_definitions/`。选择理由是当前Python3.10可恢复性与已有依赖，未按轨迹成功或耗时选择。requests proxy/HTTP和SymPy可选依赖仍需VM资格；完整回放失败应保留，不能删命令使之成功。

```bash
cd /path/to/research-host/shimos-linux-native-mvp
python3 research/real_agent_workload/parsers/acquire_corpus.py
python3 research/real_agent_workload/parsers/acquire_extended.py --download
/usr/bin/python3.10 research/real_agent_workload/parsers/export_task_definitions.py
python3 research/real_agent_workload/parsers/analyze_corpus.py
python3 research/real_agent_workload/parsers/validate_corpus.py
python3 research/real_agent_workload/parsers/build_corpus_report.py
```

前三项复用已固定manifest/历史数据和下载收据，后面为离线分析；不启动模型、不执行轨迹、不修改历史。主结论是：重复短工具与反复修改测试确实存在，长超时也显著；现有数据仍不足以把这些调用换算成安全heap/template复用频率或ShimOS端到端加速。系统级过程与实际回放结果应单独结合，不能用本报告填补其缺失测量。
'''
(R/'03_trajectory_workload_analysis.md').write_text(body)
print('Generated report, derived findings, retry index and SVG from corpus data')
