# 多 Session 观测：真实任务内容、受控到达与完整成本

本报告是 **B0_INIT 单执行器的发现型负载观测**。完整B0/B1故障与安全合同未共同通过，故没有运行严格双执行器排名。不是在线自主Agent，不是生产到达流，没有新的未见Holdout，也没有自然CLI的heap准入。当前数据不能证明某种ShimOS架构优越。

## 实际运行与合同

使用原Discovery的13个任务、原动作和固定两个block到达顺序；每个C各两个独立私有VM，同物理宿主，一次只运行一个。顺序为block0 C=1→2→4，block1 C=4→2→1。到达均为已登记的同刻burst，FIFO只控制同时准入数，不是新调度算法。各C均保留13任务分母。

VM为4vCPU/4GiB。业务父组3CPU/2GiB/512PID，每Session1CPU/512MiB/128PID；Controller、Docker daemon及观察者在业务父预算之外。全guest CPU包含它们，父业务配额不是整个平台的硬预算。单任务180秒从admit开始，排队不占该期限；batch900秒从到达开始。动作30秒。外部期限/补清只算研究兜底，不把缺失故障保证变成PASS。

## 六个完整批次

|block / C|batch秒|COMPLETED+released|定向P / TF / B|同时满足正常验收|补清|root CPU秒|业务 / 控制 / 其他CPU秒|
|---|---|---|---|---|---|---|---|
|0 / 1|261.07|13/13|6 / 4 / 3|6/13|0|230.46|141.93/24.45/64.08|
|0 / 2|156.60|13/13|6 / 4 / 3|6/13|0|213.29|141.34/24.15/47.79|
|0 / 4|116.28|13/13|6 / 4 / 3|6/13|0|204.58|141.05/23.58/39.95|
|1 / 1|252.84|13/13|6 / 4 / 3|6/13|0|222.34|138.64/23.59/60.11|
|1 / 2|150.57|13/13|6 / 4 / 3|6/13|0|210.95|139.89/24.43/46.63|
|1 / 4|119.35|13/13|6 / 4 / 3|6/13|0|206.70|142.33/23.68/40.69|

正常验收要求COMPLETED、released、Submitted、定向PASS，动作日志与最终回执完整一致且没有工具异常/超时/取消/输出限制/UNKNOWN，同时没有本Session的观察者/期限/取消兜底；普通非零业务退出可以属于原任务失败后修复序列，不自动排除。即使满足这些条件，仍不是完整故障资格。TF是独立定向测试失败，B是评分或环境证据不足，均保留；评分是batch之后的独立阶段，不是官方SWE-bench完整resolution rate。不能把13个执行器完成当作13项业务修复成功。

逐动作异常、超时、取消、输出限制、未知结果及正常非零退出分别保存在JSON的action_result_counts和每任务action_result_issues；缺最终回执不推断未执行。接受条件修订有19个离线统计反例核验，见动作结果审查 (`../analysis/action-result-contract-review.md`, omitted from this source release)。

## 并发、排队与变化范围

|C|两block batch秒|两block rootCPU秒|两block业务MiB·s|
|---|---|---|---|
|1|261.07 / 252.84|230.46 / 222.34|42722 / 40754|
|2|156.60 / 150.57|213.29 / 210.95|30938 / 27745|
|4|116.28 / 119.35|204.58 / 206.70|24908 / 25902|

|block / C|queue中位/最大秒|response中位/最大秒|Session中位/最大秒|实记tool重叠≥2秒|实记tool并存峰值|
|---|---|---|---|---|---|
|0/1|92.65/233.87|103.72/261.03|17.89/41.00|0.00|1|
|0/2|43.60/128.37|58.19/156.56|19.09/46.00|63.42|2|
|0/4|24.47/73.16|58.16/116.24|26.41/53.19|68.69|4|
|1/1|76.62/242.39|104.19/252.81|16.82/39.57|0.00|1|
|1/2|42.92/128.60|79.15/150.54|18.41/41.01|64.13|2|
|1/4|27.54/80.27|55.11/119.31|27.34/48.12|57.50|4|

block0的同任务序列C1−C2 batch差为104.47秒，C2−C4为40.32秒。这里只描述固定到达与预算下的差额，不把它当跨平台加速或新联合调度收益。

block1的同任务序列C1−C2 batch差为102.26秒，C2−C4为31.22秒。这里只描述固定到达与预算下的差额，不把它当跨平台加速或新联合调度收益。

queue来自预设burst和FIFO，不能推断生产到达频率或普遍排队。response=arrival→Controller真实wait，Session则从admit开始；response超过180秒不等于Session期限违约。tool区间重叠不等于同时使用CPU。每块内13个相关任务不是13次独立机器重复；只有两个同宿主VM块，不给生产p99或显著性宣称。

## 执行阶段与研究采集

|block / C|domain准备中位秒|工具累计中位秒|本地证据快照中位秒|cleanup中位秒|全部工具wall之和秒|
|---|---|---|---|---|---|
|0/1|1.88|9.26|0.25|1.03|176.58|
|0/2|1.82|11.11|0.30|1.25|184.62|
|0/4|4.33|15.55|0.94|1.79|219.23|
|1/1|1.76|9.09|0.39|1.07|171.31|
|1/2|2.37|10.84|0.36|1.19|181.47|
|1/4|3.99|13.41|0.37|1.78|214.20|

这些阶段可能嵌套，跨Session还会重叠，不能把中位数或工具wall求和当batch时间。domain准备含Docker控制与观测，不是纯namespace系统调用。工作区在每Session准入时复制一次，之后持久；没有每动作复制。

本批次先在guest本地保全静止最终快照，再正常清理业务资源；评分和完整tar归档在batch之后，仍计入整VM时间。此前依赖第一块直接9p导出版本不能混在本表。必要输出/退出/资源检查保留，进程事件追踪与约100ms扫描也保留，因此不是无诊断的产品性能。

|block / C|fixture秒|整VM秒|driver起点→释放rootCPU秒|扫描中位ms|driver/observer采样CPU下界秒|
|---|---|---|---|---|---|
|0/1|116.94|570.19|441.13|13.57|37.97|
|0/2|119.17|458.09|424.42|13.79|25.65|
|0/4|111.19|419.89|413.64|15.12|20.75|
|1/1|114.65|553.76|427.38|13.03|35.44|
|1/2|112.95|450.48|415.75|13.93|24.90|
|1/4|113.58|419.73|411.95|14.41|20.84|

整VM时间包括准备、业务、追踪、独立评分、证据归档和关闭。guest driver CPU不含marker之前启动及之后关闭，也不含宿主QEMU CPU。root−business−control是daemon/runtime/driver/observer及其他活动残差，不能全部归为可消除的控制成本。采样CPU遗漏短进程与端点，扫描消耗不能直接从wall扣除；本轮没有独立无trace批次精确剥离观测开销。

## 内存与资源预算

|block / C|业务lifetime peak MiB|业务采样max MiB|业务积分MiB·s|父组throttled秒|memory事件delta|pids事件delta|
|---|---|---|---|---|---|---|
|0/1|355.37|351.37|42722|0.00|{"high": 0.0, "oom_kill": 0.0, "oom": 0.0, "oom_group_kill": 0.0, "low": 0.0, "max": 0.0}|{"max": 0.0}|
|0/2|456.06|454.31|30938|0.00|{"high": 0.0, "oom_kill": 0.0, "oom": 0.0, "oom_group_kill": 0.0, "low": 0.0, "max": 0.0}|{"max": 0.0}|
|0/4|529.20|528.53|24908|0.26|{"high": 0.0, "oom_kill": 0.0, "oom": 0.0, "oom_group_kill": 0.0, "low": 0.0, "max": 0.0}|{"max": 0.0}|
|1/1|370.97|370.97|40754|0.00|{"high": 0.0, "oom_kill": 0.0, "oom": 0.0, "oom_group_kill": 0.0, "low": 0.0, "max": 0.0}|{"max": 0.0}|
|1/2|401.52|398.52|27745|0.00|{"high": 0.0, "oom_kill": 0.0, "oom": 0.0, "oom_group_kill": 0.0, "low": 0.0, "max": 0.0}|{"max": 0.0}|
|1/4|416.08|412.83|25902|2.29|{"high": 0.0, "oom_kill": 0.0, "oom": 0.0, "oom_group_kill": 0.0, "low": 0.0, "max": 0.0}|{"max": 0.0}|

memcg charge不是系统净物理内存；peak从该组创建起累计。PSS/RSS/Private_Dirty各角色顺序采样，角色峰值不可相加，全平台净物理内存为UNKNOWN。积分只覆盖两端有效的相邻样本，不向端点外推。throttled_usec不是可与wall相加的排队时间。每个指标的采样覆盖、最大间隔、缺失区间和角色CPU边界见JSON及统计审查 (`../analysis/resource-accounting-review.md`, omitted from this source release)。

## 原13任务的结果账本

|任务|0/C1|0/C2|0/C4|1/C1|1/C2|1/C4|
|---|---|---|---|---|---|---|
|pallets__flask-4935|TEST_FAILURE|TEST_FAILURE|TEST_FAILURE|TEST_FAILURE|TEST_FAILURE|TEST_FAILURE|
|pallets__flask-5014|PASS|PASS|PASS|PASS|PASS|PASS|
|psf__requests-1921|BLOCKED|BLOCKED|BLOCKED|BLOCKED|BLOCKED|BLOCKED|
|psf__requests-5414|TEST_FAILURE|TEST_FAILURE|TEST_FAILURE|TEST_FAILURE|TEST_FAILURE|TEST_FAILURE|
|psf__requests-6028|TEST_FAILURE|TEST_FAILURE|TEST_FAILURE|TEST_FAILURE|TEST_FAILURE|TEST_FAILURE|
|pytest-dev__pytest-7205|BLOCKED|BLOCKED|BLOCKED|BLOCKED|BLOCKED|BLOCKED|
|pytest-dev__pytest-7324|BLOCKED|BLOCKED|BLOCKED|BLOCKED|BLOCKED|BLOCKED|
|sympy__sympy-19954|PASS|PASS|PASS|PASS|PASS|PASS|
|sympy__sympy-20154|PASS|PASS|PASS|PASS|PASS|PASS|
|sympy__sympy-20590|PASS|PASS|PASS|PASS|PASS|PASS|
|sympy__sympy-21379|PASS|PASS|PASS|PASS|PASS|PASS|
|sympy__sympy-21847|PASS|PASS|PASS|PASS|PASS|PASS|
|sympy__sympy-22080|TEST_FAILURE|TEST_FAILURE|TEST_FAILURE|TEST_FAILURE|TEST_FAILURE|TEST_FAILURE|

若存在任务间相同分数，不表示输出逐字相同；计时、文件metadata、随机测试输出均保留。所有原动作、补丁、定向结果及候选评分前后不变性可从逐Session证据复核。没有按成绩筛任务或只统计较快成功样本。

## 进程与域身份的独立核验

原始自然trace包含fork/exec/exit/wait，以PID出生代次与cgroup/namespace关联，不把进程消失当wait。域身份用container ID、PID1出生身份和存活区间；串行销毁后namespace inode可以重用。Docker共用guest初始userns也不等于同一PID/mount域。

全部六批最终独立审计为81,672个业务进程、81,672个可绑定的正返回wait，每批102个执行Python映像的进程；事件没有报告丢失，未解析行0。每批13,612个进程中，两个find-heavy任务贡献13,149个，其余11任务463个。每域动作中位29、范围12–61；每域进程中位43、范围21–7,379。大量短grep不能被算作Python heap机会，也不能凭数量认定CPU占比。

同时存活域对在C2两块为8/9对，C4为22/23对；pid/mnt/net/ipc/uts各自不同，共享guest初始userns。六批first-seen `/proc`身份仅覆盖1,626/81,672（约1.99%），不代表全进程PSS覆盖。

以block0 C1为参照的2,070个跨批动作，命令和返回结构全部相同，解码输出1,926条精确相同、144条不同，原文全部保留。78个Session的原档SHA各自匹配冻结输入，同一任务的源码和新增代码跨六批一致；评分前后候选不变确认72例，Requests1921六例缺清单保持UNKNOWN。实际源码检查不只依赖submission文本，也不声称未采集的owner/硬链接身份一致。详见最终执行证据审计 (`../analysis/final-execution-audit-01/audit.md`, omitted from this source release)和其逐任务CSV、原始行及输出差异。

本批仍不覆盖Controller SIGKILL的完整产品恢复；那是两个资格VM已经明确的缺口，不能由正常批次0补清倒推解决。

## 哪些解释得到支持

静态FIFO与提高准入并发已缩短batch和排队，但增加单Session服务、域准备和工具wall；业务CPU维持在138.64–142.33秒。root残差与observer采样下界随更短批次一起下降，不能全部称为架构效率，也不能估算扣除为纯产品成绩。业务peak不足530MiB/2GiB，没有内存压力或模板淘汰证据；本轮不能判断联合缓存/路由的独立价值。

早期少量宿主离线分析与运行有重叠，最终大规模trace/worktree核验全部在最后VM结束后开展；重叠记录 (`../analysis/offline-analysis-overlap-note.json`, omitted from this source release)保留，nice并不代表零扰动。以上独立审计补充可从最终审计脚本再生；表格和图表来自v4资源分析，分开保存输入SHA。

## 复现与原始索引

!六批成本分布 (`../analysis/workload-final-01/multisession-costs.png`, omitted from this source release)

完整JSON (`../analysis/workload-final-01/summary.json`, omitted from this source release)、每批CSV (`../analysis/workload-final-01/batches.csv`, omitted from this source release)、78任务行 (`../analysis/workload-final-01/tasks.csv`, omitted from this source release)、全部Session (`../analysis/workload-final-01/sessions.csv`, omitted from this source release)、输入SHA (`../analysis/workload-final-01/input-sha.json`, omitted from this source release)。各run的command.json、source-sha.json、pilot-plan.md、fixture、actions、trace、resource-samples和validation为原始证据。host PSI是同宿主背景，不能与guest时间相减。

|run ID|原始账本|
|---|---|
|next-b0-b0-c1|batch (`../runs/next-b0-b0-c1/batch-result.json`, omitted from this source release) / VM (`../runs/next-b0-b0-c1/result.json`, omitted from this source release)|
|next-b0-b0-c2|batch (`../runs/next-b0-b0-c2/batch-result.json`, omitted from this source release) / VM (`../runs/next-b0-b0-c2/result.json`, omitted from this source release)|
|next-b0-b0-c4|batch (`../runs/next-b0-b0-c4/batch-result.json`, omitted from this source release) / VM (`../runs/next-b0-b0-c4/result.json`, omitted from this source release)|
|next-b0-b1-c1|batch (`../runs/next-b0-b1-c1/batch-result.json`, omitted from this source release) / VM (`../runs/next-b0-b1-c1/result.json`, omitted from this source release)|
|next-b0-b1-c2|batch (`../runs/next-b0-b1-c2/batch-result.json`, omitted from this source release) / VM (`../runs/next-b0-b1-c2/result.json`, omitted from this source release)|
|next-b0-b1-c4|batch (`../runs/next-b0-b1-c4/batch-result.json`, omitted from this source release) / VM (`../runs/next-b0-b1-c4/result.json`, omitted from this source release)|

结论限于固定13个Python仓库任务的离线真实动作回放、合成burst、4vCPU/4GiB和当前诊断模式。没有自然跨任务heap命中，没有新缓存/路由机制对照，不能据此推断联合调度的独立收益或生产资源最优布局。不同架构路线的决策另见综合报告。
