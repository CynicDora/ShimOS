# Tool 执行路径：跨域 Python 链与原生工具链的有限对照

**本轮支持一个有限判断：只需要启动外部工具时，没有必要把预热 Python 的跨域派生链作为唯一入口。** T2 在这些固定工具上减少了观测 CPU 和部分完整会话延迟；但两类 ELF 各保留一次明显反向耗时，不能写成所有短工具都稳定加速。这不是 Bubblewrap 与替代沙箱的比较，两条路径都使用 Bubblewrap。

全部正式样本来自同一物理宿主上的 5 个 VM：原计划 3 块五类工具，加上因 ELF 波动而预登记的 2 块有限复核，共 38 个独立 H 会话、114 个请求。每个会话真实执行同一工具 3 次。主表中 ELF 各 5 个同 VM 配对，其他工具各 3 个配对。没有删除慢样本，没有为获得正结果继续追加。

## 两条路径及相同的目标合同

T1 保留外部可信 Python Z，经 Z→S→W 跨域派生，再由 W 执行原 launcher 与外部工具。工具 exec 会替换 Python 地址空间，本实验没有让 NumPy 等应用初始化状态在该 exec 后继续使用。T2 在 Bubblewrap 域内由可信单线程 C PID1 直接派生原生 gate，降权、安装同工具策略并取得业务许可后执行同 launcher/工具。它没有外部 Python Z，也没有 S。

两者都保持六种目标 namespace、最终 UID/GID 65534、capabilities 清零、NNP/seccomp、原子 cgroup 出生、私有授权与 exec 回执、stdout/stderr 分离、真实 wait、取消先封闭许可以及强 Supervisor H 接管。实际父子关系和异常清理组织不同，不能用相同进程树要求代替关键终态合同核验。

固定 VM 为 4 vCPU/4 GiB，沿用既有 Kernel `6.18.49-agentic-runtime-opt-v1`；没有修改 Kernel。T1 使用资格绑定的 glibc candidate D，实际 loader/DSO 已核验。T2 的公共夹具也安装该 bundle，但这不表示 T2 原生进程实际运行或占用它。业务 rootfs、工具源码/二进制、输入和每任务 CPU/内存/PID 预算相同。工具 H 是加强后的双流恢复版本，不与 NumPy 主实验的 H 混成一个排名。

## 资格与历史失败

资格阶段 14 VM、108 尝试使用同一产品版本、同一最终检查器核验，覆盖每条路径 54 尝试、53 种固定场景。包括非零、取消、超时、后代、资源拒绝、私有 exec 回执、输出边界和 Controller 死亡后的 H 接管。该批全部符合各自合同，详情见独立资格报告 (`docs/tool-qualification-independent-review.md`, omitted from this source release)。它们不是性能重复样本。

正式原三块 30 会话/90 请求与追加两块 8 会话/24 请求，均已通过同一冻结检查器首检及实际独立二审：合计 5 VM、38 会话、114 请求，0 FAIL、0 BLOCKED。最终证据汇总 (`analysis/formal-tool-final-summary-v1.json`, omitted from this source release)同时绑定两批首检、二审及追加数字复核，历史首检文件中的“二审待完成”标志原样保留。正式 trace=0，不把它说成重新观察了所有内核 exec：执行映像证据来自精确版本的 trace=1 资格，正式样本仍逐项核验实际身份、授权、wait、私有回执、输出、FD、目录/cgroup 和 H 终态。

T2 pilot01 的实际产品失败保留：正常 DRAINED 后，PID1 通道 EOF 早于 monitor 被 wait，曾错误报告域丢失。独立副本只允许有严格终态证据的正常 EOF；新 pilot 实际触发修复分支后才进入完整资格。另有 T1 首轮检查器误判：异常整域终止本就不能等待 PID1 正常 DRAINED，丢 exec 回执也不等于真实 wait 的退出码必须未知。修正说明 (`docs/checker-t1-failure-correction.md`, omitted from this source release)保留旧检查器、首 FAIL、23 项纯数据反例和统一重核；没有通过改产品或弱化清理换取 PASS。

## 完整三请求会话时间

主 wall 是同 guest 的 **H 创建前→H 被真实 wait**，包含会话准备、T1 Z 初始化、3 次独立建域与工具执行、业务验证、结果整理和最终产品回收。每块先相同工具配对，再对差值取中位数，正值表示 T2 较低。差额不能除以 3 后称为纯启动成本。

| 工具 | VM 配对数 | T1 中位 [范围]，s | T2 中位 [范围]，s | 配对差中位 [范围]，s | T2 较低 |
|---|---:|---|---|---|---:|
|静态 ELF|5|0.594 [0.572, 1.341]|0.311 [0.279, 1.091]|0.285 [-0.497, 1.062]|4/5|
|动态 ELF|5|0.602 [0.585, 0.641]|0.305 [0.291, 1.130]|0.301 [-0.528, 0.337]|4/5|
|Shell pipeline|3|0.587 [0.559, 0.621]|0.328 [0.308, 0.341]|0.247 [0.231, 0.313]|3/3|
|GCC 编译|3|0.846 [0.814, 0.853]|0.532 [0.531, 0.546]|0.313 [0.269, 0.322]|3/3|
|Python unittest|3|1.325 [1.313, 1.340]|1.021 [1.018, 1.028]|0.304 [0.284, 0.322]|3/3|

两个 ELF 的实际配对差如下，原三块没有被后来的结果替换：

| 工具 | 原块 1/2/3，s | 追加块 4/5，s | 原三块中位→五块中位，s |
|---|---|---|---|
|静态 ELF|1.062 / -0.497 / 0.287|0.285 / 0.261|0.287 → 0.285|
|动态 ELF|0.325 / 0.337 / -0.528|0.273 / 0.301|0.325 → 0.301|

追加是看到原始波动后登记的有限复核，不是完全盲测；执行顺序在块间轮换，仍只有同宿主的少量块。不能据此估计稳定 p99、宣称跨硬件优势或在线 Agent E2E 收益。

!全部原始点及同 VM 配对差 (`analysis/formal-tool-presentation-v2/tool-costs.png`, omitted from this source release)

## 时间差落在哪里

下表是每次请求的描述性中位数，ELF 每组 15 请求，其他每组 9 请求；请求在会话内相关，不是独立重复。R 发出许可不是工具已经 ready，R 收到 wait 回执也不是内核刚刚退出。各列中位数不能直接相加。

| 工具/路径 | 请求→响应，ms | 请求→域引用就绪，ms | 域就绪→业务许可，ms | 许可→收到 wait，ms | 收到 wait→响应，ms |
|---|---:|---:|---:|---:|---:|
|静态 ELF T1/T2|109.3 / 69.9|30.8 / 34.2|28.5 / 10.5|3.7 / 4.1|49.6 / 20.4|
|动态 ELF T1/T2|112.6 / 70.5|30.7 / 35.9|29.4 / 10.1|4.2 / 4.1|50.2 / 20.7|
|Shell T1/T2|107.4 / 82.0|30.5 / 34.4|28.5 / 10.4|7.8 / 13.4|41.9 / 23.7|
|GCC T1/T2|189.0 / 147.1|31.3 / 34.4|26.6 / 10.3|71.1 / 74.5|57.8 / 28.7|
|unittest T1/T2|343.9 / 306.2|32.1 / 35.0|29.1 / 10.7|233.6 / 234.7|50.5 / 25.0|

在这些观测中，T2 的建域前段没有更快；差距主要出现在建域之后的派生/授权控制，以及收到 wait 后的状态整理与回收。会话开始到首次请求，T1 中位 195 ms、T2 48 ms；它包含 H/R 启动、Z 准备等，不能全部归为解释器初始化。最后一次响应到 H 被 wait 中位为 74/45 ms，包含会话收尾。每个会话另存了严格不重叠的四段并逐纳秒验证闭合，见关键路径分区 (`analysis/formal-tool-presentation-v2/critical-path-partition.csv`, omitted from this source release)。

这些都是现有研究原型的完整成本，仍包含必要状态验证和证据 I/O；不能把约 30–36 ms 的“请求→域引用就绪”直接当作裸 Bubblewrap syscall 成本。所有细分 span 保留，但没有把嵌套等待、写盘和 syscall 时间相加冒充总延迟。

三个较慢 ELF 会话的时间同时增大在请求内部与最后收尾：T1 静态块1完整 1.341 s，其中三请求累计 0.740 s、最后收尾 0.404 s；T2 静态块2为 1.091/0.682/0.355 s；T2 动态块3为 1.130/0.880/0.202 s。仅凭这些阶段无法把异常完全归因于某个 syscall。宿主五个完整 VM 窗口的 IO PSI avg10 最大 16.02%、memory PSI 最大 4.67%，MemAvailable 最低 48.38 GiB；这些窗口含 fixture，且没有宿主/guest 的逐请求时钟映射，不能直接解释哪条请求为何反向。宿主记录 (`../analysis/tool-formal-host-pressure-02/`, omitted from this source release)

## CPU 与内存

CPU 采用 H 两次 `getrusage` 的 **SELF 增量 + CHILDREN 增量**。H 实际使用 waitpid 回收，后者累计它已 wait 的 R/收养后代，以及经过逐级真实 wait 合入的后代 CPU；不是直接记录每次 wait4 返回值，也不是全系统 CPU。它包含 H 自身，不应再加 R、task 或 Worker 的明细。

H 初始 usage 之前、最终 usage 之后的 memory 采样/flush/退出，以及 fixture 自身 CPU 不在这个窗口。最终 usage 已位于 supervisor.json 写入和 FINISHED 事件之后。完整根 cgroup CPU 未采集，保持 Unknown。

| 工具 | T1 H 观测包含 CPU 中位，s | T2 中位，s | 同 VM 配对 CPU 差中位 [范围]，s |
|---|---:|---:|---|
|静态 ELF|0.404|0.138|0.265 [0.220, 0.307]|
|动态 ELF|0.397|0.137|0.270 [0.230, 0.303]|
|Shell|0.410|0.142|0.256 [0.243, 0.279]|
|GCC|0.621|0.348|0.274 [0.229, 0.289]|
|unittest|1.131|0.853|0.276 [0.270, 0.295]|

19 个配对的这个 CPU 差均为正。它支持减少整条控制链确实少做了一部分工作，但不能把 0.25 s 左右归成单次 fork，或者与 NumPy 的 root-cgroup CPU 混算。

T1 的外部 Z ready 时，19 个时点的 PSS 中位 14.46 MiB（14.27–14.57），RSS 中位 19.13 MiB；T2 没有这个进程。**这不等于已经测得全系统净省 14.46 MiB。** 异步各进程 PSS 不能相加冒充整体峰值，短工具采样还可能只捕获 launcher 或漏采。

| 工具 | T1 task memory.peak 中位，MiB | T2 中位，MiB |
|---|---:|---:|
|静态 ELF|5.98|2.43|
|动态 ELF|6.16|2.52|
|Shell|6.51|3.68|
|GCC|11.20|8.45|
|unittest|16.99|14.43|

这是请求 cgroup 层级峰值，不含外部 Z/H/R；不是 PSS，也不是跨角色物理峰值。完整 PSS 时间积分、整个会话物理峰值和净物理节省保持 Unknown。逐样本与缺测记录见角色时点 (`analysis/formal-tool-presentation-v2/role-memory-points.csv`, omitted from this source release)及原始 memory-observations。

## 夹具、复现与结论范围

源码复制约 0.112–0.151 s、运行时安装约 1.637–2.061 s 位于主时间之外，是各组同样执行的可复用部署夹具，不是免费的应用模板初始化。H wait 后的观察器、空委托目录删除/记录尾段约 0.124–0.137 s 单列；没有把主产品未回收资源移到这个尾段。所有正式样本 H 与产品都确认释放，observer 不参与补杀或删除。

本结果值得保留一个面向明确工作负载的选择：需要继承 Python 初始化内存时继续研究预热路径；本来就要 exec 外部工具时，独立原生工具路径可以减少不再使用的 Python 控制与派生准备。它并不证明某个统一 Scheduler 最优，也不是 Bubblewrap 本身的缺陷。T2 的 raw clone 来自可信单线程 C，不能拿它作为绕开 CPython/glibc fork 契约的先例。

范围仍是固定可信工具、同主体私有工作区、串行三请求和可信 H 正常存活。没有任意第三方工具、H 死亡、宿主 OOM、完整文件系统故障或生产规模资格。原异常清理语义与 exec UNKNOWN 不能被性能表替代。

复现和原始索引：

- 原始预登记 (`frozen/formal-tool-paired-plan-v2.json`, omitted from this source release)、两 ELF 追加登记 (`frozen/formal-tool-elf-extension-v1.json`, omitted from this source release)、实际资格准入 (`frozen/tool-performance-admission-v1.json`, omitted from this source release)。
- 30/90 首检 (`analysis/formal-tool-performance-check-v1/summary.json`, omitted from this source release)、原三块独立二审 (`analysis/formal-tool-performance-independent-review-v1.json`, omitted from this source release)、追加 8/24 首检 (`analysis/formal-tool-elf-extension-check-v1/summary.json`, omitted from this source release)、追加两块独立二审 (`analysis/formal-tool-elf-extension-independent-review-v1.json`, omitted from this source release)、追加数字独立复核 (`analysis/tool-elf-extension-analysis-independent-review-v1.json`, omitted from this source release)、最终证据汇总 (`analysis/formal-tool-final-summary-v1.json`, omitted from this source release)。
- 原三块冻结分析 (`analysis/formal-tool-paired-results-v1/manifest.json`, omitted from this source release)、独立追加分析 (`analysis/formal-tool-elf-extension-results-v1/manifest.json`, omitted from this source release)、全部配对原值 (`analysis/formal-tool-presentation-v2/paired-summary.csv`, omitted from this source release)。
- 逐请求阶段 (`analysis/formal-tool-presentation-v2/request-stage-summary.csv`, omitted from this source release)、实际 session 小表 (`analysis/formal-tool-presentation-v2/session-summary.csv`, omitted from this source release)、图表及来源 SHA (`analysis/formal-tool-presentation-v2/manifest.json`, omitted from this source release)。
- 实际执行说明 (`docs/formal-paired-execution.md`, omitted from this source release)、冻结分析口径 (`docs/paired-analysis-contract.md`, omitted from this source release)、T2 pilot 失败与修补 (`docs/pilot-eof-race-and-fix.md`, omitted from this source release)。
