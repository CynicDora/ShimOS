# A+B 执行链成本分解与最小协议优化

**结论：合并 PING 的局部精简成立，完整请求的稳定净收益尚未证实。** 两组完成的同 VM 对照中，末端 FORGET/PING 合计跨度分别减少约 0.264 ms、0.389 ms；正常消息骨架由 25 个降为 23 个。但完整响应的两组中位数一升一降，反向顺序 VM 的候选尾部反而更长，R CPU 两组均增加。当前更大的观测成本来自正确性探针、证据写入和测试业务等待，不能将这些直接当成双 fork 或 Linux 固有成本。

本报告保留 4 个正式 VM 尝试中的 2 个建域失败，不用成功对照掩盖失败。所有数值仅描述当前可信串行机制原型；没有真实 Agent E2E、第三方依赖、吞吐或大模板测试。

## 1. 比较对象、环境与资格

基线是 A+B 集成后的 `baseline_instrumented`，候选是 `ping_merged` v2。候选将模板状态和 FD 检查并入 FORGOTTEN，再核验模板 pidfd 仍未退出，删除单独 PING/PONG；没有删除清理、业务门禁、真实 wait 或状态检查。它属于可独立消融的协议精简，不是新调度架构。FORGOTTEN承载的快照不是之后任意时刻的响应性证明；pidfd能发现退出，不能证明模板未卡死，所以任意模板卡死合同仍不等价。实现与资格见 [协议变更与资格](ping-merge-design-and-results.md)、资格总表 (`../analysis/qualification-and-counterexample-final-matrix.md`, omitted from this source release)。两条路径各通过 29 个受限资格尝试，合并候选另有 6 个专门反例；这与下文性能会话的启动失败是不同证据。

正式性能使用同一物理宿主上的 KVM 私有 VM，4 vCPU、4 GiB、CPU host；guest kernel `6.18.49-agentic-runtime-opt-v1`，host kernel `6.18.55-DAMON`，Python 3.10.12，候选 D 的固定 glibc 2.35 runtime，Bubblewrap 0.13.1。保留原 namespace、UID/GID、capability、NNP、seccomp、cgroup 出生归属和 H 清理合同。自然 page cache，不 drop cache，不运行 syscall tracing；每个 session 都重新建立 H/R/Z 及私有资源。VM 内两个 session 串行，缓存、调度和宿主压力仍可能变化。

每 session 5 次 warmup + 35 次计量。原计划 3 个 VM；因启动失败作一次有界续跑，最终共尝试 4 个，只有 VM1（`formal-pair-01-1`）和 VM4（`formal-pair-02-1`）完成两方案。没有继续追凑 3 个成功 VM。两个成功 pair 共 160 请求，其中 140 个计量点、20 个 warmup。各 VM 是同宿主重复环境，不是独立硬件；35 个点不能当作 35 台机器。

## 2. 全部运行账本与失败

| VM | 实际顺序 | 结果 |
|---|---|---|
| formal-pair-01-1 | 基线→合并 | 两会话各 40 次完成 |
| formal-pair-01-2 | 合并→基线 | 合并完成 11 次，第 12 次等待 DOMAIN_READY 超时；基线未启动 |
| formal-pair-01-3 | 基线→合并 | 基线第 1 次等待 DOMAIN_READY 超时；合并未启动 |
| formal-pair-02-1 | 合并→基线 | 两会话各 40 次完成 |

总计 **173 个已开始 attempt，171 个最终 PASS/RELEASED 收据，2 个未正常完成的建域 attempt**。这 2 个不能记为成功请求；也不能把“2/4 VM 会话未完成”推广为生产失败率。两次 H 都保守记录 UNKNOWN，实际收养/wait、域和目录清理、FD 恢复完成，最终 RELEASED，未借观察者补杀。未完成 attempt 的旧 journal 仍为 PENDING，须与 H 收据一起读。

两次均在该 attempt 的 REGISTER/SPAWN 前等待域导出，没有进入被优化的 FORGET 路径。现有证据只能确认 R 没及时收到 DOMAIN_READY；目标 send 侧没有持久的对应事件，无法区分“尚未发送”和“已发送但处理迟到”。不能说已经证明 Bubblewrap 本身故障，也不能只归因于合并候选。

VM2 中 R 的 COST 缓冲导出还被 H 终止打断：最终收据已到 repeat 10，而部分计时只到 repeat 7。缺记录不补造，失败日志不进入成功配对均值。原始证据：完整尝试账本 (`../analysis/final-cost-analysis-01/attempt-ledger.json`, omitted from this source release)、VM2 审计 (`../analysis/formal-measurements-01/vm2-failure-audit.md`, omitted from this source release)、VM3 环境审计 (`../analysis/formal-pair-01-3-environment-audit.json`, omitted from this source release)、失败计时及缺失项 (`../analysis/final-cost-analysis-01/failed-session-timing.json`, omitted from this source release)。

共享宿主后来记录到明显压力：13:04:25 UTC 快照 (`../analysis/host-pressure-observation-01.json`, omitted from this source release)中 I/O PSI full avg10=58.53%、avg60=60.10%，memory PSI full avg10=18.73%、avg60=22.80%。这是环境干扰证据，不能用稍后的宿主快照精确解释此前某次 guest 超时，也不把宿主与 guest 绝对单调时间直接相减。

## 3. 主要结果：完整 response-ready

以下全部是**完成两个会话的条件性比较**；失败单列，不静默排除。每格 n=35，单位 ms，P90 为线性插值的小样本分位数。

| VM / 顺序 | 基线中位数 | 合并中位数 | 基线−合并 | 基线 P90 | 合并 P90 |
|---|---:|---:|---:|---:|---:|
| VM1：基线→合并 | 150.325 | 150.932 | −0.607 | 157.179 | 156.619 |
| VM4：合并→基线 | 201.150 | 173.375 | +27.775 | 421.024 | 690.138 |

主指标从 R `request_begin` 到 `response_ready`，包含建域、输出读回、wait、域空条件、FD/目录/cgroup 删除、结果检查、RETIRE 与响应构造。业务入口不代表全部后代结束；域空不代表响应已准备好。

同 repeat ID 只匹配输入，不代表相同瞬间和相同缓存状态。逐 repeat 差值仅作诊断：VM1 中位数 −1.155 ms，范围 −11.288～+23.423；VM4 中位数 +5.716 ms，范围 −963.326～+710.325。它们不等于两会话中位数之差。只有 2 个同宿主完整 pair，且分布不稳定，不给出泛化显著性或生产尾延迟结论。

## 4. 相邻阶段与真正可触及的局部预算

下表是同 guest CLOCK_MONOTONIC 的相邻阶段，各原始请求区间不重叠。**阶段名字不是纯 syscall 成本；各行中位数不能相加重建完整中位数。**

| 相邻阶段（ms，中位数） | VM1 基线 | VM1 合并 | VM4 基线 | VM4 合并 |
|---|---:|---:|---:|---:|
| 请求→域就绪 | 28.949 | 30.003 | 30.614 | 31.086 |
| H 清理责任登记 | 1.527 | 1.489 | 1.590 | 1.585 |
| 请求准备至 PREPARED | 3.901 | 3.684 | 4.090 | 4.407 |
| 第一次派生、进入及通知 | 17.653 | 17.186 | 30.722 | 22.303 |
| 第二次派生与 Worker 门禁 | 17.000 | 17.259 | 24.119 | 19.642 |
| 业务许可送达 | 3.389 | 3.379 | 3.408 | 3.405 |
| W 主进程业务 | 2.624 | 2.913 | 3.886 | 3.961 |
| 后代、输出和域结束 | 58.196 | 59.308 | 62.873 | 59.377 |
| 域结束→FORGOTTEN | 0.999 | 2.420 | 1.123 | 2.257 |
| FD、目录与 cgroup 删除 | 1.713 | 1.573 | 1.750 | 1.675 |
| 最终业务/模板检查 | 4.547 | 3.010 | 5.214 | 3.293 |
| RETIRE 与响应准备 | 6.984 | 7.203 | 8.111 | 7.375 |

最大阶段是后代、输出和域结束（58–63 ms），包含原 normal 用例中人为设置的约 40 ms 后代延迟，不能当成自然 Agent 计算或无谓监督等待。其次是域准备（29–31 ms）、第一次派生/进入和第二次派生/门禁。这些阶段包含控制器、探针和日志，不是 fork 或 namespace 的纯成本。

### 4.1 实际删除一轮 PING，省下多少？

| 局部指标（ms，中位数） | VM1 基线 | VM1 合并 | VM4 基线 | VM4 合并 |
|---|---:|---:|---:|---:|
| 单独 PING RPC | 1.588 | 不再单独调用 | 1.447 | 不再单独调用 |
| 单独 FORGET RPC | 0.259 | 1.544 | 0.236 | 1.316 |
| 每请求 FORGET+PING 合计 | 1.808 | 1.544 | 1.705 | 1.316 |

最后一行先在每个请求内求和再取中位数，避免相加中位数。状态检查被搬到 FORGOTTEN，候选该回执更慢，所以不能将原 1.4–1.6 ms PING 全算成可节省成本。局部差值约 **0.264 / 0.389 ms**；这仍是相继会话的观测差，不是随机逐请求因果估计。

R 的固定消息骨架由 25 个降为 23 个。VM1 实际消息恰为 25/23；VM4 基线为 25–33（中位数27），候选为23–27（中位数23），额外 QUERY/SNAPSHOT 随等待而触发。统计只取请求窗口内 R 边界的包，不把各角色观察同一包重复加总，不把最终会话 STOP/DONE 算进最后请求。不存在唯一包 ID 时不猜测 RTT。

### 4.2 诊断与证据写入是明显成本，但可删除量仍未知

R journal 区间并集中位数：VM1 基线/合并 **49.645/50.761 ms**；VM4 **97.797/67.220 ms**。它横跨多个相邻阶段，不能再加到主路径上。该实现是同步 JSON 写文件和 rename，位于 9p `/evidence`；`dump()` 没有 fsync，因此不能称为每条 durable journal 成本。wall 含调度和 I/O 等待，不等于文件系统 CPU。

S 的三次诊断 snapshot（早降权、第二 fork 前、第二 fork 后父分支）各有约 4.9–7.9 ms 中位跨度。它们含 native 查询、0–4095 FD 扫描、JSON 以及日志 write。这是当前正确性观测开销，不能说成 Worker 每次必须枚举 4096 个 FD。尚未拆开纯扫描、I/O、CPU 和停顿成本；也没有证明所有检查可删或可异步化。

Pilot02（5warm+8计量）曾有 response 中位数322.090 ms、R journal并集236.488 ms。最慢 repeat7 response2213.202 ms，其中 Z fork前RP snapshot1678.858 ms，而同次第一 fork bridge父分支仅3.182 ms。秒级停顿发生在 fork前诊断，不能据此宣称双 fork 昂贵。该 pilot 独立保留，不混入正式成绩。

### 4.3 fork、权限与 namespace 的边界

| 角色局部跨度（ms，中位数） | VM1 基线 | VM1 合并 | VM4 基线 | VM4 合并 |
|---|---:|---:|---:|---:|
| 第一次 bridge 入口→Z 父分支返回 | 2.051 | 1.829 | 2.844 | 2.722 |
| 其中 libc 调用→父分支返回 | 1.014 | 0.871 | 1.455 | 1.161 |
| 第二次 bridge 入口→S 父分支返回 | 1.490 | 1.509 | 1.955 | 1.859 |
| 其中 libc 调用→父分支返回 | 0.748 | 0.709 | 0.839 | 0.810 |

这些跨度含 callbacks、进程创建和调度；不能把同一 fork 的父子返回跨度相加，不能把外层跨度减内层中位数当严格阶段拆解。当前 S 各 setns/root 细分中位跨度在微秒量级，seccomp 安装约数十至百微秒；不足以解释数十毫秒的外层阶段。更精确值保留在 JSON，不以跨样本中位数差额强行分配全部 wall。

独立 clone3 tracing 诊断 (`../analysis/clone3-diagnostic-01/clone-trace-analysis.json`, omitted from this source release)校验 mono 和零丢失：同一次请求 Z clone3 syscall wall0.673 ms、S0.325 ms，各 n=1。它只用于区分 syscall 与 wrapper 边界，不是无扰动均值或内核 CPU，不进入正式表格，也不代表不同模板内存大小。

## 5. 冷建立、整会话和退出成本

本轮每个 session 重新创建 H/R/Z；热请求表不能代替冷启动成本。下表按可观察边界单列，没有将 H/R 启动与 Z 初始化免费摊销。`Z Python 入口` 位于 Python 已加载若干模块之后，不是解释器第一条指令；R 起点→该入口还含校准、初始快照、目录/cgroup 和 spawn 等准备。因此不能将约150 ms 全说成 Python 初始化。

| 会话建立/退出跨度（ms，各会话一次） | VM1 基线 | VM1 合并 | VM4 基线 | VM4 合并 |
|---|---:|---:|---:|---:|
| fixture 起点→H 进入 | 17.385 | 17.696 | 25.877 | 17.740 |
| H 进入→R 会话起点 | 3.876 | 3.820 | 5.312 | 4.420 |
| R 起点→Z Python 插桩入口 | 151.780 | 151.604 | 157.790 | 155.540 |
| Z Python 入口→Z ready | 2.390 | 2.351 | 2.518 | 3.066 |
| Z ready→R 收到 ready | 9.674 | 8.291 | 9.495 | 9.452 |
| R 会话终点→fixture 真实 wait(H) | 67.628 | 173.279 | 626.051 | 418.907 |
| R 完整会话（ms，40 请求） | 6241.100 | 6223.745 | 14475.288 | 13787.448 |
| fixture 起点→真实 wait(H)（ms） | 6329.989 | 6418.540 | 15132.528 | 14228.515 |

这些都是各会话一次的诊断，不是独立冷启动重复样本。`fixture→wait(H)` 包含 H/R/Z 初始化、全部40请求以及实际退出；R session不含之前H建立和之后H尾部。R结束后 Hwait 的部分跨度包含 R/Z/H COST缓冲输出、收养检查和 H退出，未单独归因，不能藏到 ACK 后称为零。fixture 最终 release另含约100ms观察者等待，不是产品清理。root fixture 编译、固定 runtime 安装和9p拷贝在此会话边界之外，见每session命令/日志，不将一次实验软件安装冒充每请求业务初始化。

精确边界和原始时间戳见 session-startup-account.json (`../analysis/final-cost-analysis-01/session-startup-account.json`, omitted from this source release)。

## 6. CPU、PSS/RSS、峰值和回收

| 指标 | VM1 基线 | VM1 合并 | VM4 基线 | VM4 合并 |
|---|---:|---:|---:|---:|
| R 自身 CPU / 请求（ms，中位数） | 26.351 | 27.578 | 30.523 | 31.803 |
| 私有 task cgroup CPU / 请求（ms，中位数） | 43.169 | 43.441 | 52.006 | 52.226 |
| task cgroup memory.peak（MiB，中位数） | 7.293 | 7.270 | 7.570 | 7.402 |
| S 退出前自身 CPU（ms，中位数） | 22.863 | 22.370 | 27.453 | 26.901 |
| W 退出前自身 CPU（ms，中位数） | 6.615 | 5.925 | 8.466 | 8.328 |
| H 已计会话 CPU（ms，40 请求） | 3387.301 | 3369.321 | 4121.255 | 4155.161 |

R CPU 是自身累计差；task cgroup CPU含该域及子组，S/W自身CPU也已在其他账本中，**不能全部相加**。H已计会话CPU是H自身+真实wait后累计孩子CPU，不再加R、Z或cgroup；采样早于H最终内存读取、COSTflush及exit，因而尚缺H这一小段尾部CPU。完整wall已经包含尾部。

| 非同时内存快照：RSS / PSS（KiB） | VM1 基线 | VM1 合并 | VM4 基线 | VM4 合并 |
|---|---:|---:|---:|---:|
| R 会话开始 | 19084 / 7160 | 19444 / 7240 | 19152 / 7174 | 19436 / 7186 |
| R 会话结束 | 24056 / 13164 | 24132 / 13201 | 24012 / 13234 | 24236 / 13290 |
| Z 初始化就绪 | 19428 / 14728 | 19616 / 14771 | 19580 / 14706 | 19628 / 14768 |
| H 开始 | 19204 / 9905 | 19500 / 10035 | 19272 / 9948 | 19556 / 10058 |
| H 结束 | 21608 / 11631 | 21668 / 11695 | 21504 / 11597 | 21608 / 11621 |

快照并不同时发生，不能求和为峰值；Z/H/R缓冲日志也占内存。S/W lifetime maxRSS原始样本保留在JSON。task memory.peak不是全产品内存，Z原有COW页的计费和跨cgroup共享不能用它单独估算；没有测同时PSS、内存时间积分、页表/COW写放大或长期稳态增长。两组R CPU均增，完整H CPU一降一升，当前不能声称CPU或内存稳定改善。

成功会话的进程wait、输出EOF、资源删除、FD恢复以及H最终收据均保留；失败两会话也由H报告RELEASED。没有观察者补清理。上述结果是本轮有限运行的回收事实，不是宿主OOM、H死亡、文件系统故障或长期运行保证。

## 7. 打点开销对照：不能得出固定扣除值

两独立VM各4session，方案和 on/off 次序记录；每格5warm+8计量。off只关闭本轮新增COST细分，仍保留强制请求/会话端点、RP/native atfork正确性探针、FD扫描、原journal和40ms夹具。

| VM / 方案 | timing on中位数（ms） | off中位数 | on−off |
|---|---:|---:|---:|
| overhead1 基线 | 198.103 | 208.624 | −10.521 |
| overhead1 合并 | 149.377 | 250.171 | −100.794 |
| overhead2 基线 | 156.950 | 213.976 | −57.026 |
| overhead2 合并 | 160.118 | 159.998 | +0.120 |

104请求全部完成，64计量、40warmup。顺序块的差异远大于预期打点预算，并且方向混杂；当前无法从这种共享宿主下的小样本中隔离出打点成本。**不扣除负数，不宣称打点免费或使程序变快。** on/off完整点、P90和顺序见 overhead-summary.json (`../analysis/final-cost-analysis-01/overhead-summary.json`, omitted from this source release)。off缺失阶段和消息数记N/A，不写成零。

## 8. 可以下的结论与不能下的结论

**已测事实：**固定末端协议少两条消息，局部合计跨度在两个完成pair均较低；阶段和CPU/PSS账本已建立。完整请求没有稳定净收益，两次域准备超时与缺失计时如实保留。原型整体成本中，证据写入和运行时探针比本次可触及的PING预算明显更大。

**分析：**当前最有信息价值的是先分清产品必需状态检查与资格诊断的职责、缩小证据路径干扰，并在受控宿主上复核同合同成本。它不授权删除检查，不以“少一轮RPC”自动推断Agent加速，也不据此删除H/S或启动内核改造。

**尚未解释：**宿主压力对每个慢请求的因果贡献；建域内部各Linux原语占比；journal中CPU/I/O/调度份额；RP扫描与日志各自成本；完整打点扰动；H最终尾部CPU；真实业务初始化和不同模板内存下的fork/COW成本。现有数据不能支持这些更强结论。

## 9. 原始数据、版本和复现

统一入口是 raw-data-index.md (`../analysis/final-cost-analysis-01/raw-data-index.md`, omitted from this source release)，包括正式成功/失败、on/off、pilot及trace的分组说明。核心文件：

- formal-cost-summary.json (`../analysis/final-cost-analysis-01/formal-cost-summary.json`, omitted from this source release)：阶段、局部跨度、CPU/PSS、会话和配对摘要。
- formal-success-pairs.json (`../analysis/final-cost-analysis-01/formal-success-pairs.json`, omitted from this source release)、逐请求CSV (`../analysis/final-cost-analysis-01/formal-success-requests.csv`, omitted from this source release)：全部160成功pair请求，warmup不删除。
- cost-events.jsonl (`../analysis/final-cost-analysis-01/cost-events.jsonl`, omitted from this source release)：32763条原始COST记录的只读导出，附source run/file/line；导出清单及SHA (`../analysis/final-cost-analysis-01/cost-events-manifest.json`, omitted from this source release)。失败时未flush记录不重构。
- attempt-ledger.json (`../analysis/final-cost-analysis-01/attempt-ledger.json`, omitted from this source release)：全部4正式VM、173已开始attempt、未启动session和失败账本。
- measurement-method.md (`measurement-method.md`, omitted from this source release)、[analyze_cost.py](../runner/analyze_cost.py)、[export_cost_events.py](../runner/export_cost_events.py)：边界、离线统计与导出方法；执行命令保存于analysis。

精确版本以每session `environment.json`、`variant-manifest.json`、`candidate-runtime-sha.json`、`guest-session-config.json` 和VM `command.json`为准。正式源码审查v2 SHA256为 `9f6ed551de470a0210e3a652b9e8b67d0328a3ad7e90103baf1def683c906c7f`；候选runtime libc SHA256 `a03b51fe69f36b630ecf7997af05cd36885b1f2f0b52e278391fa6e17047eff4`，loader SHA256 `0682f493d0434391d4ec027d0bcb54dd5f9e46d044dc7810f69abea58fe1398e`。不能只凭 `glibc 2.35` 字符串推断实际加载闭包。原A/B与旧研究输入保持不变，完整性见 input-integrity-after.json (`../analysis/input-integrity-after.json`, omitted from this source release)。
