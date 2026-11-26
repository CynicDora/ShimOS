# 域内 Zygote 与持久 Worker：固定任务对照结果 v2

2026-10-20。正式三块私有 VM 采样完成；独立性能资格 (`../analysis/persistent-v2-qualification-final-01/summary.json`, omitted from this source release)为 **72 会话 PASS、0 FAIL、0 BLOCKED，覆盖全部 2292 次请求**。这只确认本轮固定可信任务和已声明的生命周期检查，不授予任意业务状态复用或生产级资格。

## 比较范围

每会话只创建一个域，D=1，连续 K=N 次请求；K 为 1、5、10、25、50、100。两种任务配方为 `v1:blas:8:readonly:light` 和 `v1:blas:8:full:light`，对应相同 8 MiB 固定数组、相同轻量数值计算，只改变本轮已定义的写入模式。三个 VM 在同一物理宿主上，以同 VM、同 K、同配方配对。

| 路径 | 保留什么 | 每请求如何完成 | 最终何时退出和回收 |
|---|---|---|---|
| G3 域内 Zygote | 一个干净域内模板 | 创建独立 Worker / 业务 cgroup；真实 wait、输出 EOF、业务资源清理后完成 | 会话末停止模板与 PID1、清空并移除域，由 H 验收 |
| G4 持久 Worker | 同一个已经初始化的 Python Worker | 固定函数返回后逆转本任务已知写入，恢复 geterr，检查指纹及进程状态，收集本次输出 EOF 后确认；Worker 保留 | 会话末真实 wait Worker/PID1并释放域；不伪造逐请求进程退出 |

**两者不是任意不可信请求下的相同隔离合同。** G4 只适用于本轮同信任主体、串行、固定函数和已知状态恢复范围。它不会清除任意第三方库的隐藏状态，不承担跨租户复用。正常 reset 失败、状态不明或不能恢复时，需要停止并回收该 Worker/域，不能继续当作干净实例。此成本对照也不改变上述范围。

主指标为 H 创建前至 H 被真实 wait 的完整会话时间，包含域与模板初始化、所有业务、G4 同步 reset 和最终清理。观察夹具尾段单列，不计入主指标。请求内的 call 计时位于持久域准备之后，不能用它替代完整会话成本。CPU 使用产品根 cgroup 的层级 usage，不再叠加子组。

## 完整会话耗时

Δ=G3−G4，正数表示该固定合同下 G4 成本更低。先逐 VM 作差，再取三个差值的中位数；表中的区间是三个实际差值的最小～最大值，不是置信区间。没有根据耗时删除样本。

| 写入模式 | K | G3 中位 s | G4 中位 s | 配对 Δ 中位 s | 配对范围 s |
|---|---:|---:|---:|---:|---:|
| readonly | 1 | 0.700 | 0.682 | +0.018 | -0.398～+0.023 |
| readonly | 5 | 1.267 | 0.966 | +0.262 | +0.200～+0.490 |
| readonly | 10 | 1.892 | 1.414 | +0.526 | +0.479～+0.556 |
| readonly | 25 | 4.009 | 2.573 | +1.371 | +1.283～+1.587 |
| readonly | 50 | 7.273 | 4.647 | +2.636 | +2.324～+2.893 |
| readonly | 100 | 14.022 | 8.604 | +5.352 | +4.853～+6.412 |
| full | 1 | 0.730 | 0.675 | +0.034 | +0.006～+0.060 |
| full | 5 | 1.216 | 0.969 | +0.229 | +0.221～+0.305 |
| full | 10 | 1.958 | 1.472 | +0.484 | +0.386～+0.490 |
| full | 25 | 4.146 | 2.636 | +1.639 | +1.227～+1.716 |
| full | 50 | 7.584 | 4.630 | +2.978 | +2.955～+3.037 |
| full | 100 | 14.628 | 8.663 | +5.447 | +4.271～+6.114 |

K≥5 的两种配方中，所有受测同 VM 配对都是 G4 更快；readonly K=1 保留一次 **−0.398 s** 的反向差值，另外两次为正。因此单请求下不能声称稳定收益。full K=1 虽三次均为正，但只有约 6～60 ms，不足以推导通用的最小请求阈值。

这些差值是完整路径对照，并非纯 fork 成本。G3 的逐请求真实退出、cgroup 生命周期和更多控制过程，与 G4 的函数调用、已知状态恢复和保持进程存活不同；本轮没有把总差值严格拆成各机制的因果贡献。

## CPU 与 root 记账峰值

| 写入模式 | K | G3 CPU中位 s | G4 CPU中位 s | CPU配对Δ中位 s | G3 / G4 root memory.peak MiB |
|---|---:|---:|---:|---:|---:|
| readonly | 1 | 0.618 | 0.591 | +0.032 | 53.68 / 41.21 |
| readonly | 5 | 1.072 | 0.811 | +0.239 | 53.43 / 41.46 |
| readonly | 10 | 1.674 | 1.124 | +0.564 | 53.45 / 41.77 |
| readonly | 25 | 3.447 | 2.072 | +1.322 | 54.17 / 43.18 |
| readonly | 50 | 6.401 | 3.621 | +2.672 | 55.53 / 45.39 |
| readonly | 100 | 12.301 | 6.543 | +5.759 | 59.16 / 50.38 |
| full | 1 | 0.642 | 0.604 | +0.025 | 61.67 / 41.21 |
| full | 5 | 1.083 | 0.817 | +0.244 | 61.47 / 41.57 |
| full | 10 | 1.721 | 1.175 | +0.513 | 61.70 / 41.81 |
| full | 25 | 3.556 | 2.111 | +1.560 | 62.40 / 43.15 |
| full | 50 | 6.717 | 3.642 | +3.098 | 63.65 / 45.71 |
| full | 100 | 12.620 | 6.798 | +5.686 | 66.93 / 50.40 |

本轮 G4 的根 cgroup 峰值较低，但随 K 从 1 到 100 也从约 41 MiB 增至约 50 MiB。它包含产品控制进程、私有页及该 cgroup 被计费的其他内容，不能直接叫作“Worker heap 泄漏”，也不能据此证明净物理内存节省。G3 也包含模板、短命 Worker、控制过程及日志相关资源。

## 状态恢复并非免费

1146 条 G4 `NP_RESET` 都有本地 `fixed_state_restored=true`、恢复前后期望指纹相等的记录；整体正确性另由前述独立资格确认。下面先对每会话的请求 reset 取中位数，再取三个 VM 的中位数。

| K | readonly reset wall / CPU 中位 ms | full reset wall / CPU 中位 ms |
|---:|---:|---:|
| 1 | 14.49 / 14.49 | 14.90 / 14.90 |
| 5 | 14.47 / 14.47 | 14.89 / 14.89 |
| 10 | 14.49 / 14.49 | 14.88 / 14.88 |
| 25 | 14.48 / 14.48 | 14.89 / 14.89 |
| 50 | 14.48 / 14.48 | 14.90 / 14.90 |
| 100 | 14.49 / 14.49 | 14.89 / 14.89 |

K=100 时，同一会话全部 reset 的累计 wall 中位数约 readonly **1.461 s**、full **1.497 s**，对应累计 CPU 也约 1.461 s / 1.497 s。这些成本已包含在完整会话时间中，不能再加一次。即使 readonly 没有 DATA 写入，也保留指纹检查和 NumPy 状态恢复；full 再逆转固定 DATA 写入。

该 span 包含指纹计算及验证，不是纯数组恢复时间；后续线程、FD、环境、信号等进程状态检查还有自己的成本，不全部包含在 NP_RESET span 内。实现依据：local_zygote.py 的 g4 (`../frozen/sequential-v2/local_zygote.py`, omitted from this source release)与numpy_workload.py 的 reset_persistent (`../frozen/sequential-v2/numpy_workload.py`, omitted from this source release)。原始 reset 事件在resets.csv (`../analysis/persistent-v2-numpy-costs/resets.csv`, omitted from this source release)，逐会话汇总 (`../analysis/persistent-v2-numpy-costs/reset_session_summary.csv`, omitted from this source release)保留请求数及检查结果。

## 内存积分的可观察范围

root memory.current 的梯形积分仅在两侧覆盖均≥90%时配对。K=1、5、10 的短会话没有可用配对，不补零，也不按覆盖率外推；K≥25 的结果如下。正 Δ 表示 G4 使用较少的 root 记账内存时间，单位 MiB·s。

| 写入模式 | K | 可用 VM 配对 | root 记账积分Δ中位 MiB·s | 配对范围 MiB·s |
|---|---:|---:|---:|---:|
| readonly | 25 | 3/3 | 64.6 | 63.0～71.2 |
| readonly | 50 | 3/3 | 130.2 | 122.4～146.2 |
| readonly | 100 | 3/3 | 269.4 | 250.0～302.9 |
| full | 25 | 3/3 | 87.7 | 70.6～96.1 |
| full | 50 | 3/3 | 169.9 | 168.2～171.4 |
| full | 100 | 3/3 | 320.9 | 261.7～351.9 |

**完整 PSS 积分仍不足以给出架构结论。** 36 个架构配对中，只有 full/K=25 的一个 VM 配对达到两侧 90% 覆盖，其余 35 对都不可用。这个孤立配对和各单组可观察点原样保留，但不能取代三个 VM 的完整对照；没有降低覆盖阈值。

G4 的角色映射已明确为 `W_PERSISTENT`，原 sampler 的 Z 标签保留在 `role_observed`。当前导出表的 `numpy_initialized_business` phase 没有合格的 G4 进程样本，因此该 phase 的 PSS 为 Unknown。全会话有进程样本，但 first→last 覆盖了初始化过程，约 25～29 MiB 的增长不能叫作请求间泄漏；也不能据此宣布长期内存稳定。root 峰值趋势只覆盖单域、至多 100 次请求及本固定任务，没有数小时运行、压力退化或任意状态恢复证据。

### 已预热后的同一 Worker 业务快照

另用 `NP_RESULT` 自带的 smaps 做一个更窄的检查，避免把初始化增长算进复用过程：按 session、nonce、实际 call_index 绑定请求，要求同一域、同一 local PID、一个实际 sampler PID/starttime、`completed_level=blas` 且未在本 Worker 重新初始化。36 个 G4 会话均满足这些输入条件，并有前述独立资格作为身份/生命周期依据。

取第一请求业务前，与最后请求业务前和业务后的差值。前者已经完成预热；最后业务前位于之前请求 reset 之后，最后业务后仍位于最后一次 reset 之前。以下为三个 VM 的进程 PSS 差值中位数，没有跨进程求和。

| K | readonly：首 before→末 before / after MiB | full：首 before→末 before / after MiB |
|---:|---:|---:|
| 1 | 0.000 / 1.085 | 0.000 / 1.086 |
| 5 | 0.920 / 0.920 | 0.971 / 0.971 |
| 10 | 0.959 / 0.959 | 1.016 / 1.016 |
| 25 | 0.841 / 0.841 | 0.973 / 0.973 |
| 50 | 0.906 / 0.906 | 0.964 / 0.964 |
| 100 | 0.960 / 0.960 | 0.978 / 0.978 |

K=100 时，末次业务后相对首次业务前的 PSS 增量为 readonly **0.960 MiB**（0.874～1.046）、full **0.978 MiB**（0.975～1.038）；Private_Dirty 对应约 **0.973 MiB**（0.867～1.043）和 **0.988 MiB**（0.980～1.043）。K=1 的业务后 PSS 增量中位数已经约 1.085 MiB，因此不能把 K=100 的约 1 MiB 全部视作随请求线性累积。

这些离散点未显示本固定配方在受测 100 次内出现大幅、随 K 扩张的业务后内存增长，但没有测到最后 reset 后 smaps，也不能证明长期无泄漏、精确 COW 或整个会话净物理收益。数值、字段和缺口见逐会话业务内存点 (`../analysis/persistent-v2-business-memory/sessions.csv`, omitted from this source release)、汇总 (`../analysis/persistent-v2-business-memory/summary.json`, omitted from this source release)及输入与身份检查口径 (`../analysis/persistent-v2-business-memory/manifest.json`, omitted from this source release)。

## 解释与后续边界

这轮证据说明：如果同信任固定任务允许可靠的已知状态恢复，保留完整 Worker 能避免逐请求创建和回收进程的一部分成本；同步 reset 仍是需要支付的费用。它没有证明 G4 可以替代 G3 的逐请求退出语义，更没有证明任意 Agent 工具都可复用同一进程。

完整结果保留了每组初始化、回收和观察开销；所有数值来自同一固定版本和实验配方。只有三个同宿主 VM，未进行第二种宿主复核。宿主压力与观察器影响应在最终统一报告中一并解释，不把调度/I/O 噪声归为某个 fork 或状态机制。没有在本节拟合通用模型、推断生产尾延迟或宣称最优调度阈值。

## 复核入口

- 最终独立资格与逐会话证据索引 (`../analysis/persistent-v2-qualification-final-01/summary.json`, omitted from this source release)：72 会话、2292 次尝试，源码/产物/证据 SHA 在逐会话文件。
- 完整 session 表 (`../analysis/persistent-v2-paired-01/sessions.csv`, omitted from this source release)、逐 VM 配对差 (`../analysis/persistent-v2-paired-01/block_pairs.csv`, omitted from this source release)、配对汇总 (`../analysis/persistent-v2-paired-01/pair_summary.json`, omitted from this source release)。
- root/PSS 积分及覆盖 (`../analysis/persistent-v2-paired-01/resource_integrals.csv`, omitted from this source release)、逐角色采样 (`../analysis/persistent-v2-paired-01/resource_role_summary.csv`, omitted from this source release)、同一进程的首末采样 (`../analysis/persistent-v2-paired-01/resource_role_growth.csv`, omitted from this source release)。
- 图表索引 (`../analysis/persistent-v2-paired-01/plots/index.json`, omitted from this source release)：十组 SVG/PNG，同时保存 gnuplot 数据、脚本及日志。PSS 图上的零星单组点不能视为完整配对。
- 绘图和汇总输入 SHA (`../analysis/persistent-v2-paired-01/manifest.json`, omitted from this source release)、NumPy/reset 导出记录 (`../analysis/persistent-v2-numpy-costs/analysis.json`, omitted from this source release)。
- 测量边界修订 (`../reports/analyzer-boundary-review.md`, omitted from this source release)、[实际实现与合同](../reports/implementation-and-contract-index.md)。

本次仅解析统一导出表，没有重新执行业务或扫描 raw trace；组件 spans 未纳入本节。导出的初始化记录是含快照/指纹的 envelope，纯初始化阶段无显式事件，保持 Unknown，不从 envelope 减猜。
