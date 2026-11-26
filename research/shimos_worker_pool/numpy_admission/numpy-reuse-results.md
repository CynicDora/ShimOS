# 固定 NumPy CPU 模板：复用成本与资源结果

日期：2026-10-19。这是固定私有 VM、串行请求、固定可信 NumPy 配方的探索性实验，不是在线 Agent 成绩，也不是四种执行架构的排名。

## 1. 本轮得到什么结果

**在相同跨域生命周期路径上，避免每次重新初始化 NumPy，对本轮重复请求有实际收益；本轮两次单请求对照没有收益。** N=10、50 的两个独立 VM 配对均为正，N=1 两次均为负。N=100 的冷路径两次触发既有 Supervisor H 的 60 秒会话期限，不能填入完整配对成绩。主测量中的热路径有一次实际完成 100 个独立目标域；额外诊断另完成一次 100 请求，分开报告。

固定 NumPy 2.2.6 / OpenBLAS 0.3.29 的受限准入、真实回调、完整 fork runtime、路径安全和故障验证见 [numpy-admission-report.md](numpy-admission-report.md)。正式资格为 19 个 VM、65 个场景尝试全部符合各自验收条件，其中 45 次有独立数值证据。**这些资格样本没有被当作性能重复样本。**

本轮没有证明整个系统净节省多少物理内存：Worker 自身 PSS 下降，但热 Z 必须常驻，S 也短暂存活；COW、页记账与诊断缓存有额外成本。不能只减两个 Worker 的 RSS/PSS 就得到总内存收益。

## 2. 对照究竟是什么

| 项目 | A：cold | B：hot |
|---|---|---|
| Python/NumPy | 每次请求重新启动 D-Python Z；W 获得业务许可后 import、创建固定数据并初始化 BLAS | 会话开始在一个可信 Z 中做相同初始化；各请求继承该状态 |
| 请求执行 | 每次独立 Bubblewrap 域，Z→S→W、两次完整 fork wrapper | 相同；Z 跨请求保留，执行域各自创建和释放 |
| 业务输入和输出 | 同一 ndarray/广播/求和/矩阵乘法、同一冷参考及容差、同一输出保存和检查 | 相同 |
| 正确性责任 | H/R、门禁、nonce、真实 wait、EOF、域与目录回收、FD 与模板检查 | 相同；多请求还检查同一 Z 未被 W 污染 |
| 安全和预算 | 同一 namespace、W 降权/NNP/seccomp、CLONE_INTO_CGROUP 与资源预算 | 相同的最终执行域；NumPy 初始化发生在具有跨域资格的可信 Z，信任范围更大 |
| 完整计费 | 每个 Z 的启动、停止，以及全部域、请求和最后 H 退出 | 一次 Z 初始化、全部域与请求、最终 Z/H 停止 |

A 是**在同一可靠跨域机制上的初始化复用消融**，包含每请求新 Z 和两次派生；并非已优化到最短路径的“Bubblewrap 直接执行冷 Python”。因此，本结果不能声称击败所有成熟冷启动实现。独立冷 Python 数值参考只用于正确性，不是安全等价性能对手。

这也不是把执行过任意业务的 Worker 放回池中。本轮共享的是固定可信配方初始化的 Z，W 中的写入通过进程 COW 私有化，执行完后 W 退出。

## 3. 环境、样本与时间边界

沿用已冻结的 CPython 3.10.12、glibc candidate-04 D、Linux 6.18.49、4 vCPU / 4 GiB 私有 KVM VM，以及同一 NumPy wheel/DSO 闭包。宿主为 Xeon Platinum 8468V、192 个逻辑 CPU，宿主内核 6.18.55-DAMON、QEMU 6.2.0；不能与 guest 内核混淆。每个实际 run 保存 command、kernel/runtime/source/binary SHA 和 guest/host 压力信息。未修改内核、D 运行时、安全策略或 H 的期限。

主实验预先安排 N=1、10、50、100，每个 N 两个独立初始化 VM：一轮 cold→hot，一轮 hot→cold；固定输入、串行、无并发 VM。无人为 page-cache 清空，安装 fixture 后使用自然缓存。所有 VM 位于同一物理宿主。完整顺序见 预登记 (`analysis/paired-numpy-01/predeclared.json`, omitted from this source release)、执行矩阵 (`analysis/paired-numpy-01/matrix.json`, omitted from this source release)。

两组均使用 architecture_cost 的 low diagnostics 和相同 NumPy 验证，`audit=0, timing=1, trace=0, warmup=0`。不把原生回调插桩或 ftrace 的资格耗时混进主成绩。每组第一个请求单列；后续属于同一会话内相关的连续请求，不假装是独立机器重复。样本有限，只报告配对值、范围及描述性分布，不声称生产 p95/p99。

所有时间差来自同一 guest 的 CLOCK_MONOTONIC：

| 边界 | 含义 |
|---|---|
| 完整 N 次序列，主指标 | `fixture_session_start → session_supervisor_waited`：H/R/Z 启动、NumPy 初始化、N 次业务与域回收、Z/H 退出和真实 wait；包含最终诊断写出 |
| 完整外部释放账本 | 继续到 `fixture_release`，包含外部检查、约 100 ms 人为观察延迟、实验 fixture 的委派目录释放；另列而非藏掉 |
| 单次调用 | `numpy_call_begin → numpy_call_complete`：冷组包含每次 Z 启停；热组一次性 Z 成本仍在完整序列内计费 |
| 单次域请求 | `request_begin → response_ready`：域准备到该请求输出、结果、资源状态就绪；不包含冷组此前启动 Z 或热组最终停止 Z |
| NumPy 业务 | `call_start_ns → done_ns`：冷组包含 NumPy 初始化；两组均包含验证、指纹、数据保存及观察 |
| 纯数值片段 | `compute_begin_ns → compute_end_ns`：固定计算；不等于完整业务或请求 |

VM 启动、每 session 的源码复制、运行时复制/校验、编译、独立冷参考是实验 fixture，分别保留在 `session-execution.json` 与参考报告中，不混成每请求执行器成本。两组均使用预先安装的相同只读资产；其准备不是免费且不可追踪的隐藏步骤。

沿用约 40 ms 的业务测试后代等待，两组都保留。它不是 ShimOS 或 NumPy 的固有成本。CSV 单列观察到的等待重叠区间，但主结果不减掉它；减法残差也不被当作“移除等待后一定达到的性能”。

## 4. 完整序列实测

单位为毫秒，节省 = cold − hot。每行是同一 VM 中相同输入的完整两组会话，包含初始化和最终回收。

| N | VM 顺序 | cold | hot | 节省 |
|---:|---|---:|---:|---:|
| 1 | cold→hot | 734.7 | 842.1 | −107.4 |
| 1 | hot→cold | 697.9 | 812.4 | −114.5 |
| 10 | cold→hot | 6469.0 | 2953.0 | 3516.0 |
| 10 | hot→cold | 7066.1 | 3213.2 | 3852.9 |
| 50 | cold→hot | 33564.9 | 13693.6 | 19871.3 |
| 50 | hot→cold | 32557.0 | 14582.8 | 17974.2 |
| 100 | cold→hot | 未完成，H 期限触发 | NOT_RUN | 不计算 |
| 100 | hot→cold | 未完成，H 期限触发 | 27830.3，完成 100 次 | 不计算完整配对收益 |

前六个 VM 合计 244 次实际业务请求，逐个经过独立生命周期/runtime/NumPy 数值核验。再加主矩阵中单独完成的 hot100，共 13 个完整 session、344 次通过；失败 cold 中保存的 184 份正确数组单独列为观测，不计完整 session 通过。N=10 配对完整耗时约减少 54.4%–54.5%，N=50 约减少 55.2%–59.2%；这是本原型和该受控配方的结果，不能推广到全部 NumPy 操作或完整 Agent 加速。

两次 N=1 均慢约 0.11 秒。两组都必须初始化一次，hot 没有可摊销的重复初始化，且具有更大的派生状态、模板检查和停止路径。本实验没有将该差值全部归给某一个 fork、callback 或页表操作。

N=100 的失败保留原始过程：两次 cold 均已登记 93 个 attempt，仅 92 个完成最终请求回执；最后一个保留 UNKNOWN。一次已有 W/S 的部分 wait、EOF 和数值副作用，仍不能在 R 未最终提交时改写为成功。H 在期限触发后收养/清理，最终 RELEASED、无残留、无 observer 补杀。**这是未完成的性能序列，不能因清理成功而算 N=100 性能 PASS。**未延长 H 的既有安全期限。

两次失败序列从会话开始到 H 真实退出分别为 60242.9/60243.2 ms，包含超时后的清理，保留为失败耗时。主矩阵 hot100 的完整外部释放为 27962.6 ms，晚于主终点约 132.3 ms；这个差额包含实验观察和委派目录收尾，没有省略后再称“全部资源零成本释放”。完整回收事实见最终 sessions.csv (`analysis/cost-final-01/sessions.csv`, omitted from this source release)。

## 5. 初始化、请求与 CPU：减少了什么

N=10/50 各 session 的中位数范围如下，不把重叠阶段相加。

| 观察项 | cold | hot | 解释 |
|---|---:|---:|---|
| 每次/一次 NumPy 初始化 wall | 每次约 253.1–253.8 ms | 会话一次约 249.4–252.9 ms | 含固定数据/BLAS 初始化及前后快照、指纹；不是纯 import 时间 |
| 对应初始化 self CPU | 每次约 253.1–253.8 ms | 一次约 248.2–251.5 ms | 不含其他进程 CPU |
| 域请求到 response-ready | 456.8–463.1 ms | 238.1–251.4 ms | 包含建域与回收；不含全部会话/每次 Z 启停 |
| W NumPy 完整业务片段 | 约 300–301 ms | 52.5–53.4 ms | 包含验证、输出、观察；不可称纯计算 |
| 纯数值片段 | 1.16–1.18 ms | 1.60–1.62 ms | hot 反而略慢；没有删除这一负结果 |

实测支持“避免重复初始化”的收益，**不支持“复用会让矩阵乘法本身更快”**。OpenBLAS prepare 会清理部分 native 缓冲，继承模块和显式数据不等于完整复用所有 BLAS 工作缓存。

完整序列差额不只来自 NumPy import：cold 还每次新建/停止 Python Z、执行会话诊断与状态检查，而 hot 保留同一 Z。这些变化都是本轮 A/B 定义的一部分，不能把 50 次序列节省的全部约 18–20 秒都称为“NumPy 初始化成本”。也不能用一次约 0.25 秒直接乘 N，代替实测完整差额。

N=50 各 session 的中位数进一步分开如下。`call→gate` 不能当 NumPy 已经 ready：cold 在此之后才 import；`call→NumPy 计算入口` 两组都已经初始化，但仍包含计算前的观察和指纹检查。

| VM/组别 | 建域 ms | call→gate ms | call→NumPy 计算入口 ms | 完整 call ms | cgroup / workspace 删除 ms |
|---|---:|---:|---:|---:|---:|
| r1 cold | 27.65 | 212.23 | 481.85 | 645.38 | 0.22 / 0.17 |
| r1 hot | 28.45 | 58.21 | 84.87 | 252.09 | 0.22 / 0.16 |
| r2 cold | 28.16 | 212.10 | 481.64 | 641.16 | 0.19 / 0.15 |
| r2 hot | 28.72 | 57.65 | 83.84 | 249.62 | 0.19 / 0.15 |

删除调用只覆盖对应最后操作，不包含前面的取消封口、真实 wait、EOF、PID1 DRAINED 与 monitor 退出，不能把它称为完整资源回收时间。建域在两组没有明显减少，符合本轮每请求都建立新域的设计。

CPU 账本以 H/R self、真实 Z 的 self 累计样本、每域 task cgroup 为互不重叠的部分；不再加 task 子组或 waited-child CPU。单位为毫秒：

| N=50 组别 | H self | R self | Z self 合计 | task cgroup 合计 | 已采样小计 |
|---|---:|---:|---:|---:|---:|
| r1 cold | 536.4 | 2192.9 | 8030.1 | 17221.3 | 27980.8 |
| r1 hot | 381.5 | 1726.0 | 1877.8 | 5559.2 | 9544.5 |
| r2 cold | 535.9 | 2089.5 | 7903.0 | 17243.3 | 27771.7 |
| r2 hot | 372.8 | 1692.8 | 1798.8 | 5525.3 | 9389.7 |

这些数值支持已采样 CPU 成本下降，但缺少部分角色启动前及最后 flush 后 CPU，**不是完整机器总 CPU**。不把 RPC wall time、重叠阶段或层级 cgroup 重复计入。证据和遗漏口径见 cpu_ledger.csv (`analysis/cost-final-01/cpu_ledger.csv`, omitted from this source release)。

## 6. PSS、COW 与常驻成本

在 NumPy 已初始化、即将计算的 W 匹配阶段，N=10/50 的 W PSS 中位范围为 cold 34.33–34.40 MiB、hot 13.46–14.13 MiB。**这不是系统净内存节省**：hot Z 在请求结束后仍常驻约 39–40 MiB PSS，运行时还有 S，PSS 分摊也随亲缘进程退出而变化。

门禁时刻的 cold W 尚未 import NumPy，而 hot W 已继承初始化内存，两个 gated 快照并不处于等价应用状态。不能用 gated 的 Z/S/W 总和比较“同样业务的物理内存”。本轮没有在相同 NumPy 就绪瞬间取得完整域外/域内全部角色的原子内存样本，因此净物理内存节省保持 **Unknown**。

原始数据另外保存 RSS、Private_Dirty、minor faults、cgroup memory.current/peak。RSS 不能跨进程相加当物理内存；memcg peak 是记账峰值，继承页通常已有原归属，也不能直接当 PSS 或该 Worker 独占的物理成本。

COW 正确性测试固定 8 MiB 数组：普通 W 写 1 个 float64（8 字节），数组页 exclusive 标志首样本从 0 变为 1；跨页测试实际写 2048 个元素（16 KiB），触达约 8 MiB，标志从 0 变为 2048，数组覆盖 2049 页。Z 摘要与后继域原始状态不变。该标志是共享变化代理，**不是精确 COW 拷页数**；PSS 增量也混有 Python/native 分配和诊断成本。

常驻 Z 的内存时间以稀疏 PSS 快照作梯形积分，同时给出左右保持敏感度及观测覆盖比例。它只覆盖已采样端点之间的 Z，不外推未观察的启动/退出区间，不包含 S/W/H/R，不能称为整个系统的精确内存时间。

以 N=50 为例：hot Z 的稀疏 PSS 时间积分约 399.1/428.1 MiB·s，覆盖其观测生命周期的 97.7%/97.8%。H 初/末 PSS 约 9.9/12.5 MiB，R 约 7.2/20.7–20.8 MiB；cold 的 H 末样本约 13.4–13.5 MiB、R 约 23.9–24.0 MiB。这是具体采样时点，不是各角色真实峰值。两次每请求 task memory.peak 的最大值分别 cold 32.56/32.32 MiB、hot 23.40/23.15 MiB；热模板页的原有记账不全进入目标 task，所以不能把这个差直接当全系统节省。

## 7. 诊断扰动与长序列限制

即使 low diagnostics，固定 NumPy 资格仍执行 maps/线程/FD/security 快照、8 MiB 数据指纹、数值比较和 NPZ 保存；这些成本完整保留在本轮主延迟内。初始化约 0.25 秒及热业务约 53 ms 都不能直接认作纯 NumPy 初始化/计算成本。

还发现已有 `cost.ROWS` 把阶段记录留在 Z 内，直到 Z 退出才写出；这些对象随 fork 继承，长序列会增加诊断内存和收尾。N=50 两次 hot Z 首个请求后至最终检查 PSS 增长约 1256/1288 KiB，FD 不增长。仅凭这些观察不能将全部增长判为 NumPy 泄漏，也不能把它全部归因于计时缓冲。

为核查该因素，仅预登记追加一组 N=100、hot→cold、`timing=0` 的诊断敏感度；其余源码、H 期限、NumPy、安全和回收合同不变，单列结果而不与主样本拼接。方案见 timing0-predeclared.json (`analysis/timing0-predeclared.json`, omitted from this source release)。关闭的是额外阶段时间记录，未删除真实 wait、执行许可、数值与状态验证；因此仍不是零诊断产品基线。无 native 时序记录时，回调顺序本次未观测，H/R 组件 CPU 为 N/A，不能填零。

该诊断实际 hot100 通过生命周期/runtime/独立数值验收；cold 又因 H 期限未完成，保存 94 份匹配数组，不授予完整 N=100 性能资格。不能将该诊断与主实验拼出一个成功配对。证据见 timing0 独立矩阵 (`analysis/paired-numpy-timing0-diagnostic-final.json`, omitted from this source release)。

| hot100 观察项 | 主 timing=1 | 追加 timing=0 |
|---|---:|---:|
| 完整产品序列 | 27830.3 ms | 24823.1 ms |
| 完整外部释放 | 27962.6 ms | 24962.2 ms |
| Z 首个请求后→末次 PSS | 38.87→44.51 MiB | 39.13→39.13 MiB |
| PSS 增量 | 5784 KiB | 3 KiB |
| Z 阶段记录数 | 11400 | 0 |
| 这些记录的原始日志字节 | 4573426 | 0 |
| 最后模板检查→Z 真实 wait | 277.76 ms | 26.05 ms |
| FD 增量 | 0 | 0 |

这表明计时记录值得单独控制，避免把诊断堆增长误判成 NumPy 泄漏。**两列来自不同 VM、各一次成功长序列，不能把约 3 秒差额全部因果归于计时器，或当作稳定加速。**原始日志字节不等于 Python 堆大小，最后 check→wait 也同时包含协议收尾、写出、退出、调度及等待。timing0 hot 的 Z 稀疏 PSS 时间估计为 731.3 MiB·s，主样本为 867.7 MiB·s；timing0 的 Z 全生命周期覆盖率未完整观测，不能用它们推出净内存时间收益。

三次 cold N=100 截断均由 H 自行释放所有已登记域、确认输出 EOF、FD 恢复并真实 wait；主样本为 93/92 登记/RETIRE，诊断为 95/94，均保留一个 UNKNOWN。没有通过增加时限让某一组获得额外执行预算。

## 8. 证据与复核

- 原始配对命令/失败：analysis/paired-numpy-01/ (`analysis/paired-numpy-01/`, omitted from this source release)，每 run 的 `sessions/` 保留实际源码、二进制、guest 输出、NPZ、attempt journal、H/R wait、cgroup/FD 与最终释放。
- 独立性能资格：主矩阵 (`analysis/paired-numpy-admission-final.json`, omitted from this source release)，只允许 6 个完整配对用于完整 N 收益，hot100 单独报告；失败和范围台账 (`analysis/failure-and-scope-ledger.json`, omitted from this source release) 保留所有失败、BLOCKED、NOT_RUN 及未观测项。
- 最终成本表：analysis/cost-final-01/ (`analysis/cost-final-01/`, omitted from this source release)，以及 数值摘录 (`analysis/cost-final-01/report-extract.md`, omitted from this source release)：包含全部 9 VM / 18 个计划 session、725 个实际 attempt，未运行和未完成项保留。sessions、requests、initialization、worker、CPU、cgroup、memory、COW、PSS 时间积分及配对差均可复核；statistics.csv 的 p90 仅为会话内描述性分位。
- 分析中的 10 个缺失项来自三个被期限截断的 cold session 和一个 NOT_RUN session；没有用零值补齐。原 N≤50 中间表仍保留于 analysis/cost-formal-complete-through-n50-01/ (`analysis/cost-formal-complete-through-n50-01/`, omitted from this source release)。
- 成本解析：[runner/analyze_numpy_cost.py](runner/analyze_numpy_cost.py)，仅解析原始事实，不自行授予性能资格。
- 独立验收：[runner/verify_perf_matrix.py](runner/verify_perf_matrix.py)、[runner/verify_numpy.py](runner/verify_numpy.py)、核验范围说明 (`docs/independent-verification.md`, omitted from this source release)。
- 冻结输入及历史保护：frozen/input-sources.json (`frozen/input-sources.json`, omitted from this source release)、frozen/historical-evidence-sha.json (`frozen/historical-evidence-sha.json`, omitted from this source release)。

复现必须使用新编号，并通过私有 VM 驱动。例如：

```bash
python3 -B runner/paired_vm.py <新编号> --requests 10 --warmup 0 \
  --order cold,hot --np-level blas --np-audit 0 --timing 1 --trace 0 \
  --source-review docs/variant-source-review-v2.json
```

不要在宿主直接运行 prototype、导入被测 NumPy 或执行 mount/namespace 故障测试。驱动拒绝覆盖已有 run，第一组未满足释放/完整回执时不启动第二组；测试观察者没有替产品完成补杀或资源删除。

## 9. 下一步可以和不可以得出的判断

固定配方已经提供真实依赖、受限 fork/生命周期兼容性和重复初始化成本的证据，值得进入四种复用架构的**资格设计与公平对照准备**。本轮没有实现四组同保障基线，不能宣布跨域优于完整 Worker 复用或域内 Zygote。

下一步需要先明确共同的会话时限和资源合同，避免将 100 次冷路径被期限截断当作性能优胜；继续区分研究日志与必要检查，在不同架构的等价 NumPy 就绪点采集完整内存账本。不得直接取消 H 期限、降低检查或从成绩中减去未实际消除的工作。

保留固定 NumPy 配方与独立审计原型；不推广到任意第三方依赖、多线程 BLAS、GPU、插件、共享可写状态或并发请求。已验证的复用收益与仍未知的系统净物理内存收益应分开记录。
