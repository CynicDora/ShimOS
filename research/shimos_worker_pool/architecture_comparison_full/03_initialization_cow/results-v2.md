# 阶段 3：初始化层级、模板大小、受控写入与计算强度（v2 实测）

102 个正式会话、1,020 次请求全部通过当次独立资格检查，未剔除慢样本或反向结果。这里回答的是固定 NumPy CPU 配方下的准备成本与状态复用取舍，不是在线 Agent 加速，也不是任意 NumPy/第三方依赖的通用 fork 安全结论。

## 范围与证据

- 输入是 `frozen/sequential-v2`；三个独立初始化的 VM 块，各 34 个已登记配置。每个会话 **N=10、D=10、K=1**，相同 profile 的组在同一 VM 内比较；三个 VM 属于同一宿主，不能称三台独立硬件。
- G0 每请求冷 Python；G1 每请求新外部 Z、W 冷初始化；G2 一个外部干净模板服务十个独立新域；G3 每个新域有自己的本地 Z，每域仅执行一次。本节没有把长期复用域的 G3 当成已比较，也不替代持久域阶段结果。
- 固定 NumPy 2.2.6、已冻结的 D 运行时、单线程 CPU 配置、原安全与回收合同。128 MiB 保留原限制并实际通过，没有采用 64 MiB 回退；没有提高限额换取成功。
- 完整 wall：`fixture_session_start → session_supervisor_waited`，含 H/R/Z、建域、初始化、数值/状态验证、结果保存和最终真实 wait。部署运行时、生成独立冷数值 oracle 在共同夹具阶段，**不在产品序列边界内**；它们可能预热文件缓存。observer/trace 导出等夹具尾段另列，不藏到产品成本里。
- 最终独立资格摘要 (`../analysis/profiles-v2-qualification-final-01/summary.json`, omitted from this source release)，SHA256 `e9a5ffec4b0d0256ad5c7fc58bfb89d92c21ca8c75cd7a10288611407b8844db`；实际导出 (`../analysis/profiles-v2-ledger-02/`, omitted from this source release)；逐计划配对 (`../analysis/profiles-v2-comparison-01/`, omitted from this source release)；NumPy 原始事件小表 (`../analysis/profiles-v2-numpy-cost-01/`, omitted from this source release)。首次导出的 CLI 路径错误保留在旧目录，不是产品执行失败。

以下完整序列数值是三块中位数；配对节省先在同一 VM 计算，再给中位数与三点范围。W 局部指标先取每会话十次请求中位数，再跨三块取中位数，不能把 30 个相关请求当 30 个独立重复。四图均保留原始块点和范围，不只有最佳柱状图。

## 1. 初始化层级：越早准备、准备越多，并不总是越快

base/import/data/blas 只改变准备发生的位置；最终每个任务都必须完成相同 NumPy、数组、固定 BLAS warmup 与业务。在冷 G0/G1 中，四种标签仍由 W 完整初始化，耗时小差不能解释为它们省略了业务。

| 预热标签 | G0 完整 s | G1 完整 s | G2 完整 s | G3 完整 s | G2 相对 G0 配对节省 s〔范围〕 |
| --- | --- | --- | --- | --- | --- |
| base | 5.560 | 6.323 | 4.646 | 5.923 | 0.915 [0.672, 1.249] |
| import | 5.565 | 6.307 | 2.482 | 6.021 | 3.116 [2.942, 3.149] |
| data | 5.576 | 6.290 | 3.008 | 6.470 | 2.574 [2.448, 2.745] |
| blas | 5.550 | 6.320 | 2.752 | 6.304 | 2.815 [2.713, 2.859] |

G2 import 是本组条件下最短的观察值；把 DATA 一并放进模板、或进一步做 BLAS warmup，没有产生单调改善。data 的完整中位数还高于 blas。三个块均保留这一结果，不能选 import 后宣布它对所有工作负载最优。数组进入模板会同时改变指纹与状态检查的工作量；没有独立干预证据时，不能把整段差值全归给 COW 或某一初始化动作。

G2 base 相对 G0 仍有约 0.915 s 的配对节省，但它**没有预热 NumPy**。这表明完整组织路径、Python 基态和控制开销也会影响序列结果，不能把所有组间收益都写成 NumPy import 节省。

!初始化层级完整成本与配对差 (`figures-v2-02/initialization.png`, omitted from this source release)

## 2. 模板大小：大数组的完整代价明显上升，但不是纯 fork 曲线

| 数组 MiB | G2 完整 s | G3 完整 s | G2 相对 G3 配对节省 s〔范围〕 | G2 root 峰值 MiB |
| --- | --- | --- | --- | --- |
| 8 | 2.752 | 6.304 | 3.553 [3.429, 3.614] | 54.2 |
| 32 | 4.339 | 7.751 | 3.475 [3.278, 3.563] | 78.5 |
| 128 | 10.476 | 13.743 | 3.291 [3.111, 3.487] | 176.6 |

8→128 MiB 时，G2 完整序列从约 2.752 s 升到 10.476 s。G3 同样变慢。G2 相对 G3 的配对节省没有随数组扩大同步增加：8/32/128 MiB 分别约 3.553/3.475/3.291 s。这组结果保留了大模板更贵、相对优势未随之变大的负面证据。

模板大小同时影响 DATA 初始化、完整 SHA 指纹、数组求和、NPZ 结果与复制，以及运行时页表/共享页行为。实际 light 数值计算并未随 DATA 大小变长：G2 W 的 compute 中位数约 1.972 / 1.970 / 1.865 ms；但 execute 包络约 59.654 / 108.097 / 311.559 ms。后者包含审计、验证和结果构造，不是 fork 或纯业务时间。**不能把 8→128 的全流程斜率全部归为页表复制或 COW。**

!模板大小完整成本与配对差 (`figures-v2-02/size.png`, omitted from this source release)

## 3. COW 写入：触达页数比逻辑字节更有解释力，但仍不是精确复制计数

固定 blas / 32 MiB / light；下表局部数据来自 W 业务前后真实快照，时间为 mutation 包络。

| 写法 | G2 完整 s | G3 完整 s | 逻辑 store bytes | 触达虚拟页 | G2 ΔPrivate_Dirty KiB | G2 minor faults | G2 mutation ms |
| --- | --- | --- | --- | --- | --- | --- | --- |
| readonly | 4.339 | 7.751 | 0 | 0 | 9440 | 2443.5 | 3.023 |
| element | 4.253 | 7.838 | 8 | 1 | 9562 | 2442.0 | 3.087 |
| sparse | 4.251 | 7.855 | 1024 | 128 | 9500 | 2562.0 | 3.580 |
| many | 4.571 | 8.078 | 65536 | 8192 | 41852 | 10634.5 | 27.382 |
| full | 4.467 | 8.070 | 33554432 | 8193 | 42274 | 10634.5 | 28.005 |

`many` 每页写一个 float64，逻辑存储只有 65,536 字节，却触达 8,192 页；`full` 存储 32 MiB，触达 8,193 页（数组起点与页边界不一定对齐）。两者的 minor faults、Private_Dirty 增量和 mutation 耗时相近，符合“触达更多共享页会增加私有化成本”的解释，但不能据此宣称得到了精确 COW 字节数。

只读也出现约 9,440 KiB 的 Private_Dirty 增量和约 2,443.5 个 minor faults，说明这个前后区间还包含计算、验证、输出和诊断。minor faults 不是专用 COW 计数器；pagemap exclusive/soft-dirty 仅为代理。**精确 COW pages/bytes 与纯 store wall/CPU 均为 Unknown。** mutation 包络含写前/写后数组求和，所以只读也约 3.023 ms，不是“没有写却产生 3 ms 写入”。

完整成本并不严格随写入量递增：G2 many 中位数 4.571 s，full 4.467 s，readonly 4.339 s；element/sparse 的中位数略低于 readonly。保留全部块，不把跨配置小差当作“写越多越快”，也不从完整序列差中倒推出 COW 机制时间。G2/G3 全部写法的配对优势均在本组观察中为正；这只适用于当前十次新域合同。

!受控写入完整成本与配对差 (`figures-v2-02/write.png`, omitted from this source release)

## 4. 计算强度：初始化收益仍在，但业务变长后占比下降

light/medium/heavy 分别是 128×128 一次、256×256 四次、512×512 十六次的固定数值配方。它们不是自然 Agent 的频率分布。

| 强度 | G0 完整 s | G2 完整 s | G3 完整 s | G2 W compute ms | G2 相对 G0 配对节省 s〔范围〕 |
| --- | --- | --- | --- | --- | --- |
| light | 5.550 | 2.752 | 6.304 | 1.972 | 2.815 [2.713, 2.859] |
| medium | 5.717 | 3.071 | 6.493 | 9.093 | 2.646 [2.557, 2.780] |
| heavy | 7.152 | 4.443 | 7.932 | 97.922 | 2.737 [2.650, 2.790] |

从 light 到 heavy，G2 相对 G0 的配对绝对节省约 2.815→2.737 s，没有随业务增强而扩大；完整耗时从 2.752→4.443 s，因此相对收益下降。W compute 是狭义数值操作跨度，不能当作整个业务包络，更不能与同区间的 process CPU、完整 wall 相加。

!计算强度完整成本与配对差 (`figures-v2-02/compute.png`, omitted from this source release)

## 5. 初始化包络与纯操作成本要分开

| G2 模板层级 | Z 初始化包络 ms | 每 W 补齐包络 ms | 说明 |
| --- | --- | --- | --- |
| base | 2.141 | 260.042 | 包络包含状态扫描/校验，不是纯 import 或分配 |
| import | 244.961 | 16.198 | 包络包含状态扫描/校验，不是纯 import 或分配 |
| data | 250.246 | 11.893 | 包络包含状态扫描/校验，不是纯 import 或分配 |
| blas | 269.479 | Unknown | 没有缺失初始化；不应伪造补齐样本 |

这些是 `NP_ADMISSION.start → complete` 包络，含 snapshot、指纹与控制侧工作；不是纯 import、分配或 BLAS 时间。正式 v2 没有 `NP_INIT_STAGE`，因此纯初始化 wall/CPU 仍是 Unknown，不能用猜测填表。

例如 128 MiB G2 模板包络约 464.944 ms，其中 `initialized → complete` 约 117.054 ms；这后段仍包含多项校验，不能直接命名为纯 SHA 时间。独立 `initialization_probe` 仅用于后续局部诊断，必须有独立资格与版本边界；它不会给本轮正式样本补出原本没有的跨度，也不能跨 VM 相减作严格因果归因。

cold_reference 事件仅用于数值 oracle，已在机器可读表中单独标为不计入产品性能。正式共有 978 条初始化包络记录，其中也包含这些夹具记录；不能拿总条数当作业务重复初始化次数。

## 5.1 独立局部诊断：实际 import、分配、BLAS 与指纹

独立初始化 probe 的 **11 会话 / 22 请求已全部通过** 最终检查 (`../analysis/initialization-probe-qualification-final-02/summary.json`, omitted from this source release)，SHA256 `b50f8fa1c4b5fc87e4eb88fa801af463c3ece8bfeaa015294df544897c156ebb`。与正式 v2 是不同源码副本与不同运行：每配置仅一个诊断会话、N=2；G3 诊断使用一域两次请求，不替代正式 D=10/K=1。以下是少量命名操作跨度，不能估计跨 VM 方差或直接扣减正式 E2E。

| 位置（8 MiB blas） | 实际 import wall / CPU ms | 数组分配 wall / CPU ms | BLAS warmup wall / CPU ms |
| --- | --- | --- | --- |
| G0 W_cold | 240.677 / 240.605 | 5.164 / 5.156 | 1.235 / 1.235 |
| G2 Z | 245.916 / 245.577 | 2.603 / 2.604 | 1.201 / 1.202 |
| G3 Z_domain | 255.833 / 255.597 | 2.543 / 2.527 | 1.210 / 1.211 |

单次 G2 模板的 import 约 245.916 ms；8 MiB 分配约 2.603 ms，固定 BLAS warmup 约 1.201 ms。import 的过程包括依赖自身工作；BLAS warmup 包含构造固定小矩阵与 matmul，不是纯内核调用。W 的缺失阶段按原门禁之后补齐：

| G2 预热层级 | W import wall / CPU ms | W 数组分配 wall / CPU ms | W BLAS warmup wall / CPU ms |
| --- | --- | --- | --- |
| base | 247.825 / 247.779 | 2.771 / 2.772 | 1.227 / 1.227 |
| import | 未再次调用（继承已有状态） | 2.433 / 2.434 | 1.701 / 1.701 |
| data | 未再次调用（继承已有状态） | 未再次调用（继承已有状态） | 1.608 / 1.609 |

上表“未再次调用”是按已验证的层级继承语义标注，不把没有事件写成 0 ms。base 标记本身不代表 Python 解释器启动。

| G2 Z 数组 MiB | 指纹 wall / CPU ms | snapshot before | snapshot imported | snapshot after |
| --- | --- | --- | --- | --- |
| 8 | 7.268 / 7.269 | 1.002 / 0.679 | 1.597 / 1.182 | 1.295 / 0.937 |
| 32 | 28.848 / 28.849 | 1.011 / 0.685 | 1.408 / 1.038 | 1.361 / 0.961 |
| 128 | 115.504 / 115.506 | 1.024 / 0.724 | 1.388 / 1.049 | 1.517 / 1.166 |

表中各 snapshot 单元同样是 wall / CPU ms。G2 的 32/128 MiB 实际分配分别约 9.174/49.418 ms；其指纹约 28.848/115.504 ms。8/32/128 的 import 分别约 245.916/277.721/234.766 ms，没有随 DATA 单调增长。这提供了**大数组指纹与扫描是真实可观测成本**的证据，但只测了初始化时这一次指纹；不能据此估计所有请求的完整指纹成本，更不能把其值跨 VM 从正式耗时中减掉。

212 条阶段记录中 **146 条属于产品初始化，66 条是 cold_reference 数值 oracle**；后者单列在 oracle-operation-records.csv (`../analysis/initialization-probe-tables-01/oracle-operation-records.csv`, omitted from this source release)，未混入 Z/W 表。阶段小表 (`../analysis/initialization-probe-tables-01/stage-summary.csv`, omitted from this source release) 保留 wall/CPU 与样本数；产品操作记录 (`../analysis/initialization-probe-tables-01/product-operation-records.csv`, omitted from this source release) 另保留每次原始起止。阶段跨度嵌套在初始化包络内，不能再次相加到总时间；新增阶段日志在包络结束后写出，其 I/O 不会冒充被测 import 时长。

首版诊断 checker 将 cold_reference 阶段误判为孤立 span，原 FAIL 记录保留；最终同一版 checker 分别核对产品和 oracle 的实际 PID、阶段层级与时间边界后通过。没有为通过修改产品或删掉 oracle 证据。

## 6. CPU 与内存：能确定什么，仍不能确定什么

| 配置 | 组 | root CPU s | root 峰值 MiB | 已观测 charge MiB·s | charge覆盖 | 已观测 PSS MiB·s | PSS覆盖 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 8 MiB readonly | G0 | 5.085 | 40.4 | 123.7 | 96.3% | 221.9 | 92.5% |
| 8 MiB readonly | G1 | 5.800 | 49.1 | 167.2 | 96.9% | 258.4 | 87.5% |
| 8 MiB readonly | G2 | 2.231 | 54.2 | 99.0 | 92.7% | 143.8 | 85.4% |
| 8 MiB readonly | G3 | 5.769 | 53.8 | 172.7 | 96.8% | 281.1 | 90.3% |
| 32 MiB readonly | G2 | 3.770 | 78.5 | 256.4 | 95.3% | 308.5 | 81.9% |
| 32 MiB readonly | G3 | 7.324 | 78.2 | 314.6 | 97.4% | 424.5 | 87.0% |
| 128 MiB readonly | G2 | 10.046 | 176.6 | 1634.4 | 98.0% | 1755.2 | 94.1% |
| 128 MiB readonly | G3 | 13.343 | 175.9 | 1576.8 | 98.5% | 1798.2 | 94.1% |

CPU 是产品根 cgroup 账本，包括后代；不再把 H/R/Z/S/W 或 waited-child CPU 相加。8 MiB blas/light 下 G2 root CPU 约 2.231 s，G0 5.085 s，G3 5.769 s，支持该固定十次序列确实少支付了 CPU 成本。它不证明每个组件分别省了多少。

全 102 会话的 root charge 积分覆盖率为 91.9–98.5%，中位 96.6%；PSS 批采样覆盖率为 47.7–97.6%，中位 87.7%。表中积分仅是**有效采样段的已观测面积**，不是整个序列精确 memory-time；缺段不填零。role RSS/PSS、root charge 与 memory.peak 是不同口径，不能互相替代。

更少 CPU/wall 并不等于更低峰值：8 MiB blas/light 的 G2 root peak 约 54.2 MiB，高于 G0 40.4 MiB。保留模板是实际资源成本。32 MiB many/full 的 G2 root peak 约 110.5/110.7 MiB，高于 readonly 78.5 MiB，但这仍不是完整物理复制量。继承页可能沿父记账，PSS 扫描也不是完全同步；**系统净物理内存节省、完整未采区间内存积分与精确 COW 量仍 Unknown。**

## 7. 本阶段可以支持的判断

1. 在同一固定任务、每请求新域的十次序列中，G2 的已初始化状态复用能降低完整 wall 与 root CPU；这不是每次只计 fork 的微基准结果。
2. 更深、更大的预热状态有额外校验、扫描和内存成本。现有数据反对“预热越多一定越好”，尚不能选出普适最优层级。
3. 大范围触页会增加已观测的 faults、Private_Dirty 和包络耗时，但本轮不能精确拆出纯写入与内核 COW 时间。
4. 这些数据没有证明 G2 普遍优于长期保留的 G3/G4，也没有证明任意依赖、并发、内存紧张或 Scheduler 的效果。不能用 K=1 的 G3 结果替代它在持久域中的强基线。
5. 不同配置、原始审计 I/O 和宿主压力都可能影响小差。三个同宿主块只支持描述性范围和方向；不作稳定尾延迟、跨硬件或自然 Agent 回本结论。

下一步成本归因可据独立初始化诊断继续区分重复指纹、结果构造与状态派生；若考虑减少指纹/验证成本，必须另做同等正确性的独立候选，不能把当前资格检查免费删除来重算成绩。

## 复核入口

- 完整序列与资源小表 (`../analysis/profiles-v2-report-tables-02/complete-sequence-summary.csv`, omitted from this source release)
- W 写入、fault、smaps、pagemap 与计算小表 (`../analysis/profiles-v2-report-tables-02/worker-cow-observations.csv`, omitted from this source release)
- 初始化包络小表 (`../analysis/profiles-v2-report-tables-02/initialization-envelopes.csv`, omitted from this source release)
- 三块逐对差和完整计划状态 (`../analysis/profiles-v2-comparison-01/paired_summary.csv`, omitted from this source release)
- 图表 manifest、TSV 与 gnuplot 脚本 (`figures-v2-02/figure-manifest.json`, omitted from this source release)

`analyze_numpy_costs.py → compare_profile_costs.py → plot_profile_costs.py → write_results_v2.py` 只读导出复现。所有输出都写入新目录。早期 figures-v2-01 保留为图例布局修正前产物，不混为额外实验；本报告引用视检后的 figures-v2-02。没有新增 VM、实验参数或产品改动。
