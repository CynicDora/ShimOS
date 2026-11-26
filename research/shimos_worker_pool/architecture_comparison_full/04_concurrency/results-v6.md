# 并发：固定 N16 的完整生命周期结果（v6）

三块独立初始化的 VM 共 39 个会话、624 次请求，独立核验全部 PASS，0 FAIL、0 BLOCKED；没有排除或只保留成功前缀。它们来自同一物理宿主。

先说明响应边界：G2/G3 当前要等整批请求结束、全局模板检查完成后才提交结果，G0 则逐请求返回。完整 N16 序列可以按同一最终回收边界比较，但较短的序列不等于较低的单请求交互延迟。本轮 light G2 C4 的 call→response-ready 中位数约 1.177 s，反而高于 G0 C1 的 0.551 s；这一协议成本保留在结果中。

资格：最终矩阵 (`../analysis/concurrent-v6-qualification-final-01/summary.json`, omitted from this source release)，SHA `13a0a93086a6482545d567cf4cf6a180d5a9f57b40f261c6bf49b5853d69ac32`。所有成本来自已结束的原始运行导出；本报告脚本不重新授予资格。

## 比较的是什么

G0 是每请求创建 Bubblewrap 域并 exec 新 Python 的 C1 冷参考。G2 保留一个外部模板，向每请求的新域派生 Worker；Z 仍单线程串行派生。G3 为每请求的新域创建域内模板，再派生 Worker，本地模板初始化可并行进行。每组均为 N16、实际 D16、每域一个请求；这不是域内模板长期复用的成本对照。G0 没有 C2+，不补造其并发成绩。

light 与 heavy 使用同一 8 MiB readonly 固定配方、单线程依赖配置和 512 MiB 产品根预算，只有数值计算强度不同。有限 heavy C1/C4 交互是在 light pilot 的实际计算重叠很低后登记；没有扩成全参数矩阵。

主 wall 是 `fixture_session_start → session_supervisor_waited`，包括 H/R、域、模板准备、全部业务及最终真实 wait/释放。它不使用宿主 collector 总耗时计算吞吐；编译/runtime 安装和独立数值 oracle 是共同预置夹具，额外 observer/trace-export 尾段另列。

## 完整序列时间、吞吐与 CPU

表内为三个 VM 块的中位数；方括号是原始最小—最大值。吞吐为每个完整成功序列的 `16/full_s`，再求中位数，属于封闭固定 burst。

| 强度 | 组 | C | 完整 wall，s [范围] | 正确请求/s | root CPU，s |
|---|---|---:|---:|---:|---:|
| heavy | G2 | 1 | 6.653 [6.645, 7.023] | 2.40 | 5.316 |
| heavy | G2 | 4 | 3.920 [3.824, 3.987] | 4.08 | 5.276 |
| heavy | G3 | 1 | 13.371 [13.122, 13.371] | 1.20 | 12.021 |
| heavy | G3 | 4 | 5.200 [5.064, 5.830] | 3.08 | 11.739 |
| light | G0 | 1 | 9.069 [8.834, 9.078] | 1.76 | 8.222 |
| light | G2 | 1 | 4.228 [4.156, 4.308] | 3.78 | 3.310 |
| light | G2 | 2 | 2.849 [2.849, 2.949] | 5.62 | 3.033 |
| light | G2 | 4 | 2.513 [2.454, 2.520] | 6.37 | 3.031 |
| light | G2 | 8 | 2.529 [2.484, 2.615] | 6.33 | 3.015 |
| light | G3 | 1 | 10.441 [10.419, 10.560] | 1.53 | 9.678 |
| light | G3 | 2 | 6.208 [6.048, 6.293] | 2.58 | 9.476 |
| light | G3 | 4 | 4.001 [3.853, 4.117] | 4.00 | 9.431 |
| light | G3 | 8 | 3.707 [3.678, 3.897] | 4.32 | 9.981 |

light 下 G2 从 C1 到 C4 的完整时间下降；C8 未继续缩短三块的中位时间。G3 的并发初始化减少了完整等待，但总 CPU 仍需支付每请求的本地初始化。G3 C1 比 G0 C1 更慢也保留在表中：这组任务没有复用域内模板的机会，不能据此否定持久域内复用。

heavy 下两组 C4 的实际数值计算重叠在三块都达到 4，说明较长计算能利用并发。该结论只适用于当前固定任务和预算，不是任意工作负载的调度结论。

## 同 VM 配对

以下每个差值先在同一 VM 内计算。正值表示 G2 更短，不能用两个组的独立中位数相减替代。

| 强度 | 比较 | C | 三块原始节省，s | 配对节省中位数，s |
|---|---|---:|---|---:|
| heavy | G3 − G2 | 1 | 6.717, 6.349, 6.478 | 6.478 |
| heavy | G3 − G2 | 4 | 1.909, 1.212, 1.241 | 1.241 |
| light | G0 C1 − G2 C1 | 1 | 4.761, 4.850, 4.678 | 4.761 |
| light | G3 − G2 | 1 | 6.132, 6.332, 6.263 | 6.263 |
| light | G3 − G2 | 2 | 3.199, 3.259, 3.444 | 3.259 |
| light | G3 − G2 | 4 | 1.596, 1.488, 1.398 | 1.488 |
| light | G3 − G2 | 8 | 1.150, 1.282, 1.223 | 1.223 |

G2 的优势包含外部模板在 16 次请求间共享初始化，以及控制链的不同组织；本对照不能将全部差值归为 fork/COW，也不能据它宣称跨域方案在任何 D/K 配置下都优于域内 Zygote。

## 请求可执行、资源结束与响应提交

并发协议在最后一次全局模板检查完成后才提交整批结果。较早完成的请求仍会等待批尾检查；因此 `response_commit` 不是 Worker 业务开始，也不是其资源完成。以下是每配置 48 个相关请求的描述性统计，不是 48 个独立实验或稳定生产尾延迟。G0 逐请求到达 response-ready，未单独记录 response_commit；不能把它与批提交的交互等待直接解释为同一在线服务语义。

| 强度/组/C | call→业务许可 median，ms | call→业务结束 median，s | call→commit median / p90，s | call→response-ready median，s | call→自身资源完成 median，s | 资源完成→commit median，s |
|---|---:|---:|---:|---:|---:|---:|
| heavy/G2/1 | 67.6 | 0.265 | 3.229 / 5.573 | 3.236 | 0.362 | 2.872 |
| heavy/G2/4 | 180.4 | 0.405 | 2.013 / 3.220 | 2.019 | 0.661 | 1.410 |
| heavy/G3/1 | 483.3 | 0.667 | 6.961 / 12.087 | 6.968 | 0.761 | 6.199 |
| heavy/G3/4 | 568.2 | 0.771 | 3.066 / 4.904 | 3.094 | 1.000 | 2.070 |
| light/G0/1 | Unknown | Unknown | Unknown / Unknown | 0.551 | Unknown | Unknown |
| light/G2/1 | 71.7 | 0.153 | 1.911 / 3.240 | 1.918 | 0.202 | 1.710 |
| light/G2/2 | 95.8 | 0.176 | 1.284 / 2.159 | 1.291 | 0.243 | 1.039 |
| light/G2/4 | 178.5 | 0.266 | 1.171 / 1.835 | 1.177 | 0.387 | 0.802 |
| light/G2/8 | 381.0 | 0.526 | 1.426 / 1.930 | 1.434 | 0.773 | 0.666 |
| light/G3/1 | 481.3 | 0.545 | 5.484 / 9.554 | 5.492 | 0.590 | 4.903 |
| light/G3/2 | 497.1 | 0.562 | 3.273 / 5.598 | 3.280 | 0.639 | 2.649 |
| light/G3/4 | 566.0 | 0.638 | 2.353 / 3.710 | 2.362 | 0.767 | 1.614 |
| light/G3/8 | 1166.4 | 1.260 | 2.631 / 3.673 | 2.639 | 1.437 | 1.315 |

`call→业务许可` 还包含各组相应准备和门禁，不等于纯排队或所有依赖已就绪；G0 在 Worker 执行时才做冷初始化。业务结束使用 W 的实际 business_end，与真实 wait 和资源回收分开；按每请求同一业务开始边界衔接后再统计，不是相加分位数。G0 独立 commit/业务事件字段未导出，保留 Unknown；实际 ready 列仍有观测。完整 call→ready、min/max、每块中位数及观测条数另见请求 CSV。

当前协议有一项不能省略的负结果：light G0 C1 的逐请求 call→response-ready 中位数约 0.551 s，G2 C4 为 1.177 s，尽管 G2 的整个 N16 序列更短。批尾确认使单请求返回更迟；不能把整体吞吐改善写成已经改善了交互式请求延迟。若将来改变提交时机，必须另行验证同样的模板完整性和故障合同。

## 实际并发和内存代价

| 强度/组/C | 三块实际数值计算峰值 | 三块 ready 请求区间峰值 | root memory.peak median，MiB |
|---|---|---|---:|
| heavy/G2/1 | 1, 1, 1 | 1, 1, 1 | 71.0 |
| heavy/G2/4 | 4, 4, 4 | 4, 4, 4 | 151.1 |
| heavy/G3/1 | 1, 1, 1 | 1, 1, 1 | 68.5 |
| heavy/G3/4 | 4, 4, 4 | 4, 4, 4 | 209.2 |
| light/G0/1 | Unknown, Unknown, Unknown | Unknown, Unknown, Unknown | 41.0 |
| light/G2/1 | 1, 1, 1 | 1, 1, 1 | 58.2 |
| light/G2/2 | 2, 1, 2 | 2, 2, 2 | 75.5 |
| light/G2/4 | 2, 2, 2 | 4, 4, 4 | 107.7 |
| light/G2/8 | 1, 1, 2 | 8, 8, 8 | 157.0 |
| light/G3/1 | 1, 1, 1 | 1, 1, 1 | 55.1 |
| light/G3/2 | 1, 1, 1 | 2, 2, 2 | 97.2 |
| light/G3/4 | 2, 1, 1 | 4, 4, 4 | 177.8 |
| light/G3/8 | 1, 2, 2 | 7, 5, 6 | 270.1 |

配置 C 是容量上限，不等于计算同时进行的数量。light 的计算短，G2/G3 C8 的实际数值峰值仅 1–2；不能因此认为只有 1–2 个 Worker 或域。G3 ready 请求区间从 LOCAL_READY 后开始，排除了本地模板初始化，也早于整域关闭。

独立 traced 资格诊断中 C8 G2/G3 的实际 PID1 fork→exit 峰值均 8，G3 ready 请求重叠为 5。正式本轮 trace0 的 PID1 生存期仍 Unknown，不复制资格数值。PID1 进程生存期本身也不是完整 namespace 对象寿命，外部 FD 可继续持有对象。

light G2 从 C4 到 C8 的 root 峰值中位数约 107.7→157.0 MiB，而完整中位时间没有降低；这是一项明确的资源权衡。G3 C8 峰值更高，但还包含每个域内模板及控制数据，不能将差额全部归于 COW。

| 强度/组/C | 观测 root charge，MiB·s | root 覆盖范围 | 观测 PSS，MiB·s | PSS 覆盖范围 |
|---|---:|---|---:|---|
| heavy/G2/1 | 330.7 | 97.0–97.2% | 445.9 | 85.0–90.9% |
| heavy/G2/4 | 230.5 | 94.7–94.9% | 247.3 | 70.9–79.5% |
| heavy/G3/1 | 486.8 | 98.5–98.5% | 667.0 | 83.5–96.9% |
| heavy/G3/4 | 461.0 | 96.0–96.3% | 486.0 | 75.7–84.2% |
| light/G0/1 | 204.0 | 97.1–97.8% | 357.9 | 91.2–93.3% |
| light/G2/1 | 175.1 | 94.8–95.3% | 204.2 | 72.1–76.4% |
| light/G2/2 | 125.0 | 92.6–93.3% | 147.2 | 64.4–73.8% |
| light/G2/4 | 113.0 | 92.0–92.0% | 90.0 | 38.7–55.9% |
| light/G2/8 | 135.2 | 91.9–92.3% | 85.7 | 43.6–51.8% |
| light/G3/1 | 297.3 | 98.0–98.1% | 476.2 | 90.5–92.4% |
| light/G3/2 | 271.5 | 96.7–96.8% | 328.1 | 79.1–86.8% |
| light/G3/4 | 289.4 | 94.8–94.9% | 277.2 | 73.1–79.2% |
| light/G3/8 | 450.0 | 94.2–94.6% | 344.1 | 58.8–70.2% |

这些积分只覆盖相邻有效观测段，没有填补缺段或未采到的短命进程；不是完整精确内存时间。root charge、PSS、RSS 分账，系统净物理内存节省 Unknown。root CPU 已包括后代，不能再加角色 CPU/waited-child。角色观测、实际预算、节流和 OOM 原字段保存在导出中；缺失不补零。

## 适用范围和未解释成本

结果来自固定版本、可信单线程自有模板、固定纯 CPU NumPy 任务、私有 VM 和正常存活的 H。固定 burst 没有外部到达流、混合信任主体或在线 Agent 行为。三块同宿主重复不足以确定通用最优 C、稳定尾延迟或普适扩缩容策略。

原数值校验、模板指纹、状态/FD 检查与 9p 证据 I/O 均继续执行，成本包含在完整路径中。没有把这些检查称为免费；也没有将 RPC wall 当作纯 CPU，或把多个重叠组件跨度相加。宿主活动与采样扰动没有被当作可精确扣除的校正项。

下一步应结合压力试验看完成率、H 回收和内存预算边界，再判断并发收益是否值得常驻状态及管理成本。当前结果支持研究这些取舍，尚不能单独选定最终布局或 Scheduler。

## 复现与原始表

- 逐会话正式值与准入 (`../analysis/concurrency-v6-comparison-01/planned_sessions.csv`, omitted from this source release)
- 三块完整序列摘要 (`../analysis/concurrency-v6-report-tables-02/configuration-summary.csv`, omitted from this source release)
- 请求提交/资源/就绪分布 (`../analysis/concurrency-v6-report-tables-02/request-distributions.csv`, omitted from this source release)
- 同 VM 配对原值 (`../analysis/concurrency-v6-comparison-01/paired_comparisons.csv`, omitted from this source release)
- 报告和图形输入 SHA (`../analysis/concurrency-v6-report-tables-02/report-manifest.json`, omitted from this source release)
- 独立 PID1 资格诊断 (`../analysis/concurrent-pid1-diagnostic-tables-01/summary.json`, omitted from this source release)
- 显式三块计划映射 (`formal-v6-block-map.json`, omitted from this source release)；独立验收索引 (`formal-v6-verification-index.json`, omitted from this source release)。

!light-scalability: 原始三点及配对中位范围 (`figures-v6-02/light-scalability.png`, omitted from this source release)

!heavy-scalability: 原始三点及配对中位范围 (`figures-v6-02/heavy-scalability.png`, omitted from this source release)

!paired-savings: 原始三点及配对中位范围 (`figures-v6-02/paired-savings.png`, omitted from this source release)
