# 内存压力：完成业务和安全回收分开记录（v4）

三块 VM 的 12 个会话全部完成了产品自身的资源回收。但只有 192 MiB 下的六个 N16 序列完整成功；96 MiB 下的六个序列均未完成。不能把“能清理失败现场”写成“能在该预算下成功执行业务”。

独立业务资格 (`../analysis/pressure-v4-business-final-01/summary.json`, omitted from this source release)：6 PASS、6 FAIL、0 BLOCKED，SHA `29d86b6f82f587b444a03c48462b78496077512c7817c33bda6cea5c213a038c`。独立采集与释放资格 (`../analysis/pressure-v4-collection-final-01/summary.json`, omitted from this source release)：12/12 PASS，SHA `f613fa531d2ce547a055bc95027bcaeefface74256544dde6732a5b35ef4ebe5`。

## 固定条件与比较边界

本轮固定 G2/G3、C4、N16、8 MiB readonly/light，实际读取根 cgroup 的 memory.max 为 192 或 96 MiB。根 cpu.max 为 max 100000、pids.max 为 max；它们是根层读回，不表示所有叶节点、宿主或 VM 都没有其他限制。模板、H/R 和所有任务共同计入产品根预算，未为失败提升预算。

同一压力 VM 内可以配对比较相同预算的 G2/G3。512 MiB 数据来自另一组并发 VM，不能把跨批 512→192 的差额当作降低预算的严格因果效应。全部原始失败保留，不使用较短失败时间计算吞吐。

## 全部 12 个预登记会话

| VM 块 | 预算 MiB | 组 | 计划/实际 attempt/已提交 | 完整 N16 | 生命周期到 H 真实 wait，s | 根 CPU，s | 根峰值 MiB | oom_kill 末值 | 产品释放 |
|---|---:|---|---:|---|---:|---:|---:|---:|---|
| 1 | 192 | G2 | 16/16/16 | PASS | 2.477 | 3.053 | 105.8 | 0 | PASS |
| 1 | 192 | G3 | 16/16/16 | PASS | 4.278 | 9.851 | 165.7 | 0 | PASS |
| 1 | 96 | G3 | 16/1/0 | FAIL | 0.729 | 1.889 | 96.0 | 2 | PASS |
| 1 | 96 | G2 | 16/4/0 | FAIL | 0.943 | 1.050 | 96.0 | 1 | PASS |
| 2 | 96 | G3 | 16/1/0 | FAIL | 0.756 | 1.888 | 96.0 | 1 | PASS |
| 2 | 96 | G2 | 16/4/0 | FAIL | 1.837 | 1.025 | 96.0 | 1 | PASS |
| 2 | 192 | G2 | 16/16/16 | PASS | 2.569 | 2.951 | 107.6 | 0 | PASS |
| 2 | 192 | G3 | 16/16/16 | PASS | 4.000 | 9.552 | 167.2 | 0 | PASS |
| 3 | 192 | G2 | 16/16/16 | PASS | 2.564 | 2.896 | 107.7 | 0 | PASS |
| 3 | 192 | G3 | 16/16/16 | PASS | 3.993 | 9.903 | 166.7 | 0 | PASS |
| 3 | 96 | G3 | 16/0/0 | FAIL | 0.664 | 1.782 | 96.0 | 1 | PASS |
| 3 | 96 | G2 | 16/4/0 | FAIL | 0.914 | 1.016 | 96.0 | 1 | PASS |

生命周期 wall 使用同一 guest 的 fixture_session_start→session_supervisor_waited。失败行含失败前准备、已启动工作和 H 清理；它不是 16 次成功请求耗时，也不是纯清理时间。现有小表没有单独、完整导出故障开始→H 释放区间，该细分保持 Unknown。额外 observer/夹具导出尾段另存 fixture_tail_s。

## 192 MiB：六个完整序列成功

| 组 | 完整 wall 中位 [三块范围]，s | 正确请求/s 中位 | 根 CPU 中位，s | 根峰值中位，MiB |
|---|---:|---:|---:|---:|
| G2 | 2.564 [2.477, 2.569] | 6.24 | 2.951 | 107.6 |
| G3 | 4.000 [3.993, 4.278] | 4.00 | 9.851 | 166.7 |

同 VM 的 G3−G2 完整时间差依次为 1.801, 1.431, 1.429 s，中位 1.431 s。两组均完整成功才能作这项配对。root CPU 已包含所有后代，不再叠加 Worker、模板或 waited-child CPU。

192 MiB 三块均未观测到根 oom/oom_kill。G2 减少了每请求重新初始化模板的 CPU，G3 同时运行的本地模板占用更多根记账内存；不能据此将全部差额归于页表或 COW。

## 96 MiB：六个完整序列失败，但产品全部收回资源

六个序列仍按计划 96 次请求记账。只出现 14 个实际 attempt 文件，均无成功提交；其中 2 个独立标为 NOT_EXECUTED、11 个为 NOT_OBSERVED，另一个只有结果元信息、原始输出没有保留，独立状态是 UNKNOWN_RAW_OUTPUT_NOT_PRESERVED。不能将其记作成功，也不能推断未出现文件的请求已经执行或未执行。

六个根 memory.peak 均到达 96 MiB，末端 memory.events 都记录了 oom 与 oom_kill。这里报告实际末值，不用某个 SIGKILL 单独推断 OOM，也不把 oom 次数等同于失败请求数。H 收到控制通道未正常 DONE 的关闭，执行保守清理；独立验收核对真实 wait、EOF、FD、目录和 cgroup，没有把测试观察者补清理计作通过。

所有失败会话 collection/release 都通过，允许在该 VM 中安全继续后面的预登记会话。这只证明本轮存活的 H 完成了清理，不能保证任意更低预算、H 被 OOM 杀死、宿主故障时仍能做到。当前没有自适应降并发或自动重试，不能用本结果宣布已实现内存压力调度。

## 内存观测与覆盖

| 预算/组 | 观测 root charge 中位，MiB·s | root 覆盖范围 | 观测 PSS 中位，MiB·s | PSS 覆盖范围 |
|---|---:|---|---:|---|
| 96/G2 | 32.2 | 77.2–89.3% | 32.1 | 51.5–58.0% |
| 96/G3 | 33.2 | 71.3–73.8% | 43.5 | 71.0–73.6% |
| 192/G2 | 115.1 | 91.9–92.5% | 100.4 | 59.7–80.8% |
| 192/G3 | 294.0 | 94.9–95.2% | 294.1 | 64.8–76.5% |

这里只积分相邻有效采样区间，没有用零填补空白。失败更早停止，不能因其积分更小宣称资源效率更好。PSS、root charge、RSS 不是同一账本；全系统净物理内存节省仍 Unknown。实际预算、节流/内存事件、每块覆盖和缺失均保留在 CSV。

## 研究含义与复核入口

当前固定 C4 在 192 MiB 可完整执行，在 96 MiB 两条路线都失败。这支持把布局、并发与资源预算一起研究，但尚未定位精确容量阈值，也没有证明某个动态策略最优。三个同宿主 VM 的结果不外推到其他依赖和长期负载。批尾提交与 G0 逐请求响应的区别仍见并发报告，不能只根据吞吐推断交互延迟。

- 全部会话与原始资格绑定 (`../analysis/pressure-v4-report-tables-01/complete-and-failed-sequences.csv`, omitted from this source release)。
- 预算/组摘要 (`../analysis/pressure-v4-report-tables-01/budget-group-summary.csv`, omitted from this source release)；同 VM 配对，失败留空 (`../analysis/pressure-v4-report-tables-01/paired-comparisons.csv`, omitted from this source release)。
- 分析输入与 SHA (`../analysis/pressure-v4-report-tables-01/report-manifest.json`, omitted from this source release)；计划映射 (`formal-pressure-v4-block-map.json`, omitted from this source release)；独立验收索引 (`formal-pressure-v4-verification-index.json`, omitted from this source release)。
- [512 MiB 并发报告，单独批次](results-v6.md)。

采集返回码 2 表示证据完整但业务失败，不是工作负载 PASS。独立原始记录始终保留，未重新运行实验或修改冻结产品。
