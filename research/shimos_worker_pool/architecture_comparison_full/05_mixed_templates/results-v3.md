# 混合预热程度：固定单槽策略的真实切换成本（v3）

三块 VM、9 个会话、144 次请求全部通过独立数值和生命周期验收，没有排除样本。这次只测容量为 1、按 profile 完全相等匹配的固定策略，不是多模板同时驻留的 Worker Pool，也没有实现在线调度。

最终资格矩阵 (`../analysis/mixed-v3-qualification-final-01/summary.json`, omitted from this source release) SHA `5e14fe5a703fdd3ad54fdd8e50ffbb4ee7947ce04e8675a23f1f2dacb7a5425f`。正式使用独立 fixture-v2 修复后的同一源码；早期多会话夹具失败保留，未混入本表。

## 两个 key 不代表两种不兼容依赖

两个输入是 import 与 blas 预热层级，固定 8 MiB、readonly/light，最终 Worker 执行相同数值任务。import 模板只提前导入，缺少的数组和计算准备仍由 Worker 付费补齐；blas 模板提前准备得更多。较完整的 blas 状态能否覆盖 import 请求，需要另行验证兼容合同，本轮没有试图回答。

命中时保留当前 Z；未命中先真实停止、等待和回收旧 Z，再创建新 Z。每个请求仍创建独立 Bubblewrap 域；始终最多一个活模板。实际 hit/miss/初始化次数来自运行台账，并与独立 checker 一致，未用输入模式的理论次数替代实际观测。

grouped 与 alternating 都是 8 个 import、8 个 blas，只改变次序。skewed 为 14 个 import、2 个 blas，连预热层级比例也不同；它与 grouped 的差异不能只归因于排序。三种顺序都是预登记的合成敏感度，不是自然 Agent 频率。

## 完整会话成本

主 wall 为 fixture_session_start→session_supervisor_waited，包含模板创建与切换、全部 16 个请求及最后模板/域/H 回收。两个独立 oracle 的共同夹具准备在该边界之前，明确单列，没有当作免费模板预热。表为三块中位数和范围；吞吐只按完整成功的 16/full 计算。

| 顺序 | 实际 hit / miss / 初始化（三块各自） | 完整 wall 中位 [范围]，s | root CPU 中位，s | 完成请求/s | root 峰值中位，MiB |
|---|---|---:|---:|---:|---:|
| grouped | 14/2/2, 14/2/2, 14/2/2 | 4.645 [4.548, 4.760] | 3.632 | 3.44 | 55.4 |
| alternating | 0/16/16, 0/16/16, 0/16/16 | 11.198 [11.072, 11.209] | 9.894 | 1.43 | 56.2 |
| skewed | 12/4/4, 12/4/4, 12/4/4 | 5.565 [5.359, 5.915] | 4.508 | 2.87 | 55.4 |

下面按同 VM 计算相对 grouped 的额外成本，正值表示该模式更慢。不能用独立中位数相减取代配对；skewed 的准备层级比例不同，不能解释为纯顺序实验。

| 顺序 − grouped | 三块完整额外 wall，s | 配对中位，s | 三块额外 root CPU，s |
|---|---|---:|---|
| alternating | 6.564, 6.650, 6.312 | 6.564 | 6.214, 6.330, 6.268 |
| skewed | 0.714, 1.367, 0.806 | 0.806 | 0.733, 0.954, 0.833 |

## 命中与未命中的请求边界

miss 的完整调用从停止旧模板之前开始，包含新模板初始化；hit 同样支付新建目标域、业务、wait 与回收。最终模板停止在完整会话中计费。下表是相关请求的描述性分布，不是独立重复或稳定尾延迟；没有 hit 的格子保持 Unknown。

| 顺序/实际分类 | 请求数 | 完整 call 台账 median / p90，s | call→response-ready median，s |
|---|---:|---:|---:|
| grouped/all | 48 | 0.224 / 0.611 | 0.224 |
| grouped/hit | 42 | 0.222 / 0.236 | 0.222 |
| grouped/miss | 6 | 0.643 / 0.681 | 0.643 |
| alternating/all | 48 | 0.677 / 0.696 | 0.677 |
| alternating/hit | 0 | Unknown / Unknown | Unknown |
| alternating/miss | 48 | 0.677 / 0.696 | 0.677 |
| skewed/all | 48 | 0.214 / 0.682 | 0.214 |
| skewed/hit | 36 | 0.210 / 0.223 | 0.211 |
| skewed/miss | 12 | 0.679 / 0.697 | 0.679 |

这个路径按请求确认并返回，不套用并发原型整批 commit 的延迟，也不从资源结束点伪造独立 commit 时间。两者响应合同不同，单请求延迟不能跨报告直接排名。

## 内存与限制

| 顺序 | 观测 root charge 中位，MiB·s | root 覆盖范围 | 观测 PSS 中位，MiB·s | PSS 覆盖范围 |
|---|---:|---|---:|---|
| grouped | 160.0 | 95.3–95.8% | 183.6 | 59.1–78.9% |
| alternating | 303.3 | 98.1–98.3% | 496.6 | 82.9–92.9% |
| skewed | 175.7 | 96.4–96.7% | 226.8 | 73.2–83.2% |

root CPU 含所有后代，不再相加角色 CPU。root charge 与 PSS 各自只积分有观测的区间，缺段不填零，不是完整精确内存时间，更不是系统净物理内存节省。各模板和工作集准备、指纹/数值核验、证据 I/O 都实际计费。

本轮证明固定精确 key 单槽策略对这些顺序有实际成本差异；它没有证明依赖互不兼容、必须同时驻留多个模板，或新的依赖感知调度已经产生收益。先验证“更完整模板能否安全满足较浅预热请求”可能改变这组人工 miss，应作为独立兼容问题，而不是把本轮 miss 自动当成系统需求。

只有三个同宿主 VM、可信单线程固定模板和串行请求；没有任意第三方依赖、在线 Agent、长时间运行或不同信任主体复用的资格。

## 历史失败与复现

原 pilot 第二会话在 H 启动前准备 oracle 目录时触发 FileExistsError。独立 fixture-v2 只修复受保护私有夹具的重复准备：检查路径、owner、目录成员，每会话重新生成两份 oracle；不修改 Controller、隔离或生命周期机制。旧失败与静态开发失败均保留，不能算正式样本或产品回收失败。

- 独立夹具修复与原始失败 (`fixture-v2/README.md`, omitted from this source release)；既定单槽合同 (`single-slot-contract.md`, omitted from this source release)。
- 模式摘要 (`../analysis/mixed-v3-report-tables-01/pattern-summary.csv`, omitted from this source release)；实际 hit/miss 分布 (`../analysis/mixed-v3-report-tables-01/hit-miss-distributions.csv`, omitted from this source release)；同 VM 配对 (`../analysis/mixed-v3-report-tables-01/paired-comparisons.csv`, omitted from this source release)。
- 原始导出与资格输入 SHA (`../analysis/mixed-v3-report-tables-01/report-manifest.json`, omitted from this source release)；正式计划映射 (`formal-v3-block-map.json`, omitted from this source release)；独立验收索引 (`formal-v3-verification-index.json`, omitted from this source release)。

!原始三块与完整成本中位范围 (`figures-v3-01/mixed-sequence-cost.png`, omitted from this source release)
