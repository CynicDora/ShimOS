# 04 — 实测变量与初步成本模型

模型目的：把隔离域与应用Worker初始化分开记账，不发明预测调度器。以下为受限固定输入、同信任串行请求模型；所有数值来自指定分析输入。

|变量|定义|当前可测边界|
|---|---|---|
|D|隔离域创建/准备|B/C domain constructor，含原基线初始化/身份检查；A只有域+Worker联合launch时长，不能凭差减填纯namespace成本|
|I|Worker进程及依赖初始化|launch→READY，脚本entry和dependency init为嵌套诊断；clangd初parse可能延后|
|Q₀|首次有效业务请求|submit→完整解析响应；独立Oracle时长/CPU另存，纳入完整序列|
|Qw|同Worker后续请求|C同身份下后续IPC+业务；不是纯应用计算或零成本IPC|
|Rw|Worker正常shutdown到严格group release|每个A/B与C最终都完整计费|
|Rd|最终隔离域/工作区清理|B/C task close；A含在每次Raw release中，不重复相加|
|Md|空隔离域PSS|独立resource cohort完整root observer；missing→Unknown|
|Mw|保留应用Worker的空闲PSS|Python只计同PID一次；clangd包含wrapper+child；与域PSS不可再次相加|
|V|独立Oracle/验证|读取verified时间与verify_cpu_ns；禁止将wall称CPU|

## 条件公式

令H为显式诊断/控制/协议记录开销，冷初始化包括I以及首业务可能承担的解析：

```text
T_A(n) = Σ_j [D_j + I_j + Q₀,j + V_j + Rw,j + Rd,j] + H_A
T_B(n) = D + Σ_j [I_j + Q₀,j + V_j + Rw,j] + Rd + H_B
T_C(n) = D + I + Q₀ + V₀ + Σ_{j>0}[Qw,j + V_j] + Rw + Rd + H_C
```

公式区分逻辑成本，并非声称每项都有独立无重叠计时。实测主值始终使用完整sequence_total；不得将表中嵌套阶段直接相加来替代。不同n的结果是实验参数敏感度，不是自然调用概率。

## 当前完整成本观测

| Worker | n | 策略 | 完整wall ms | CPU ms | Workers创建数 |
|---|---|---|---|---|---|
| clangd | 1 | A | 141.030 | 141.479 | 1.000 |
| clangd | 1 | B | 148.474 | 147.094 | 1.000 |
| clangd | 1 | C | 144.278 | 145.354 | 1.000 |
| clangd | 16 | A | 2331.212 | 2349.517 | 16.000 |
| clangd | 16 | B | 2261.728 | 2292.538 | 16.000 |
| clangd | 16 | C | 182.166 | 184.302 | 1.000 |
| clangd | 4 | A | 699.781 | 719.597 | 4.000 |
| clangd | 4 | B | 643.113 | 656.904 | 4.000 |
| clangd | 4 | C | 177.554 | 181.792 | 1.000 |
| numpy | 1 | A | 150.550 | 150.878 | 1.000 |
| numpy | 1 | B | 142.224 | 140.554 | 1.000 |
| numpy | 1 | C | 145.303 | 143.368 | 1.000 |
| numpy | 16 | A | 2204.586 | 2209.002 | 16.000 |
| numpy | 16 | B | 2052.968 | 2057.103 | 16.000 |
| numpy | 16 | C | 221.782 | 220.000 | 1.000 |
| numpy | 4 | A | 560.633 | 561.724 | 4.000 |
| numpy | 4 | B | 555.406 | 554.620 | 4.000 |
| numpy | 4 | C | 163.325 | 161.708 | 1.000 |


隔离域的真实占比只能从已分开的B/C创建与最终域关闭中给出受测合同的近似控制开销；A的domain+worker联合路径不能拆成同一个D。A−B还改变monitor/owner执行方式，不能称为纯Bubblewrap namespace微秒成本。

## 可分开的域预算与保留内存

| Worker | n | 策略 | 域构造ms | 最终域释放ms | 每序列(构造+释放)/总wall中位% |
|---|---|---|---|---|---|
| clangd | 1 | B | 7.966 | 1.878 | 6.819 |
| clangd | 1 | C | 8.611 | 2.745 | 7.736 |
| clangd | 16 | B | 9.402 | 3.852 | 0.533 |
| clangd | 16 | C | 10.319 | 2.935 | 6.922 |
| clangd | 4 | B | 10.114 | 3.471 | 2.112 |
| clangd | 4 | C | 9.708 | 2.669 | 7.344 |
| numpy | 1 | B | 9.456 | 2.924 | 8.315 |
| numpy | 1 | C | 11.019 | 2.028 | 8.794 |
| numpy | 16 | B | 7.980 | 3.115 | 0.529 |
| numpy | 16 | C | 9.016 | 2.411 | 5.320 |
| numpy | 4 | B | 9.588 | 2.545 | 2.167 |
| numpy | 4 | C | 9.146 | 2.654 | 6.928 |

百分比先逐样本计算再取中位；仅B/C直接分开的控制路径，不含Worker组创建/释放、业务期间控制开销或close后审计。这是一个可复核子预算，不是全部隔离成本或纯内核成本。

| Worker(C,N4,1样本) | 空域MiB | app wrapper+worker MiB | 热完整域MiB | 首末域PSS差KiB |
|---|---|---|---|---|
| clangd | 2.832 | 102.093 | 104.940 | 12.000 |
| numpy | 2.828 | 27.665 | 30.513 | 4.000 |

空域与Worker分别运行时的PSS不可线性相加，保留成本还包含guardian、页共享比例与协议元数据。本轮只测快照，RSS/峰值/长期MiB·s不得互换。

## 保活内存何时值得

### 两类 Worker 的收益结构不同

**实测 / 解释：** C、N=16 时，NumPy 首业务响应中位0.999ms、后续响应中位0.993ms，计算本身没有明显变快；避免的是重复解释器/协议包装器、依赖导入和进程回收。clangd 则从首业务响应42.330ms降到后续中位0.776ms，除了启动成本，还避免了本次冻结翻译单元的重复解析。具体阶段和计时边界见[06](06-benchmark-results.md)。这不是对任意更改后AST有效性的证明。

clangd保留的应用PSS约102MiB，NumPy约28MiB；因此仅按节省毫秒排序，与按有限内存下保留价值排序可能不同。当前两个工具的调用频率与空闲间隔未知，不能由这组时间/内存直接给出部署优先级。这是值得下一轮测固定预算取舍的依据，不是已验证的保活算法。

成本维度不能直接相减：节省100ms不自动抵消若干MiB。对于同信任、输入仍有效、无排队的下一次调用，设可避免的重新初始化与回收成本为S，验证/保活/刷新开销为Vkeep，额外空闲内存为M MiB，间隔为h秒。给定**外部指定**影子价格λ（ms等价成本/(MiB·s)），保活条件为：

```text
S > Vkeep + λ × M × h
h_max = (S − Vkeep) / (λ × M), only if S > Vkeep, λ > 0, M > 0
```

λ不是本轮测得的价格；未来调用概率、内存压力、SLO和租户优先级均未知。不能据此宣布生产保活时限。若没有内存影子价格，正确输出是一个二维前沿：完整时间/CPU节省与额外MiB·s；本轮没有真实等待间隔分布，也没有测量长期内存积分。

## 尚未可推断的调度结论

本轮不提供reuse probability、在线pool resize、跨域迁移或受争用动态placement最优策略。需要自然调用间隔、Worker类型/依赖命中、信任/工作区限制与容量下的排队/淘汰数据，才能判断固定集中池、静态分池、细粒度布局的性能前沿。现有成本只为下一轮提供预算；成熟serverless预热/缓存工作仍是强竞争方案。

## 一次性部署账本与测量限制

字节码准备收据 (`experiments/workers/bytecode-preparation.json`, omitted from this source release)：1112个CHECKED_HASH pyc，15,310,096字节，一次host准备wall3.913秒、CPU2.693秒。各A/B/C同runtime输入；这是共享部署准备而非每次请求成本，不把source-only pilot的额外编译计入正式收益。直接执行server.py的主脚本编译及协议wrapper仍属于每次Worker准备的实测成本；不能把总I全称为NumPy导入或clangd初始化。

[完整测量与配对](06-benchmark-results.md)、只读分析器 (`analysis/analyze.py`, omitted from this source release)、原始数据/摘要 (`analysis/final03/summary.json`, omitted from this source release)。N=1是必要反例：没有后续命中就没有稳定应用复用收益；N=4/16是在稳定输入下的受控机会，不是实际Agent请求概率。

