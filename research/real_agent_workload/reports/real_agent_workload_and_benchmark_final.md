# ShimOS：真实 Agent 执行负载与 Benchmark 综合研究

日期：2026-10-20。本报告只汇总本目录实际取得的资料、源码和运行证据；不改变 ShimOS 架构、内核、H/R/Z 协议或依赖准入，也不替项目负责人决定研究路线。

## 1. 结论与证据范围

**真实 Coding Agent 中，持久工作区和隔离域已经很常见；其内部仍反复创建短进程和 Python 映像。两者同时成立，但都不能直接证明跨域预热 heap 的合法复用次数。** 本轮找到了可观测、可复现的负载，也找到了现有 ShimOS 适配器的实际成本与语义限制；尚未测得可归因于 ShimOS 的新在线 Agent 加速。

| 证据层次 | 本次实际完成 | 不能声称 |
|---|---|---|
| 官方资料与固定源码 | 12个Benchmark/Harness条目；执行器44条源码结论/10种后端合同 | 所有版本/全部任务已在本机运行 |
| 完整自然轨迹 | 122次运行、108个task ID、5,288工具动作；另50份不完整补充 | PID、沙箱和heap来自文本猜测 |
| 新私有VM系统观测 | 13个不同任务、14次主观察尝试（含导出失败重试）；414动作 | 新在线模型自主决策 |
| 新受限L2后端Pilot | 1个任务、29条固定真实动作、2个配对block/4个新VM；另trace/importtime诊断 | 跨任务普遍加速、同安全合同排行榜 |
| 旧真实live复核 | 2任务×2后端共4次真实运行，3,273证据输入SHA | 本轮新live结果、可归因执行器加速 |
| 全部本轮VM尝试 | 24次，22份完整task/VM回执；失败仍留账 | 回执完成等于业务成功或完整官方评分 |

公开语料来自两个 Agent 框架、两个主要 Benchmark 家族。第三类 Terminal-Bench 轨迹镜像存在未解析引用，未用不完整文本补齐样本。新增私有 VM 运行是**冻结真实决策、真实执行工具**；模型不依据新的观察重新规划，不能称为本轮新自主 Agent E2E。已有四次真正 live 运行经过独立原始证据核验，单独列作历史结果。新增在线调用因未确认免费端点或付费额度而 BLOCKED，其他工作已继续执行。

## 2. Benchmark 与执行框架：哪些事实影响实验设计

本轮冻结并审查 12 个 Benchmark/Harness 条目、35 项机器字段，以及 mini-SWE-agent、SWE-agent/SWE-ReX、OpenHands 历史 runtime 与当前 SDK 的实际函数。详细版本、许可、源文件与行号分别见 [01](../01_benchmark_survey.md)、[02](../02_agent_execution_architecture.md)。

| 对象 | 核实到的事实 | 对 ShimOS 测量的约束 |
|---|---|---|
| SWE-bench Full/Lite/Verified | 2,294/300/500 test；Agent 运行与最终 patch 评分分离 | 评分容器的启动不等于 Agent 每动作建域 |
| SWE-bench Multilingual | 300 任务、42 仓库、9 语言 | Python 样本不足以代表编译/多语言总体 |
| Pro V1 / V2 | V1 public 731；V2 于2026-09-22发布，642任务/11仓库，独立 fresh-sandbox 重评分 | 本轮22份公开Pro轨迹来自V1，不能当V2运行；HF default和镜像必须固定版本 |
| Terminal-Bench 2.0 / Harbor | TB2.0冻结89题；Harbor是执行与评分Harness；另有2.1/3/4版本 | 持久tmux、多服务和分阶段网络有不同合同；Oracle不是Agent轨迹 |
| DS-1000 | 单题代码生成与正确性评分，部分依赖要求每题独立进程 | 适合初始化/状态正确性补充，不能代替自然多轮Agent |
| DA-Code | 持久Docker中写脚本，再启动新Python | 数据分析Agent也不一定有持久heap |
| DABstep / smolagents1.3.0 | 固定baseline跨step保留AST解释器state；不是IPython | 是另一种可研究的状态模型，尚未取得本项目的PID、资源与安全实测 |

mini当前2.4.6源码与本轮实际运行的v1.0.0不是同一版本。新增Agent控制面使用上游要求的CPython3.11.17；业务环境仍为固定CPython3.10.12。OpenHands当前执行核心已转向SDK；不得用旧Jupyter实现解释全部当前用户。代码仓库许可证也不能自动授予轨迹和原仓库补丁的重新发布权。本研究仅本地保存，没有对外发布数据。

## 3. A：真实工具动作分布

主语料为 **122 次完整真实运行、108 个不同 task ID、5,288 次业务工具动作**，另有28条终止/控制记录。每运行动作均值43.34、中位33、范围7–214、描述性p90为82.7。SWE-agent/mini两类框架，SWE-bench与Pro V1两类主要来源；40份历史原件复用、82份新获取。10份OpenHands不完整记录与40份Terminal-Bench镜像作为补充/排除保留，不混入主分母。

| 静态动作信号 | 动作数 | 应怎样理解 |
|---|---:|---|
| 代码读取/查找/搜索 | 3,468 | 可与其他类重叠；不是read系统调用数 |
| 文件修改 | 1,397 | 包括脚本修改，说明工作区连续性重要 |
| Python入口 | 991 | 包含脚本/重现/测试候选，不等于真实Python进程或heap资格 |
| Shell基本命令 | 902 | pipeline和脚本内部进程只能靠追踪 |
| pytest/unittest信号 | 178 | Python入口的交叠子类，不能再相加求总比例 |
| JavaScript/TypeScript工具 | 128 | 多语言候选，尚未在本轮VM恢复其镜像 |
| Git | 127 | 包含失败、等待和网络合同 |
| 其他语言构建/测试 | 93 | 静态分类，不是CPU密集比例 |
| 等待/轮询 | 89 | 不能全部算依赖初始化成本 |
| 依赖安装 / 无法可靠分类 | 8 / 52 | 缺失类别没有用猜测补齐 |

537次精确重复命令中，468次之间出现编辑动作；有256次Python入口重复和522个修改—执行候选片段。重复测试存在，但正在编辑的项目代码恰好可能让预热状态失效。

轨迹版本/模型/项目和成功失败分布均保留原字段，不把“Submitted”当“resolved”。旧SWE样本官方已知8/30解决，mini样本41/70；Pro缺失结果保持缺失。所选22个Pro配置均用“Python仓库/写Python重现”提示，即便实际是JS/Go项目。因此其202次Python入口受scaffold影响，不是自然依赖偏好的无偏统计。

公开时间覆盖仅1,847/5,288动作（34.9%），主要来自Pro工具wrapper；没有完整LLM与Task边界。其工具wall合计4,472.675秒，三个明确450秒取消的Git操作合计1,356.913秒、占30.3%。这些等待不能通过预加载NumPy消除。其余动作的时长、CPU和PID均未补造。统计与逐动作表 (`../03_trajectory_workload_analysis.md`, omitted from this source release)、manifest (`../trajectory_manifest.csv`, omitted from this source release)。

## 4. B：隔离域、进程和解释器的实际关系

在已完成的13个任务中，原mini Docker后端每task一个持久业务容器。共观察到 **414动作、13612个业务进程出生代次、13933个业务exec映像、102个Python exec映像**。

| 指标 | 均值 | 中位数 | 范围 |
|---|---:|---:|---:|
| K_tool（已确认同域动作） | 31.85 | 29.0 | 12–61 |
| K_proc（实际业务进程代次） | 1047.08 | 43.0 | 21–7379 |
| 每任务Python exec | 7.85 | 9.0 | 4–13 |

Python退出/wait4关联分别为102/102与102/102；跨action仍活着的Python采样证据为0。这支持受测Python是新exec映像，不证明所有Agent都不复用解释器。进程退出/wait4关联为13612/13612、13612/13612；proc整代次只采到325/13612（2.39%），其中包含exec前状态。业务exec后采到139个进程；严格处于Python映像存活区间的完整扫描为100/102。这些不同覆盖口径不能混用。

独立定向验收结果{"PASS": 6, "TEST_FAILURE": 3, "BLOCKED": 4}，其中6个任务满足目标验收。与原轨迹已知returncode不同的动作10条；都保留。详细逐任务表、六namespace覆盖、异常与资源账本见04 (`../04_process_lifecycle_measurement.md`, omitted from this source release)。

受测容器区间CPU为1.745–26.977秒，非同步采样PSS峰值为22.36–159.07MiB，memcg peak为16.04–164.82MiB。三者不是同一资源边界；CPU不含整个控制面，采样峰值漏短进程，memcg共享页计账也不等于物理PSS。没有把这些数相加称系统总CPU/净物理内存。

源码与运行共同支持以下区分：

- mini Docker：Environment创建一次容器，每动作`docker exec bash -lc`；文件持续，上一Shell的局部变量不自动持续，Python通常是新的exec映像。
- SWE-agent的SWE-ReX BashSession：持续PTY Shell，cwd/export跨动作保留；mini的SWE-ReX Command接口却是另一条独立subprocess路径。
- 历史OpenHands：持续Shell与可选Jupyter Kernel，后者能够保留Python对象；当前SDK还具备tmux pane复用和并发控制。
- “同一个容器”不等于“同一个Shell”，更不等于“同一个Python heap”。Benchmark题目本身也不统一规定以上关系。

**短进程密集负载的直接例子：**Sympy20590只有33个动作，却创建5,770个业务进程；四条真实`find -exec grep`命令触发5,725次grep exec，整个任务共有5,736次grep exec、仅4次Python exec。Sympy21379为61动作、7,379个业务进程。二者会主导汇总exec比例，必须同时看逐任务分布。不能将这些数乘某个平均fork耗时，或据此宣称Zygote复用有收益。

私有VM跟踪完整fork/exec/exit、wait4、cgroup attach及动作marker，并用出生事件/启动代次避免PID复用和namespace内外PID数值混淆。`/proc`名义50ms扫描漏掉大量短进程，PSS与六namespace只对采到的身份成立；trace生命周期完整也不能替漏采进程补写内存。旧初版误计runc预exec线程的分析结果保留，修订后排除控制面线程。

该Docker现实基线使用guest初始userns中的uid65534，并非ShimOS独立Base/Inner userns；它的正常清理证明也不自动等于H故障合同。没有通过放宽ShimOS安全策略“对齐”基线。独立定向holdout在工具任务结束后运行，不计为业务动作，也不冒充完整官方SWE-bench得分。

## 5. C、D：真正值得复用什么，真实K如何对应旧实验

| 状态或计数 | 本轮证据 | 目前结论 |
|---|---|---|
| Task内文件与隔离域 | 源码和实际container ID/cgroup生命周期 | **Observed**：原执行器已经复用，不能将每动作冷建域当唯一强基线 |
| `K_tool`、`K_proc` | 新VM真实动作和进程身份 | 已测；数值与单位见04，不能相互代换 |
| 重复Python启动 | 新Python exec和真实退出/wait | **Observed**；昂贵可消除初始化子集仍需分解 |
| `K_heap` | 缺合法状态兼容/失效/reset资格 | **UNKNOWN**，不是按Python入口数量填值 |
| `K_template` | 缺跨信任域需求与固定依赖准入 | **UNKNOWN**；本轮0次直接合格跨域heap命中证据，不等于潜在机会为0 |
| 文件/page cache | 持久文件和相同依赖路径 | 文件持续已知；缓存驻留/物理共享收益未充分测量，不能当已初始化heap |
| 长寿命Python Worker | OpenHands/DABstep固定源码支持，主自然语料无显式IPython调用 | 本轮未完成该执行模型的运行样本，不推广“Agent没有持久Python” |

旧固定NumPy实验N=100时G0/G1/G2耗时53.793/61.759/22.503秒，以及N=50下K≤5的受测点G2胜、K≥10时G3胜，仍是有效的**受控业务结果**。但其中K是兼容数值协议请求密度，本轮K_tool包含搜索、编辑、Git和测试，不能按动作中位33就宣布落在G3优势区。

当前Flask/Sympy/pytest会导入可写项目代码及测试插件。普通`python script.py`经exec替换地址空间，不透明继承预热Python；把它重写为可信函数协议会改变执行合同。本轮没有将这些依赖扩展到既有NumPy2.2.6/OpenBLAS单线程准入。

### 一个已经量到的重复初始化候选

Sympy19954的23条真实动作另做两次私有VM诊断，均观察到10次Python exec，命令/退出码相同、独立定向holdout通过且资源释放。开启importtime的8个动作中，仅5个单解释器、完整包级计时且无错误的动作纳入预算：SymPy cumulative导入中位 **1.114秒**，范围 **1.096–1.184秒**，合计 **5.631秒**；对应五动作wall为 **7.440秒**。只跨独立串行动作求和，没有叠加嵌套模块的cumulative。

捕获原始错误、缺包级行、多解释器混合输出的三个动作均排除并保留。开启/关闭计时的工具累计28.056/28.112秒，差−0.057秒；两个独立VM的环境和随机性使它不能作为严格因果探针开销。去计时行后仍有两个动作的测试用时/随机seed输出不同，原差异保留。

**这证明存在重复导入预算，没有证明5.631秒可以全部删除。** SymPy是正在被修改的项目，未获得可信预加载/fork准入；这些wall也不是CPU或完整初始化账本，不能填入K_heap、K_template或推导Agent端到端加速。完整诊断及纳排 (`../reuse_analysis/import-diagnostic.md`, omitted from this source release)、原始数值与SHA (`../reuse_analysis/import-diagnostic/completed-02/summary.json`, omitted from this source release)。


## 6. E：轻量隔离是否已体现额外优势

**本轮没有验证“更多新域能改善现实Coding Agent整体性能”。** 原持久容器已经摊销建域；现在观察到的许多成本是命令结构、业务初始化、测试或等待。Bubblewrap对明确需要新信任边界的任务仍有作用，但本样本没有足够权限变化/跨主体信息来估计自然频率。

本轮在支持的Agent控制面版本上实际完成两个新配对block。原始时间如下，未按结果筛选：

| 新配对block | Docker工具秒 | T2工具秒 | Docker session秒 | T2 session秒 | Docker/T2 root CPU秒 |
|---|---:|---:|---:|---:|---:|
| 1 | 6.437 | 26.939 | 9.484 | 32.744 | 8.150/20.262 |
| 2 | 6.461 | 26.577 | 10.032 | 32.602 | 7.899/20.649 |

这两个block的T2 session差额中位数为 **+22.915秒**，范围22.570–23.260秒（正数表示T2额外成本）。只描述两个同宿主配对，不给生产分位或显著性结论。每条动作、输出差异、patch、定向测试、wait/EOF与释放核验见07 (`../07_real_agent_e2e_pilot.md`, omitted from this source release)。

两块均29条命令/退出码相同、28条原始输出字节相同、patch一致且60项定向测试通过；第1条`ls -la`暴露`..`的owner/权限/链接数与时间差异，保留为可见合同差异。因此只能比较该固定业务子集的运行账本，不能声称Agent可无感替换。

该对照有意保留现实合同差异：Docker在一个任务中保留容器，T2每动作新域并archive工作区。两组业务预算一致不等于安全、总控制面资源或状态合同完全一致。T2还包含研究入口的helper构建/runtime检查和文件复制；不能把差额全归因于Bubblewrap。补丁与定向测试相同只支持这个同步普通文件子集，不支持后台任务、任意symlink、打开FD、inode锁、持续Shell或网络语义。

既有Flask4935反例在`/tmp/fix.py`的两个动作上退出码不同；即使最终patch相同，仍为NOT_ADMITTED。没有将该组混入速度排名。强基线必须保留这些现有状态能力，而不是只和一条缺少监督的冷启动命令比较。

## 7. 真正在线Agent与可优化上限

本轮只读核验了旧四次真实模型运行：两个任务各两后端，原模型响应、token回执、真实动作、候选补丁与独立测试均可关联。旧mini控制面使用3.10低于上游声明3.11，是受限旧运行；本轮新增回放已修正控制面版本。

| 历史live | Docker完整任务秒 | T2完整任务秒 | 定向结果 |
|---|---:|---:|---|
| Flask5014 | 37.111 | 67.124 | 两侧60测试通过 |
| Flask4935 | 58.868 | 77.418 | 两侧同一个测试失败 |

这些full_task包含当时证据导出；扣单独导出后的session另见独立核验 (`../e2e_pilot/historical-audit/historical-e2e-audit.md`, omitted from this source release)。动作、token、模型服务时间和早期业务预算不完全相同，**不能把时间差归因于执行器，不能声称新E2E加速或普适变慢倍数**。

旧四次live中，模型guest等待占同步Agent loop的82.8%–88.3%，工具占11.5%–17.1%。这不是总任务占比，更不是可删除初始化比例。以旧Flask5014 Docker为条件例，若固定相同决策/模型等待、把全部工具时间都变成0，loop缩短上界11.56%、约1.131倍；真实初始化只是工具子集，且预热/内存/回收不能免费。因此本轮尚不能给出可兑现的完整Agent加速百分比。

等待LLM也不等于本机空闲或下一个依赖可预测；尚缺模型等待与本机资源余量、下一动作类型、预热命中/浪费的联合实测。不得将这一构想写成已验证调度收益。

## 8. F：供负责人比较的候选方向

| 方向 | 已有需求/机制证据 | 主要风险和缺口 | 最有信息量的下一步与成本 |
|---|---|---|---|
| 原生执行与工作区/域连续性 | 多数真实动作涉及外部命令；13任务实际一域多进程；当前T2接入有负结果 | archive/临时目录/后台/取消合同；新域开销可能抵消Native入口优点 | 选已通过定向验收的同一任务，分离首次构建、每动作复制与域成本；独立小副本，先语义资格，不改主线 |
| 稳定依赖的域内模板 | 反复Python exec、编辑后重测真实存在 | 可写项目导入、插件/回调、状态失效；不是所有import可预热 | 固定一个真实项目环境，测只读依赖与项目初始化边界；再判断是否值得准入 |
| 跨域可信模板 | 旧受控NumPy收益和可靠性机制成立 | 真实跨域需求、版本兼容与合格密度尚未知 | 多个真实任务的依赖/权限兼容账本与完整初始化预算；先采证据，不扩大任意包准入 |
| 持久Worker与现有Kernel | OpenHands、DABstep已有相近机制 | 用户预期的持续状态不能随便reset；不同信任主体不可共享 | 一个真实持久Python任务，保留原cell语义观察PID/内存/状态；需要环境与模型额度 |
| 联合资源调度 | 不同命令/初始化/域生命周期确实不同 | 本轮串行任务不能提供真实到达、排队、并发和信任分布 | 多任务到达与完整资源观测，先对比成熟静态策略；不需要立刻开发Scheduler |
| 取消和生命周期 | 旧ShimOS受限故障资格，原执行器源码有不同终止合同 | 本轮主要正常路径，没有新的广覆盖Controller故障实验 | 在独立VM对同一真实长命令注入取消/父死，比较结果知识与释放；不能把observer补杀算产品通过 |
| 空闲窗口预热 | 旧live存在长模型等待 | 空闲资源、预测命中、过期和内存时间都未测 | 合并同钟模型/工具/资源事件，小量在线任务即可增加信息；需明确模型授权 |
| 单次派生/内核辅助 | 旧A/B/C受限权限与机制证据 | 本轮无自然合格跨域heap命中分布；省fork不等于整体获益 | 先得到合法模板请求与完整路径预算，再由负责人判断是否需要内核研究；本轮无内核改动 |

这是证据与新增实验代价的比较，不是研究路线排序或Go/No-Go。本轮最充分的事实是状态合同差异和原执行器的持久化；对于调度、跨域模板和内核新能力，数据还不足以直接选择架构。

## 9. G：可以实际使用的三级Benchmark

**Level 1：负载刻画。** 122条自然轨迹、固定执行器源码、13项真实执行观察，统一action/process/domain/runtime身份。不能从文本直接给heap资格。

**Level 2：固定真实轨迹回放。** 当前13task manifest保留源码commit、依赖、动作和失败。优先从独立定向验收通过且动作语义可保持的任务开始。原Docker是现有强基线；普通bwrap、持久B-strict、G2/G3/G4只在对应合同通过后加入。每组包含部署/预热/输出/回收；镜像准备、证据导出和评分另列明确边界。

**Level 3：真正在线Agent。** 原模型/提示词/任务/工具不变，实际自主生成动作，分别报告任务质量、full_task、工具累计、模型网络等待、CPU、内存和回收。固定回放提供控制变量，live路径变化单列。当前新增该层BLOCKED，不用DeterministicModel或Oracle填空。

近期可复现对象是固定SWE任务+mini v1.0.0+新增受支持3.11控制面；精确命令、SHA、任务结果见 06设计 (`../06_benchmark_design.md`, omitted from this source release)、manifest (`../benchmark_manifest.csv`, omitted from this source release)、协议 (`../benchmark_protocol.md`, omitted from this source release)。TB2.0/Harbor CPU任务、ProV2多语言与DABstep dev是有明确源码入口的扩展候选，不是已测配置。TB2资源声明69题2GiB、17题4GiB、3题8GiB，当前4GiB VM不能默认容纳全部。

本轮全部24次有VM结束回执的运行，宿主等待VM累计36.0分钟，单次范围13.0–184.1秒。这包含环境准备、诊断和独立评分，不是Agent执行器每任务成本，也不包括资料下载/分析时间。逐任务工具/session/VM账本见manifest和run-ledger。未调用新的模型API，不能给出在线费用或通用任务预计耗时；后续模型与大镜像成本保持UNKNOWN。

## 10. H：哪些问题已成立，哪些还没有证据

1. **实测成立：**工具动作与进程数严重不一一对应；同任务容器复用与多次新Python映像可以同时发生；当前T2的普通文件接入存在实际开销，临时目录差异会破坏等价；观察/导出代码也可能失败。
2. **强证据但缺严格系统对照：**重复Python/测试可能有初始化预算；短进程搜索与长工具等待是不同成本；持久Shell/Kernel已被成熟执行器利用。
3. **仍是假设：**合法固定依赖能频繁跨任务/跨域复用；联合域/模板调度优于独立成熟策略；LLM等待可稳定隐藏预热；减少一次派生会改变真实Agent资源最优选择。
4. **已有系统已经处理的部分：**任务级容器/文件持续、SWE-ReX PTY状态、OpenHands终端池和Kernel、Harbor trial和评分生命周期。ShimOS新增价值必须在这些基线之上证明。
5. **目前没有足够证据：**自然K_heap常到10/50、通用第三方fork安全、跨主体模板安全共享、精确系统净物理内存节省、新在线Agent加速、生产级p99或新调度算法收益。

因此，**受控NumPy机制优势没有被本轮否定，但也没有被自然工具动作数量自动证实。** 当前可以建立可复核的执行Benchmark与明确的资格门槛；下一步要选择哪个合同、哪种状态和哪种机制，仍由项目负责人决定。

## 11. 失败、限制与复现

- 新增任务均为离线重建fixture，不是原提交者完整镜像；模型冻结不随环境变化修正。网络、依赖/测试版本和git历史的差异保留，不能把公开成功标签迁移到重放。
- 固定VM单宿主4vCPU/4GiB、串行运行。新低干扰对照只有两block；没有跨硬件独立性、生产尾延迟或大范围统计显著性。
- 新配对VM窗口仍有宿主memory/I/O PSI压力（memory some avg10峰值3.42%–5.69%、I/O 1.79%–3.54%），因此数值是受测环境描述，不能将差额全归于执行架构。压力原件与按VM时间窗分组均保存，未删除较慢样本或改选窗口。
- PSS扫描漏短进程、异步采样、cgroup共享页计账等使全系统净物理内存仍UNKNOWN。CPU部分账本不冒充完整系统CPU；root与子cgroup不重复相加。
- Requests6028初次证据导出跟随悬空symlink失败，最终receipt/trace尾缺失，保留INCOMPLETE；独立修订重试不覆盖原件。Agent运行时第一次3.11尝试缺libpthread在导入前失败，也完整保留。
- Terminal-Bench40份镜像共有1,265个未解析RSC引用，没有原响应绑定表，不能恢复完整ATIF；OpenHands10份补充也不满足完整轨迹条件。检索与失败见对应manifest。
- 新在线模型未获额度/免费端点确认，没有新增调用；未购买云资源、修改宿主隔离、发布数据或访问任务不需要的私密材料。

统一入口：README (`../README.md`, omitted from this source release)。机器账本：轨迹manifest (`../trajectory_manifest.csv`, omitted from this source release)、Benchmark机器表 (`../benchmark_survey/benchmark_catalog.csv`, omitted from this source release)、进程统计 (`../process_tracing/analysis/process-measurement-summary.json`, omitted from this source release)、新Pilot (`../e2e_pilot/analysis/new-pilot-01/report.json`, omitted from this source release)、全部新运行登记 (`../analysis/run-ledger.csv`, omitted from this source release)。所有报告由保存输入和脚本生成或链接到固定源码行号；失败、修订和BLOCKED分别保留。历史输入哈希复核和新来源manifest见 `sources/`。没有修改历史实验或更新飞书。
