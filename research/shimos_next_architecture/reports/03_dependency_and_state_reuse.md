# 工作包 C：真实依赖身份、初始化与状态复用边界

当前状态：已完成两个私有 VM 的依赖身份与导入诊断、一个独立普通字节码缓存反事实，以及原动作回放和独立定向评分；另一次 fixture 准备失败完整保留。发现了实际重复加载的相同外部依赖，并实测其中一部分导入成本可由普通 pyc 缓存减少，因此不能全部算作 heap 复用机会。**新增 Zygote 依赖准入为 0。**

## 已确认的事实与本轮缺口

旧13个真实任务的重建fixture共有78个两两比较，全部至少共享7个同SHA wheel，18对wheel集合完全相同，Jaccard中位0.611。这证明安装字节有交集，不证明实际用了相同依赖，更不证明Python对象可以安全共享。同一批旧任务观测到102次Python exec，但没有逐次实际模块身份。两个分母不能相乘生成“复用命中数”。原事实账本 (`../../shimos_architecture_challenge/pilot_v1/reports/dependency-mechanism-opportunities.md`, omitted from this source release)

另一个独立SymPy19954诊断中，5个单解释器成功动作有完整SymPy导入wall，合计5.631秒、中位1.114秒；其中mpmath嵌套导入合计1.179秒、中位0.236秒。mpmath已经包含在SymPy内，不能相加。5次中只有4次是首次之后的重复；上述wall既不是CPU，也不是已证明可删的预算。该cohort不等于旧102次Python exec的覆盖子集。原计时报告 (`../../real_agent_workload/reuse_analysis/import-diagnostic.md`, omitted from this source release)

本轮补充的是实际 `sys.path` 解析、模块文件与pyc字节、映射DSO/ABI以及线程/FD/环境/信号的可观察变化。即使这些身份一致，fork安全、权限兼容、请求状态隔离与净收益仍要另行验证。

## 固定任务与来源

|任务|实际base commit|依赖边界|
|---|---|---|
|Flask5014|`7ee9ceb71e868944a46e1ff00b506772a53a4f1d`|可变Flask源码；外部Werkzeug/Jinja2/Click/MarkupSafe等|
|SymPy19954|`6f54459aa0248bf1467ad12ee6333d8bc924a642`|可变SymPy源码；外部mpmath1.2.1|
|SymPy20154|`bdb49c4abfb35554a3c8ce761696ffff3bb837fe`|另一源码版本；同一预期mpmath wheel|

三个源码archive与旧fixture SHA都匹配，保留17个原直接Python动作。选择依据是源码/外部依赖边界及已有复现条件，而非ShimOS速度或任务成功。Flask原动作020失败、SymPy19954动作008虽退出0却报告业务错误，仍保留在自然序列中。初始源码是真实base tree，安装环境是冻结离线重建；不能冒称完全复原公开运行的原镜像。完整来源和SHA (`../dependency/input-manifest.json`, omitted from this source release)、原Python动作索引 (`../dependency/real-python-action-candidates.csv`, omitted from this source release)

## 新诊断的两个证据层

**原命令身份观察。** 在独立identity-on cohort通过显式 `sitecustomize` 注入，保留原命令、动作、业务文件修改和评分。每个解释器按PID与startticks保存开始/结束记录，记录实际atexit驻留模块和映射文件，不主动导入目标依赖，不输出到业务stdout/stderr。自然identity-off与独立holdout评分仍保留；所有失败、缺end和资源回收结果由原执行器裁定。

**受控import机制诊断。** 在另一workspace内依次观察首次import、同一进程再次import、多个fresh Python的import。首个fresh过程没有清page cache，也不称磁盘冷启动；同解释器命中 `sys.modules` 不等于不同任务兼容。微型计时只在固定边界内采wall与process CPU，完整解释器生存时间另列。文件/DSO SHA重型收集排在timing之后，并且不用identity模式的时间与轻量计时混合排名。

跨两个VM反转任务/module/on-off顺序只是控制部分顺序影响；样本量不支持稳健尾延迟或独立宿主推广。每task从冻结rootfs恢复，避免旧prepare叠加安装包污染下一fixture。可执行接口与限制 (`../dependency/README.md`, omitted from this source release)

## 实际完成情况与任务正确性

`next-dependency-01` 的三个 fixture 均因准备工具查找 global git 失败，6 个计划回放槽位记为 BLOCKED，未执行业务。新副本修复为使用任务 runtime 内的 git/DSO 后，重新登记的 `next-dependency-01r1` 与反顺序 `next-dependency-02` 完成。失败没有被重写为成功。

两个有效 VM 共 3 个任务 × 2 种身份诊断模式 × 2 块 = **12 个完整回放、296 个 Tool Action**。12/12 均 Submitted，原 Controller 有真实 wait，业务域、工作区和控制器目录按记录释放；12/12 独立定向评分 PASS，评分前后候选未被修改。6 对原命令、返回码序列、原轨迹 SHA 与提交补丁一致。

这不是在线自主 Agent，也不是官方 SWE-bench resolution rate，更不是完整异常恢复资格。原序列中的失败动作仍保留。9 处 stdout/stderr 原文差异包括 `ls` 的诊断挂载目录元数据、两输出流的到达顺序、随机生成器次序、测试随机种子和耗时；原文没有过滤，不能写成逐字输出完全一致。逐会话/配对矩阵 (`../dependency/cohort-analysis-final-01/cohorts.csv`, omitted from this source release)、原文差异 (`../dependency/cohort-analysis-final-01/output-differences.json`, omitted from this source release)

两个 VM 总 wall 分别约 **847.23 s / 272.24 s**，均正常退出、外层无补杀。第一块直接经 9p 导出并评分，第二块先保存 guest 本地静止快照、评分后归档；这改变研究采集边界，不能把总时差称为执行器优化，不能合并完整 Session wall 排名。公共 Docker/VM 平台最终关闭也不等于业务 Controller 已独立 wait 全部宿主服务。原 VM4 (`../runs/next-dependency-01r1/result.json`, omitted from this source release)、原 VM5 (`../runs/next-dependency-02/result.json`, omitted from this source release)

## 从“装了相同包”推进到“实际解释器看到相同文件”

两块共取得 **36 对 start/end 身份记录，0 条 hook 错误或缺 end**，按同一 guest 单调时钟唯一对应到原动作。每块 Flask 有 5 个、SymPy19954 有 9 个、SymPy20154 有 4 个解释器观察。独立进程审计另外确认两块 on/off 合计 76 次 Python exec，其中 identity-on 为 38 次，因此 hook 对 exec 的覆盖为 **36/38（94.7%）**。缺少的两次都位于 SymPy19954 动作20：冻结 `runtests.py:252–254` 先调用 `python -RV` 检查选项，之后第273行才创建有 hook 的测试子进程；原始 exec/exit/wait 和顺序支持该解释，但 trace 没有解码 argv，不能写成逐字运行参数已证实。旧 102 次 exec 不是本轮分母。独立进程核验 (`../analysis/study-process-dependency-01/independent-raw-validation.json`, omitted from this source release)、缺失覆盖定位及限制 (`../analysis/hook-coverage-02/hook-coverage.json`, omitted from this source release)

|实际任务|业务树内模块|实际外部依赖例子|观察到的身份边界|
|---|---|---|---|
|Flask5014|`/testbed/src/flask`，2.3.0.dev|Werkzeug 2.2.3、Jinja2 3.1.2、MarkupSafe 2.1.2|业务树可写；外部模块源文件对业务 UID 不可写|
|SymPy19954|`/testbed/sympy`，1.7.dev|mpmath 1.2.1|项目源码与另一任务的 base commit 不同|
|SymPy20154|另一版本 `/testbed/sympy`|同一 mpmath 1.2.1|可比较外部文件身份，不能把完整 SymPy 模板视为兼容|

两 SymPy 任务共有 **50 个实际驻留的 mpmath 模块文件身份**，在 26 个解释器观察中一致。根模块 SHA 为 `46cd24a875e8dd00fb47c6a5cf28fd06878d4dfe7562446b8d23ca69ca65b413`。全部外部模块按 `module + realpath + SHA` 计算，有 177 个身份在两个任务中出现；其中还包括 setuptools、pkg_resources 等工具依赖，**不是 177 个独立依赖包**。独立比对得到 492 个 task/path/SHA 条目匹配冻结 wheel 成员字节。

与之相对，两块均观察到原动作之间 Flask `blueprints.py`、SymPy `perm_groups.py`、`iterables.py` 字节变化，合计 6 条 task×VM 文件变动记录；迭代器文件各有 3 个版本。复用完整项目 import 状态必须处理这些失效，不能仅匹配包名、路径或版本字符串。身份数据 (`../dependency/analysis-final-01/module-identities.csv`, omitted from this source release)、wheel/base 比对 (`../dependency/artifact-verification-final-01/summary.json`, omitted from this source release)、按动作排序的变动 (`../dependency/analysis-final-01/project-identity-changes.json`, omitted from this source release)

这些 SHA 是 **atexit 时读取路径的文件字节**。若命令在 import 后修改文件，不能据此还原真正加载的那版代码；pyc 身份单独保存。新生成的项目文件和与 base 不同的源码也没有被错误判为损坏。

实际 ABI 记录为 `cpython-310-x86_64-linux-gnu` / glibc 2.35；这不是已有 candidate D fork runtime 的兼容性验证。Flask 的全部 10 个观察都驻留 `markupsafe._native`，未观察到 wheel 所带 `_speedups.so` 被映射。源码在 ImportError 后走该 fallback，但本轮没有捕获原 ImportError 原因，标为 UNKNOWN，不能声称已经覆盖该 native 扩展。

36 个观察在采样前后均为 1 线程、3 个有效 FD，未见允许清单环境、Python signal handler 或能力集变化。记录排除了扫描瞬间的临时 FD；该结果不覆盖瞬时线程、原生回调注册和 fork 后行为。

## 独立 fresh Python 导入成本

每个单元格为一个 VM 内 3 个 fresh Python 的首次 import wall 中位数；括号为范围，单位 ms。两块是两个同物理宿主的 VM 重复，不是 6 个独立机器样本。每进程再做两次同解释器 import；重型身份模式另有 10 次，未混入这些 30 次轻量样本。

|任务 / 模块|块 01r1 wall|块 02 wall|两块 CPU 中位数|
|---|---:|---:|---:|
|Flask5014 / flask|675.8（653.9–796.0）|656.2（651.5–694.6）|675.8 / 656.1|
|SymPy19954 / sympy|1162.2（1092.5–2157.0）|1103.0（1088.1–2116.0）|1162.2 / 1103.0|
|SymPy19954 / mpmath|232.2（231.8–234.9）|246.6（240.3–252.7）|232.2 / 246.6|
|SymPy20154 / sympy|1102.5（1088.1–2154.0）|1084.6（1080.6–2345.7）|1102.4 / 1084.6|
|SymPy20154 / mpmath|235.3（231.5–237.3）|240.4（233.2–246.7）|235.3 / 240.4|

较慢的首次进程保留。没有清 page cache；业务树可能形成普通 pyc，因而 fresh Python 不等于严格冷文件缓存。CPU 接近 wall 表明受测导入包含明显 CPU 工作，但未进一步分解编译、对象创建和其他导入步骤。单测 mpmath 已嵌套在 sympy 导入中，不能再相加。完整解释器启动、真实业务和最终收尾不在此 import 区间内。

同解释器再次 import 的各组中位数约 2–3 µs，接近这种微型测量的开销尺度。它只反映 `sys.modules` 命中，不证明原本经过 exec 的不同命令可以无改动复用 heap。逐次 wall/CPU (`../dependency/analysis-final-01/import-samples.csv`, omitted from this source release)、分 VM 分组 (`../dependency/analysis-final-01/timing-summary.json`, omitted from this source release)

## 不能忽略的普通缓存缺口

实际 mpmath 26 个解释器 × 50 模块 = **1300 个有 cached 路径的观察条目，0 个读到 pyc 字节**；缺失错误均为 ENOENT。Werkzeug、Jinja2 同样未读到普通 pyc，而业务树中的 Flask/SymPy 大多数 pyc 存在。安装源码对业务 UID 不可写；父目录是否可写在这些旧观察中没有直接 stat，仍不能仅凭源文件权限推导。

这与 fixture 直接解包 wheel、没有普通安装预编译步骤一致。**缺 pyc 不是重复编译时间的直接证明，更不是生产 Agent 普遍存在同样问题的证据。** 当前 232–247 ms 的 mpmath 导入成本不能全记为只有 Zygote 才能消除的工作。缓存覆盖率与错误 (`../dependency/pyc-audit-final-01/summary.json`, omitted from this source release)

为区分普通缓存与 heap 复用，已按预登记完成最后一个 VM `next-pyc-01`。只对固定 mpmath 1.2.1 使用 CPython 3.10.12 的 CHECKED_HASH 编译，不 import 包；两份 runtime 各仅新增 86 个 pyc（1,653,295 字节），源字节、源码及已有目录权限不变。准备时 package 目录 root:root、0755，新缓存为 0644。单独的非 root `-B -v` 诊断在两无缓存组各记录 50 次 source code 读取，在两缓存组各记录 50 次 `matches` 和 pyc code-object 读取。它证明这四个诊断进程使用了缓存，不冒称所有自然动作均保存了同等 file-open 证据。

|任务|mpmath 首次 import wall：无→有 pyc，ms|SymPy 整体 wall：无→有，ms|原工具累计：无→有，s|
|---|---:|---:|---:|
|19954|230.75→70.32|1116.06→934.40|27.767→26.399|
|20154|232.72→70.34|1128.04→928.48|8.319→7.499|

每个导入单元格是 3 个 fresh Python 的中位数；**只有一个 VM**。mpmath CPU 同方向从约 231–233 ms 降至 70 ms。SymPy 包含 mpmath，差额不能相加；全部慢样本保留。四个原回放共 90 动作，原命令、返回码、轨迹 SHA 和补丁一致，独立定向评分 4/4 PASS，Controller wait/清理回执完整，无观察者补杀。独立 trace 审计确认 144 个业务进程/144 个真实 wait、28 个 Python 进程，PID1/shim 另有 8 次 wait；`/proc` 资源身份采样仅 52/144，不冒称完整内存账本。这不是在线 Agent E2E 或完整故障资格。原始进程审计 (`../analysis/study-process-final-01/next-pyc-01-study-audit.json`, omitted from this source release)

准备没有免费提供：两次纯编译约 0.259 / 0.258 s，辅助进程约 0.692 / 0.788 s，包含复制和额外镜像的完整候选准备为 **7.075 / 5.848 s**，新 pyc 约 1.58 MiB 文件空间，不是 PSS。上述范围有包含关系。本次工具层少 1.369 / 0.820 s，不能在忽略候选准备后宣称单任务完整成本获益，也不能把实验的额外镜像构建误当作生产预编译的必然成本。

这是一个对原成本解释有用的负向约束：**缺少成熟普通缓存的冷启动不能直接作为 heap 复用的全部潜在收益。** 尚余的对象初始化、跨任务安全兼容和净资源成本仍需验证。两任务反顺序、相同配额不能消除全部 page-cache/镜像顺序及原测试随机性，因此不把此次单块差额推广为普遍加速。预登记 (`../experiments/pyc-counterfactual-v1.md`, omitted from this source release)、完整反事实结果与范围 (`../counterfactuals/pyc/results.md`, omitted from this source release)、逐样本和严格资格 (`../counterfactuals/pyc/analysis-01/summary.json`, omitted from this source release)

## 身份诊断本身的影响

同 VM on/off 的工具累计时间差分别为：Flask **+1.167 / +1.178 s**，SymPy19954 **+2.287 / +2.982 s**，SymPy20154 **+1.004 / +1.040 s**。这是原动作路径上可见的诊断成本及运行变化，不能忽略，也不能在仅两个块、有随机测试输出和缓存顺序的情况下全部解释成严格因果开销。详细 SHA、metadata 和退出采集应与低干扰性能批次分开。它们不提供任何 ShimOS 加速成绩。配对边界与数值 (`../dependency/cohort-analysis-final-01/on-off-pairs.csv`, omitted from this source release)

## 解释结果必须保留的限制

- **可变项目状态**：Flask/SymPy源码会被真实动作修改。工作区文件连续不意味着已经import的模块随修改更新；同名包、同路径甚至相同版本字符串都不够。
- **外部固定依赖**：相同实际文件SHA与ABI是兼容候选的必要证据，不证明相同底层inode、物理页共享、可变global状态或回调安全。完整Python导入状态也不是只读wheel的同义词。
- **诊断干扰**：sitecustomize提前导入少量stdlib、改变PYTHONPATH并在退出时散列文件。它不能作为免费诊断；性能比较必须分离。源文件SHA是采样时文件身份，不自动证明执行的字节码完全相同；同时保存pyc身份和采样稳定性。
- **可观察范围**：前后线程数、FD与Python signal handler没有覆盖瞬时线程、所有native handler、native atfork注册或运行中的峰值状态。atexit也可能不运行。没有据此取得fork-safe资格。
- **权限与生命周期**：业务域内导入和具备跨域管理权限的共享Z内导入属于不同信任边界。当前普通fresh CLI、原动作cwd/env、超时及收尾不能因预热而默默换成另一协议。

## 状态复用可以支持到哪一步

只读文件、wheel缓存与pyc能够复用文件准备，但不能自动省掉解释器内对象初始化。持久Worker能够复用对象，却需要明确请求/reset/工作区失效规则；普通脚本经过exec会替换旧映像。forkserver/SOCK式模板需要准入、runtime与权限契约，不能借已有NumPy资格把本轮依赖列为安全。

因此，本轮将把证据分成“安装重叠”“实际导入身份”“重复初始化时间”“安全兼容”“完整净收益”五层。新增模板准入为0；合法 `K_heap`、`K_template`、可删除初始化预算与跨域净内存收益继续保持UNKNOWN，直到有对应验证。成熟机制的比较由本轮其他工作包汇总，本节不自行改变架构或优先级。

## 复现与结果导航

- 只读输入审计 (`../dependency/audit_inputs.py`, omitted from this source release)；静态语法和身份记录 (`../dependency/static-syntax-check.json`, omitted from this source release)。AST通过不是guest运行通过。
- 轻量import探针 (`../dependency/guest_import_probe.py`, omitted from this source release)、有界batch (`../dependency/guest_dependency_batch.py`, omitted from this source release)、真实命令观察器 (`../dependency/hook/sitecustomize.py`, omitted from this source release)。
- 离线分析器 (`../dependency/analyze_diagnostics.py`, omitted from this source release)、原任务与评分关联 (`../dependency/analyze_cohorts.py`, omitted from this source release)、固定成员字节核对 (`../dependency/verify_imported_artifacts.py`, omitted from this source release)、普通缓存覆盖审计 (`../dependency/audit_bytecode_cache.py`, omitted from this source release)。最终分析显式限定两依赖块，后续 pyc 反事实单列；`analysis-partial-*` 保留但不用于替代完整结论。

```sh
python3 research/shimos_next_architecture/dependency/analyze_diagnostics.py \
  --runs research/shimos_next_architecture/runs \
  --run-id next-dependency-01r1 --run-id next-dependency-02 \
  --out /tmp/dependency-reanalysis-NEW
```

输出目录必须不存在。分析脚本只解析记录和 archive 字节，不在宿主执行原命令或导入业务依赖。
