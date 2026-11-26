# 实现、合同与运行入口索引

记录日期：2026-10-20。本文件说明代码已经实现什么、哪些保证属于每次请求、哪些只在会话结束时成立，以及后续应该从哪里运行和验收。**没有性能结论，也不把编译成功、collector 完成或 H 清理成功当成业务资格通过。**

源码链接指本目录当前独立副本，行号用于定位函数。正式运行必须另核对该次 `source-sha.json`、runtime 清单和准入文件；不能因为文件名相同，就把旧版本的资格转给新版本。

## 1. 各组到底比较什么

|组及入口|已经实现的执行方式|每次请求的结束条件|保留到更晚的资源 / 限制|
|---|---|---|---|
|G0：`ARCH_GROUP=G0`|新 Bubblewrap 域；域内可信 C PID1 原子派生到业务 cgroup，启动新 D-Python；最终安全配置和业务许可后初始化 NumPy|PID1 实际 wait Worker/后代，输出 EOF，业务及整个执行域释放|没有外部 Python Z，没有预热 NumPy 内存继承。可信 C 的 pre-exec clone 不是通用 raw-clone Python 路径|
|G1：`NP_BASELINE=cold`|每请求新外部 Python Z，再走 Z→S→W；W 获许可后初始化 NumPy|S wait W、Z wait S、目标 PID1 收养回收、输出 EOF、域释放；随后停止本次 Z|保留完整 glibc D/CPython 派生处理，但不复用 NumPy 预热状态，也不跨请求保留 Z|
|G2，新域模式|长期干净外部 Z 预热固定 NumPy 配方，每请求新 Bubblewrap 域和 Z→S→W|逐请求真实 wait、门禁封闭、输出 EOF、域释放|Z 在整个会话末才退出；预热和最终 Z/H 关闭必须计入会话|
|G2，`FULL_MODE=G2_REUSE`|同一外部 Z 向按 D/K 组织的目标域派生新 W|逐请求 S/W wait；PID1 `QUIESCE→QUIESCENT` 验证收养后代 wait 到 ECHILD；请求 cgroup/输出释放|目标域处理 K 次后才 STOP/DRAINED、monitor wait 和释放。工作区仅清理固定任务的已知产物，不是通用文件系统回滚|
|G3：`FULL_MODE=G3`|每域新解释器在最终降权后形成域内 Z；每请求通过完整 D/CPython fork 原子创建独立业务 W|Z 实际 wait W 及收养后代到 ECHILD；模板检查、请求输出 EOF、业务 cgroup 删除和请求 RETIRE|域内 Z 与 PID1 留到域结束；PID1 最后真实 wait Z。串行 D/K 实验逐域创建/销毁，不是同时保留 D 个 Z|
|G4：`FULL_MODE=G4`|一个域内 Python Worker 通过 FD0 私有协议重复执行固定可信函数|每轮授权、计算、同步已知状态复位、FD/线程/环境/信号检查和该轮输出 EOF|**没有逐请求 Worker 退出、wait 或业务 cgroup 空的保证**。状态为 `RETAINED_WORKER_AND_DOMAIN`；最终域结束才真实 wait。取消、失去结果或复位失败保守销毁域|

G0–G3 的新进程请求与 G4 的可信函数会话是不同状态合同。G4 只能复位本任务已知的数组写入和 NumPy 错误设置，并检查自有状态；不支持任意第三方代码、任意 Python 堆或不同信任主体之间的透明复用。

所有 NumPy 路径均限定为已准入版本、CPU、可信单线程模板、固定配方及声明的资源预算。外部 Z 仍属于可信构造路径；不能把任意 import 代码放进去。业务 W 的 namespace、UID/GID、capabilities、NNP/seccomp、管理 FD 排除和授权要求没有因性能组而取消。完整合同见 architecture-contracts.md (`architecture-contracts.md`, omitted from this source release)。

## 2. 组件与实际调用位置

### 共同底座

|组件|实际职责与源码入口|
|---|---|
|fixture / 分组派发|[run.py `main()`](../prototype/run.py#L438) 构建/核验运行环境、独立数值参考、启动 H；[execute](../prototype/run.py#L493) 选择 G0、G2_REUSE、G3/G4、并发或 mixed Controller。独立参考和构建位于产品主区间之外，必须另列|
|Supervisor H|[supervisor.py `run_supervised()`](../prototype/supervisor.py#L50)：REGISTER/RETIRE、R 失效接管、真实 wait、cgroup 终止与清理。此 NumPy H 的受限保证以 H 正常存活为前提，不自动继承 Tool followup 的额外恢复资格|
|Controller R|[run.py `Controller.bwrap()`](../prototype/run.py#L48)、[`rpc_supervisor()`](../prototype/run.py#L67)、[`reap()`](../prototype/run.py#L74)：建域配置、H 登记、实际子进程 wait；不能把 pidfd 就绪替代 wait|
|D/CPython 派生|[bridge_d.c `py_fork_cgroup()`](../prototype/bridge_d.c#L20)：CPython before hooks → glibc D `shimos_fork_into_cgroup` → native wrapper/clone3 → Python parent/child hooks。没有 stock-libc fallback，也没有跳过必要 fork callbacks|
|进入目标及降权|[bridge_d.c `enter_target()`](../prototype/bridge_d.c#L55) 依序进入 base user、mount/net/ipc/uts/PID-for-children、root/cwd、inner user；[`drop_final()`](../prototype/bridge_d.c#L71) 清 capabilities、设置 NNP 和原策略；[`forbid_exec()`](../prototype/bridge_d.c#L91) 保留 NumPy 路径的业务 no-exec 限制|
|跨域 Z / S / W|[zygote.py `transition()`](../prototype/zygote.py#L114)、[`commit()`](../prototype/zygote.py#L251)：逐请求身份、两次派生、启动与业务门禁、取消 seal、真实 wait、FORGET 状态回执。模板加载由[模块入口](../prototype/zygote.py#L12) 的 hot/cold 配置决定|
|固定业务与复位|[numpy_workload.py `initialize()`](../prototype/numpy_workload.py#L224)、[`execute()`](../prototype/numpy_workload.py#L388)、[`reset_persistent()`](../prototype/numpy_workload.py#L477)。profile 绑定、数值结果、状态指纹和复位都属于实际请求路径，不应从计时中免费删去|
|测量及资源采样|[cost.py](../prototype/cost.py)、[resource_sampler.py `sample()`](../prototype/resource_sampler.py#L39)。采样器不接管产品补杀；根 memcg CPU 是层级计数，不再与子组相加；PSS 和 memcg 记账分别报告|

### 组别差异的实现位置

- **G0：** [run_g0.py `domain()`](../prototype/run_g0.py#L28) 管理目标域与授权；[domain_init_g0.c `start_worker()`](../prototype/domain_init_g0.c#L85) 在业务 cgroup 原子创建可信 bootstrap；[g0_worker.py `run()`](../prototype/g0_worker.py#L32) 安装最终安全约束、上报门禁，再进入 [`business()`](../prototype/g0_worker.py#L70)。Python bootstrap 的 exec 在可信启动阶段；业务阶段仍禁止 exec。
- **G2 留域：** [run_cross_reuse.py `open_domain()`](../prototype/run_cross_reuse.py#L44)、[`domain()`](../prototype/run_cross_reuse.py#L114) 分开外层域与请求生命周期；[`request_quiesce()`](../prototype/run_cross_reuse.py#L61) 与 [domain_init.c 的 QUIESCE 分支](../prototype/domain_init.c#L82) 实际核对 PID1 后代回收；[`close_domain()`](../prototype/run_cross_reuse.py#L67) 完成最终退出。
- **G3：** [run_local.py `create_domain()`](../prototype/run_local.py#L55) 启动域内运行时并核验 namespace、权限及 DSO；[`request_g3()`](../prototype/run_local.py#L115) 负责逐请求资源与许可；[local_zygote.py `g3()`](../prototype/local_zygote.py#L123) 管理单活跃请求、真实 wait/ECHILD 和模板快照；[`child()`](../prototype/local_zygote.py#L104) 到达 W 业务门禁。
- **G4：** [g4_controller_methods.py `request_g4()`](../prototype/g4_controller_methods.py#L14) 明确记录请求完成与 Worker 仍存活；[local_zygote.py `g4()`](../prototype/local_zygote.py#L217) 同步复位、检查并应答。FD0 是这份可信函数合同的请求通道，不声称与任意业务代码的无控制通道合同相同。
- **G3/G4 最终回收：** [run_local.py `close_domain()`](../prototype/run_local.py#L257) 等待 Z/Worker、PID1 DRAINED、monitor wait、EOF 和资源删除；[domain_init_local.c `reap_ready()`](../prototype/domain_init_local.c#L43) 是真实父进程 wait。域异常时最终 H 回收不等于丢失的业务结果已经恢复。

## 3. 已写出的扩展，不替它们预先授予资格

|扩展|源码与实际范围|仍须独立运行确认的部分|
|---|---|---|
|G2 并发|[run_concurrent.py `Controller.run()`](../prototype/run_concurrent.py#L456) 与 [concurrent_router.py `Router`](../prototype/concurrent_router.py#L56)：单线程 R 的合作式多请求，按 nonce 转发 FD/回执，单外部 Z 派生，多目标域执行|新并发错误交错、late message、预算拒绝及回收资格；不能直接套串行 PASS|
|G3 并发|[run_local_concurrent.py `Lane`](../prototype/run_local_concurrent.py#L20)、[`Controller.run()`](../prototype/run_local_concurrent.py#L253)：多个独立域，每域自己的 Z，每请求独立业务组|多域同时活动的真实 wait、身份绑定、总预算和故障隔离；不同于串行逐域 K 次|
|mixed profile|[run_mixed.py `Controller.plan()`](../prototype/run_mixed.py#L83)、[`run()`](../prototype/run_mixed.py#L101)：固定 schedule 的单模板槽，按已声明 profile 切换|集中/交替/偏斜顺序与内存预算下的结果。没有实现预测调度器、通用依赖兼容推断或自动最佳模板选择|
|T2 工具路径|见下一节；静态 C gate 直接执行原固定 launcher/工具，保留强 H/私有 exec 回执/双输出合同|本索引核查时仅完成静态源码及编译检查；必须经过真实 VM 资格，才可进入 T1/T2 性能对照|

本轮正式执行按 density、persistent、profile，再到 concurrency/mixed、Tool 的顺序推进。**本表只记录待验证范围，不替代每个运行的最终状态。**

## 4. Tool T1 / T2 是另一份完整合同

T1 沿用 `exec_support_followup` 的外部 Z→S→W；W 获授权后原位 exec 静态 launcher 及工具，Python 映像被替换，不额外创建一个独立 T。T2 是 Bubblewrap → 静态 C PID1 → `native_gate` → 原 `tool_launcher` → 固定工具。T2 不复用 Python 初始化内存，不能拿它替代 NumPy 的状态继承组。

关键入口：

- run_native.py `Controller.domain()` (`../06_tool_exec_native/prototype/run_native.py#L21`, omitted from this source release)：REGISTER、SCM_CREDENTIALS/业务 cgroup 绑定、先 seal 再 kill、结果与资源状态分离、两个输出 EOF、RETIRE。
- domain_init_native.c `start_worker()` (`../06_tool_exec_native/prototype/domain_init_native.c#L87`, omitted from this source release) 与 `reap_ready()` (`../06_tool_exec_native/prototype/domain_init_native.c#L45`, omitted from this source release)：原子 cgroup 出生、PID1 真实 wait 主进程及收养后代，CANCEL 封闭创建，STOP 要求 ECHILD。
- native_gate.c `gate_drop()` (`../06_tool_exec_native/prototype/native_gate.c#L41`, omitted from this source release)、`native_gate()` (`../06_tool_exec_native/prototype/native_gate.c#L73`, omitted from this source release)：最终权限/原 tool seccomp 在业务许可前完成；FD3 是 gate，FD4 是私有回执；授权后 FD3 关闭，目标不继承管理 FD。
- tool_launcher.c `main()` (`../06_tool_exec_native/prototype/tool_launcher.c#L119`, omitted from this source release) 与 exec_receipt.py `decode_receipts()` (`../06_tool_exec_native/prototype/exec_receipt.py#L72`, omitted from this source release)：原 followup 输入原样保留。私有回执 EOF、ATTEMPT 或退出 0 都不等于观察到 exec 成功；无法恢复的结果保留 UNKNOWN。

工具组使用 **exec_support_followup 的强 H**，与 NumPy 主研究 H 不同；双输出恢复、写入失败、截断和 INCOMPLETE 语义也必须保留。两组工具 argv、stock rootfs、权限、资源限额和回执一致；T1 使用 D-Python 构造执行链，T2 目标使用 stock rootfs。共同准备 D bundle 是 fixture，不是 T2 的运行内存。详见 T2 合同 (`../06_tool_exec_native/docs/t2-native-contract.md`, omitted from this source release) 和 配对测量边界 (`../06_tool_exec_native/docs/paired-measurement-boundary.md`, omitted from this source release)。

2026-10-20 后续验证：上表保留初次静态审查时的待验范围。并发、混合模板已分别完成实际资格与正式运行，见[并发结果](../04_concurrency/results-v6.md)、[混合模板结果](../05_mixed_templates/results-v3.md)。Tool 同版 14 VM / 108 次尝试已完成独立资格二审 (`../06_tool_exec_native/docs/tool-qualification-independent-review.md`, omitted from this source release)，原产品和检查器失败仍保留；正式性能须再核验当次样本，不能仅凭该表视为完成。

## 5. 历史来源和当前资格证据

|来源|本轮实际继承什么|
|---|---|
|[A+B 集成](../../integration_ab/integration-report.md)、[架构组件成本](../../architecture_cost/architecture-component-cost.md)|Supervisor H、attempt/许可/真实 wait、D glibc 与 CPython fork hooks，以及测量边界；本轮没有修改历史版本|
|[NumPy 准入](../../numpy_admission/numpy-admission-report.md)|固定 wheel/DSO/CPU 配方、可信模板、数值及 fork 运行时限制；不是所有 NumPy/PyTorch 依赖的通用 fork-safe 保证|
|[round1](../../architecture_comparison_round1/round1-final-report.md)|G0/G1/G2 已有独立执行路径、固定 VM 与 runtime 来源；新 G2 留域、G3/G4 不凭历史目录自动通过|
|exec 回执 (`../../exec_support_followup/exec-receipt-report.md`, omitted from this source release)、H 恢复 (`../../exec_support_followup/supervisor-recovery-report.md`, omitted from this source release)|T1 工具底座与 T2 要保持的强输出/恢复合同；来源 SHA 见 followup-source-inputs.json (`../06_tool_exec_native/frozen/followup-source-inputs.json`, omitted from this source release)，原样组件核查见 native-source-review.json (`../06_tool_exec_native/frozen/native-source-review.json`, omitted from this source release)|

本轮已存在的机器可读资格入口：

- 串行生命周期汇总 (`../analysis/qualification-sequential-final-02/summary.json`, omitted from this source release)：限定的旧执行闭包资格。
- profile 边界/数值汇总 (`../analysis/qualification-profile-final-01/summary.json`, omitted from this source release)：对应版本的实际 profile 验证。
- observer-v2 边界资格 (`../analysis/qualification-observer-v2-final-02/summary.json`, omitted from this source release) 与 独立采样覆盖检查 (`../analysis/qualification-observer-v2-01-observation.json`, omitted from this source release)：补足 local-template 观测。
- 正式串行性能所用快照是 frozen/sequential-v2 (`../frozen/sequential-v2/`, omitted from this source release)，准入分别见 density (`../docs/sequential-performance-review-v2.json`, omitted from this source release)、persistent (`../docs/persistent-performance-review-v2.json`, omitted from this source release)、profile (`../docs/profile-performance-review-v2.json`, omitted from this source release)。这些准入明确说明**旧执行逻辑资格加新的只读观察验证**，不是声称全部旧故障在每个新 SHA 上重跑。
- 初始输入清单见 copied-inputs.json (`../frozen/copied-inputs.json`, omitted from this source release)，D runtime 见 candidate-04-runtime-sha.json (`../frozen/candidate-04-runtime-sha.json`, omitted from this source release)。并发、mixed 和 T2 的资格仍应看各自新增证据，不借用上述串行汇总。

## 6. Tool 资格 CLI 静态核查及最短执行清单

以下是给统一 VM 执行者的命令，**本次没有执行**。从项目根目录运行；每个编号必须不存在。入口 runner/vm.py (`../06_tool_exec_native/runner/vm.py#L6`, omitted from this source release) 使用全研究统一排他 VM 锁，核验固定 kernel/initramfs 和 candidate-04 清单，4 vCPU / 4096 MiB。

### 必须注意的 CLI 差异

1. **T2 按 `--tool-suite` 选用例。** run_native.Controller.run (`../06_tool_exec_native/prototype/run_native.py#L244`, omitted from this source release) 不读取通用 `RELIABILITY_CASE`。因此 `--case double_cancel` 虽被 argparse 接受，不能算 T2 运行了重复取消；不传 `--tool-suite` 实际只运行默认的 `followup_regression`。本索引不据此虚报 T2 具备全部 A+B 故障资格。
2. `--profile` 只是 runner 的登记元数据，不选择实际工具，也不自动运行独立验收器。`--protocol-case` 则进入独立 H 协议夹具，**绕过 T1/T2 Controller**，不能拿其成功证明 T2 gate 已执行。
3. `tool_cases.py` (`../06_tool_exec_native/prototype/tool_cases.py`, omitted from this source release) 共有 57 个固定 case；`all` 只有 35 个，含静态/动态 ELF、Shell、gcc、unittest、后代/取消/超时/结果丢失和预算。`receipt` 另有 12 个；`output_boundary` 3 个，其中 stdout 伪造与 `all` 重复。两个 Controller 死亡和六个 H 恢复 case 都需单独运行。宿主静态枚举没有执行工具或导入 NumPy。
4. `recovery_flood`/`recovery_flood_prefix` 需要 `--big-pipes` 的私有 VM 夹具；不能省去后把业务堵在管道上误判为 H 恢复通过。输出写入 ENOSPC/EIO 是额外故障注入，不是 `all` 已覆盖的内容。

首个可运行小试仅四例：正常、门禁前取消、stdout 伪造和 Shell 取消。

```bash
python3 research/shimos_worker_pool/architecture_comparison_full/06_tool_exec_native/runner/vm.py pilot-t2-regression-01 --arch T2 --tool-suite followup_regression --variant low --timing 1 --trace 1
```

首轮资格的简短核心清单为下列 7 个独立 VM 会话，名义 54 次尝试、53 个不同 case；这是计划覆盖数，若中途失败，实际执行数必须从记录重新核对。它仍未覆盖后表四种特殊恢复夹具。

```bash
tool_vm=research/shimos_worker_pool/architecture_comparison_full/06_tool_exec_native/runner/vm.py
for suite in all receipt output_boundary tool_controller_death receipt_controller_death recovery_hostile; do
  python3 "$tool_vm" "qual-t2-${suite}-01" --arch T2 --tool-suite "$suite" --variant low --timing 1 --trace 1 || exit 1
done
python3 "$tool_vm" qual-t2-recovery_flood-01 --arch T2 --tool-suite recovery_flood --big-pipes --variant low --timing 1 --trace 1
```

这段命令应作为脚本执行，任一非零退出就停止；执行者先检查失败和实际产品残留，再决定后续动作，不能用后面的成功补齐前面的失败。runner 退出 0 仍不是独立资格 PASS。每个 VM 有独立编号和完整原始输出。

|补充项目|实际入口 / 期望核查|
|---|---|
|R 已读走一段输出后死亡|`--tool-suite recovery_flood_prefix --big-pipes`；明确 H 只能恢复仍可见部分，不能虚构已丢失前缀|
|结果文件 / 目录不可读|分别 `--tool-suite recovery_unreadable_file`、`recovery_unreadable_dir`；保留读取错误和实际恢复范围|
|工作区无法删除|`--tool-suite recovery_undeletable`；资源事实不完整必须为 INCOMPLETE，外部 observer 不补清理成成功|
|H 输出持久化失败|`--tool-suite recovery_flood --big-pipes --h-write-fault ENOSPC --h-after-bytes 4096`；EIO 用同入口替换故障名；保留真实写入失败、输出/资源分离状态|
|T2 特有创建回执丢失、重复 CANCEL 等|现有目录未提供每个专项注入入口；不能以通用 `--case` 代替。若要求该覆盖，先增加独立资格适配、冻结版本，再运行；本索引不擅自修改候选|

T1 对照把 `--arch` 改为 T1 并使用新编号。历史 T1 证据可用于源码继承说明，但真正进入新同 VM 配对前，仍需独立审核当前精确 SHA 和所选五类工具。

### 正式性能入口的准入条件

paired_vm.py (`../06_tool_exec_native/runner/paired_vm.py#L110`, omitted from this source release) 默认五类：`elf_static,elf_dynamic,shell_pipeline,gcc_success,unittest_pass`，同一 VM 内各建 T1/T2 独立会话；默认每类每组 3 次。正式调用必须提供独立审核生成的 `--admission` JSON，包含 `status=PASS`、完全一致的 `source_sha256`、非空证据、受准入 case 和 T1/T2 两组。**现在不能为了让 runner 接受而创建占位 PASS。**

```bash
python3 research/shimos_worker_pool/architecture_comparison_full/06_tool_exec_native/runner/paired_vm.py tool-paired-block-1 --order T1,T2 --repeats 3 --timing 1 --trace 0 --admission /absolute/path/to/verified-tool-admission.json
```

三个独立 VM 块应预先轮换顺序，编号分别唯一。每组主区间从 H fork 前到 H 被真实 wait；预热、建域、授权、业务、wait 和清理均在内。fixture 安装/编译及末尾 100 ms observer 检查另列；不同 H 合同的 NumPy 与工具不能混排。

逐项验收至少要有 nonce/SCM 身份与原子业务 cgroup 出生、最终权限、PID1 实际 wait 与 host/local PID 对应、双输出 EOF、私有 SXRC 解码、取消 seal、DRAINED、monitor wait、目录/cgroup/FD 回收、H 最终状态。UNKNOWN/INCOMPLETE 是真实失败语义，不得改成成功；事实提取器 extract_tool_facts.py (`../06_tool_exec_native/runner/extract_tool_facts.py`, omitted from this source release) 只整理证据，本身不授予 PASS。
