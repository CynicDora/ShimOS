# A+B 集成原型：架构复杂度与精简候选

日期：2026-10-19。本文依据**已完成的 A+B 同一路径集成资格**分析架构复杂度。最终批次共 8 个私有 VM 会话、29 个执行尝试，29 PASS / 0 FAIL / 0 BLOCKED：其中前 7 会话复核 A 的 20 类场景、26 次尝试，第 8 会话额外执行 3 次实际跨域 robust 组合测试。所有 VM 位于同一物理宿主，不能视为独立硬件验证。详细实现、失败记录和适用范围见 [integration-report.md](integration-report.md)；逐项证据见 [正式矩阵](analysis/qualification-ab-02-matrix.md)。

本文只做源码与证据分析，没有实施任何精简，也没有性能测量。限定资格通过不等于生产保证、第三方依赖准入或完整 glibc 兼容认证。

本文区分三种内容：**事实**来自源码或原始证据；**分析**说明职责和代价；**候选**需要另做原型及资格验证。成本统计是代码、消息和产物数量，不是性能收益。

## 1. 先保留职责，再判断能否减少进程

当前路径如下。根权限 VM 夹具只准备环境和观察，不承担产品故障补杀。

```text
Supervisor H
└─ Controller R
   ├─ Bubblewrap monitor
   │  └─ 目标 PID1
   └─ Zygote Z
      └─ Transition S
         └─ Worker W → 业务后代
```

| 组件 | 当前存在的原因和真实职责 | 删除或合并会失去什么 | 是否必须保持这个具体进程 |
|---|---|---|---|
| H | R 的真实父进程及 subreaper；R 死后停止创建者、接管孤儿 wait、确认输出 EOF、删除私有目录和 cgroup，留下 UNKNOWN/INCOMPLETE 收据 | R SIGKILL 后没有独立清理责任者；旧故障会重现 | 独立于 R 故障域的责任不能删除；具体实现可由宿主监督机制承担，但尚未验证替代 |
| R | 建域和校验对象身份；绑定 attempt；发出许可；关联退出和业务结果；正常清理、验收、回复 | 不再有请求身份、安全许可与结果验收的协调点 | 可以精简内部状态与消息；直接并入 H 会消除 H 对 R 失效的独立性 |
| Bubblewrap monitor | 现成 Bubblewrap 启动、父死和目标进程退出路径的一部分；R 等待其真正退出 | 不可只删除 monitor 而沿用原 Bubblewrap 故障合同 | 本轮不改 Bubblewrap，不提出未经验证的替换 |
| 目标 PID1 | 由 Bubblewrap 先创建；导出自身 namespace/root 引用；回收域内孤儿；STOP 时 wait 到 ECHILD 后报告 DRAINED | 已有 PID namespace 没有活的 init 时无法接纳后来 Worker；域内孤儿回收与域寿命失去责任者 | 这个 namespace 必须有 PID1；本例的导出/收尾代码可以调整，但职责不能省略 |
| Z | 长期保留干净 Python 内存；串行接纳/撤销请求；真实 wait S；缓存 S 创建、回收事实 | 丧失预热状态与稳定派生来源，或无处查询丢失的回执 | 保留模板是本研究前提；不应把完整 Controller 塞进含依赖 callbacks 的 Z |
| S | 单独承担不可逆 namespace/root/降权切换；第二次派生 W；真正 wait W 并报告状态 | Z 必须自己改变环境，或重做目标接纳与 wait 关系 | 在“Z 保持原环境、Bubblewrap 先建域”的当前路线中有明确作用；不能外推为所有未来架构都必须有 S |
| W | 在目标域执行业务；继承模板内存；最终策略和 FD 清理后等业务许可 | 无执行实体；若直接让 S 执行业务，S 的活动 PID namespace 仍不对 | 在当前 Linux 路线中不能直接以 S 替代 |

集成源码依据：[run.py](prototype/run.py#L33)、[supervisor.py](prototype/supervisor.py#L47)、[zygote.py](prototype/zygote.py#L81)、[domain_init.c](prototype/domain_init.c#L17)。A 原 trace 与集成 pilot 均确认相同父子结构：原 A trace (`../reliability_fix/runs/qualification-01-control/process-trace.txt`, omitted from this source release)、集成正式 trace (`runs/qualification-ab-02-control/process-trace.txt`, omitted from this source release)。H/R 继续使用 stock guest libc；只有 Z/S/W 及其后代使用 candidate D，这没有增加常驻角色。

**进程数量事实：**不计 VM root 夹具和基础服务，会话间保留 H、R、Z 共 3 个进程；每个活动请求另有 monitor、PID1、S、W 共 4 个，合计 7 个角色进程。A 的正常业务额外 fork 一个测试后代，所以该例瞬间可达 8 个。不是每个请求都有 7 个新进程，也不是 7 个进程全都长期空闲。集成新增探针若再派生辅助子进程，应单独记入诊断进程，不混入基础角色数。

### 1.1 S 的作用不能只用“第二次 fork”概括

冻结 Linux `pidns_install()` 改的是 `pid_ns_for_children`；不迁移调用者的活动 PID namespace。权限和祖先关系检查仍然存在。见 Linux 6.18.49 对应 commit `1c732c6b94f0faee1526bd375add2fe10cba2e26` 的 pid_namespace.c:401–424 (`../../process-lifecycle-discovery-20261015/linux/sources/linux-pid_namespace.c#L401`, omitted from this source release)，以及实际构建来源中的 fork.c:2202 (`../fork_runtime_compat/sources/runtime-source/kernel/fork.c#L2202`, omitted from this source release)。

S 还承担进入后代 user namespace、切换 root/cwd、丢弃权限等动作。这些不能在长期 Z 中执行完后随意恢复。因此，不能凭 `setns` 名称就删除 S。让 Z 仅改变未来孩子的 PID namespace，再由孩子完成其他切换，属于另一条需要重新证明权限、并发和生命周期的路径，本轮未实现，也不据此宣布不可行。允许新进程出生时显式指定目标 PID namespace 的内核接口仍是研究设想，不是本轮已有替代。

S 可以在 W 创建后提早退出吗？这可能缩短 S 存活时间，但不省去创建本身，而且会改变 W 的收养和真实 wait 责任，要求 PID1/R 新增结果协议。现有准确业务退出结果来自 S 的 wait，不能只看到 pidfd 可读就移除此责任。

### 1.2 H 能否交给已有宿主监督机制

已有冻结 systemd v257、commit `70bae7648f2c18010187c9cf20093155eaa26029` 文档支持：`KillMode=control-group` 在 unit 停止时终止剩余成员；scope 的寿命按成员存在，而非单一主进程；scope 不负责把每个业务退出码汇总成结果，实际父进程仍需 collect。见 scope:49 (`../../process-lifecycle-discovery-20261015/linux/sources/systemd-scope.xml#L49`, omitted from this source release)、kill:63 (`../../process-lifecycle-discovery-20261015/linux/sources/systemd-kill.xml#L63`, omitted from this source release)、service 的 ExitType (`../../process-lifecycle-discovery-20261015/linux/sources/systemd-service.xml#L305`, omitted from this source release)。

因此，稳定的宿主 service 可以承接“R 死亡后仍有人停止整组进程”的一部分职责。它**不会自动**恢复已被 S/Z 消耗的 wait 状态，不会自动知道本次工作目录、读取输出 EOF、保存副作用证据或生成逐请求 UNKNOWN。`ExitType=cgroup` 也不意味着主进程死亡立即关闭还活着的 Z；需明确整个 unit 的失败/停止策略。不能把 `systemd-run --scope --wait` 当成基线：冻结 run 文档:461 (`../../process-lifecycle-discovery-20261015/linux/sources/systemd-run.xml#L461`, omitted from this source release) 明确两选项不兼容。

合格替代方案必须重新证明：稳定责任者能停止创建者、杀掉全部私有域、合法回收实际收养的进程、取得必要 EOF/删除证据，并在业务结果丢失时保留 UNKNOWN。进程已 kill、cgroup 空、manager 返回 ACK 都不单独等价于业务成功。

## 2. 正常请求到底经过多少消息

以下统计以**健康 Z、无 QUERY 超时、没有重复消息的一次正常请求**为准。已经将 A 与本轮集成源码逐项对照，并检查正式 `qualification-ab-02-control/0-normal.json`：9 种收到的逐请求事件与 A 一致，无 SNAPSHOT/QUERY；正常控制协议未新增消息。它是源码和原始记录交叉核查，不是新增延迟测量。stdout 业务数据与日志不计作控制包；会话启动/结束另列；继承 FD 和系统调用也不是额外 IPC 包。

| 顺序/阶段 | 消息 | 包数 | 为什么存在、是否在关键路径 |
|---|---|---:|---|
| 目标域就绪 | PID1 → R：DOMAIN_READY + 7 FD | 1 | 绑定真实目标对象；启动前必须取得 |
| 外部清理责任登记 | R → H：REGISTER；H → R：REGISTERED | 2 | 在 Z 派生前确认有人持有输出读端和资源身份；阻塞 RPC |
| 派生准备 | R → Z：SPAWN；Z → R：PREPARED | 2 | Z 持有配置但尚不派生；事件驱动许可屏障 |
| 创建 S | R → Z：COMMIT；Z → R：TRANSITION_CREATED | 2 | 只允许一次派生；CREATED 与 S 的通知可乱序，不是独立必等 RPC |
| S 进入目标 | S → R：TRANSITION_BORN、ENTERED | 2 | 身份/故障诊断及进入完成；R 等 ENTERED 再发下一许可 |
| 创建 W | R → S：START_WORKER；S → R：WORKER_GATED | 2 | W 已完成最终限制并停在业务门前；事件驱动许可屏障 |
| 放行业务 | R → S：RUN_BUSINESS；S → R：BUSINESS_RELEASED | 2 | 先记录可能发生业务，再放行；RELEASED 是观察，不是最终结果 |
| 真实退出 | S → R：WORKER_WAITED；Z → R：TRANSITION_REAPED | 2 | 两个不同父子层级的真实 wait，不可互相代替 |
| 关闭未来创建许可 | R → Z：CANCEL(reason=COMPLETE)；Z → R：CANCEL_ACK | 2 | 正常完成也显式 seal；进入域收尾前要求确认 |
| 目标域收尾 | R → PID1：STOP；PID1 → R：DRAINED | 2 | 不只等 W；目标 PID1 确认其孩子已回收 |
| 释放 Z 请求对象 | R → Z：FORGET；Z → R：FORGOTTEN | 2 | 只在 SEALED 且 S ABSENT/REAPED 时删除 FD/对象；阻塞等待 |
| 模板不变性诊断 | R → Z：PING；Z → R：PONG | 2 | 当前资格中检查模板内存和 FD；阻塞诊断 RPC |
| 外部责任退休 | R → H：RETIRE；H → R：RETIRED | 2 | R 已清理并完成验证之后，H 才释放副本；阻塞 RPC |
| **合计** | **跨角色控制消息** | **25** | **不是 12.5 次串行 RTT，也不是已测延迟** |

此外 S/W 之间有两个私有 pipe token：W 向 S 报告就绪，S 向 W 发业务许可；总计 27 次逻辑控制发送。W 输出的 WORKER_READY 和后代日志另属数据通道。QUERY/SNAPSHOT 每触发一次再加 2 包；普通取消、重复取消和故障回收不适用此固定数。

源码中显式阻塞请求/应答有 **4 组**：REGISTER、FORGET、PING、RETIRE；其他许可和结束条件主要在事件循环中推进，仍然可能产生等待，不能因为不调用同步函数就认为没有同步成本。上述 4 组也不等于整个关键路径只有 4 个屏障。

会话额外消息为 ZYGOTE_READY 1 包、STOP/ZYGOTE_STOP 2 包、DONE/DONE_ACK 2 包，共 5 包。正常终结 `DONE_ACK` 只是收件确认；最终 `supervisor.json` 的资源确认才是会话收尾证据。

集成源码位置：[run.py:122–131](prototype/run.py#L122)、[228–282](prototype/run.py#L228)、[300–349](prototype/run.py#L300)；[zygote.py:81–187](prototype/zygote.py#L81)、[256–325](prototype/zygote.py#L256)。本轮已核的正常例：正式正常请求 0-normal.json (`runs/qualification-ab-02-control/0-normal.json`, omitted from this source release)。运行时探针增加日志和既有消息载荷，不另建 Worker Manager 或控制通道。

### 2.1 哪些协议语义不能靠删消息消除

- 取消必须关闭未来创建许可，不能只 kill 当前 cgroup；已经发出的许可也不能假装被撤回。
- 业务放行前要建立可追踪的 attempt 和清理责任，并记录“可能执行”；丢回执时允许 UNKNOWN。
- S/W 的实际创建与 wait 是不同事实；不能重新用单个 `transition_reaped` 表示。
- 退出结果、输出 EOF、域空、FD/目录释放分别证明不同事情；消息可以合并，事实不能合并为一个模糊成功位。
- FINALIZE/合并回执即使未来实现，也必须包含 nonce，不能靠裸 PID 关联历史事件。

ENTERED/START_WORKER 这道门理论上值得单独研究，但删掉后 W 可以在 R 看到 ENTERED 前已创建，现有 `cancel_during_entry` 的“W 尚未创建”测试合同就会变化。即使 W 最终仍停在业务门前，也不能称为原合同无变化。SPAWN/PREPARED/COMMIT 同理：它给“Z 已收请求、尚未派生时取消”一个可控制和可验证的边界。本轮不直接删除这两道门。

## 3. 状态复杂度来自哪些事实

R 不是单一线性状态机，至少记录 5 个状态轴：

| 状态轴 | 实际枚举数及内容 | 精简边界 |
|---|---|---|
| admission | 6：OPEN、COMMITTED、REVOKING、CREATOR_STOPPING、SEALED、SEALED_CREATOR_WAITED | Z 的授权事实与 R 的撤销进度不能混为一件事 |
| S | 5：ABSENT、POSSIBLE、CREATED、REAPED、RECLAIMED_STATUS_UNKNOWN | 创建回执和 wait 回执可分别丢失 |
| W | 5：ABSENT、POSSIBLE、CREATED_GATED、REAPED、RECLAIMED_STATUS_UNKNOWN | “存在但未执行业务”必须可表示 |
| 业务结果 | 3：NOT_EXECUTED、UNKNOWN、KNOWN | KNOWN 还需真实退出码；不能以资源已清理推断业务成功 |
| 资源 | 3：PENDING、RELEASED、INCOMPLETE | 不可被业务结果轴替代 |

这些不是 22 个全局线性状态，也不能把全部笛卡尔积当成可达状态。进程 PID/pidfd、wait 状态、EOF、DRAINED、fd 集合等是附加证据，部分布尔值是过程缓存。可读性最值得改善的是把“权威事实、待完成动作、诊断镜像”分开，而不是仅减少字段数。

重复记录确实存在：Z 保存 admission/S 创建和 wait；R 保存这些事实的投影以及业务/资源结论；H 保存资源身份、输出 FD 和最终退休结果。它们跨故障边界承担不同恢复责任，不是全部冗余。可以统一消息 schema、减少同一事件反复序列化，但不应把三个进程的状态硬合成一个单点内存字典。

`used` attempt tombstone、R rows、H attempts 当前会随会话增长；串行短会话通过不证明长期上界。收敛为有界历史需要同时定义迟到消息、跨重启身份和审计保存规则，不在本轮直接重写。

## 4. 可量化的源码与运行时维护面

### 4.1 实际集成源码规模

按物理行统计，包含空行/注释，另列非空行。Python 多条语句压在一行，因此这些数字不是逻辑复杂度，也不是成熟产品代码规模。下表为本轮实际 `prototype/`，A 原同范围合计为 1,385 行。

| 集成文件 | 物理行 | 非空行 | 说明 |
|---|---:|---:|---|
| run.py | 416 | 413 | Controller、运行时接入、故障钩子、验收及 root 夹具；A 为 407 行 |
| supervisor.py | 453 | 426 | 产品 H；与 A 逐字一致 |
| zygote.py | 337 | 319 | Z/S/W、业务探针和故障钩子；A 为 321 行 |
| common.py | 44 | 44 | IPC、FD、身份及 bridge 入口 |
| bridge.c | 67 | 65 | 保留 stock H/R 所用安全/监督辅助代码；其 raw fork 入口不是集成 Z/S/W 的派生入口 |
| bridge_d.c | 70 | 68 | B 原文件逐字接入，用于 Z/S/W 的完整 wrapper 派生 |
| domain_init.c | 47 | 46 | 可信 PID1 |
| native.c | 27 | 27 | 冷启动后立即 exec 的宿主 launcher；不执行 warm Python 业务 |
| policy.h | 19 | 19 | 原安全策略 |
| runtime_support.py | 71 | 68 | 候选 DSO/hash、只读覆盖、实际 maps 核验及缺 API 拒绝探针 |
| install_runtime.py | 10 | 10 | 私有 guest 的 bundle 安装入口 |
| **上述合计** | **1,561** | **1,505** | **包含研究夹具，较 A 多 176 行；不是纯生产核心** |

额外可信运行时诊断代码为 `runtime_probe.c` 169 行、`runtime_probe.py` 126 行，共 **295 行**。两者注册自有 callbacks、采集 TID/robust/capability 事实，不提供业务 fallback。独立验收/运行代码为 verify.py 599 行、verify_runtime.py 324 行、vm.py 52 行、qualify.py 18 行、observation.py 35 行，共 **1,028 行**。旧 analyze.py 63 行仍未用于正式资格。

逐文件源码行数与 SHA、消息口径、bundle 数量记录在 architecture-statistics.json (`analysis/architecture-statistics.json`, omitted from this source release)。8 个正式会话源码及二进制 SHA 完全一致，当前 prototype 与冻结运行匹配，见 [正式汇总](analysis/qualification-ab-02-summary.json)。

集成构建的本地辅助 ELF 为 `bridge.so`、`bridge_d.so`、`native.so`、`domain_init` 和诊断 `libab_probe.so`，另加载候选 runtime 家族。不能将研究诊断代码、探针日志与真实产品常驻资源混算。

### 4.2 B 的补丁很小，维护责任不小

候选 D 的 glibc patch 改动 3 个文件：`posix/fork.c`、`sysdeps/nptl/_Fork.c`、`posix/Versions`，**增加 59 行、删除 6 行**；统一 diff 共 116 行。bridge_d.c 为 70 行。实际集成仍保留 A 的 bridge.so 给 stock H/R 使用，另构建 bridge_d.so 给 Z/S/W；因此不是用 70 行简单替换 67 行、也不是只增加三行成本。

完整 wrapper 仍负责 native atfork、libc 锁、loader/TLS 状态、NPTL TID 与 robust list；新入口仅选择 clone3，并保留 `CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | CLONE_INTO_CGROUP | CLONE_PIDFD`，拒绝普通 fork fallback。见 [补丁](../fork_runtime_compat/sources/runtime-source/patches/shimos-fork-into-cgroup.patch)、fork.c:44–149 (`../fork_runtime_compat/sources/runtime-source/glibc-2.35-ubuntu/posix/fork.c#L44`, omitted from this source release)、_Fork.c:31–86 (`../fork_runtime_compat/sources/runtime-source/glibc-2.35-ubuntu/sysdeps/nptl/_Fork.c#L31`, omitted from this source release)。

固定来源是 Ubuntu glibc `2.35-0ubuntu3.15`、CPython `3.10.12-1~22.04.18`、x86_64，GCC `11.4.0`。自定义 ABI `shimos_fork_into_cgroup` 被导出在 `GLIBC_2.35` 节点，不表示 stock glibc 有这个函数。外部 bridge 不调用私有符号，但源补丁仍依赖 libc 的内部实现。缺 symbol 必须失败，不能静默换回 raw 路径。

candidate-04 bundle manifest 有 **283 个 runtime 成员**：275 个普通文件及 8 个符号链接；普通成员总字节 **36,999,198（约 35.29 MiB）**，不含 manifest 本身。255 个成员位于 gconv 目录，剩余 28 个包括 loader、libc 和兼容 DSO/链接。libc 为 12,733,032 字节、loader 为 1,370,368 字节。它们是打包文件大小，**不是 RSS/PSS、实际映射大小，也不是每请求分配量**；不能据此宣称运行内存增加 35 MiB。

精确 SHA256：manifest `8c7a3494339f2400dd8d2ab1e0843be51d435d9c35e47dd2ad61b1ab8ecb5a79`；libc `a03b51fe69f36b630ecf7997af05cd36885b1f2f0b52e278391fa6e17047eff4`；loader `0682f493d0434391d4ec027d0bcb54dd5f9e46d044dc7810f69abea58fe1398e`；bridge_d.c `5aa8289a556c1e97fa3a2cefd6f44a9a6d83ebf979f7511fd93392cc82a16d56`。本轮 guest 的 candidate-runtime.json (`runs/qualification-ab-02-runtime/candidate-runtime.json`, omitted from this source release) 与 Z 的真实 maps (`runs/qualification-ab-02-runtime/zygote-0-maps.txt`, omitted from this source release) 对应候选文件身份；不允许同名 stock DSO 静默混入。

证据：candidate-04 bundle manifest (`../fork_runtime_compat/build/glibc-bundle-no-legacy-crypt/opt/shimos-glibc/manifest.json`, omitted from this source release)、[构建说明](../fork_runtime_compat/sources/runtime-source/README.md)。此前 extra libcrypt 与 guest `_crypt` 的 ABI 冲突已经实际暴露出打包维护风险；candidate-04 排除旧 provider，不能由有限测试推出整个 Python 标准库闭包兼容。全 glibc 回归未运行。

需持续维护的责任至少包括：

1. 每次安全更新都要重新合并这三个内部文件、构建 loader/libc、重做 ABI/DSO provider 核验。
2. 模板原环境与目标 rootfs 必须支持同一已加载 DSO 及后续动态装载；不能只替换一个 libc.so。
3. CPython hooks、主线程/GIL/解释器限制以及 native callbacks 的顺序、失败路径需逐版本验证；现 bridge 不等于 stock os.fork 全部 API 语义。
4. callbacks 不得擅自关闭/复用管理 FD、起线程、重入派生或改变权限。A 提前 drop 可以限制第二轮 capability，但不会使 gate 前 callbacks 变成可信业务代码。
5. 新内核/架构的 clone3、seccomp、robust/TID、资源拒绝都需回归；x86_64 本例不建立其他架构资格。

**当前判断：**保留 D 作为固定实验基线是合理的，因为它回答“完整 wrapper 与原子 cgroup 出生能否同时工作”。将其直接定为生产默认尚无足够证据；不应因补丁短而忽视发行与更新成本，也不应因维护麻烦而退回已证实错误的 raw clone3。

### 4.3 已观察到的集成回调边界

本轮正式 `qualification-ab-02-runtime` 取得 28 个阶段快照、48 条 native callbacks、48 条 Python callbacks，以及 3 次在真实 wait(W) 后的 robust owner-death 恢复；这是自有可信探针的实际跨域组合观察，不是独立微测试数量，也不是完整运行时兼容认证。正式运行时分析 (`analysis/qualification-ab-02-runtime-runtime.json`, omitted from this source release)、模板原始日志 (`runs/qualification-ab-02-runtime/zygote-0.log`, omitted from this source release)。其余 7 个故障会话也分别通过生命周期与运行时核验器；故障打断而未运行的阶段不计作已通过。

- 第一轮 Z/S：effective/permitted capability 为 0、NNP=1，但最终 seccomp 尚未安装（观测为 0），bounding set 尚在，且持有目标对象引用。Z 仍凭 user namespace 所有者关系具有接纳资格。不能因 cap_eff=0 就认为 callbacks 已处于业务隔离边界。
- 第二轮 S/W：A 的 early drop 已发生；实际 S_before_second_fork、W_after_second_fork、S_after_second_parent 及 native 回调观测为 capability effective/permitted 0、NNP=1、seccomp=2；阶段快照进一步记录 bounding/ambient 为 0。D 在原策略下运行，没有通过新增权限或放宽 seccomp 来通过。
- 但第二轮 callbacks 仍先于业务门禁与管理 FD 最终关闭。该批 S_before_second_fork 和 W_after_second_fork 可见 11 个 FD；W_gated 为 5 个，业务时才只剩 0/1/2。因此 early drop 没有把任意第三方 callbacks 变成安全业务代码。
- S 进入目标 `/proc` 后不能以 `/proc/self` 枚举其外层活动 PID，探针改用 0–4095 的有界 FD 扫描，并标记不完整；W 业务的最终 FD 检查仍通过完整 `/proc` 观察。这是诊断，不能将扫描开销算作产品必须成本。
- robust 检查使用 Z 在可信阶段创建的一页 `MAP_SHARED` 自有诊断状态；W 持锁退出，S 真实 wait 后恢复。它不证明跨信任任务可以共享任意锁状态，也不意味着业务初始化内存全是 COW 私有页。

对象身份按当前持有的 FD、nonce、根引用、namespace owner 与权限链校验。namespace inode 数字可在旧域销毁后重用；同一个数字既不证明同一请求，也不表示两次新建域发生混用。不可复用的请求身份是 attempt nonce，不能把 namespace inode 当作永久全局 ID。

### 4.4 四条运行时路线的维护取舍

| 路线 | 可能减少的维护 | 保留或新增的责任 | 是否满足本轮合同 |
|---|---|---|---|
| 继续 D | 不必在 bridge 里手工补 libc 内部状态；复用完整 wrapper | 固定 libc/loader、发行闭包、安全更新、CPython hooks 和逐版本回归 | 本轮限定实际通过；不是通用认证 |
| stock fork 后迁移 cgroup | 可使用发行版 fork wrapper | 出生到迁移前 callbacks/内存分配仍在原域，需定义有预算的过渡区和迁移失败协议 | 不等价于出生即受目标预算约束；未实施 |
| 域内 stock Zygote | 可以去掉跨域 fork runtime 补丁及部分切换流程 | 初始化状态与域寿命绑定；要付保留域和分域重复初始化成本 | 属另一资源组织合同，不能直接替代本轮结论 |
| 未来内核机制 | 若获得合适接口，可能改变目标域出生/切换组织 | 仍需正确 libc wrapper/CPython callbacks；另有内核版本、安全权限、wait/PID/cgroup 语义和发行维护 | 仅研究设想，无现成实现、无本轮资格；不能提前记为免维护替代 |

这些是后续取舍的分析，不是已经测得的性能排名。尤其是新增 syscall 并不会自动执行用户态 fork callbacks，也不能自动消除第三方库的锁和线程状态问题。

## 5. 三个值得独立验证的精简候选

以下都未实现，不代表选定最终架构。

### 候选一：先减少正常收尾的重复交互，不删安全门

**当前实现：**正常请求末尾分别 CANCEL/ACK、FORGET/FORGOTTEN、PING/PONG；后两组是阻塞等待。PING 检查模板状态/FD，属于资格诊断，而非给业务授权。

**最小版本：**让 FORGOTTEN 同时返回原 PONG 所需的模板指纹、FD 集合和活动请求数；在同一个 Z 事件处理点关闭本请求对象并取得快照。R 保留完全相同验证，不再另发 PING。正常 25 包可降到 23 包，显式阻塞 RPC 从 4 到 3。仅证明消息减少，不承诺节省若干毫秒。

后续才评估能否把**正常已 wait S**后的 seal 与 forget 合为一个 FINALIZE；失败取消仍保留独立 CANCEL、QUERY 和真实 wait。必须拒绝 live/POSSIBLE S，不能让请求对象在结果关联完成前被丢掉；先不同时修改两项，以便查明回归来源。

这不改变 namespace、资源模型或业务门禁。最小验证重跑全部 A 26 次资格和集成额外 3 次运行时组合探针，重点重跑 REAPED 丢失、CANCEL 重复、晚消息、同 Z 两域、FORGET 前后故障、FD 恢复。若状态快照被遗漏、指纹验证放宽，或完整路径收益低于噪声，停止扩大。这是普通协议工程精简，不应包装成独立系统创新。

### 候选二：将 H 的存活与整组停止交给宿主监督，保留最小收尾收据

**当前实现：**每会话独立 Python H，453 行；自己维护子进程、域发现、EOF、副作用留证和清理。

**准备替换：**仅在具备合适 systemd/delegation 的部署中，将 Controller 及私有执行树纳入一个服务管理边界，由稳定 manager 承担 R 死亡后的整体停止；另保留最小清理/证据入口，完成业务 UNKNOWN、工作区删除、输出关闭和资源释放核验。scope 不会自动完成这些职责，不能把一条命令当作整项实现。

预期减少自建常驻监督循环与部分进程管理代码，但 unit/IPC/清理程序仍有成本；不保证总进程更少。平台依赖增加，等待和结果来源可能改变：被 manager 收养后，原执行器未必还能取得退出码，必须保留 UNKNOWN，不能称为错误结果“恢复成功”。需明确 R 死亡如何触发 service stop，而非等全部后代自然退出。

最小原型只覆盖一会话一私有树，对照 H 跑 Controller 两个死亡窗口、Z/PID1 死亡、回执丢失、超时、迟到创建及 EOF/目录/cgroup 清理。若原模型中的真实 wait 证据无法等价获取，则明确这是资源清理替代合同，不准混入同合同排名。维护收益取决于目标部署是否本来就有稳定 manager，不能提前选为全平台方案。

### 候选三：用 stock fork 的域内模板作为运行时维护的对照

**当前实现：**跨域干净 Z 在模板 cgroup，S/W 通过 D 出生即进入各自受限 cgroup；此合同使定制 runtime 有实际原因。

**比较方案：**固定隔离域及资源预算内保留干净模板，采用 stock glibc/os.fork，孩子继承同域同 cgroup。它可减少自定义 libc/跨域 bridge 的维护，但改变了昂贵状态与域寿命分离、每请求出生预算的资源模型。不能当作当前 D 的直接等价替换。

另一常见办法是 stock fork 后门禁，再由 Controller 迁移 cgroup；它仍有从出生到迁移的窗口，native/CPython child callbacks 已在旧域运行，内存 charge 也不因为迁移自动全部转账。因此它不满足当前原子出生合同，除非单独提出并验证有预算的过渡域新合同；本轮不采用。

最小验证应比较“保留一个域内模板”的真实维护与资源成本，保持可信单线程与业务输出合同，明确牺牲了哪些跨域自由度。只有若真实使用场景不需要本轮原子跨域出生约束，才值得考虑替代。未来内核接口不是已实现替代，也不能解决所有 glibc callbacks/TID/robust 维护义务。

| 候选 | 可确认减少的东西 | 实现风险 | 维护取舍 | 验证难度 |
|---|---|---|---|---|
| 收尾快照合并 | 最小版本少 2 包、1 次显式阻塞 RPC | 较低；仍要防迟到状态和过早忘记 | 变更小，无新平台/安全合同 | 重跑同资格，补 FINALIZE/FORGET 邻近窗口 |
| 宿主监督替 H | 有机会减少自建监督逻辑，数量/延迟尚未知 | 中高；真实 wait、EOF、输出留证仍需归属 | 少维护自建存活监督，多依赖宿主服务语义 | 整套故障资格及 manager 故障边界 |
| 域内 stock 模板 | 不维护自定义 libc，可减少跨域控制 | 技术机制成熟但资源合同变化大 | 长期保留域；不能直接满足跨域模板寿命目标 | 必须分合同比较，不能用它掩盖 D 的要求 |

## 6. 目前可以形成的架构判断

1. 最明显的复杂度来自**跨越故障域的责任交接**和**把运行时 fork 与原子资源出生绑在一起的 runtime 维护**。进程数是表象，不是唯一指标。
2. 独立故障清理责任、请求身份、许可撤销、真实 wait、最终策略与资源证据不能删除；具体消息数量、正常路径诊断、状态镜像和 H 承载方式值得精简。
3. 优先验证收尾快照合并：它不改安全或资源模型，改动与可期待收益可准确界定，而且能保留当前最重要的故障验收。先不删除 S、H 或多道启动门。
4. D 暂留作受控机制基线，同时研究其他资源组织合同；不能将“可运行”升级为“必须长期维护自己的 libc”，也不能把未验证内核方案当作已经免维护。
5. 本轮 A+B 已在同一实际路径通过限定资格，第二轮 callbacks 的权限、TID/robust、原安全检查和生命周期共同成立。它为精简提供可回归的基线；不证明其中任何一个进程或门禁已经可以删除。

## 7. 最终复核与研究边界

- 实际集成代码及分析器规模已按最终文件重算；8 个正式会话源文件、二进制完全一致，当前 prototype 与冻结会话相同。
- 正常控制消息仍为 25 包，另加 2 个 pipe token；探针增加日志与载荷，没有增加授权通道。没有从这些数量推导延迟收益。
- 正式第二轮提前 drop 后的 cap/seccomp/FD、native/Python callbacks、pthread TID 与 robust 行为通过对应检查；S 有界 FD 扫描与任意依赖不准入的限制仍然保留。
- 8 会话的缺 vendor API 控制探针均得到 ENOSYS，而非 raw/fork fallback；candidate DSO/mapping 校验保持启用，原 policy 未放宽。
- 输入完整性复核 (`analysis/input-integrity-final.json`, omitted from this source release) 记录 1,658 个历史输入无变化。开发 pilot 与首轮观察/分析修正记录保留，详见 [集成报告](integration-report.md)，不隐藏失败来制造“首次全部通过”。
- 当前保证仍限可信单线程模板、串行请求、固定私有 VM、H 存活。H 自身死亡、宿主 OOM/重启、文件系统故障、长期并发与任意依赖均未获得资格。

## 8. 对五个问题的直接回答

**Q1：A+B 是否已经在同一实际路径通过关键正确性验证？** 是，在上述限定范围通过：7 会话的 A 故障回归 26 次，加 1 会话的实际跨域 robust 组合 3 次，共 29 PASS。它是运行时与生命周期共同通过，不是把两个独立报告相加。

**Q2：当前最明显的复杂度来自哪里？** 一是 R、Z、S、PID1、H 之间的许可、真实 wait 与异常清理责任交接；二是为了原子 cgroup 出生而维护独立 libc/loader/DSO。多个诊断快照与故障钩子也增加源码量，不能误认它们全是部署时不可避免的成本。

**Q3：哪些不可删除，哪些值得简化？** 不可删除的是独立清理责任、目标 PID1、正确运行时派生、当前路线的 namespace 过渡责任、业务门禁、真实结果和资源证据。可以研究的是收尾快照合并、诊断消息组织与 H 的宿主承载；删除具体进程前必须把原职责交给经过验证的替代者。

**Q4：是否继续维护 D？** 现阶段把 D 保留为固定机制与回归基线合理，不宜马上认定其为生产默认。它避免回到已证实错误的 raw 路径，但完整 glibc 维护、发行闭包、安全更新与更多依赖资格成本仍需单独评估。改变资源模型或域内模板可以作为明确非等价的比较方案；内核设想暂不是现成替代。

**Q5：最值得先验证哪个精简方向？** 先让 FORGOTTEN 携带现有 PONG 的模板快照，保留相同检查、所有安全门和 H。改动小、预期减少的消息和同步可数、可直接重跑完整 29 次资格。是否产生值得保留的性能或维护收益，需要下一轮测量；本轮未实现，也未替项目选定最终架构。
