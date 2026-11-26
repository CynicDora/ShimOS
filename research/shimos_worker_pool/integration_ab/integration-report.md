# A+B 最小集成与正确性验证

日期：2026-10-19。范围：独立实验原型；不修改 A、B、B-strict 或生产实现，不更新飞书，不开展性能 Benchmark。

## 1. 结论及资格边界

**A 的生命周期协议与 B candidate-04 的完整 fork wrapper，已经在同一条实际 Z→S→W 路径中通过本轮限定资格。**最终固定版本 `qualification-ab-02` 包含：

- 原 A 的 7 个 VM 会话、20 类场景、26 个执行尝试：26 PASS、0 FAIL、0 BLOCKED。
- 另一个 VM 中的 3 次跨域运行时组合验证：3 PASS。W 持有 robust mutex 退出，S 真实 wait 后三次得到 `EOWNERDEAD=130`，均完成 consistent/unlock。
- 合计 8 个重新初始化的私有 VM、29 个尝试，全部通过。它们位于同一物理宿主，不是 8 台独立机器。
- 所有正式会话的原型源码与编译产物 SHA 一致；原有 1,658 项冻结输入复核无变化。

这是**可信、单线程、自有 Python 模板，串行请求，固定 x86_64 Linux/CPython/glibc，H 正常存活**条件下的机制资格。不是任意依赖准入、通用 fork 安全、长期运行或生产可靠性证明。PASS 表示符合故障预期，不能把取消、UNKNOWN 或非零退出称为业务成功。

完整逐请求结果见 [最终矩阵](analysis/qualification-ab-02-matrix.md)、[机器可读汇总](analysis/qualification-ab-02-summary.json)。架构分析单独见 [architecture-simplification-review.md](architecture-simplification-review.md)，本轮未实施其中任何精简。

另有 独立证据复核 (`final-evidence-review.md`, omitted from this source release)，逐项检查原 A 矩阵、真实派生/回调、H 接管和 UNKNOWN 处理；不计为新实验。

## 2. 基线、版本与冻结方式

A 的依据是 完整修复报告 (`../reliability_fix/跨域Zygote生命周期可靠性修复与验证-完整汇总.md`, omitted from this source release)、[26 次正式矩阵](../reliability_fix/05-test-matrix.md) 和对应 prototype/runs；B 的依据是 [运行时完整报告](../fork_runtime_compat/fork-runtime-compat-complete.md)、[candidate-04](../fork_runtime_compat/runs/candidate-04/) 及其实际源码、loader 和 DSO。没有将各自独立通过直接视作集成通过。

input-freeze.json (`input-freeze.json`, omitted from this source release) 固定全部 A 文件、B 报告/原型/candidate-04/最终 bundle/补丁/关键源码/构建日志及 VM 输入，共 286,611,605 字节。不是整个 B 中间构建树的完整归档。运行后 input-integrity-final.json (`analysis/input-integrity-final.json`, omitted from this source release) 再核对 1,658 项，改变或缺失为 0。新增文件均在本目录。

| 项目 | 本轮实际使用版本 / SHA256 |
|---|---|
| Guest Linux | `6.18.49-agentic-runtime-opt-v1`，来源 commit `1c732c6b94f0faee1526bd375add2fe10cba2e26`；未加内核补丁 |
| kernel ELF image | `bd303a80ab8fe396ac83d18e2dcd0936143eb0778fbcf6acaf47ea3fba11dd4f` |
| initramfs | `79505c01cc39cb00dea51d4a8101c1bfea187a84515782520d1b58ef3d4a32f9` |
| Bubblewrap | 0.13.1；沿用冻结 assets 和显式配套 loader |
| CPython | Ubuntu `3.10.12-1~22.04.18`，guest 为 3.10.12；Python ELF `a2f33a6e006989270f4340528eb61f8f97366e00a5d1b602ac8672ea44fc56ae` |
| D glibc | Ubuntu `2.35-0ubuntu3.15` 源码与发行补丁，加 B 的 vendor fork 补丁；GCC 11.4.0 |
| D libc.so.6 | `a03b51fe69f36b630ecf7997af05cd36885b1f2f0b52e278391fa6e17047eff4`；Build ID `2218522fcaa1ec292c7fbb909f19474d79395d1f` |
| D loader | `0682f493d0434391d4ec027d0bcb54dd5f9e46d044dc7810f69abea58fe1398e` |
| D glibc patch | `71901c8bea4702c2833493b41c7f979821575b62fd6f081366eaab285f6555da` |
| bridge_d.c / bridge_d.so | `5aa8289a556c1e97fa3a2cefd6f44a9a6d83ebf979f7511fd93392cc82a16d56` / `2cf5d6afb1fe44bcb736c44c2582294c995b1c7a56656653746be4aabd7c7fa0` |

精确构建参数和来源在 B 的 [runtime-source/README](../fork_runtime_compat/sources/runtime-source/README.md) 与 最终 bundle manifest (`../fork_runtime_compat/build/glibc-bundle-no-legacy-crypt/opt/shimos-glibc/manifest.json`, omitted from this source release)。沿用的是 **glibc-bundle-no-legacy-crypt**：保留 guest 的 libxcrypt，避免 B 已发现的同名旧 libcrypt provider 冲突。没有重新编译或改变 D 的 ELF。

每次 VM 保存 `source-sha.json`、`build.json`、`candidate-runtime-sha.json`、`candidate-runtime-install.json`、`environment.json`、`command.json` 和 `lab-manifest.json`。复制时将 bundle 内部 8 个 symlink materialize 为相同字节，单独记录别名映射；284 个摘要条目（283 runtime 成员及 manifest）与 candidate-04 一致。不能把打包路径变化称为新运行时实现。

## 3. 实际接入方式与修改文件

```text
H（stock libc，独立清理责任）
└─ R（stock libc，A 的执行协议）
   ├─ Bubblewrap monitor → 目标 PID1
   └─ Z（candidate loader + D libc + bridge_d）
      └─ S（第一次完整 wrapper + clone3，出生在 transition cgroup）
         ├─ 进入目标 namespace/root；按 A 提前永久降权
         └─ W（第二次完整 wrapper + clone3，出生在 business cgroup）
            └─ 完成最终 FD/安全设置，获 RUN_BUSINESS 许可后执行业务
```

Z 的初始启动仍需要一次 exec；**S、W 不重新 exec Python**。两次真实 fork 边、exec/exit 由 guest trace 交叉核查，内存对象身份、不可重新构造属性和模板不变性由原 A 业务探针验证。目标 PID1 是 Bubblewrap 先创建的实体，未改变研究路线。

| 新目录内文件 | 实际变化与原因 |
|---|---|
| [run.py](prototype/run.py#L40) | 用 B 的显式 loader 启动 Z；只读挂载同一 runtime 与对应 DSO；读取实际 Z maps 校验对象；增加 runtime 测试组和探针构建。A 的许可、取消、wait、H 协议未重写 |
| [zygote.py](prototype/zygote.py#L81) | 在现有 Z/S/W 阶段加入 native/Python 诊断；保留 S 提前 drop、START_WORKER 和 RUN_BUSINESS；仅 runtime 组启用 robust owner-death 探针 |
| [bridge_d.c](prototype/bridge_d.c#L19) | 原样采用 B candidate-04；经 PyDLL 保持 GIL，CPython hooks 包住完整 D libc wrapper；缺 symbol 立即 ENOSYS，无 raw/迁移 fallback |
| [runtime_support.py](prototype/runtime_support.py) | 从 B 提取固定 bundle、只读 overlay、映射 identity 和缺 API 拒绝检查；没有配置缓存或常驻服务 |
| [install_runtime.py](prototype/install_runtime.py)、[vm.py](prototype/vm.py) | 只在带私有 VM 标记的环境安装实验 bundle；核对原候选哈希，冻结每次源码及配置；不替换宿主 libc |
| [runtime_probe.c](prototype/runtime_probe.c)、[runtime_probe.py](prototype/runtime_probe.py) | 自有可信小模块，记录两组 native/Python callbacks、TID/TLS/robust head/权限/FD；提供共享诊断 mutex；不是第三方依赖预加载 |
| [verify.py](prototype/verify.py)、[verify_runtime.py](prototype/verify_runtime.py)、[qualify.py](prototype/qualify.py) | 在 A 验收上增加 DSO/来源/真实组合路径核验；资格脚本运行原 7 组与额外 runtime 组，两份分析器分别判定 |

`supervisor.py`、`common.py`、`bridge.c`、`domain_init.c`、`native.c`、`policy.h` 与 A 一致。原三份 C 产物亦与冻结基线一致。旧 bridge 仍供 H/R 的基础操作，冷 launcher 仍沿原 A 路径立即 exec；**修复的是 Z→S→W 的保留解释器路径，不宣称项目里所有 raw clone 调用都被替换了。**完整改动可由 integration-changes.patch (`analysis/integration-changes.patch`, omitted from this source release) 复核。

## 4. 六项兼容性检查

### 4.1 S 提前降权后能否再次走 glibc wrapper

可以，在本轮固定合同内实际通过。A 在 [transition():105](prototype/zygote.py#L105) 完成 `drop_final()`，第二次 fork 在其后。记录显示 S 的 permitted/effective/inheritable/bounding/ambient capabilities 均为 0、NNP=1、seccomp=2；第二轮 native prepare/parent 与 W child callbacks 同样处于这个受限状态。business 预算为 0 时第二次 clone 实际返回 EAGAIN，wrapper 的 parent callbacks 和 CPython parent hooks 仍正确完成，W 没有创建，Z 能服务下一域。

### 4.2 原 seccomp 是否容纳完整 fork 路径

[policy.h](prototype/policy.h) 完全未改。它是固定研究 denylist，**不是通用生产 allowlist**；拒绝 setns、mount、ptrace 等隔离变更，未拒绝本轮 fork wrapper 所需的 clone3、robust list 与信号管理接口。不能仅以“seccomp=2”证明调用成功，因此还实测 pthread clock、robust head 和 owner-death 行为。W 额外的 execve/execveat 禁止仍保留；没有为通过测试添加豁免。

### 4.3 两层 callbacks 的真实时机

两次派生均观察到：Python prepare 逆注册序 → native prepare 逆注册序 → fork；父路径 native parent 正序 → Python parent 正序；子路径 native child 正序 → Python child 正序。PID 预算失败也执行 parent 收尾，没有虚假的 child callback。

**callbacks 发生在 wrapper 返回前，不受后面的业务许可门禁保护。**第一轮仍在可信构造路径中；第二轮虽已降权，S/W 回调阶段仍持有管理 FD。实际快照中第二轮相关阶段可见 11 个 FD，W_gated 尚有 5 个，到 W_business 才只剩 0/1/2。因此只允许自有可信 callbacks；不能因为 caps=0 就准入任意 import、回调、线程池或关闭管理 FD 的代码。

### 4.4 TID、TLS 与 robust mutex

使用公开 `pthread_getcpuclockid` 和 `clock_gettime`，把 pthread 记录的线程 ID 与内核 gettid 比较；观察 `get_robust_list` 非零、TLS cookie 与 pthread/TLS 地址继承、信号 mask 和 native owner 正确。没有从外部硬编码私有 glibc pthread 结构偏移来“修复”TID。

额外 runtime 组里，同一个 Z 依次服务三个独立目标域。每次 W 锁住自有的 process-shared robust mutex 后以 0、0、7 退出；S 先真实 wait，再恢复锁，三次均 `EOWNERDEAD=130`，`pthread_mutex_consistent=0`、unlock=0。该共享页**专为诊断**，不等于允许业务任务任意共享可变状态。普通 A 故障矩阵不启用持锁测试；不能把“robust head 已登记”与“实际 owner-death 恢复”合并计数。

### 4.5 门禁、失败和资源归属

SPAWN/PREPARED/COMMIT、S 的 START_WORKER、W 的 RUN_BUSINESS 和取消 seal 语义均保留。两次 D clone 使用 `CLONE_INTO_CGROUP | CLONE_PIDFD | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID`，没有退回 fork 后迁移。两次真实 pids.max=0 拒绝和后续正常请求均通过。请求状态仍区分派生、业务知识与资源；副作用已发生但 wait 回执丢失时保持 UNKNOWN。

这保证的是本轮 cgroup 出生/预算合同，不表示已有 COW 共享页自动按每个新 Worker 重新记账。共享物理页、后续 COW 与长期内存归属仍需单独研究。

### 4.6 loader/DSO/rootfs 一致性

H/R 用 stock libc；Z 明确由 D loader 加载 D libc。每个新目标域只读绑定同一 bundle，并覆盖相应的原 glibc 目标路径，避免 chroot 后重新加载同名 stock provider。R 在 Z ready 后按真实 `/proc/<pid>/maps` 的 inode/device 与 manifest 校验，不只检查 argv。

原 B 的 provider 修正被原样继承；stock 环境缺 vendor API 的探针返回 ENOSYS，未偷偷退回 raw clone。只对固定已加载闭包与本轮探针建立资格，尚未运行全 glibc 回归或全部 Python 扩展导入；不是任意 DSO ABI 兼容证明。

## 5. 正式测试与原始证据

| VM 组 | 次数 | 主要覆盖 | 生命周期 / 运行时 | 结果 |
|---|---:|---|---|---|
| control (`runs/qualification-ab-02-control/`, omitted from this source release) | 3 | 同 Z 连续两正常域、非零域；真实两代 callbacks 与 no-exec 继承 | 185 / 233 项 | PASS |
| budgets (`runs/qualification-ab-02-budgets/`, omitted from this source release) | 4 | 第一及第二 clone EAGAIN，分别继续下一正常请求 | 194 / 222 项 | PASS |
| receipts (`runs/qualification-ab-02-receipts/`, omitted from this source release) | 4 | CREATED/REAPED 单独丢失、业务副作用后结果丢失 | 212 / 312 项 | PASS |
| cancels (`runs/qualification-ab-02-cancels/`, omitted from this source release) | 7 | 迟到 COMMIT、W 业务前取消、S 进入后取消、重复取消、超时、撤销 ACK 丢失 | 282 / 390 项 | PASS |
| failures (`runs/qualification-ab-02-failures/`, omitted from this source release) | 6 | Z 在创建/真实 wait 后死亡、业务期间 Z/PID1 死亡、控制通道 EOF、正常恢复 | 309 / 374 项 | PASS |
| controller-death (`runs/qualification-ab-02-controller-death/`, omitted from this source release) | 1 | 业务期间 R SIGKILL，H 接管和真实收养 wait | 139 / 78 项 | PASS |
| controller-during-entry (`runs/qualification-ab-02-controller-during-entry/`, omitted from this source release) | 1 | S 派生/进入阶段 R SIGKILL，H 关闭创建者并回收 | 131 / 42 项 | PASS |
| runtime (`runs/qualification-ab-02-runtime/`, omitted from this source release) | 3 | 同 Z 三域、两代 fork、W 持锁退出后 S 实际恢复 | 185 / 240 项 | PASS |

合计 1,637 项生命周期/来源断言、1,891 项运行时断言、230 个快照，包含大量重复检查，**不是这些数量的独立故障样本**。不估计生产故障率，不报告性能收益。

每组除了执行器返回值，还核对：真实 parent wait/收养记录、业务知识与退出码、输出 EOF、域空和实际删除、R/H FD 前后、工作目录、只读外部进程观察、trace 的 fork/exec/exit 和丢事件统计。业务实际运行时保留原 19 项隔离检查；故障阻止业务启动时，不把未运行检查算作通过，而核对未授权执行、出生及清理证据。

Controller 死亡的 attempt journal 是中途快照，最终结论必须读取 H 的 `supervisor.json`，不能把旧 PENDING 当最终泄漏，也不能以 H 清理成功填造业务退出码。H 可能无法恢复 R 已读入内存但尚未落盘的完整输出；本轮保留 UNKNOWN，不承诺输出恢复。

root 观察者不 kill 或删除产品执行资源。产品 H 完成并真实退出后，外层夹具仅删除已经空的 `client` 和委派根；它不是替 H 做业务域清理。每组都有 `observer-after.json`、`observer-later.json`、`external-final-release.json` 和 `supervisor.json` 明确区分两者。正式 VM 无紧急超时补杀。

## 6. 开发期失败和修正记录

旧失败保留，不计入最终 29 次正式通过。

| 记录 | 原判定与原因 | 处理方式 |
|---|---|---|
| pilot-02-runtime-runtime.json (`analysis/pilot-02-runtime-runtime.json`, omitted from this source release) | FAIL：三次日志无法证明 wait 在 robust 恢复前。源码实际先 wait，再 recover，最后才写 wait 日志 | 仅把真实 wait 日志移到 recover 前；保留原运行与 FAIL；pilot-03-runtime (`analysis/pilot-03-runtime-runtime.json`, omitted from this source release) 和正式 runtime 新运行通过 |
| qualification-ab-01-failures.json (`analysis/qualification-ab-01-failures.json`, omitted from this source release) | FAIL：reap_ack_loss 比历史多一次合法的 channel-first 发现顺序，标签为 TEMPLATE_CHANNEL_LOST 而非 TEMPLATE_LOST | 独立审计 (`qualification-ab-01-failures-classification-audit.md`, omitted from this source release) 确认原 A 只保留首个失败原因。只对本场景允许两标签，并加强 Z/S/W 真实 wait、回执丢失、状态未知及释放条件；核心协议未改 |
| qualification-ab-01-controller-death-runtime.json (`analysis/qualification-ab-01-controller-death-runtime.json`, omitted from this source release) | FAIL：旧分析器只读末尾输出文件，R 死亡使该文件未保存，漏读持久 WORKER_READY.runtime | 证据审计 (`controller-death-runtime-evidence-audit.md`, omitted from this source release) 严格匹配 events.jsonl 与 attempt 中的同一实际快照，来源可追踪；不补造未保存阶段，不改变 UNKNOWN |

`qualification-ab-01` 的原失败分析、修订只读审计和 `pilot-*` 都在 analysis/runs 中保留。最终 `qualification-ab-02` 重新启动全部 8 个 VM，使用同一最终源码和核验器，避免从不同版本挑选通过项拼成资格。

## 7. 尚未解决的问题

**生产前必须继续验证：**H 自身死亡、宿主 OOM/重启、文件系统或日志故障、不可中断进程、并发接纳、长期 tombstone/状态增长、PID 重用压力、非受控信号及更多故障交错。本轮仅复跑原 A 故障合同，不把范围外情形记为已解决。

**运行时边界：**没有多线程模板、第三方 atfork callbacks、NumPy/PyTorch、设备状态、所有 CPython 版本或完整 glibc 测试。桥接 CPython hooks 不等于 stock `os.fork` 所有 API 前置校验、审计事件及子解释器语义。原始 raw clone 问题在受测路径得到补救，不能宣布 ISSUE-02 已获通用解决。

**仍需可信初始化：**外部 Z 具有进入后代 user namespace 的资格，并持有管理对象。零 capability 数值不是任意依赖安全准入证明。门禁前 callbacks 仍在 TCB 内；必须禁止它们任意动管理 FD、重入派生、创建线程或改变协议信号状态。

**测量边界：**探针有日志、快照、信号/FD 查询和诊断共享页；S 进入目标 proc 视图后使用 0–4095 有界 FD 扫描，明确标记不完整。最终 W 业务 FD 检查是实际 proc 枚举。不得拿这套诊断运行的时间、内存当未插桩产品性能。

独立域销毁后，namespace inode 可以被内核重用。产品使用 attempt nonce、受保护 FD、进程真实派生边和 pidfd 关联；报告不把 inode 永久唯一作为前提。

## 8. 复核与重现

只读复核现有结果，不启动 VM：

```bash
cd /path/to/research-host/shimos-linux-native-mvp
python3 -B research/shimos_worker_pool/integration_ab/prototype/verify.py \
  qualification-ab-02-runtime --check-only
python3 -B research/shimos_worker_pool/integration_ab/prototype/verify_runtime.py \
  qualification-ab-02-runtime --check-only
```

在具备原冻结 kernel/initramfs、KVM、QEMU 和 assets 的同类实验宿主，使用**新前缀**重跑全部 8 个独立私有 VM；已存在目录会拒绝覆盖：

```bash
python3 -B research/shimos_worker_pool/integration_ab/prototype/qualify.py reproduction-new-01
python3 -B research/shimos_worker_pool/integration_ab/analysis/summarize_qualification.py reproduction-new-01
```

VM 使用 4 vCPU、4 GiB RAM、私有 3 GiB 临时磁盘、无外网；源码/工具通过只读 9p，证据通过独立可写目录。实验 libc 只装入 guest `/opt/shimos-glibc`。运行命令及二进制在每个 runs 子目录保留。不是对宿主执行 mount/cgroup 故障测试。

## 9. 对本轮五个问题的回答

**Q1：是否在同一实际路径通过？** 是，原 A 26 次与新增 3 次组合验证通过；不是拼接 A/B 各自结论，仍受上述环境和模板合同限制。

**Q2：最明显的复杂度是什么？** R、H、Z、S、PID1 分别掌握不同创建/退出事实，消息丢失后不能互相冒充；其次是为完整 wrapper 与原子 cgroup 出生维护匹配的 libc/loader/DSO。

**Q3：什么不能删除、什么可精简？** 独立清理责任、许可撤销、真实 wait、UNKNOWN 与资源证据不能删除。当前路线 S 还负责不可逆切换及 W 的实际 wait。可先合并正常收尾的重复诊断快照，或单独研究宿主 supervisor 承接 H；本轮没有实施。

**Q4：是否继续维护 D？** 固定实验基线值得保留，当前证据不足以确定生产默认。不能退回已复现错误的 raw clone；也不能把 fork 后迁移或域内模板当同合同替代。详见另一份评估中的维护与资源模型比较。

**Q5：优先精简哪一项？** 先验证将 PING/PONG 的模板检查合并进 FORGET/FORGOTTEN。保留同样核验与全部门禁，可少两条消息、一次显式阻塞 RPC；维护变更小，验收边界明确。尚未测出时间收益，也不据此决定最终架构。

## 10. 供以后更新台账的简短摘要（本轮未写飞书）

**ISSUE-01：**生命周期修复已与 candidate-04 fork runtime 集成。相同源码下原 20 类/26 次故障资格全部通过，另 3 次跨域运行时组合测试通过；H 接管、取消、真实 wait、UNKNOWN 和资源回收仍成立。范围仍为可信单线程模板、串行私有 VM、H 存活；H 死亡、OOM、并发和长期运行未验证。

**ISSUE-02：**完整 fork wrapper 候选 D 已接入实际 Z→S→W 路径。在 S 提前降权及原 seccomp 下，两代 native/Python callbacks、pthread TID、robust 登记和三次实际 owner-death 恢复通过，PID 预算失败也正确收尾。尚需维护定制 glibc/loader/DSO，未获任意依赖、多线程或跨版本通用兼容资格，不标为全面解决。
