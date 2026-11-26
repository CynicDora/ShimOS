# ShimOS 工作线 B：Tool Exec 两项最小正确性补充总报告

日期：2026-10-20。项目：`/path/to/research-host/shimos-linux-native-mvp`。本轮全部新代码和证据位于 `research/shimos_worker_pool/exec_support_followup/`。

## 1. 结论

**本轮完成了目标 exec 私有尝试/错误回执，以及 H 四类异常恢复补充。新副本通过受限资格；明确保留 UNKNOWN、INCOMPLETE、旧产品 FAIL 和夹具判定偏差。没有建立通用的目标 exec 成功确认，也没有解决任意程序的 loader 完成判定。**

实际修订是原 Tool 路径中的私有 pipe 接线，以及 H 的匿名 pipe 验证、独立 EOF 核验、目录枚举异常处理和状态表达。没有增加替代 launcher 架构、放宽 Warm no-exec、修改 namespace/seccomp/cgroup 策略或扩大工具种类。

| 问题 | 本轮结论 | 主要证据 |
|---|---|---|
| launcher 是否建立、目标 execve 是否返回错误 | 私有记录可区分第一跳失败、launcher READY、目标尝试和目标返回 errno | [A 报告](exec-receipt-report.md)、12 项正式请求 (`runs/receipt-qualification-01/`, omitted from this source release) |
| EOF 能否证明 exec 成功 | 不能；预 exec SIGKILL、提前退出、回执丢失都可得到相似观察 | A 原始 `.bin`、固定内核源码 (`frozen/kernel-evidence/manifest.json`, omitted from this source release) |
| 大输出恢复 | 每流超过 1 MiB 仍继续 drain；每流最多保存 1 MiB；实际未保存的 R 前缀无法恢复 | 无前缀例 (`runs/h-flood-01/`, omitted from this source release)、4096 字节前缀例 (`runs/h-flood-prefix-01/`, omitted from this source release) |
| 存储失败 | 实际注入 ENOSPC、部分写入后 EIO；继续清理，证据保存失败明确 INCOMPLETE | ENOSPC (`runs/h-enospc-01/`, omitted from this source release)、EIO (`runs/h-eio-partial-01/`, omitted from this source release) |
| 双流畸形登记/退休 | 新 H 拒绝非法数量、对象、标签、后续身份变化及伪 EOF；合法重复与迟到消息单独验证 | [H 报告](supervisor-recovery-report.md)、`runs/protocol-*` |
| 敌意工作区 | FIFO 不读、symlink 不跟随、稀疏文件/条目快照有界；真实拒绝保留错误或残留 | hostile (`runs/h-hostile-01/`, omitted from this source release)、不可读目录 (`runs/h-unreadable-dir-01/`, omitted from this source release)、不可删目录 (`runs/h-undeletable-01/`, omitted from this source release) |
| 既有合同 | 定向 Tool/Warm 回归保留 no-exec、双门禁、D 两次派生、真实 wait、EOF 与回收合同 | Tool 回归 (`runs/tool-regression-01/`, omitted from this source release)、Warm 回归 (`runs/warm-regression-01/`, omitted from this source release)、Warm 死亡 (`runs/warm-controller-death-01/`, omitted from this source release) |

这里的“通过”表示与声明的故障预期一致。例如不可删除工作区的正确结果是 INCOMPLETE，绝不是工作区已经释放。详细逐 VM/请求/流结果以 最终独立审计 (`analysis/final-audit-01/summary.json`, omitted from this source release) 和 资格矩阵 (`analysis/final-audit-01/qualification-matrix.csv`, omitted from this source release) 为准。

最终共 42 个独立 VM：6 个旧机制基线、1 个接线 pilot、35 个正式补充 VM。正式覆盖 **29 次完整请求（25 Tool、4 Warm）及 22 项 H 微型协议 case**；35 个正式 VM 与 pilot 的独立审计均 PASS，6 个基线保留 FAIL。正式产品仍有 **5 个 INCOMPLETE**；全体记录另含 1 个基线缺失 H 最终账本。统一验证器执行 19,407 条离线断言，包含重复 SHA 核验，不是独立试验数。分组计数见 coverage.json (`analysis/final-audit-01/coverage.json`, omitted from this source release)。

## 2. 冻结、环境和实验范围

先读取并冻结旧 `exec_support` 的源码、双流合同、正式资格与来源 SHA。旧交付 manifest 的 8050 个文件（4,158,232,963 个逻辑字节）逐一核对；后补的 `exec-support-consolidated.md` 不在旧 manifest 内，另行纳入 55 项引用冻结。见 初次完整性复核 (`analysis/baseline-integrity.json`, omitted from this source release)、输入冻结 (`frozen/exec-support-inputs.json`, omitted from this source release)。所有新补丁仅作用于本目录的独立副本。

完成实验后的终态只读复核 (`analysis/baseline-integrity-final.json`, omitted from this source release)再次确认 8050/8050 旧文件的 SHA、字节数和 mode，以及 55/55 冻结引用均一致。

实际 guest 为 Linux `6.18.49-agentic-runtime-opt-v1`、glibc `2.35`、CPython `3.10.12`、GCC `11.4.0`。QEMU/KVM、4 vCPU、4 GiB、无网络、独立 3 GiB 私有磁盘；宿主环境另行记录。内核与 initramfs SHA、固定 D runtime 的逐文件 SHA 在每次 run 中验证，D runtime 与旧 `candidate-04` 保持一致。

本轮所有真实 fork/exec、SIGKILL、SCM_RIGHTS、权限拒绝、文件对象和存储故障均发生在私有 VM。宿主只组织 VM、只读复核和写研究产物。没有运行性能 Benchmark；时间戳用于确认事件顺序，不能作为性能结论。

执行分两个来源冻结：

- candidate-01 (`frozen/followup-candidate-01.json`, omitted from this source release)：A 正式资格、最初 B1/B2/B4，42 个产品/夹具文件。
- candidate-02 (`frozen/followup-candidate-02.json`, omitted from this source release)：仅增加 R 真正消费但未保存输出前缀的测试入口，改变 `run.py` 和 `tool_cases.py`；H、launcher、S 和策略未变。随后完成前缀、双流协议和定向回归。

每个 run 保存自己的源码和二进制 SHA，不能把不同 fixture 版本描述成逐字节相同。`--supervisor-baseline` 使用冻结原 H；新夹具并不使旧 H 自动获得新功能。构建、重现、离线复核命令见 README (`README.md`, omitted from this source release)。

## 3. A：可信 exec 回执合同

保留 `Z → S → W → exec 静态 launcher → exec 指定工具`。S 在第二次 D fork 前创建请求私有 `pipe2(O_CLOEXEC)`；S 只持 read，W 只持 write。W 完成原降权和 G 门禁后记录第一跳尝试，临时使 write 可继承。静态 launcher 在 main 初期立即重新设 CLOEXEC，通过安全检查后记录 READY 和目标尝试，再执行目标。第二跳返回 errno 时私写错误；真正进入目标映像时 write 已关闭。

帧为固定 24 字节、版本化、有界记录；S 真实 wait 后非阻塞收集，最大 192 字节，超限、坏格式或缺失证据不能升级成功。原始字节保存为 `*-exec-receipt.bin`，与 S 日志及 R 的私有 WORKER_WAITED 消息对照。stdout/stderr 不参与回执解析。

| 结果维度 | 可信含义 |
|---|---|
| LAUNCHER_FAILED | 第一跳返回 errno；或已建立的可信 launcher 报准备失败。后者有实现，本组未注入全部准备失败分支 |
| LAUNCHER_READY | 第一跳已进入可信静态 launcher 并完成准备，不表示目标已 exec |
| TARGET_EXEC_FAILED | 目标 execve 实际返回 errno；实测 ENOENT=2、EACCES=13、ENOEXEC=8 |
| TARGET_EXEC_ATTEMPT | 可信代码即将调用目标；之后仍可能被杀或发生致命失败 |
| EXEC_STATUS_UNKNOWN | 没有足够的目标成功/失败证据；正常 EOF+wait0 也不能自动升级 |
| TARGET_EXEC_OBSERVED | **只在离线分析层**由对应 PID/路径的 guest `sched_process_exec` 支持；没有接入产品状态 |
| PROCESS_EXITED | 真实 wait 得到的进程退出状态；与 exec 阶段独立 |

12 项正式请求加 1 项独立 Controller 死亡实验，实际覆盖正常静态 launcher、launcher 缺失、目标不存在/无执行权限/格式错、exec 后缺 DSO、工具 0/127、自杀前置 SIGKILL、丢错误帧、launcher 提前退出、超时及输出伪造。不是把若干固定 errno 直接写成预期回执：这些 errno 来自 guest 内实际系统调用返回。

**loader 缺 DSO和工具自行退出 127 在通用产品状态上仍不可区分。** 本组借助自有 fixture 源码、离线 exec 事件和 stderr 可以解释各例，但不信任任意工具的 stderr，也没有声称 loader 已完成。即使有内核 exec 事件，也只证明映像切换经过该内核成功点，不能证明 main 或业务执行成功。

实际 guest 对应 `fs/exec.c` 进一步表明，`do_close_on_exec` 早于 `trace_sched_process_exec`；超过 point_of_no_return 后仍可能致命失败而不能返回 launcher 写 errno。因此 EOF 的歧义不仅是进程被杀的竞态。固定源码与 SHA (`frozen/kernel-evidence/manifest.json`, omitted from this source release)，[Linux execve 文档](https://man7.org/linux/man-pages/man2/execve.2.html)。致命后半程失败是源码确认、未实际注入的路径。

三项进入自有目标 probe 的实际样本只见 FD 0/1/2。合法外观的二进制帧和 JSON 写入 stdout 不影响私有状态。受测路径未发现回执 FD 或管理 FD 进入不可信目标映像；这不是对任意程序、任意 libc 或所有故障窗口的普遍证明。

## 4. B：H 四类反例与最小修订

### B1：大输出与未落盘前缀

旧 H 本来就会持续 drain 并限制保存，基线验证了这一点；本轮没有将原本成功的回收描述成新修复。为实际覆盖 H 的 1 MiB 上限，VM root 在降权前为测试建立两个 2 MiB 匿名 pipe，记录容量和身份；随后 H/R 的权限与登记流程不变，没有修改 sysctl。

固定工具每流写 1.5 MiB，stdout 另有可信 launcher 诊断前缀。R 实际 SIGKILL 后，H 每流保存 1,048,576 字节，仍读完其余数据并明确记录丢弃/截断、真实 EOF、wait/ECHILD 和空 cgroup。新 H 将已知丢弃的 `complete` 置 false，旧版为 null。

前缀例让 R 每流真实读取 4096 字节，仅记录长度和 hash，不保存内容，再死亡。H 的 drained 与消费后的 FIONREAD 相等；缺失前缀没有被重新生成。业务 UNKNOWN、输出 complete=false，与资源 RELEASED 同时成立。

### B2：ENOSPC 和部分写入后 EIO

注入只匹配 H 恢复输出文件的 write，不影响日志和最终 JSON；它是受控错误注入，不是实际损坏宿主磁盘。两个流都实际触发错误。H 继续 drain 至 EOF、真实 wait 至 ECHILD，物理 cgroup/workspace 均清理；`physical_resources_released=true`、`recovery_evidence_complete=false`、总状态 INCOMPLETE。

EIO 例每流实际上已写 4096 字节后才抛错。H 的 `stored_bytes=0` 表示没有确认成功的该次保存，`stored_bytes_exact=false` 表明不精确；不能把它解释成物理文件为零字节，或把逻辑 discarded 当作精确物理丢失量。独立审计核对真实文件长度和故障记录。

尚未注入整个证据盘、最终账本和日志同时不可写；本轮结论不能覆盖这种完全失去持久化证据的失败。

### B3：畸形双流与退休

这是实际 H/R、真实 SCM_RIGHTS/pipe/wait/cgroup 的 **22 项微型协议实验**，不冒充 22 次完整 Tool 跨域任务。新 H 拒绝错误 FD 数量、重复底层 pipe、非 pipe、命名 FIFO、write 端、错误流名/顺序、同 nonce 换对象或对调，以及不完整/伪造 EOF、未退休 DONE、未知操作、畸形 JSON。非法 FD 被关闭，已经接手的有效 read 端继续由 H 负责恢复。

核心新检查为匿名 pipe 身份，以及 RETIRE 时对受托 read 端做不消费数据的 `POLLHUP && FIONREAD==0` 检查。只看 HUP 会漏掉缓冲数据；只看零字节会漏掉仍存活 writer。对应固定内核 `pipe_poll/pipe_ioctl` 源码也已冻结。

合法重复 REGISTER/RETIRE、丢失 RETIRE 和迟到 RETIRE 分别验证。首次收到两个合法匿名 pipe 时，H 无法凭对象判断哪个原先叫 stdout，语义标签仍依赖可信 R；后续对已绑定对象进行交换则拒绝。这个边界实测为接受，不能记成“首次错误身份已被检测”。

迟到 RETIRE 例保留了一条新夹具 FAIL：原始夹具把任何 `protocol_errors` 都当作消息拒绝。实际顺序是 H 独立确认 EOF → RETIRE 成功 → R 死亡导致 recvmsg ECONNRESET → H 真实 wait/ECHILD → UNKNOWN/RELEASED。独立审计按该明确顺序区分传输终止与语义拒绝；原始 false 和早期审计 FAIL 保留于 修订记录 (`analysis/audit-revisions.md`, omitted from this source release)，没有修改实验或放宽 EOF 条件。

### B4：敌意工作区

真实 Tool 造出 FIFO、指向 `/state` 的 symlink、64 MiB 稀疏文件和超过 128 个条目，再实际杀 R。H 不读 FIFO、不跟随 symlink，单文件至多读 65,536 字节，最多枚举 128 项、总内容预算 1 MiB。该例实际采集 128 项和 70,286 字节，快照明确截断；最终资源 RELEASED，业务 UNKNOWN。

另外三例真实权限拒绝：

- 不可读文件：记录 EACCES，但工作区可删除；物理释放 true，总状态 INCOMPLETE。
- 不可读目录：捕获 scandir 的 EACCES，继续其他清理，留下不可安全清理的 work 目录；物理释放 false、INCOMPLETE。
- 不可删子目录：真实删除拒绝，保留残留与私有磁盘；物理释放 false、INCOMPLETE。

这些拒绝没有通过 chmod、增权或观察者代删来变成成功。新例均实际清空 cgroup、完成 wait/EOF；目录残留仍如实保留。最终 VM 关机不算产品删除证据。

## 5. 新发现的产品缺陷、补丁与回归

| 已实际复现的缺口 | 冻结旧例 | 新副本最小处理 |
|---|---|---|
| 原 Tool 无目标私有错误回执，不能可靠归因 exec 失败 | 旧源码合同；本轮补差异案例 | S 私有 pipe + W 第一跳记录 + 原静态 launcher 第二跳 CLOEXEC/错误记录 |
| H 只信 R 的 EOF 声明，可提前退休 | `baseline-false-eof-01`、`baseline-false-open-01` | 受托 read FD 独立 poll/FIONREAD；失败保留清理责任 |
| S_IFIFO 检查接受可按名字重开的 FIFO | `baseline-named-fifo-01` | 要求匿名 `pipe:[inode]`，仍验证读端和对象唯一性 |
| 外层 scandir EACCES 逃出 H，缺失最终账本 | `baseline-scan-denied-01` | 捕获并记录枚举异常，继续可行清理并产出 INCOMPLETE |
| H 已知丢弃/保存失败后 complete 仍为 null，物理与证据维度未分开 | `baseline-h-flood-01`、`baseline-h-enospc-01` | 已知丢失置 false，新增 physical/EOF/evidence 维度，保持总状态严格 |

基线 ENOSPC 本来就能继续清理并返回 INCOMPLETE；不能把字段改善写成修复了原本不存在的进程泄漏。旧 scandir 例没有最终账本，缺失的 wait/FD/清理维度保持未确认，而非推断全部失败或补造 PASS。

源码补丁在 patches/manifest.json (`patches/manifest.json`, omitted from this source release)，包含逐文件前后 SHA。产品接线、H 修订和故障夹具分成三份补丁。`bridge.c`、`bridge_d.c`、`native.c`、Warm/Tool policy、D runtime 和内核都未变。

定向回归为 4 个 Tool 请求、3 个 Warm 正常/非零请求和 1 个 Warm Controller 死亡请求：

- Tool 包含 ELF 正常、G 前取消、stdout 伪造和 Shell 树取消。G 前取消无 launcher/目标 exec，业务 NOT_EXECUTED；Shell 树取消维持真实收养 wait 与双流 EOF。
- Warm 同一 Z 顺序产生三个请求，均通过既有 19 项隔离/继承检查，包括实际 exec_denied；保留 heap 继承和 stdio-only FD。非零 exit 7 没有改写为成功。
- Warm Controller 死亡维持 combined 单流协议、真实 wait/ECHILD 和资源回收，业务 UNKNOWN。新双流 EOF 核验没有破坏原单流路径。
- D 两次 fork 的桥接与 runtime 保持冻结 SHA，原子 cgroup 出生、native/CPython 回调的运行时检查继续在实际 Z/S/W 路径执行。回归不等于完整 glibc 回归或第三方依赖准入。

## 6. 仍然必须保留的限制

1. 没有在线、无歧义的目标 exec 成功事件。私有 EOF+wait0 仍可 UNKNOWN；Controller/S 死亡、回执丢失或无法消除的竞态不补造结果。
2. loader 完成、main 进入和业务成功没有被合并。任意程序的 loader 127 与自行 127 仍无法通用区分。
3. launcher 所有准备失败、半帧/超量/私有 read_error、内核越过 point_of_no_return 后失败未在本组逐一注入。已有严格解析不等于这些分支已获实测资格。
4. 初次 stdout/stderr 语义绑定仍依赖可信 R；H 的 EOF 观测不能推广为恶意管理进程并发重开写端的证明。
5. 全盘故障、日志和最终账本同时不可写、H 自身死亡及长期压力不在本次资格范围。证据不可持久化时不能承诺恢复完整。
6. 不可读/不可删工作区故意留下 INCOMPLETE 与磁盘证据；没有通过提高权限达成无条件清理。

## 7. 对任务五问的直接回答

**1. 哪些 exec 阶段可以可信区分？** 第一跳返回错误、可信 launcher READY、目标尝试、目标返回 errno；另有真实 wait。目标 exec 成功仅有本次离线 kernel 观测，未接入产品状态。动态 loader 完成没有通用可信回执。

**2. 哪些情况仍 UNKNOWN？** 无错误记录的 EOF、exec 前死亡、半途回执丢失、超时或 Controller/S 丢失汇总，以及无法排除的致命失败窗口；有 wait 不自动消除 exec UNKNOWN。R 死亡后的业务结果仍 UNKNOWN。

**3. H 四类反例实际通过了吗？** 四类均已实际执行并按声明范围复核。大输出持续 drain；写错继续清理但 INCOMPLETE；非法双流拒绝；敌意对象有界观察。首次语义对调不可识别、不可删目录保留残留，不能概括为所有异常均完全恢复成功。

**4. 是否发现新的正确性缺陷？** 是：伪 EOF 提前退休、命名 FIFO 被接受、目录枚举失败丢最终账本，以及已知输出损失的表达缺口。最小修订仅在新副本，原 FAIL 保留；迟到 RETIRE 的新夹具误判也明确保留。

**5. 是否保留原合同？** 受影响路径的实际定向回归支持保留 Warm no-exec、两道业务门禁、D 两次派生、真实 wait、EOF 和资源回收。未更改旧策略、内核/glibc D，也未将本轮受限资格扩展为生产级或任意依赖保证。

本轮到此停止；不继续增加架构、控制协议优化、Scheduler 或性能对照。完整复核入口为 README (`README.md`, omitted from this source release)，原始失败和所有源 SHA 随目录保留。
