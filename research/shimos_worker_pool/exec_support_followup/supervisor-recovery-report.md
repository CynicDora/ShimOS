# Supervisor H 异常恢复补充：真实协议、输出和工作区证据

本报告记录工作线 B 的 H 恢复结果，不把另一工作线的 exec 回执设计算作 H 的实现成果。B1、B2、B4、R 已消费前缀、22 项正式 H 协议实验及 3 个 Warm/Tool 回归 VM 均已完成，基线失败和审计修订历史全部保留。所有执行均在私有 VM；本报告和独立核验器只读取已有记录。

## 1. 当前确认了什么

原 H 已经能够在 Controller 死亡后真实收养/wait、继续 drain 两流、限制保存量并清理资源；ENOSPC 注入下原实现也正确保留 INCOMPLETE，没有因为写失败停止进程回收。本轮没有把这些原本已工作的机制描述成新修复。

实际基线复现了三个缺口：

1. RETIRE 仅信 R 的 EOF=true 声明，在 pipe 还有未读数据或写端仍存活时提前关闭 H 的责任 FD并回复 RETIRED。
2. REGISTER 的 `S_ISFIFO` 校验接受了命名 FIFO，未落实“匿名 pipe”的对象合同。此样本证明误接受，不单独证明攻击者已成功利用后来 writer 造成逃逸。
3. 工作区目录的真实 EACCES 从 `os.scandir()` 逃出 H，未生成最终 `supervisor.json`，无法完成原有最终账本合同。

新副本最小修订上述三处，并收紧两类结果语义：已知丢弃/读写错误的 `complete=false` 不再被后续 drain 重置为 null；物理资源释放与恢复证据错误分别记录。总体 INCOMPLETE 条件没有放宽，业务 UNKNOWN 没有因为文件、EOF 或 cgroup 删除而升级。

这是固定环境、可信 H/R 和受控错误注入下的机制资格，不是对恶意 Controller、任意文件系统故障或生产级通用恢复的证明。

## 2. 来源、冻结与实际运行边界

旧实验 `exec_support/` 不修改。基线运行由新 runner 的 `--supervisor-baseline` 将 冻结原 H (`frozen/prototype/supervisor.py`, omitted from this source release) 复制到该 VM 的运行目录；新运行使用 [supervisor.py](prototype/supervisor.py)。各 run 的 `source-sha.json`、`prototype/`、环境、构建记录与 D runtime SHA 保留独立身份。

| H 版本 | SHA-256 |
|---|---|
| 冻结原 H | `ccba4cba231111d14e2d4aa61cf56127f468bf07c1a8d76314faf8aade31873c` |
| 本轮修订 H | `6b30661c54c87f61632004f1dea541e64adf8cad80c951f5b34ff76596514001` |

`baseline-h-flood-01` 与 `h-flood-01` 的 `source-sha.json` 仅 `supervisor.py` 不同；不能据此将整个新实验目录与旧轮所有文件称为完全相同。实际 H 无 guest root 权限，使用原委托 cgroup、subreaper、NNP 和真实父子关系。VM root 只做既有隔离夹具准备、记录和空外层委派收尾；不补杀产品进程、不代删产品工作区。

两类执行证据须分开：

- **真实 Tool 恢复**：R→Z→S→W 在目标域内执行固定 [recovery_probe.c](tools/recovery_probe.c)，R 在受控故障点 SIGKILL，实际 H 接管。B1、B2、B4 使用这条路径。
- **H 微型协议夹具**：[supervisor_protocol_fixture.py](tools/supervisor_protocol_fixture.py) 使用真实 H/R fork、SOCK_SEQPACKET、SCM_RIGHTS、委托 cgroup 和实际 wait，专门注入错误消息。它没有完整 Bubblewrap Tool 域，不冒充完整业务路径。

运行命令见各 run 的 `command.json`/`guest-command.sh` 与 基线账本 (`analysis/baseline-run-ledger.json`, omitted from this source release)、初始补充账本 (`analysis/initial-followup-ledger.json`, omitted from this source release)、候选资格账本 (`analysis/qualification-candidate-01-ledger.json`, omitted from this source release)。最终验收应读取原始证据与对应离线审计，不能只看 VM driver 返回值。

最终权威索引是 final-audit-01/summary.json (`analysis/final-audit-01/summary.json`, omitted from this source release)、覆盖与原始 false 记录 (`analysis/final-audit-01/coverage.json`, omitted from this source release)、逐 VM 矩阵 (`analysis/final-audit-01/qualification-matrix.json`, omitted from this source release)、逐请求结果 (`analysis/final-audit-01/requests.json`, omitted from this source release) 和 逐 H 输出流 (`analysis/final-audit-01/H-streams.json`, omitted from this source release)，另有同名 CSV。整个 followup（包括工作线 A）共 42 个 VM：6 个基线、1 个先导、32 个正式资格和 3 个回归；最终选定审计为 36 PASS / 6 基线 FAIL。正式资格与回归共 35 个 VM，含 29 个业务请求（25 Tool、4 Warm）及另外 22 项纯 H 协议实验，不能相加成同类业务任务。正式产品结果中的 5 个 INCOMPLETE 均保留，审计 PASS 只表示符合该故障实验合同。审计断言含重复 SHA 检查，不是独立测试数或生产安全度量。

审计选择 (`analysis/final-audit-01/audit-selection.json`, omitted from this source release) 使用每个 run 最高明确版本；全部历史 (`analysis/final-audit-01/audit-history.json`, omitted from this source release) 保留早期失败，下文引用的早期逐例审计不被覆盖。最终输入 SHA 列表见 input-sha256.json (`analysis/final-audit-01/input-sha256.json`, omitted from this source release)。

## 3. 基线失败与修订方式

| 原始运行 | 确认事实 | 修订及范围 |
|---|---|---|
| baseline-false-eof-01 (`runs/baseline-false-eof-01/protocol-fixture-controller-events.jsonl`, omitted from this source release) | R 尚持有 writer、两流仍有数据时收到 RETIRED，记录 FALSE_EOF_WAS_ACKNOWLEDGED；H RELEASED | RETIRE 在关闭任何责任 FD 前用 H 持有对象独立确认 EOF |
| baseline-false-open-01 (`runs/baseline-false-open-01/protocol-fixture-controller-events.jsonl`, omitted from this source release) | 没有积压数据但 writer 仍存活，仍被确认 RETIRED | FIONREAD==0 不足，必须同时有 POLLHUP |
| baseline-named-fifo-01 (`runs/baseline-named-fifo-01/protocol-fixture-controller-events.jsonl`, omitted from this source release) | 命名 FIFO 被接受 REGISTER，H RELEASED | 除 FIFO 类型与只读端，还核对 `/proc/self/fd/N` 为匿名 `pipe:[inode]` |
| baseline-scan-denied-01 (`runs/baseline-scan-denied-01/protocol-fixture-h-events.jsonl`, omitted from this source release) | chmod000 工作区触发 PermissionError(13)；H 异常退出，无最终 supervisor.json | 捕获目录枚举创建/迭代异常，记录错误并继续其余回收；不 chmod 绕过拒绝 |

独立基线审计保留为 伪 EOF buffered (`analysis/verify-baseline-false-eof-01-v1.json`, omitted from this source release)、伪 EOF open writer (`analysis/verify-baseline-false-open-01-v1.json`, omitted from this source release)、命名 FIFO (`analysis/verify-baseline-named-fifo-01-v1.json`, omitted from this source release)、枚举异常 (`analysis/verify-baseline-scan-denied-01-v2.json`, omitted from this source release)。它们仍为 FAIL；缺失最终 H 账本的维度标为不可完成核验，而非凭空推断全部资源事件。枚举审计的早期 v1 也保留，不能以缺少字段直接断言观察者真的补杀过进程。

`_pipe_eof_state()` 同时要求 `POLLHUP`、`FIONREAD==0` 且没有 POLLERR/POLLNVAL，整个检查不消费输出。POLLHUP 单独可能仍有缓冲内容；零字节单独可能仍有 writer。拒绝伪 EOF 后保留已登记 FD，由原恢复路径停 R/创建者再 drain，不让错误消息卸除责任。

固定 guest 内核源码依据为提交 `1c732c6b94f0faee1526bd375add2fe10cba2e26` 的 fs/pipe.c (`frozen/kernel-evidence/fs/pipe.c`, omitted from this source release)：`pipe_ioctl()` 的 FIONREAD 分支在 pipe mutex 内累加 buffer 长度；`pipe_poll()` 在没有 writer 且 writer 计数条件满足时报告 EPOLLHUP。`alloc_pipe_info()` 初始化 writer counter，`create_pipe_files()` 将匿名 pipe 文件的 `f_pipe` 初始化为 0。完整文件与该提交一致及 SHA 记录在 manifest (`frozen/kernel-evidence/manifest.json`, omitted from this source release)。这支持匿名 pipe 的非消费检查，不推广到所有 FD，也不替代可信 R/创建者终止合同；不能用两个分开的观测宣称隔离任意恶意发送方的重新开写竞态。

正常 RETIRE 新增 `retire_eof_observation` 和 `SUPERVISOR_RETIRE_EOF_CONFIRMED`；失败记录 `SUPERVISOR_RETIRE_EOF_REJECTED`。正常流的 `eof_source=supervisor_retire_poll`。外部 REGISTER/RETIRE/DONE 参数格式不变，同一对象重复登记和已退休请求重复 RETIRE 保持原有兼容行为。

## 4. B1：真实触发 H 的两流保存上限

H 先停止/kill 再 drain，默认 pipe 容量通常无法留下超过 1 MiB 的积压；只让工具“计划输出很多”并不能覆盖 H 的截断分支。本例由 **VM root 夹具**为每流设置并确认 2 MiB pipe，未修改 sysctl、未授予 H/W 新能力。实际容量和 UID 保存在 `fixture-pipe-preparation.json`。

[supervisor_faults.py](prototype/supervisor_faults.py) 的显式 `install_prefork_pipe_transfer()` 仅把已建 FD 交给真实 R：H 首次 fork 后父分支关闭全部四个夹具副本，之后仍经真实 REGISTER 取得两个 readFD。初始库存排除这四个声明的传输 FD，原库存和关闭事件另存；最终库存不做过滤，不能用编号复用掩盖泄漏。正常产品不安装这一夹具钩子。

R 不读取业务输出，Tool 每流写 1.5 MiB 后停留；R 死前 FIONREAD 积压量与 H 最终 drained 完全一致。对照 旧 H (`runs/baseline-h-flood-01/supervisor.json`, omitted from this source release) 与 新 H (`runs/h-flood-01/supervisor.json`, omitted from this source release)：

| 流 | H 实际读到 | 实际恢复文件 | 丢弃/未保存 | 旧 complete | 新 complete |
|---|---:|---:|---:|---|---|
| stdout | 1572933 | 1048576 | 524357 | null | false |
| stderr | 1572864 | 1048576 | 524288 | null | false |

stdout 多出的 69 字节是固定 launcher 诊断前缀，随后是 O；stderr 是 E。实际文件长度与前缀内容核对相符。不同 run 的时间戳位数可能使该前缀长度相差一字节，不能跨 run 固定总数。

新 H 两流 EOF、实际 wait/ECHILD、空域、FD 恢复和删除成立，`physical_resources_released=true`、`recovery_evidence_complete=true`，最终 RELEASED / UNKNOWN；内容因正常有界丢弃而明确不完整。这不是业务成功。旧 H 已经正确执行有界保存与继续 drain，其 基线审计 FAIL (`analysis/verify-baseline-h-flood-01-v1.json`, omitted from this source release) 指向新合同下的已知丢弃完整性语义；新 H 审计 (`analysis/verify-h-flood-01-v1.json`, omitted from this source release) 为 PASS。

### R 已消费但未保存的前缀

h-flood-prefix-01 (`runs/h-flood-prefix-01/supervisor.json`, omitted from this source release) 使用同一 H，明确增加的 R 夹具先从每流真正读取 4096 字节，只记录长度和 SHA、不保存内容，再 SIGKILL。对应 `run.py`/`tool_cases.py` 与无前缀例不同，源身份按本次 run 保存，不能合称完全相同执行器源码的对照。

R 记录的剩余 FIONREAD 与 H drained 一致：stdout=1568837、stderr=1568768，各比无消费数据少 4096。H 保存的 stdout 文件从 O 开始，原 launcher 前缀已随 R 消费而消失；stderr 也只来自剩余数据。H 不能从 pipe 再取回那段内容，前缀 hash 不是原始字节的恢复。

此例仍达到两流 EOF、真实 wait/ECHILD、空域与资源删除，RELEASED / UNKNOWN。两流还存在 H 保存上限丢弃，因此 `complete=false`；不能因为 H 完成后缀 drain 就声称整个输出完整。独立 478 项证据审计 (`analysis/verify-h-flood-prefix-01-v1.json`, omitted from this source release) 为 PASS，这一请求单列，不覆盖原无前缀样本。

## 5. B2：只针对恢复文件的写入错误

注入仅匹配安装它的 H PID、严格命名的恢复输出文件和 `.write()`，不影响 `supervisor.json`、H 事件或注入日志。这是受控 errno 注入，不是真实磁盘耗尽或介质故障。目标、errno 和部分写入量见各 run 的 `fault-injection-events.jsonl`；健康日志路径使真实失败仍可审计。

| 运行 | 实际写入效果 | 内容状态 | 资源 / 总状态 |
|---|---|---|---|
| baseline-h-enospc-01 (`runs/baseline-h-enospc-01/supervisor.json`, omitted from this source release) | 两流首次写入 ENOSPC；文件各 0 字节；继续 drain 到 EOF | 旧 complete=null | 实际无目录/cgroup遗留、ECHILD；总体正确为 INCOMPLETE |
| h-enospc-01 (`runs/h-enospc-01/supervisor.json`, omitted from this source release) | 两流 ENOSPC；文件各 0 字节；继续 drain 到 EOF | complete=false | physical=true、evidence=false、INCOMPLETE / UNKNOWN |
| h-eio-partial-01 (`runs/h-eio-partial-01/supervisor.json`, omitted from this source release) | 两流各先实际写入 4096 字节再 EIO；继续 drain 到 EOF | complete=false | physical=true、evidence=false、INCOMPLETE / UNKNOWN |

部分 EIO 的 `stored_bytes=0` 是 H 未收到成功 write 返回后的**已确认**计数，`stored_bytes_exact=false` 明确它不是实际磁盘长度。两个文件确实各有 4096 字节，注入日志 `partial_bytes=4096` 与其一致。此时 `discarded_bytes` 是未确认保存的字节数，不能报告为精确物理丢失量，更不能说实际文件为零。

三次均保持错误证据，真实 wait/ECHILD、双 EOF、最终 FD 与空域删除继续成立；观察者无补清理。旧 `resources_removed=false` 混合了物理释放和证据失败，新字段解释两者而不改变总体失败结论。审计：旧 ENOSPC (`analysis/verify-baseline-h-enospc-01-v1.json`, omitted from this source release)、新 ENOSPC (`analysis/verify-h-enospc-01-v1.json`, omitted from this source release)、部分 EIO (`analysis/verify-h-eio-partial-01-v2.json`, omitted from this source release)。旧 FAIL 中“证据维度未显式记录”不等于旧 H 没有生成任何错误日志；原 H 的 errors/INCOMPLETE 已真实存在。

## 6. B3：协议故障覆盖和不可独立判断的身份

修订版已完成下列 22 项真实 H 微型协议实验。全部最终独立审计符合各自实验合同；具体断言和选定版本由上节最终矩阵索引。17 项错误消息被拒绝，3 项正向兼容/声明绑定样本被接受，另外验证丢失 RETIRE 和合法 RETIRE 排队后 R 死亡。所有样本最终真实 wait/ECHILD、FD 库存恢复、资源释放，无观察者补清理。

| 实际 case / 原始 H 账本 | 判定与责任结果 |
|---|---|
| missing_fds (`runs/protocol-register-missing-fds-01/supervisor.json`, omitted from this source release)、extra_fd (`runs/protocol-register-extra-fd-01/supervisor.json`, omitted from this source release) | 拒绝 FD 数目与命名流不一致；未登记流 |
| duplicate_pipe (`runs/protocol-register-duplicate-pipe-01/supervisor.json`, omitted from this source release) | 拒绝两个 FD 指向同一底层 pipe；未登记流 |
| nonpipe (`runs/protocol-register-nonpipe-01/supervisor.json`, omitted from this source release)、write_end (`runs/protocol-register-write-end-01/supervisor.json`, omitted from this source release)、named_fifo (`runs/protocol-register-named-fifo-01/supervisor.json`, omitted from this source release) | 分别拒绝类型、读端权限、非匿名 pipe；未登记流 |
| bad_names (`runs/protocol-register-bad-names-01/supervisor.json`, omitted from this source release)、bad_order (`runs/protocol-register-bad-order-01/supervisor.json`, omitted from this source release) | 拒绝 metadata 中流名/声明次序错误；未登记流 |
| malformed_json_with_fd (`runs/protocol-malformed-json-with-fd-01/supervisor.json`, omitted from this source release)、unknown_op_with_fd (`runs/protocol-unknown-op-with-fd-01/supervisor.json`, omitted from this source release) | 拒绝 JSON/未知操作且传入 FD 不泄漏；未登记流 |
| same_nonce_new_pipe (`runs/protocol-register-same-nonce-new-pipe-01/supervisor.json`, omitted from this source release)、same_nonce_swapped_pipe (`runs/protocol-register-same-nonce-swapped-pipe-01/supervisor.json`, omitted from this source release) | 拒绝已绑定对象改变；保留原责任，恢复时确认两流 EOF |
| identical_duplicate (`runs/protocol-register-identical-duplicate-01/supervisor.json`, omitted from this source release) | 相同 nonce、原对象重复登记兼容；随后正常两流 RETIRE |
| first_swapped_pipe (`runs/protocol-register-first-swapped-pipe-01/supervisor.json`, omitted from this source release) | 按 R 的首次声明绑定，正常两流 RETIRE；原语义身份另列 BLOCKED_UNOBSERVABLE |
| retire_missing_stream (`runs/protocol-retire-missing-stream-01/supervisor.json`, omitted from this source release)、retire_false_stream (`runs/protocol-retire-false-stream-01/supervisor.json`, omitted from this source release) | 拒绝缺少两流 EOF=true 的声明；不提前退休，恢复两流 EOF |
| retire_fake_eof_buffered (`runs/protocol-retire-fake-eof-buffered-01/supervisor.json`, omitted from this source release)、retire_fake_eof_open_writer (`runs/protocol-retire-fake-eof-open-writer-01/supervisor.json`, omitted from this source release) | H 独立 EOF 检查拒绝伪声明；保留 FD，再由恢复实际读到两流 EOF |
| retire_duplicate (`runs/protocol-retire-duplicate-01/supervisor.json`, omitted from this source release) | 首次正常 EOF 核验后退休；重复 RETIRE 保持兼容 |
| retire_dropped (`runs/protocol-retire-dropped-01/supervisor.json`, omitted from this source release) | R 正常退出但没有 RETIRE/DONE；H 恢复两流 EOF，业务仍 UNKNOWN |
| retire_late_queued (`runs/protocol-retire-late-queued-01/supervisor.json`, omitted from this source release) | 合法 RETIRE 先被确认，随后 R 死亡/传输重置；整体业务 UNKNOWN，细节见下文 |
| done_unretired (`runs/protocol-done-unretired-01/supervisor.json`, omitted from this source release) | 拒绝存在未退休责任的 DONE；H 自行恢复两流 EOF |

前 10 项未成功 REGISTER 的样本没有已登记输出责任，逐 attempt 的 `output_eof=null`，不能宣称它们也观测了两个有效业务流的 EOF。其余 12 项都具备实际登记的两个 pipe，并由正常 RETIRE 独立检查或 H 恢复 read 确认 EOF。所有已拒绝消息与丢失/排队后故障路径保持整体 UNKNOWN；三个正向样本的 CONTROLLER_REPORTED/FIXTURE_ONLY 仅是协议夹具结果，不是外部业务成功。

可执行夹具还定义了本批未运行的分支，例如 `register_path_identity` 和额外 workspace 微型用例；不能把全部已编写 case 计作 22 项之外的覆盖。设计与 case 定义见 测试设计 (`docs/supervisor-test-design.md`, omitted from this source release) 与 [夹具源码](tools/supervisor_protocol_fixture.py)。独立核验读取具体拒绝、FD、实际 wait、EOF、资源事件和最终状态，不只信夹具 verdict。

**首次交换两个合法新 pipe 的语义无法由 H 独立判断。** 两个对象本身没有“stdout”和“stderr”标签；H 只能将可信 R 声明的顺序绑定到名字。该控制例最多证明按声明绑定与最终收尾，不能把不可观察的原始语义身份写成 PASS。独立审计 v3 (`analysis/verify-protocol-register-first-swapped-pipe-01-v3.json`, omitted from this source release) 与最终矩阵在 `unsupported_dimensions` 明确记录 `first_registration_semantic_stream_identity=BLOCKED_UNOBSERVABLE`。同 nonce 已建立映射后更换/交换对象则已实际验证并拒绝。

合法 RETIRE 已排队而 R 随后死亡，与伪 EOF 是两回事：若资源实际已删、两流确已结束，H 可以确认已完成的责任，但整体 R 故障业务仍 UNKNOWN。丢失 RETIRE 则必须由 H 自己 drain 和确认资源。

已出现的 protocol-retire-late-queued-01 原事件 (`runs/protocol-retire-late-queued-01/supervisor-events.jsonl`, omitted from this source release) 明确先记录两流 `poll_flags=16`、`unread_bytes=0` 的 EOF 确认和 ATTEMPT_RETIRED，之后因 R SIGKILL 发生 recvmsg ConnectionResetError(104)，最终真实 wait R status=9、ECHILD、UNKNOWN / RELEASED。原 fixture verdict (`runs/protocol-retire-late-queued-01/protocol-fixture-verdict.json`, omitted from this source release) 为 false，因为它把所有非空 protocol_errors 都当作“消息校验拒绝”。这是夹具分类过粗，不能描述成 H 拒绝合法 RETIRE；应保留原 false，用具体退休、传输中断和恢复证据进行独立复核，不全局豁免 protocol_errors，也不修改冻结产品来美化这个计数。

该原始 false 与 早期独立审计 v1 FAIL (`analysis/verify-protocol-retire-late-queued-01-v1.json`, omitted from this source release) 均保留；最终 v3 (`analysis/verify-protocol-retire-late-queued-01-v3.json`, omitted from this source release) 只对上述确定时序细分“合法退休”和随后 ECONNRESET，439 项证据断言通过。它没有抹掉 protocol_errors；逐 attempt 已有 FIXTURE_ONLY 记录也没有被伪称全部改写为 UNKNOWN，UNKNOWN 是最终整体 R 故障结果。

## 7. B4：敌意对象、有界快照和真实权限拒绝

这些样本通过真实 Tool 路径创建对象并使 R 死亡。快照只作诊断，不作为可信业务结果。

| 运行 | 实际观测 | 物理资源释放 | 总体 |
|---|---|---|---|
| h-hostile-01 (`runs/h-hostile-01/supervisor.json`, omitted from this source release) | FIFO 不读；symlink 只记录 `/state`；64 MiB sparse 只读 65536 字节；超过 128 个条目，只记录 128 项/70286 内容字节，明确截断 | true | RELEASED / UNKNOWN |
| h-unreadable-file-01 (`runs/h-unreadable-file-01/supervisor.json`, omitted from this source release) | 常规文件 chmod000 后真实读取 EACCES；记录错误，目录仍可删除 | true | INCOMPLETE / UNKNOWN |
| h-unreadable-dir-01 (`runs/h-unreadable-dir-01/supervisor.json`, omitted from this source release) | scandir EACCES 被捕获并最终持久记录；删除也 EACCES | false，工作区残留 | INCOMPLETE / UNKNOWN |
| h-undeletable-01 (`runs/h-undeletable-01/supervisor.json`, omitted from this source release) | 不可访问子目录导致 rmtree EACCES | false，工作区残留 | INCOMPLETE / UNKNOWN |

上述都完成真实 wait/ECHILD、双流 EOF、最终 FD 0/1/2 和 cgroup 清理。后两例**没有完成工作区删除**；外层空 cgroup 委派删除不能改变此事实。原失败磁盘保留，未提升 H 权限、修改目标权限或由观察者代删。

独立审计分别为 hostile (`analysis/verify-h-hostile-01-v1.json`, omitted from this source release)、文件拒绝 (`analysis/verify-h-unreadable-file-01-v1.json`, omitted from this source release)、目录枚举拒绝 (`analysis/verify-h-unreadable-dir-01-v1.json`, omitted from this source release)、删除拒绝 (`analysis/verify-h-undeletable-01-v1.json`, omitted from this source release)。此处 PASS 表示符合既定错误合同；INCOMPLETE/残留不是“清理成功”。

实际 Tool 的 sparse 为 64 MiB，不是另一个微型协议夹具中尚未运行的 1 TiB 例。当前 70286 字节也未触发 1 MiB 内容总量上限；不能由单文件/条数边界覆盖推导所有上限分支都已执行。

## 8. Warm 与 Tool 回归

3 个回归 VM 使用相同运行源码清单 SHA `82b608bbbbaa6d895f543dd515d30c84b52171d57e30d6f2fc722899ca62f577`，H 均为第 2 节修订版本；完整源清单与 D runtime 各自留存在 run 中。回归只覆盖下表，不代替重跑旧轮全部资格。

| 运行与审计 | 实际任务与业务结果 | H 兼容与回收结果 |
|---|---|---|
| tool-regression-01 (`runs/tool-regression-01/summary.json`, omitted from this source release) / 独立审计 (`analysis/verify-tool-regression-01-v1.json`, omitted from this source release) | 同一 Z 服务静态 ELF、业务门前取消、输出伪造、Shell 取消；依次 SUCCEEDED/KNOWN/0、CANCELLED/NOT_EXECUTED、SUCCEEDED/KNOWN/0、CANCELLED/KNOWN/-9 | 4 请求各有 9 项 Tool 域/降权/FD 检查；真实 W wait 或收养 wait、两流 EOF、资源删除；4 次 RETIRE 均由 H 独立 poll 确认；H RELEASED |
| warm-regression-01 (`runs/warm-regression-01/summary.json`, omitted from this source release) / 独立审计 (`analysis/verify-warm-regression-01-v1.json`, omitted from this source release) | 同一 Z=318 顺序服务 normal、normal、nonzero；真实 W exit 为 0、0、7 | 每次原有 19 项检查全 true，含 Python heap 继承、未重建、exec_denied；单 combined pipe 的正常 RETIRE 均独立 poll 确认；H RELEASED |
| warm-controller-death-01 (`runs/warm-controller-death-01/supervisor.json`, omitted from this source release) / 独立审计 (`analysis/verify-warm-controller-death-01-v1.json`, omitted from this source release) | Warm R 被 SIGKILL，无正常最终业务行；整体 UNKNOWN | H 真实 wait R status=9、收养 wait、ECHILD；只有 1 个 combined 流，H read 得到 EOF；资源删除、最终 FD 一致，H RELEASED |

三次 H 均为 `physical_resources_released=true`、`output_eof_confirmed=true`、`recovery_evidence_complete=true`，errors/protocol_errors 为空，观察者没有补清理。Tool 和正常 Warm 有合法 DONE 与 R wait=0；Warm 死亡没有 DONE。原 Tool H 账本 (`runs/tool-regression-01/supervisor.json`, omitted from this source release)、Warm H 账本 (`runs/warm-regression-01/supervisor.json`, omitted from this source release) 保留逐流观测与真实 wait。

门前取消的 -9 是 W/bootstrap 的实际 wait，目标没有业务许可，不能称“业务返回 -9”。Shell 取消保留目标 wait=-9 和取消语义；私有 exec 状态即使仍 UNKNOWN 也不被 H 的 EOF/RELEASED 改写。输出伪造的内容只作为普通数据，不能产生管理回执。Tool 首次 exec 及 loader 的判断边界属于工作线 A，不因本表回归而获得新的在线成功证明。

Warm 死亡的 H 恢复流为 `eof_source=supervisor_read`，本次剩余 drained=0、stored=0、discarded=0、`complete=null`。它只证明剩余 pipe 到 EOF，不能推断 R 生前已读数据均持久化。逐请求账本缺少正常完成行与 H 最终回收成功同时成立；不能用 H 资源结果补造业务退出码。正常 Warm 的单流路径也未被强制改成 Tool 双流协议。

## 9. 最终字段解释

| 字段 | 含义与本轮边界 |
|---|---|
| `physical_resources_released` | 无 cgroup/workspace 遗留，真实 ECHILD，最终 FD 库存一致；不表示业务成功或所有输出已保存 |
| `output_eof_confirmed` | 全部已登记流的 EOF 成立；不表示应用协议完成 |
| `recovery_evidence_complete` | EOF 成立且没有恢复错误；不等于输出完整、全部诊断内容未截断或介质断电耐久 |
| `release_state` | 上述要求全部成立才 RELEASED，否则 INCOMPLETE；既有 `resources_removed` 继续保持总体语义 |
| `output_streams[*].complete` | 已知丢弃/读写错误为 false；没有已知丢失但 R 前缀可能未持久化时为 null；H 恢复不凭 EOF 设置 true |
| `stored_bytes_exact` | false 时逻辑已确认保存计数不能冒充实际文件长度，部分 EIO 已实际验证此区别 |
| `business_result` | R 故障整体保持 UNKNOWN；副作用、回收、EOF、输出 marker 不补造退出码 |

有界正常截断允许资源 RELEASED 且内容不完整；写入或观察失败则总体 INCOMPLETE。无法删除的目录同时使物理释放 false。这三个结果必须分别呈现。

## 10. 当前限制与证据边界

- 本轮已完成的协议、真实 Tool 恢复与 Warm/Tool 回归范围以上述原始运行和最终矩阵为准；原 FAIL、夹具 false、被后续细分的审计版本全部保留。
- H 本身死亡、日志与最终账本路径整体不可写、宿主/VM 崩溃、不可中断内核任务、文件系统永久阻塞不在已验证恢复范围。正常文件 O_NONBLOCK 不提供任意故障介质上的有限耗时保证。
- 深层敌意目录、挂载点、海量未采样组合与长期并发没有由本轮覆盖。权限拒绝下保留 INCOMPLETE 是当前真实合同，不伪装成无条件完整清理能力。
- H/R 仍是可信管理代码；匿名 pipe 和 EOF 核验提高错误消息下的责任完整性，不构成恶意 Controller 隔离。初次 stdout/stderr 语义映射仍依赖可信发送方。
- 不重新运行全部旧轮资格，也不将本轮受控 pipe 容量、fault hook 或固定 probe 作为最终架构要求。没有性能 Benchmark、调度器或真实第三方依赖准入。

实现细节、接口与初始计划见 supervisor-test-design.md (`docs/supervisor-test-design.md`, omitted from this source release)；源码事实、实际缺陷与后续原始证据复核见 supervisor-source-review.md (`docs/supervisor-source-review.md`, omitted from this source release)。原代码、JSON/trace/CSV、错误日志和磁盘均通过对应 run 索引保留，本报告不覆盖它们。
