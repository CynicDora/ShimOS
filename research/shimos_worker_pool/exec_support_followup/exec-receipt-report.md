# Tool Exec 补充 A：两阶段私有 exec 回执

## 1. 当前结论与范围

**候选已实现，并通过固定环境中的 12 项回执资格及 1 项 Controller 死亡实验。** 私有通道能区分第一跳 launcher exec 返回失败、第二跳目标 exec 返回失败，并带回实际 errno；不会因为 EOF、目标输出或主进程退出 0 就声称目标 exec 成功。未发现受测路径将回执或管理 FD 泄漏到目标映像。

证据为两个独立私有 VM：

- receipt-qualification-01 (`runs/receipt-qualification-01/`, omitted from this source release)：同一 Z=320 顺序处理 12 个请求；最终 v4 独立审计 (`analysis/verify-receipt-qualification-01-v4.json`, omitted from this source release) 为 PASS，855 条证据检查。
- receipt-controller-death-01 (`runs/receipt-controller-death-01/`, omitted from this source release)：1 个故障请求；最终 v2 独立审计 (`analysis/verify-receipt-controller-death-01-v2.json`, omitted from this source release) 为 PASS，451 条证据检查。

这是 A 专项的 13 次请求、1306 条检查，检查数不是独立攻击场景数或统计可靠性指标；pilot 不计入上述数量。报告只读取冻结源码、原始回执、wait/输出/trace 和审计记录，没有运行新实验或修改产品。

**新候选的 Tool/Warm 补充回归现已完成并通过独立审计**，单列为另外 3 VM / 8 请求，未增加 A 专项的 13 次计数：

| 回归 | 实际覆盖与结果 | 独立审计 |
|---|---|---|
| tool-regression-01 (`runs/tool-regression-01/`, omitted from this source release) | 4 请求：固定 ELF、G 前取消、真实 nonce 输出伪造、Shell 取消；分别保持 SUCCEEDED、NOT_EXECUTED/CANCELLED、SUCCEEDED、CANCELLED，四次都双 EOF、RELEASED、R FD 8→8。无私有失败帧时 exec 状态仍 UNKNOWN；G 前取消没有工具 exec。 | v1 PASS，556 检查 (`analysis/verify-tool-regression-01-v1.json`, omitted from this source release) |
| warm-regression-01 (`runs/warm-regression-01/`, omitted from this source release) | 同一 Z318 顺序服务 W322/W328/W333；normal/normal/nonzero 的原 19 项检查各全真，真实 wait 为 0/0/7；三次 execve 均 -EPERM，无成功 W exec。使用原单路输出与 Python heap 继承，H 最终 ECHILD、RELEASED。 | v1 PASS，464 检查 (`analysis/verify-warm-regression-01-v1.json`, omitted from this source release) |
| warm-controller-death-01 (`runs/warm-controller-death-01/`, omitted from this source release) | W324 的原 19 项检查全真、execve=-EPERM；H318 真实 wait 被杀的 R319，再收养/wait 320/321/322/323，最终 ECHILD、RELEASED。业务保持 UNKNOWN，combined EOF=true、complete=null，恢复读取 0 字节；不宣称恢复了 R 已读输出或取得 W 的精确 wait 状态。 | v1 PASS，439 检查 (`analysis/verify-warm-controller-death-01-v1.json`, omitted from this source release) |

三个回归使用候选 02 的 `run.py` SHA `260e81d7d79c2877c3c5974e630136c4593749a22e6491a5ea8a84ec2d006fcd`；A 回执的 `zygote.py`、launcher、decoder 和 H 与其已记录冻结版本一致。新回归实际记录支持 Warm no-exec 与生命周期兼容，未用旧实验替代；它们不覆盖下面列出的 launcher 准备失败、坏帧/读写异常或长期并发。三个 H 账本均无错误、FD 恢复，外层记录均无观察者补清理。

## 2. 实际接线与安全边界

调用链保留原 Z→S→W 两次 D fork、namespace/root 切换、原子 cgroup 出生与业务许可：

```text
S 在第二次 D fork 前创建 O_CLOEXEC 私有 pipe
  ├─ S：仅保留 read；真实 wait W 后有界读取并解析
  └─ W：仅保留 write；最终降权 / Tool filter / ready / G
         → Python 写 LAUNCHER_EXEC_ATTEMPT
         → write FD 临时 inheritable=true
         → exec 静态 launcher
             → main 首先给该 FD 设置 CLOEXEC
             → 验证 pipe、零权限、NNP/seccomp，清理其他 FD
             → LAUNCHER_READY → TARGET_EXEC_ATTEMPT → exec 目标
                  ├─ 返回 errno：私写 EXEC_FAILED，退出 127
                  └─ 不返回：目标不继承回执 FD；EOF 本身仍非成功证明
S → 私有 WORKER_WAITED（wait + exec_receipt）→ R
工具 stdout/stderr → 独立字节流，不进入上述解析
```

实际源码以该次 run 的冻结副本为准：

| 位置 | 核对结果 |
|---|---|
| zygote.py (`runs/receipt-qualification-01/prototype/zygote.py`, omitted from this source release) `transition()` | S 在目标域、早期降权和 START_WORKER 后创建 `pipe2(O_CLOEXEC)`。W 的 `close_except` 关闭 read，S 的父分支关闭 write；Z/R/H 没有该 write 端。失败路径关闭临时 FD。 |
| 同文件 `tool_worker()` | 最终 FD allowlist 从 stdio+gate+ready 增加唯一 receipt write。完成 drop/filter/身份检查后等待 G，读完即关闭 gate；随后写第一跳尝试帧、设 inheritable、exec launcher。缺失 launcher 返回 OSError 后私写 errno，再退出 **125**。 |
| tool_launcher.c (`runs/receipt-qualification-01/prototype/tool_launcher.c`, omitted from this source release) `main()` | ABI 为 `launcher --receipt-fd N --fault MODE -- /absolute/target args...`；先定位 fd 并设 CLOEXEC，验证 FIFO/pipe 与 O_WRONLY，设 O_NONBLOCK；保留 stdio+receipt，其他 fd≥3 用两段 close_range 清理。无 setns/mount/cgroup 迁移或重新授权。 |
| 同文件 `verify_security()` / `reset_signals()` | 五组 capabilities 必须为 0，NNP=1、Seccomp=2；重置信号处置和 mask。具体 filter 身份依赖已冻结 Tool 策略与前置 W 检查，不能只从 Seccomp=2 推断。 |
| `transition()` 的 wait 后分支 | 真实 `waitpid(W)` 后，把 read 端设非阻塞，最多读取 193 字节以检测 192 字节上限溢出；关闭 read，解析并保存 `raw_hex`；通过私有 WORKER_WAITED 报告。错误时不阻塞等待未知写者，也不补造成功。 |
| run.py (`runs/receipt-qualification-01/prototype/run.py`, omitted from this source release) `Controller.domain()` | 初始回执为空、`EXEC_STATUS_UNKNOWN`；只有 S 私有 WORKER_WAITED 才覆盖该字段。R 自行收养 wait 并不补造丢失的回执；stdout/stderr 的 Tool 分支只处理字节。原始回执另外保存为 `*-exec-receipt.bin`。 |
| tool_runtime.py (`runs/receipt-qualification-01/prototype/tool_runtime.py`, omitted from this source release) `validate_tool()` | 校验固定 fixture 的预期 status/errno，要求 `success_observed=false`。fixture checks 是离线/测试判断，不是工具可以发送的控制消息。 |

私有 pipe 的请求绑定来自 S 持有的对象，不来自日志里的 magic、nonce 或阶段名称。launcher 的 READY 只证实第一跳已进入可信 launcher 并完成准备；不能据此声称第二跳已发生。第一跳 Python audit hooks、D/native callbacks、静态 launcher 启动代码仍属于可信计算基础。

初版设计说明 (`docs/exec-receipt-design-review.md`, omitted from this source release)把第一跳失败退出写作 127；**本次实际接线和原始 wait 为 125**。阶段与 errno 来自私有记录，不能由这两个退出码猜测。该差异不改变目标失败 errno 的归因。

## 3. 回执格式与可确认的信息

固定 little-endian `<4sBBHiIQ>`，每帧 24 字节：`SXRC`、版本 1、stage、保留位 0、errno、setup detail、monotonic_ns。解码器 exec_receipt.py (`runs/receipt-qualification-01/prototype/exec_receipt.py`, omitted from this source release) 检查大小、头、顺序、字段及 EOF 半帧；上限为 8 帧/192 字节。

| 编号 | 阶段 | 可以确认 |
|---:|---|---|
| 1 | LAUNCHER_EXEC_ATTEMPT | Python 准备调用第一跳；还不能确认内核 exec 已完成 |
| 2 | LAUNCHER_EXEC_FAILED | 第一跳确实返回 errno，状态 LAUNCHER_FAILED |
| 3 | LAUNCHER_READY | 已进入可信 launcher 并完成准备 |
| 4 | TARGET_EXEC_ATTEMPT | 准备调用目标 exec；还不能确认目标映像完成替换 |
| 5 | EXEC_FAILED | 目标 exec 确实返回 errno，状态 TARGET_EXEC_FAILED |
| 6 | LAUNCHER_SETUP_FAILED | 已实现的 launcher 准备失败分支；**本组没有实际注入覆盖** |

成功 exec 不返回，FD_CLOEXEC 关闭 write；进程在 exec 前被杀或退出同样会关闭 write。因此 1→3→4→EOF 仍为 `EXEC_STATUS_UNKNOWN`。该结论还由**实际 guest 对应的固定内核源码**直接支持，而不依赖上游 master：

- fs/exec.c (`frozen/kernel-evidence/fs/exec.c`, omitted from this source release) 的 `begin_new_exec()` 在第 1124 行设 `point_of_no_return=true`，第 1198 行执行 `do_close_on_exec(me->files)`；这早于完整 exec 的成功 trace。
- 同文件 `exec_binprm()` 第 1706 行调用 `search_binary_handler()`，负值直接返回；只有通过该流程后才在第 1728 行执行 `trace_sched_process_exec()`。因此 CLOEXEC 关闭的时机不能等同于成功事件。
- `bprm_execve()` 第 1778–1779 行规定：越过 point_of_no_return 后失败，若没有既有致命信号，就 `force_fatal_sig(SIGSEGV)`，而非回到原 launcher 报 errno。**CLOEXEC 已关闭后仍可能发生这种致命失败**；本组没有故障注入复现，必须列为确定源码机制、未实测路径。
- fs/pipe.c (`frozen/kernel-evidence/fs/pipe.c`, omitted from this source release) 的 `anon_pipe_read()` 在无缓冲数据且无 writers 时结束读；它没有判断执行映像是否成功的逻辑。

固定源码清单 (`frozen/kernel-evidence/manifest.json`, omitted from this source release)记录 commit `1c732c6b94f0faee1526bd375add2fe10cba2e26`，逐文件与该 commit 一致；`fs/exec.c` SHA 为 `efe28bca73504f9b46745b8f0f42be452e22c02f6c7db0b745f4f1c6bc973982`。公开 [execve(2) 文档](https://man7.org/linux/man-pages/man2/execve.2.html)仅作返回值、FD 和致命失败语义的补充说明，不替代该 guest 的源码证据。

`sched_process_exec` 只在离线诊断列作 **TARGET_EXEC_OBSERVED**，实际审计字段为 `kernel_target_exec_observed`。产品状态没有从它获得升级。观测到映像转换也不证明已进入 main、动态 loader 成功或业务正确。两个 VM 的 trace stats 均没有 overrun/commit overrun/dropped；这仍不是把 trace 退出事件当作真实 wait 的理由。

## 4. 12 项资格与 Controller 死亡结果

下表编号对应 `runs/receipt-qualification-01/<编号>-<case>.json`。`1/3/4` 为上表阶段；“目标观测”只来自该请求的离线 kernel trace。未送达表示 R 没有收到 S 的私有汇总，不能描述成“读到了空回执 EOF”。

| 编号 / case | W PID | 私有阶段 / errno | 产品 exec 状态 | 真实 W wait | 离线目标观测 | 业务知识 / outcome |
|---|---:|---|---|---:|---|---|
| 0 receipt_static | 324 | 1/3/4；EOF；72 B | UNKNOWN | 0，S | 是 | KNOWN / SUCCEEDED |
| 1 receipt_launcher_missing | 328 | 1/2；ENOENT=2；48 B | LAUNCHER_FAILED | 125，S | 否；launcher 也未 exec | KNOWN / NONZERO |
| 2 receipt_target_missing | 332 | 1/3/4/5；ENOENT=2；96 B | TARGET_EXEC_FAILED | 127，S | 否 | KNOWN / NONZERO |
| 3 receipt_target_noexec | 336 | 1/3/4/5；EACCES=13；96 B | TARGET_EXEC_FAILED | 127，S | 否 | KNOWN / NONZERO |
| 4 receipt_target_format | 340 | 1/3/4/5；ENOEXEC=8；96 B | TARGET_EXEC_FAILED | 127，S | 否 | KNOWN / NONZERO |
| 5 receipt_loader_missing | 344 | 1/3/4；EOF；72 B | UNKNOWN | 127，S | 是 | KNOWN / NONZERO |
| 6 receipt_exit127 | 348 | 1/3/4；EOF；72 B | UNKNOWN | 127，S | 是 | KNOWN / NONZERO |
| 7 receipt_launcher_sigkill | 352 | 1/3/4；EOF；72 B | UNKNOWN | -9，S | 否 | KNOWN / NONZERO |
| 8 receipt_drop_error | 356 | 1/3/4；EOF；72 B | UNKNOWN | 127，S | 否 | KNOWN / NONZERO |
| 9 receipt_early_death | 360 | 仅 1；EOF；24 B | UNKNOWN | 124，S | 否；launcher 已 exec | KNOWN / NONZERO |
| 10 receipt_timeout | 365 | 私有汇总未送达，R 为 0 B/eof=false | UNKNOWN | -9，R 收养 | 否 | KNOWN / TIMED_OUT |
| 11 receipt_spoof | 369 | 1/3/4；EOF；72 B | UNKNOWN | 0，S | 是 | KNOWN / SUCCEEDED |
| 独立 receipt_controller_death | 322 | 私有汇总未送达 | UNKNOWN | H 没有 W 的精确 wait 记录 | 否 | UNKNOWN；R 的终态未送达 |

上述 UNKNOWN 是 `EXEC_STATUS_UNKNOWN` 的简写。12 个正常记录完成的请求都双路输出 EOF、资源 RELEASED、R 的 FD 数 8→8。它们的 task/control/transition/business 均为空后删除；H318 最终真实 wait R319=0、ECHILD、无错误且 FD 恢复为 0/1/2。主进程非零、超时与 exec UNKNOWN 均未被清理成功改写为成功。

固定错误 fixture 在 build-tools.sh (`runs/receipt-qualification-01/tools/build-tools.sh`, omitted from this source release) 中构造：`target-noexec` 是静态探针的副本，guest 内 chmod 0644；`target-badformat` 是无 ELF 和 shebang 的文本，chmod 0755。因此 EACCES 与 ENOEXEC 来自实际 exec 调用，不是预先写入的假错误帧。宿主导出的二进制文件权限不能代替 guest 中的 mode；本报告使用构建脚本、私有 errno 和原始 syscall/exec 记录交叉判断。

### Controller 死亡与超时的区别

死亡请求快照 (`runs/receipt-controller-death-01/attempt-02abff40fb29a566d3f428c25b4430e7.json`, omitted from this source release)记录 Z318、S321、W322，已放行 G；launcher 在 TARGET_EXEC_ATTEMPT 后 pause。R317 被 SIGKILL，快照保留 `exec_receipt=UNKNOWN`、`result=null`、`resources=PENDING`，不能把该中途快照改造成已完成回执。

H316 账本 (`runs/receipt-controller-death-01/supervisor.json`, omitted from this source release)随后真实 wait R317 的 status=9，收养并 wait 319/318/320/321，最终 ECHILD；该账本**没有 W322 的精确 wait 状态**，业务继续 UNKNOWN。H 确认双路 EOF、空 cgroup、工作区删除与 RELEASED，FD 恢复；两路恢复字节都是 0，输出完整性为 null，R 已消费的前缀未必可恢复。外层释放记录 (`runs/receipt-controller-death-01/external-final-release.json`, omitted from this source release)确认观察者未补杀或删除产品资源。

相比之下，超时请求 (`runs/receipt-qualification-01/10-receipt_timeout.json`, omitted from this source release)中 R 实际收养 W365 并 wait=-9，所以业务退出知识为 KNOWN；S 未送达私有汇总，exec 知识仍 UNKNOWN。不能因真实 wait 存在，就补上不存在的 S 私有记录。

## 5. 明确区分的结果维度

| 维度 | 本轮的含义与边界 |
|---|---|
| `exec_receipt.status` | 只回答可信两阶段调用是否报告返回失败；没有成功状态 |
| 离线 TARGET_EXEC_OBSERVED | 内核映像切换事件，留在分析证据层 |
| `process_state` / wait | PROCESS_EXITED 来源于真实 W wait；被替换过几次映像不能由它推出 |
| `business` | KNOWN/UNKNOWN 表示原合同下 W 的结果是否收到；不是目标程序正确性认证 |
| `outcome` | 沿用旧合同：SUCCEEDED 表示已授权 W 的真实 wait=0 且生命周期条件满足；**不能拿它证明目标 exec、loader 或业务语义成功** |
| 输出 | 两路 EOF、保存字节完整性、截断与应用输出是否完成是不同事实 |
| `resources` / H release | 进程树/空 cgroup/FD/目录的资源收尾，不升级上述结果知识 |

`receipt_loader_missing` 的 trace 明确进入 `/workloads/bin/linked-missing`，stderr 包含缺少 `libexec_missing_fixture.so`；`receipt_exit127` 的自有目标进入 main 后返回 127。两者在私有状态上都是 1/3/4+EOF、UNKNOWN，在 wait 上都是 127，离线也都能观察到目标 exec。**本项目只能结合已知 fixture 解释这两例，不能通用地区分任意程序的 loader 失败与自行 exit(127)**；工具可以伪造相同 stderr。

`receipt_drop_error` 实际目标 ENOENT 后故意省去 EXEC_FAILED，stderr 仍写 errno=2；产品依然 UNKNOWN。`receipt_launcher_sigkill` 在写 TARGET_EXEC_ATTEMPT 后、实际 exec 前真实 SIGKILL，wait=-9，却同样得到 EOF。这两例直接证明“EOF/预 exec 标记不是成功回执”。

## 6. FD、权限与伪造输出的实际证据

`0-receipt_static.json` 的门禁身份为域内 PID=2、PPID=0、UID/GID=65534，六类 namespace 与目标集合一致，五组 cap 全零、NNP=1、Seccomp=2、Threads=1，业务 cgroup 为 `/cdz/d-5a937bcf6e7c4f6d142f4f7493b83def/business`。PPID=0 是真实父 S 在外层 PID namespace 的可见性结果，不是没有父进程。

其门禁 FD 为 0/1/2 与 gate=3、ready=6、receipt=8；新增 write 端是明确列出的临时通道，不是未审计的隐式继承。静态目标、目标 exit127 和 spoof 三个真正进入自有 probe 的样本，原始输出都为：

```text
RECEIPT_TARGET_SECURITY nnp=1 seccomp=2
RECEIPT_TARGET_FD=0
RECEIPT_TARGET_FD=1
RECEIPT_TARGET_FD=2
RECEIPT_TARGET_FD_CHECK extras=0 scan_errno=0
```

probe 排除自己为扫描 `/proc/self/fd` 临时打开的目录 FD。该直接证据支持这些目标映像没有回执或管理 FD；结合 launcher 的 CLOEXEC/close_range 源码，说明目标后代也不会从此接口继承回执写端。未对缺失 DSO 目标进入用户 main 后作 FD 采样，因为它并未到达该状态。

spoof 原始 stdout (`runs/receipt-qualification-01/11-receipt_spoof-stdout.log`, omitted from this source release)包含完整 `SXRC` 二进制 EXEC_FAILED(errno=13) 假帧和 JSON 假失败；stderr 含假 LAUNCHER_READY。对应私有 `11-receipt_spoof-exec-receipt.bin` 仍只有 72 字节的 1/3/4，errno=null、UNKNOWN，真实 wait=0。工具输出没有改变门禁、私有阶段或退出归因。

本组没有重跑全部旧负向系统调用矩阵。user/mount/PID/network/IPC/UTS、只读 rootfs、私有 work、无 cgroup mount、原 B-strict 与 Tool denylist 的前提由冻结源码及前置身份检查保持；不能把本组 FD 探针写成对所有网络、注入接口和所有恶意工具的重新穷尽验证。没有增加 namespace 权限、移除 seccomp 或修改 D 创建路径；也没有引入生产 ptrace。

## 7. 版本、SHA 与原始证据索引

guest 为 Linux `6.18.49-agentic-runtime-opt-v1`、CPython `3.10.12`（GCC 11.4.0 构建）、stock glibc `2.35`；私有 KVM 为 4 vCPU/4096 MiB、QEMU `-net none`。数据来自各 run 的 `environment.json`、`command.json`、`lab-manifest.json`，不是宿主版本。Kernel SHA 为 `bd303a80ab8fe396ac83d18e2dcd0936143eb0778fbcf6acaf47ea3fba11dd4f`；initramfs 为 `79505c01cc39cb00dea51d4a8101c1bfea187a84515782520d1b58ef3d4a32f9`。

两次 A run 的 `source-sha.json`、`tools-source-sha.json`、`build.json`、`tool-build-sha256.json`、`candidate-runtime-sha.json` 逐项相同；主要值如下：

| 冻结输入/产物 | SHA256 |
|---|---|
| zygote.py | `b204b9e3e11e680b5efe0ae65668e197f6ae435c07234b0068ccaf4a1d8f4ba3` |
| run.py（A 实际运行版） | `f15575565b1fe2e1f138de1bfbabf97e848253978ad15c0f947a5916ab4abdd7` |
| tool_runtime.py | `da7efcbd8428caa2118959789847c388f1d15fddfe51f18527ffa6cfb7e61039` |
| exec_receipt.py | `2b06a2ad44ccaa1d5546fc465e8a11d678f554575f62866c498a2b4f83b0d46d` |
| tool_launcher.c | `da0eca8dae2883c8c40ac39184d8b26d9d605ffb1befde1beba66bc4c29cba04` |
| guest 静态 tool_launcher | `4897217555eb4b0d65b17c3fddd701d41c58b90cb5e70378dc7b65c210547e4e` |
| receipt_probe.c | `cc377d56b78f5868ac81029e193db01d782e5a932337f13e97345dfb84866b25` |
| guest 静态 receipt-probe | `24f969540657607a862a260871064d2fcc0704878e7da2cb7b4033491456471e` |
| D libc.so.6 | `a03b51fe69f36b630ecf7997af05cd36885b1f2f0b52e278391fa6e17047eff4` |
| D loader | `0682f493d0434391d4ec027d0bcb54dd5f9e46d044dc7810f69abea58fe1398e` |

审查时当前 `prototype/run.py` 已比 A 冻结版本增加 B 的 volatile-prefix 故障夹具支路；不能声明它与 A run 逐字节一致。A 的 launcher、S 回执接线和纯解析模块没有因此改变；本报告所有实测归因均绑定上表 A 版本。

原始证据在两 run 内包括：`prototype/`、`tools/`、`build.json`、`tool-build-sha256.json`、`*-exec-receipt.bin`、请求 JSON、`*-stdout.log`、`*-stderr.log`、`zygote-0.log`、`process-trace.txt`、`trace-config.json`、`trace-stats.json`、`supervisor.json`、`observer-after.json` 和 `external-final-release.json`。超时与 Controller 死亡未取得私有汇总，不能要求它们存在完整 `.bin` 后再补造文件。

`review-config.json` 的遗留 `requests=35` 不是实际 suite 样本数；原始请求与套件选择给出 12+1。该文件的 `raw_syscalls_requested=false` 也不能覆盖 `trace-config.json` 和实际 trace 中已启用的 syscall 事件；本报告按实际保存的观测范围解释证据。

最终统一审计使用验证器 SHA `729cc665a016b734c4edd28177e1a33aa439d2ecf27620b2525b64a2464b65df`，对应 冻结源码 (`analysis/verifier-sources/729cc665a016b734c4edd28177e1a33aa439d2ecf27620b2525b64a2464b65df.py`, omitted from this source release)；A 12 项为 v4、死亡为 v2，三个后续回归均为 v1。先前 v1/v2/v3 等历史均保留：A 12 项的 v2 唯一 FAIL 曾要求 timeout 有 S 的 actual wait log；原始记录实际是 R 收养 W365 后 wait=-9，v3接受这一合法实际 wait 来源，没有修改或重跑原 VM 数据。该 FAIL 仍见 v2 (`analysis/verify-receipt-qualification-01-v2.json`, omitted from this source release)，规则及源码恢复方式见 修订说明 (`analysis/audit-revisions.md`, omitted from this source release)，不能用最新 PASS 抹去核验规则修订过程。

## 8. 未覆盖项与需补证据

- 新候选 Warm 的两次 normal、一次 nonzero 和一次 Controller 死亡已由第 1 节新增原始记录及独立审计确认；覆盖仅限这四个请求，不等于重跑全部历史 Warm 故障矩阵或完成长期并发回归。
- 已实现但未实测的 LAUNCHER_SETUP_FAILED、安全检查失败、close_range/fcntl 失败，以及第一跳 launcher EACCES，均未因第二跳 EACCES 而获得覆盖。
- 空输入、半帧、超量、坏版本、乱序等解析约束已有源码实现；本组实际 VM 回执均为有效完整帧或未送达。恶意/损坏私有协议、读端异常、写端误保留和 errno 丢失的完整资格仍需补充。
- S 的 `read_error` 路径把顶层 `status` 改为 UNKNOWN、`protocol_valid=false`，但可能保留原解析的 errno/failure_stage/exec_result 等字段作为诊断。消费者必须以 `status` 与 `protocol_valid` 为准；不能单独采信残留 errno。本组没有触发该分支，不宣称已验证其所有消费者。
- Python 第一跳用 blocking pipe 写固定 24 字节，协议量远小于 PIPE_BUF/管道容量且只有可信写者；源码没有显式核对 `os.write` 的短写返回值。现有单写者 Linux 原子小写入前提支持当前路径；并未做注入短写/破坏 pipe 所有权的故障验证，不把这种前提扩展为任意传输保证。
- Controller 或 S 先死亡会丢失私有回执；本次明确保留 UNKNOWN。H 继续存活、固定私有 VM 和证据可保存仍是恢复合同前提。没有实现持久化 exec 成功证明、任意 loader 错误分类、并发/长时间稳定性或多版本 ABI 回归。
- 模板必须可信单线程，fork/audit/native 回调继续属于 TCB；原 denylist 不等于生产级通用沙箱。该候选没有批准 NumPy/PyTorch 或任何不可信初始化进入管理阶段，也未替项目选择最终架构。

当前可采用的研究结论是：**把可回传的 exec 返回失败精确归因，把其余状态保守保留为 UNKNOWN，并与真实 wait 和资源回收独立记录。** 本组证据没有支持更强的在线目标启动成功保证。
