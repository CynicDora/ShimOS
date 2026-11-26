# ShimOS 第一轮任务 B：raw clone3 与 CPython/glibc fork 运行时契约研究及最小验证

日期：2026-10-19。项目：`/path/to/research-host/shimos-linux-native-mvp`。

本文件汇总全部研究结论、实际环境、源码路径、实验结果、失败记录、候选取舍、Q1–Q5 和重现入口。原始代码、固定版本源码、构建包及逐条日志保留为可核查附件。

**结论：现有 raw clone3 存在已经复现的 fork 运行时错误。候选 D 在固定 glibc 内保留完整 fork wrapper 并接入 clone3，已在独立 guest 中同时保留所测运行时合同、跨域 Python 内存继承和创建时 cgroup 归属。它是有限范围内验证的候选，不是最终架构决定或真实依赖准入。**

| 核心问题 | raw C | 标准 fork A/B | 候选 D（最终 candidate-04） |
|---|---|---|---|
| Python hooks | 执行 | A执行，B桥显式执行 | 显式执行 |
| native atfork hooks | 缺失，已实测 | 执行 | 执行，顺序及失败行为已测 |
| pthread 缓存 TID / robust owner death | 已复现错误 | 所测对照正常 | 所测对照正常 |
| 指定目标 cgroup 出生归属 | 保留 | 无目标FD参数，默认继承父组 | 保留 CLONE_INTO_CGROUP |
| 两次跨域继承自有 Python 对象 | 原机制及本轮通过 | 本轮未作为跨域原子出生实现 | 同Z两域、两次创建通过 |
| 采用边界 | 不能宣称通用fork兼容 | 直接替换不满足现有创建接口合同 | 需要承担固定libc发行与回归责任 |

最终运行有32个完整微探针用例；其中 D 的7项用例、14个子进程运行时观测符合受测合同。raw 用例按设计保留其错误观测，不能把32个harness完成写成32项通用兼容通过。最终两域各19项检查通过，Worker分别退出0和7，S/W无exec、资源完整回收。旧原型、qualification-02及旧B-strict的86项文件哈希未变。

本轮没有大型第三方依赖预加载、性能Benchmark、Scheduler、飞书操作或提高Z权限/关闭seccomp。完整glibc回归、广泛库ABI、任意多线程状态和长期稳定性尚未验证。候选包的libcrypt静态ABI缺口和修正前后结果均保留；没有运行`_crypt`业务测试。

正文按“环境 → 源码 → 实验 → 方案 → 支持范围与Q1–Q5”排列；附录给出执行入口、独立审查和构建来源。**源码事实、guest实测、分析推导与待验证项分别标注。** 文件、冻结run、来源hash、旧基线和本地链接另见最终完整性审计 (`evidence/final-integrity-audit.json`, omitted from this source release)。

## 01 — 实际环境、边界与可追溯清单

本轮实测在新建的私有 QEMU/KVM guest 中完成，使用既有 lab 的冻结 kernel/initramfs，以网络关闭方式启动。所有实验输出和副本只写入本目录。旧 `cross_domain_zygote/runs/qualification-02` 保持基线地位，不能将本轮发现追写成旧资格验证当时已经测过的内容。

### 1. 实际执行环境

下表来自 inventory-01/guest-environment.json (`runs/inventory-01/guest-environment.json`, omitted from this source release)，各后续运行也各自记录同名清单。

| 项目 | 实际 guest 结果 | 定位依据 |
|---|---|---|
| 架构、kernel | x86_64；`6.18.49-agentic-runtime-opt-v1`；`#2 SMP PREEMPT_DYNAMIC Sun Sep 20 13:29:34 UTC 2026` | `uname`、`/proc/version` |
| kernel 编译器 | GCC Ubuntu `11.4.0-1ubuntu1~22.04.3`；GNU ld 2.38 | `/proc/version` |
| glibc / NPTL | `2.35`，banner `Ubuntu GLIBC 2.35-0ubuntu3.15`，stable，GCC 11.4.0 | **运行中的** libc API、ELF banner、`sys.thread_info` |
| CPython | `3.10.12 (main, Aug 31 2026, 10:18:17) [GCC 11.4.0]` | 实际 `/usr/bin/python3` 的 `sys.version` |
| Python 构建元数据 | sysconfig 报告 Py_ENABLE_SHARED=1 / `--enable-shared`；非 Py_DEBUG，WITH_PYMALLOC=1，SOABI `cpython-310-x86_64-linux-gnu`，CFLAGS 含 `-fstack-protector-strong` | guest `sysconfig`，完整 CONFIG_ARGS 留在 JSON；不据此声称该 Python ELF 动态链接 libpython |
| kernel source | commit `1c732c6b94f0faee1526bd375add2fe10cba2e26`，tag 对应 Linux 6.18.49 | 冻结 lab manifest + 只读源树关联 |
| cgroup | v2；实验子树启用 cpu、memory、pids；创建失败用真实 pids controller 限制 | guest `/proc/self/mountinfo`、各 case `index.json` |
| user namespace | `CONFIG_USER_NS=y`，`/proc/sys/user/max_user_namespaces=15067` | 配置关联、guest sysctl |

**[证据限制]** kernel 未启用 `CONFIG_IKCONFIG`，无法声称从 `/proc/config.gz` 直接读出了运行内核配置。本轮在启动前校验 kernel/initramfs SHA256 和既有 manifest，读取与该构建对应的 `.config`，再把其副本/hash放入 guest 清单。配置关联依据是构建产物链，不是 uname 字符串本身。

关键配置：`CONFIG_CGROUPS`、`CONFIG_MEMCG`、`CONFIG_CGROUP_PIDS`、`CONFIG_CGROUP_SCHED`、`CONFIG_USER_NS`、`CONFIG_PID_NS`、`CONFIG_SECCOMP`、`CONFIG_SECCOMP_FILTER`、`CONFIG_FUTEX`、`CONFIG_FUTEX_PI`、`CONFIG_RSEQ`、`CONFIG_CHECKPOINT_RESTORE` 均为 y。配置全文：kernel.config (`runs/inventory-01/kernel.config`, omitted from this source release)。不存在用一个 `CONFIG_CLONE3` 字段代表所有 clone3 条件的检查；实际 syscall 成功、flags、cgroup controller 检查另有执行证据。

### 2. 固定产物与来源

| 产物 | SHA256 |
|---|---|
| guest bzImage | `bd303a80ab8fe396ac83d18e2dcd0936143eb0778fbcf6acaf47ea3fba11dd4f` |
| guest initramfs | `79505c01cc39cb00dea51d4a8101c1bfea187a84515782520d1b58ef3d4a32f9` |
| 对应 kernel config | `5f96f4a3e7e570e798789cac80313e62807e8545704e861852efdedb44ef78f5` |
| guest libc.so.6 | `b2cf6c33b74d2f22543b7a469a75b538911e690f769d0b238843a49465b83793` |
| guest ld-linux-x86-64.so.2 | `41daf7836f7fce21a40ca63a00c5caf21b05a35a76ccc075d86f1716212cdf01` |
| guest /usr/bin/python3 | `a2f33a6e006989270f4340528eb61f8f97366e00a5d1b602ac8672ea44fc56ae` |

guest Python 与宿主 dpkg 管理的 Python ELF 哈希相同，结合包元数据将发行源码定位到 `python3.10 3.10.12-1~22.04.18`。这是显式的关联证据；宿主内核、shell 默认 Python、Conda 等均不能代替 guest 版本。旧 manifest 的 `host_uname` 是旧构建机信息，也不是本轮 guest uname。本轮宿主另有 host-environment.json (`runs/inventory-01/host-environment.json`, omitted from this source release)，不能混用。

glibc / Python 源包来自 Ubuntu 官方 archive，下载哈希与 `.dsc` 声明一致，发行补丁通过 dpkg-source 应用。未完成源码包签名链验证，不能把 HTTPS + SHA256 一致写成签名认证。完整版本、下载文件、源文件哈希及该限制记录于 [source-manifest.json](sources/runtime-source/source-manifest.json)。关键 kernel 源码只读复制到 sources/runtime-source/kernel (`sources/runtime-source/kernel`, omitted from this source release)。

候选 D 是同发行源码基础上的**新构建**，新增 API 和 patch、编译配置、runtime bundle 各有单独 manifest。D 使用显式 loader 和配套 DSO；库存 guest 清单依然描述 collector 的原运行时，不能拿它宣称 D 进程加载了发行版原 ELF。D 的微探针会记录实际映射文件/hash，跨域试验另记录 Z maps 和目标域只读绑定清单。

### 3. 角色、权限、cgroup 和 namespace

实验 fixture 在 guest 内以 root 创建实验目录、设置资源上限、委派 cgroup、收集 trace。它是**测试设施**，不是把 root 赋给 Z 或 W；没有更改宿主 cgroup 或宿主 libc。固定 guest init 会启动原 lab 的 Docker daemon，实验本身不调用 Docker，也不运行任何性能 benchmark。

微探针 launcher 先进入独立 `caller` cgroup，随后 `setgroups([])`、UID/GID=65534、`PR_SET_NO_NEW_PRIVS=1`；目标 cgroup 和共同祖先所需文件委派给 65534。各 case 自带最多 15 秒外部期限、256 MiB 内存上限和 pids 上限，结束后检查 populated=0 并删除实验子树。`pids.max=1` 的失败用例把 caller/target 都置于同一受限祖先下，使标准 fork 与 INTO_CGROUP 都遭到真实创建拒绝。invalid-FD 是另一种独立负例。

跨域独立副本保留原机制：

1. Z 在 guest 初始 user/PID namespace 运行，UID/GID=65534，CapEff/CapPrm=0，NoNewPrivs=1；管理阶段尚未安装最终 W seccomp。
2. Controller 持有并传递经验证的目标 namespace/root/cgroup FD。第一代 S 出生于 transition cgroup；Z 仍留在原域。
3. S 利用同 UID 拥有的目标 base userns 关系取得进入目标 namespace 所需的 namespace 内能力，执行 setns、root/cwd 转换；`setns(PID)` 只改变后代的 PID namespace。
4. 第二次创建让 W 出生于 business cgroup 和目标 PID namespace；W 继承 Python 内存。W 完成 FD 清理、能力清零、NNP 和原 B-strict 加 exec-deny 后才执行受控业务检查。S 降权并等待 W。

**[安全含义]** CapEff=0 不等于无 namespace 管理能力。fork hooks 在最终 W 限制完成之前运行：Z prepare/parent、S 的 child/第二次 prepare/parent、W 的 child hooks 都是相应阶段的代码执行入口。修复 native hooks 会使原本漏掉的代码正确地运行，要求其受信任，并未把依赖移出 TCB。

### 4. 现有源码核查与不变性

实际核查 [原 bridge.c](../cross_domain_zygote/prototype/bridge.c)、[原 zygote.py](../cross_domain_zygote/prototype/zygote.py)、[原 native.c](../cross_domain_zygote/prototype/native.c)。C 路径 clone3 flags 是 `CLONE_INTO_CGROUP | CLONE_PIDFD = 0x200001000`，`exit_signal=SIGCHLD`；没有 child_tid 设置。CPython hooks 通过 PyDLL 持有 GIL 调用。

`native.c` 的 controller launcher 使用 raw clone 后进入最小设置再 exec；它与 Z 的“继续执行继承的 Python heap”路径不同。本轮没有以 Z 的兼容缺口直接推断 launcher 已故障，也没有把 launcher 的成功 exec 当作 Z 的兼容证明。

本轮新副本位于 prototype/cross_domain (`prototype/cross_domain`, omitted from this source release)，来源见 source-manifest.json (`prototype/cross_domain/source-manifest.json`, omitted from this source release)。raw `bridge.c`、`zygote.py`、`native.c`、`common.py`、`domain_init.c`、`policy.h` 初始复制与基线完全一致；D 使用另一个 `bridge_d.c` 和显式运行模式。旧原型、qualification-02、旧 B-strict 相关文件共 86 项的起始 hash 在 baseline-hashes.json (`evidence/baseline-hashes.json`, omitted from this source release)，收尾复核 (`evidence/baseline-final-check.json`, omitted from this source release) 全部未改变。

### 5. 证据分层规则

- **源码事实**：精确版本的函数路径直接支持，未必已经触发故障。
- **guest 实测**：具有独立 run、冻结源 hash、NDJSON/strace/trace、逐项分析结果。
- **推导**：例如同 flags + kernel 创建路径支持出生时 cgroup 归属；须明确前提。
- **未验证/待验证**：没有测试的应用锁、第三方库、全套 glibc 回归、长期稳定性和异常竞争。

实验完成、import 成功、fork 返回 PID、业务正确、重复派生稳定是不同保证。`result.json.complete=true` 仅说明测试 harness 完成；raw 的预期语义失败也能使 harness 正常结束。

## 02 — 实际 guest 的 fork 运行时路径与 raw clone3 缺口

本节的源码事实绑定 **Linux 6.18.49 / commit `1c732c6b94f0faee1526bd375add2fe10cba2e26`、Ubuntu glibc `2.35-0ubuntu3.15`、Ubuntu CPython `3.10.12-1~22.04.18`**。它不是此前报告所选 glibc 2.39 / CPython 3.14 参考源码的复述。实际执行版本见 guest inventory (`runs/inventory-01/guest-environment.json`, omitted from this source release)；下载、发行补丁、源哈希见 [source-manifest](sources/runtime-source/source-manifest.json)。候选 D 是同发行源码的独立构建，不声称与 Ubuntu 原始 ELF 位级相同。

标记含义：**[源码事实]** 是注明版本实际源码直接给出的行为；**[实测]** 须有 guest 原始记录；**[推导]** 是从路径/权限得出的结论；**[未验证]** 不被无崩溃结果自动消除。

### 1. 版本归因与证据层次

- guest `sys.version` 为 `3.10.12 (main, Aug 31 2026, 10:18:17) [GCC 11.4.0]`，`sys.thread_info` 为 pthread / NPTL 2.35；glibc 自述 `Ubuntu GLIBC 2.35-0ubuntu3.15`。
- guest Python 镜像 ELF SHA256 `a2f33a6e006989270f4340528eb61f8f97366e00a5d1b602ac8672ea44fc56ae`，与宿主受 `dpkg` 管理的 `/usr/bin/python3.10` 完全一致；宿主包元数据为 `3.10.12-1~22.04.18`。因此用的是**二进制哈希关联加实际 guest 版本**，不是把宿主的 `python3` / Conda 版本当 guest。
- kernel 源树只读自 `/path/to/research-host/shimos-v2/linux/vanilla`，HEAD 与既有 lab manifest 对齐，提交标题 `Linux 6.18.49`。实际 guest 的构建配置 SHA256 为 `5f96f4a3e7e570e798789cac80313e62807e8545704e861852efdedb44ef78f5`。本轮使用的关键源码副本位于 kernel (`sources/runtime-source/kernel`, omitted from this source release)。没有修改该源码树或运行 guest 的 kernel。
- Ubuntu `.dsc` / orig / debian 源包从官方 archive 下载并核对 `.dsc` 内 SHA256，使用 `dpkg-source` 应用完整发行 quilt 补丁。glibc `.dsc` 的本机 GPG 公钥缺失；Python 提取使用 `--no-check`。**没有声称完成签名链验证**。这与固定 HTTPS 来源及文件哈希匹配是不同证据。

官方来源：[glibc 精确源包](https://archive.ubuntu.com/ubuntu/pool/main/g/glibc/glibc_2.35-0ubuntu3.15.dsc)、[Python 精确源包](https://archive.ubuntu.com/ubuntu/pool/main/p/python3.10/python3.10_3.10.12-1~22.04.18.dsc)、[kernel 固定提交](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/fork.c?id=1c732c6b94f0faee1526bd375add2fe10cba2e26)。

### 2. 三条基线创建路径

```text
A: Python os.fork()
  os_fork_impl: isolated-interpreter check + PySys_Audit("os.fork")
  PyOS_BeforeFork
  glibc fork / __libc_fork
    native prepare handlers + libc preparation
    _Fork → arch_fork → clone syscall
    child: NPTL/robust/TID/libc repair + native child handlers
    parent or failure: libc unlock + native parent handlers
  PyOS_AfterFork_Child 或 PyOS_AfterFork_Parent
  Python PID / OSError

B: Python 桥接 glibc fork()（本轮 matrix method1）
  ctypes.PyDLL 持 GIL → PyOS_BeforeFork
  同上 glibc 部分
  PyOS_AfterFork_Child 或 PyOS_AfterFork_Parent
  保存/恢复 syscall errno
B0: standalone C glibc fork()（本轮 method3）
  只有 glibc 部分，没有 Python runtime / PyOS hooks

C: 当前 bridge.py_fork_cgroup，必须通过 ctypes.PyDLL 持有 GIL
  dlsym 查三个公开 PyOS API
  PyOS_BeforeFork
  syscall(SYS_clone3, flags=CLONE_INTO_CGROUP|CLONE_PIDFD,
          cgroup=cgfd, pidfd=out, exit_signal=SIGCHLD)
  保存 errno
  PyOS_AfterFork_Child 或 PyOS_AfterFork_Parent
  恢复 errno，返回 PID
```

**[源码事实]** C 的 flags 为 `0x200001000`；无 `CLONE_VM`、`CLONE_THREAD`、`CLONE_FS`，也无 `CLONE_CHILD_SETTID` / `CLONE_CHILD_CLEARTID`、无 `child_tid` 地址。两次派生均用这条路径。实际调用点与基线快照见 原型 bridge (`../cross_domain_zygote/runs/qualification-02/prototype/bridge.c`, omitted from this source release)、zygote (`../cross_domain_zygote/runs/qualification-02/prototype/zygote.py`, omitted from this source release)。

**[源码事实]** A 在 CPython 的 `Modules/posixmodule.c:6725`；B 在 glibc 的 `posix/fork.c`、`sysdeps/nptl/_Fork.c`、`sysdeps/unix/sysv/linux/arch-fork.h`。本地 **原始** glibc 文件是 fork.c.original (`sources/runtime-source/patches/fork.c.original`, omitted from this source release)、_Fork.c.original (`sources/runtime-source/patches/_Fork.c.original`, omitted from this source release)；完整工作源码中的上述两个文件已带本轮 D 的小补丁，不能误标成库存源码。

本轮 B 同时包含独立 C `fork` 对照以及显式包 PyOS hooks 的 Python 桥接对照；后者用于保持回入解释器所需合同。裸 ctypes `fork` 而不包 PyOS hooks 不是提出的实现方案。微探针详见 probe.c (`prototype/probes/probe.c`, omitted from this source release)、matrix index (`runs/matrix-01/micro/index.json`, omitted from this source release)、只读分析 (`evidence/matrix-01-analysis.json`, omitted from this source release)。

### 3. CPython 的公开 hooks 具体做什么

**[源码事实，Ubuntu CPython `Modules/posixmodule.c:536–624`]**：

| 阶段 | 顺序和行为 | 不覆盖的范围 |
|---|---|---|
| `PyOS_BeforeFork` | Python `before` 回调按注册逆序；然后获取 import lock | 不枚举/调用 `pthread_atfork`；不修复任意 native runtime |
| `PyOS_AfterFork_Parent` | 释放 import lock；Python parent 回调按注册顺序 | 即使创建失败也必须调用；不是 libc 解锁器 |
| `PyOS_AfterFork_Child` | 重建 GIL state / eval thread locks / import lock；信号模块 after-fork；runtime thread locks；清除非主 interpreter 状态；然后 Python child 回调 | 不写 glibc `THREAD_SELF->tid`；不注册 kernel robust list；不修复任意库的锁/设备/连接 |

`run_at_forkers` 复制当前回调列表再遍历，以免列表追加改变本轮顺序；回调异常用 `PyErr_WriteUnraisable` 报告而不会作为普通异常向创建调用者传播。Python callback 本身可以执行任意模板代码。因此 hooks 存在同时是正确性机制和管理期代码入口。CPython 精确源码 (`sources/runtime-source/cpython-3.10.12-ubuntu/Modules/posixmodule.c`, omitted from this source release)

公开 API 文档规定：三个 PyOS API 对应的创建应在**主解释器主线程**使用，parent hook 包含失败情况，child 若还会使用解释器就必须执行。在线 `/3.10/` 文档目前已滚动到 3.10.22；具体 guest 行为以上述发行源码为准。[Python C API](https://docs.python.org/3.10/c-api/sys.html#c.PyOS_BeforeFork)

**[源码事实 / 实测对照解释]** 本版本 `os_fork_impl` 在 `fork()` 返回后执行 Python parent hook，最后才调用 `posix_error()`，中间没有保存 errno。glibc 自身保存失败 errno 并不足以保护**随后**执行的 Python 回调。这些 hooks 及受控回调内部调用其他 C/Python API，有机会覆写 errno；本轮 A 的失败探针确实出现 `OSError.errno == 0`。**本轮仅定位到未保护 errno 的跨-hook区间，尚未用进一步隔离确定具体哪一次调用写入了 0。**它不证明 kernel 返回 0，也不证明 raw 路径更兼容。C / D bridge 保存 errno 是明确的附加错误传递合同；回调行为与 kernel 错误应分别记录。

### 4. glibc 普通 fork 的具体维护

**[源码事实，Ubuntu glibc `posix/fork.c`]** `__libc_fork` 按 `__libc_single_threaded == 0` 判断 `multiple_threads`。该标志曾创建线程后可能保持 0；`/proc/self/task` 当前仅有 1 个线程，不等于 libc 的这个历史状态。

1. `__run_fork_handlers(atfork_run_prepare, multiple_threads)` 执行原生 prepare handlers，顺序是最后注册者先运行。
2. 多线程路径准备 NSS database，锁住 libio 文件列表，再锁 malloc arenas。
3. `_Fork()` 调用 `arch_fork(&THREAD_SELF->tid)`；x86_64 实际使用普通 `clone` syscall，flags 含 `CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD`。
4. `_Fork()` 在 child 清空继承的 robust list 链并调用 `set_robust_list`；其含义是**不继承父进程 mutex 所有权**，重新建立当前 child 的 robust 跟踪。
5. `fork_system_setup()` 推进 `__fork_generation`，供 `pthread_once` 判断上代 fork 中遗留的 in-progress 初始化。
6. 多线程 child 重建 unwind link 锁，线程计数、stack-cache / default-attr 锁，mq/timer 子进程状态；解 malloc 锁并重建 arena 锁，重置 stdio 和 NSS 状态。
7. 无论多线程标志如何，重置 loader `dl_load_lock` / `dl_load_tls_lock`，整理 NPTL stack lists；再执行 native child handlers（注册正序）。
8. parent / 创建失败路径释放自己锁住的 malloc/libio 锁，运行 native parent handlers（注册正序）；失败时保存与恢复 syscall errno。

源码位置：fork wrapper 原文 (`sources/runtime-source/patches/fork.c.original`, omitted from this source release)、_Fork 原文 (`sources/runtime-source/patches/_Fork.c.original`, omitted from this source release)、arch-fork.h (`sources/runtime-source/glibc-2.35-ubuntu/sysdeps/unix/sysv/linux/arch-fork.h`, omitted from this source release)、fork.h (`sources/runtime-source/glibc-2.35-ubuntu/sysdeps/nptl/fork.h`, omitted from this source release)、register-atfork.c (`sources/runtime-source/glibc-2.35-ubuntu/posix/register-atfork.c`, omitted from this source release)、pthread_once.c (`sources/runtime-source/glibc-2.35-ubuntu/nptl/pthread_once.c`, omitted from this source release)。

**[重要限定]** 这些动作是 glibc 在本发行版的保证，不是任何 native 运行库均可 fork 的保证。pthread_atfork callback 可以有 bug，其他线程持有的应用锁也不会被 glibc 普遍修复。多线程父进程 fork 后执行复杂 Python/native 工作仍不能因 D 经过 glibc 就宣称获得 POSIX 的通用安全许可。

### 5. 明确差异：源码缺口不等于全部已复现

| 项目 | C raw clone3 与标准路径差异 | 本轮证据层次及限制 |
|---|---|---|
| Python callbacks | C 有 PyOS hooks，正常包含 Python before/parent/child | 不能笼统写“raw 不调用任何 atfork”；Python 和 C 是不同列表 |
| Native callbacks | C 未经过 glibc `__run_fork_handlers` | 确定源码缺口；微探针 callback 顺序/模拟库 child owner 已复现错误 |
| pthread TID | kernel 不知道 glibc TLS 中 tid 地址，C 未请求 CHILD_SETTID | 确定源码缺口；child `gettid` 与 pthread CPU clock 编码的 tid 不一致已复现 |
| robust mutex | kernel `futex_init_task` 把 child `robust_list` 清空；C 未执行 `_Fork` 重建 | 确定源码缺口；共享 robust mutex child 死亡后，raw 等待超时 vs 标准 EOWNERDEAD 已复现 |
| stdio lock | C 不做 fork wrapper 的 libio child lock 重建 | 受控 native 线程持锁探针中 raw `ftrylockfile` 返回16（非零）vs 标准返回0；不将其解释为该 API 的通用 errno 合同；这是诊断，不是允许多线程模板 |
| malloc/NSS/loader/动态 TLS/stack lists | C 全部绕过上述维护；一些仅在多线程路径执行 | 确定源码差异；没有逐项用故障注入证明全部会坏；不得归并为“全部实测死锁” |
| pthread_once | C 不推进 fork generation | 有祖代中 unfinished once 且执行线程消失时的风险有源码依据；本轮未把所有 once 组合列为已验证 |
| TLS 普通值及地址 | 内存页和 TLS 基址通常继承；相同地址是正常 fork 现象 | `pthread_self()` 指针相同不等于 tid 正确；自有 TLS canary 正确也不能代表整个 NPTL 一致 |
| rseq | `!CLONE_VM` 时 kernel 继承注册 | **不是已证明的缺口**，见下一节；不得写成 raw 必然丢 rseq |

测试的退出、errno、次数、callback 字节与 PID 取值以本轮原始 runs 为准；本节不把任何“未崩溃”扩大为完整 ABI 兼容证书。

### 6. kernel 真正维护什么

**[源码事实]** `clone3` 解析完整 `clone_args` 并进入 `kernel_clone → copy_process`。`copy_process` 根据 flags 设置 `set_child_tid` / `clear_child_tid`；没有 flags 就不会猜测 libc descriptor。在 `futex_init_task` 中重置 kernel robust pointers；与之相对，`rseq_fork` 明确在无 `CLONE_VM` 时继承 parent 的注册地址、长度和签名。因此“raw clone3 全部线程本地状态都会丢失”是错误的概括。fork.c (`sources/runtime-source/kernel/fork.c`, omitted from this source release)、futex.h (`sources/runtime-source/kernel/futex.h`, omitted from this source release)、rseq.h:73 (`sources/runtime-source/kernel/rseq.h`, omitted from this source release)

**[源码事实]** `cgroup_can_fork` / `cgroup_css_set_fork` 在 child 暴露/运行前检查目标 FD、cgroup 仍存活、写入/委派权限与各 controller 的 `can_fork` 限制。`cgroup_post_fork` 完成 css_set 归属；`kernel_clone` 随后才 `wake_up_new_task`。因此 `CLONE_INTO_CGROUP` 的关键不只是 parent 最后在 `/proc` 看见一个路径，而是 child 首次执行用户态、含 native child callback 时已经属于该 cgroup。kernel cgroup.c:6710–6950 (`sources/runtime-source/kernel/cgroup.c`, omitted from this source release)、fork.c:2642 (`sources/runtime-source/kernel/fork.c`, omitted from this source release)

`CLONE_PIDFD` 的句柄指向新 child，返回 PID 的 namespace 可见性、`SIGCHLD` 和 wait-parent 关系仍由 `kernel_clone` 决定。替换为 full wrapper 并不会将实际 wait-parent 变成 controller。原型 S 仍负责等待 W；pidfd 是稳定身份/通知手段，不等于任意进程取得 `waitpid` 父子关系。

### 7. 现有 namespace / cgroup 合同并未因 runtime 修复改变

Z 在 guest 初始 user/PID namespace 中以 UID/GID 65534 运行，`NoNewPrivs=1`。它没有宿主 root，不等于无法进入目标用户命名空间：目标 base userns owner 与委派条件赋予它所需资格。Z 的第一代 S 必须出生于 transition cgroup；S 依次进入 base user、目标 mount/net/ipc/uts、PID-for-children、root/cwd、inner user；第二次创建才使 W 真正进入目标 PID namespace。W 从创建即位于 business cgroup，随后最终清 capability、关闭管理 FD、安装原 seccomp。S 完成创建后降权并等待 W。基线 bridge (`../cross_domain_zygote/runs/qualification-02/prototype/bridge.c`, omitted from this source release)、基线 zygote (`../cross_domain_zygote/runs/qualification-02/prototype/zygote.py`, omitted from this source release)

**[推导]** D 保持同样 clone flags 的隔离相关部分、同一 creds / FD / setns 次序，额外加入的是 libc 所需 CHILD_SETTID/CLEARTID 与完整用户态 wrapper；它不需要扩大 Linux capabilities。但它会正确执行以前被遗漏的 native callbacks；这些 callbacks 在管理阶段运行，因此必须进入受信任代码准入与状态合同，不能把 runtime 修复误称为不可信代码权限隔离。

## 03 — raw clone3 与标准 fork 的实际对照证据

本轮在实际 guest 中复现了 raw 路径的运行时错误：**原生 atfork 回调缺失、pthread 缓存 TID 未更新、robust mutex 所有者死亡恢复失败**。另外，一个明确超出生产单线程合同的受控 stdio 诊断复现了 libc 文件锁未重置。与此同时，自有 Python 对象仍可继承，raw 两次跨域派生仍可完成。这些结果说明“Python 内存继承成功”与“满足完整 fork 运行时合同”是不同保证。

**候选 D 在 `candidate-03` 的有限对照中修复了上述已复现差异，同时保留目标 cgroup 出生、两次 namespace 派生、Python 内存继承和现有最终降权检查；修正额外 libcrypt 打包问题后的 `candidate-04` 又完成相同范围的复测。** 这是可运行的候选证据，不是完整 glibc/Python ABI 认证或最终架构选择；设施失败与静态 ABI 问题的历史完整保留，见第 10–12 节。

以下严格区分 **[实测]、[源码事实]、[分析推导]、[未验证]**。测试使用可信自有 C/Python 模块；没有加载 NumPy、Pandas、SciPy、PyTorch。全部次数是正确性测试次数，不是性能样本。

### 1. 实际环境与证据索引

**[实测]** 本节结果绑定 Linux `6.18.49-agentic-runtime-opt-v1`、Ubuntu glibc `2.35-0ubuntu3.15`、CPython `3.10.12 (main, Aug 31 2026, 10:18:17) [GCC 11.4.0]`。完整环境与源码归因见 实际 guest 清单 (`runs/inventory-01/guest-environment.json`, omitted from this source release)、运行时路径分析 (`02-runtime-paths.md`, omitted from this source release)。宿主仅用于源码构建检查的结果不计入本节 guest 结论。

| 证据组 | 内容 | 归因限制 |
|---|---|---|
| matrix-01 原始索引 (`runs/matrix-01/micro/index.json`, omitted from this source release) | 25 个独立测试进程；逐项 argv、身份、cgroup、退出/超时/清理结果 | 主对照；没有 ptrace |
| matrix-01 分析 v2 (`evidence/matrix-01-analysis-v2.json`, omitted from this source release) | 逐 PID 回调顺序、各事件与状态快照数量、TID/robust/native 状态、内存、cgroup | 所有预期记录完整；不把 exit 0 转换为兼容 PASS |
| verify-01 syscall 索引 (`runs/verify-01/syscall-traces/index.json`, omitted from this source release) | 三个独立的 strace 诊断：A 的失败、B 的状态、C 的两代创建 | 有 ptrace；不能替代未跟踪主对照 |
| verify-01 raw 跨域汇总 (`runs/verify-01/cross-domain-raw-c/summary.json`, omitted from this source release) | 独立副本中沿原 raw bridge 路径执行 normal / nonzero | 证明现有可信模板隔离和继承能力；明确 `runtime_compatibility_claim=false` |
| candidate-03 分析 (`evidence/candidate-03-micro-analysis.json`, omitted from this source release) | 含 A/B/C/B0/D 的 32 项完整对照 | D 的七项完成有限 runtime 检查；不是所有依赖的兼容保证 |
| candidate-03 身份核查 (`evidence/candidate-03-runtime-identity.json`, omitted from this source release) | D 七项实际映射 ELF 的 SHA256，与冻结包/manifest/guest 安装 manifest 对照 | 区分同为 glibc 2.35 的库存库与候选库；不以版本字符串代替实际加载证据 |
| candidate-04 微型分析 (`evidence/candidate-04-micro-analysis.json`, omitted from this source release)、身份核查 (`evidence/candidate-04-runtime-identity.json`, omitted from this source release) | 最新包移除旧 libcrypt provider 后重复 32 项、D 七项映射身份及跨域/trace 检查 | fork ELF 未改；没有把包修正说成整个标准库已验证 |
| 探针源码 (`prototype/probes/probe.c`, omitted from this source release)、Python 驱动 (`prototype/probes/micro.py`, omitted from this source release)、说明 (`prototype/probes/README.md`, omitted from this source release) | 自有回调、TLS、robust mutex、stdio、内存与两代测试 | 不是第三方运行库准入样本 |

只读分析器 (`prototype/probes/analyze.py`, omitted from this source release) 校验启动/完成记录、每次请求与 wait/failure 数量、每类 C/Python 状态快照数量、callback 的完整逐 PID 序列、robust/stdio/COW 事件数量及退出码。缺文件、缺行、截断、非法 JSON、缺少总结均作为证据完整性问题；原始 NDJSON 不会被重写。当前 25 项全部通过该完整性检查。这个检查只回答“证据是否齐全且符合测试计划”，不回答“运行时是否完全兼容”。

### 2. A / B / C / B0 到底比较什么

| 名称 | 实际创建路径 | Python hooks | 原生 hooks | 目标 cgroup 原子出生 |
|---|---|---|---|---|
| A，`--method os` | CPython `os.fork()` → glibc `fork()` | CPython 自己执行 | glibc 执行 | 不提供；继承 caller cgroup |
| B，`--method libc` | 经 `ctypes.PyDLL`、持 GIL 调用自有 C wrapper → glibc `fork()` | wrapper 完整括 `PyOS_BeforeFork` / parent / child | glibc 执行 | 不提供；继承 caller cgroup |
| C，`--method raw` | 同一 PyDLL wrapper → `syscall(SYS_clone3)` | 与 B 相同 | 未执行 glibc fork 路径 | `CLONE_INTO_CGROUP` 指定 target / grandchild |
| B0，`standalone` | 独立 C 可执行文件 → glibc `fork()` | 没有 Python 运行时 | glibc 执行 | 不提供；继承 caller cgroup |

B **没有跳过 CPython hooks 后直接回入 Python**。设置 B 是为了让 B/C 仅在创建及 libc 维护路径上不同；B0 才隔离掉 Python 运行时。B/C 均在创建调用后保存 `errno`，执行 parent/child hooks 后恢复；这与当前 CPython A 的失败错误传递还有一项差异，见第 5 节。

**[实测]** A/B/C 各有 callbacks、state、robust、nested、stdio、退出 7、资源失败七项；C 另有无效目标 FD 失败项；B0 有 callbacks、robust、资源失败三项。除 B0 每项一次外，每个 Python 测试进程默认执行两轮同父派生；`nested` 每轮再从第一代创建第二代。

每项由独立解释器/进程开始，避免一次测试对后续测试的线程历史或注册列表造成污染。微型探针运行身份为 UID/GID `65534`、`NoNewPrivs=1`，实际有效/许可 capabilities 为零。该 harness 不进入最终 Worker 的命名空间和 seccomp 阶段；此阶段原始记录为 `Seccomp=0`，不是修改或关闭旧 Worker 策略。最终隔离策略由第 8 节独立跨域测试验证。

每项有外部 15 秒超时，超时时由该项 cgroup 统一终止并检查清空；robust 恢复还使用 300 ms `pthread_mutex_timedlock`，stdio 使用不等待的 `ftrylockfile`。25 项均正常结束，cgroup 清空，未触发外部超时。harness (`prototype/matrix.py`, omitted from this source release)、运行汇总 (`runs/matrix-01/micro/run-summary.json`, omitted from this source release)

### 3. 回调顺序：Python 列表存在，native 列表被绕过

每类各注册两组回调，编号按注册顺序为 1、2。日志按单次 `write` 追加；**父、子之间的调度交错不用于判断次序，次序按 PID 分别检查**。

**[实测]** A/B 一次创建的调用者路径为：

```text
Python prepare2 → Python prepare1
→ C prepare2 → C prepare1
→ 创建系统调用
→ C parent1 → C parent2
→ Python parent1 → Python parent2
```

成功子进程路径为：

```text
C child1 → C child2 → Python child1 → Python child2
```

C 的 prepare/parent/child 只出现相应 Python 序列；没有任何 `c_callback` 记录。B0 只有上述 C 序列。失败时 A/B/B0 仍执行各自 parent 序列，C 执行 Python parent 序列；所有失败测试均无 child 序列。每轮重复派生与 nested 中的第二代均按这个规则核对。

直接证据：A callbacks (`runs/matrix-01/micro/00-os-callbacks.ndjson`, omitted from this source release)、B callbacks (`runs/matrix-01/micro/07-libc-callbacks.ndjson`, omitted from this source release)、C callbacks (`runs/matrix-01/micro/14-raw-callbacks.ndjson`, omitted from this source release)、B0 callbacks (`runs/matrix-01/micro/21-standalone-callbacks.ndjson`, omitted from this source release)。完整逐 PID 序列位于分析 JSON 的 `callback_traces`。

**[分析推导]** “raw 不执行 atfork”过于笼统：现有 raw bridge 的 PyOS hooks 确实运行 Python `os.register_at_fork` 回调。缺失的是 glibc 管理的 `pthread_atfork` 路径及关联维护。只补 Python hooks不能替代 native hooks。

### 4. 已复现的运行时错误

#### 4.1 原生初始化状态的确定反例

自有模块初始化时把 `native_owner` 设为 PID，并注册 child 回调把它修复为新 PID。这是明确且可控的模拟运行库合同，不是对某一第三方库行为的猜测。

**[实测]** A/B 的 14 个子进程状态观测各自全部满足 `native_owner == getpid()`；C 的 14 个观测全部不满足，且 `native_child_resets == 0`。其中 12 个 C 子进程观测来自单线程 case，另外两个属于独立 stdio 多线程诊断。两次 sibling 与两代 nested 没有改变这个差异。B0 的两个成功子进程观测也正确修复。

这已经是初始化状态的语义错误，而不只是“没有打印回调”。它不能证明任意真实库必然使用同样的 PID marker，但足以否定“PyOS hooks 已覆盖 native fork 合同”的泛化说法。C state 原文 (`runs/matrix-01/micro/15-raw-state.ndjson`, omitted from this source release)、native child2 实现 (`prototype/probes/probe.c`, omitted from this source release)

#### 4.2 pthread 缓存 TID 与 kernel TID 不一致

探针只使用公开 `pthread_getcpuclockid(pthread_self())`、`clock_gettime`、`syscall(SYS_gettid)`，按 Linux 动态 thread CPU clock 的编码解出其目标 TID；没有读取或改写 glibc 私有结构。

**[实测]** `15-raw-state` 的模板 PID/TID 为 `307`，两名 child 的 kernel TID 分别是 `308`、`309`，但两者的 pthread CPU clock 均编码为 TID `307`；对所得 clock 执行 `clock_gettime` 返回 `-1/EINVAL(22)`。其余 C child 观测同样存在 cached-TID 不符，A/B 均与各自 child 的 `gettid()` 一致。

**[源码事实 + 实测佐证]** B 的系统调用含 `CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID` 和 `child_tidptr`；C 两次调用只含 `CLONE_PIDFD|CLONE_INTO_CGROUP`，没有提供 child TID 地址。具体 flags 由 B strace (`runs/verify-01/syscall-traces/1-libc-state.strace`, omitted from this source release)、C 两代 strace (`runs/verify-01/syscall-traces/2-raw-nested.strace`, omitted from this source release) 确认。glibc getter 对应源码与 descriptor 更新路径见 运行时路径 (`02-runtime-paths.md`, omitted from this source release)。

**[实测边界]** 普通 `__thread` canary 值、TLS 地址和 `pthread_self()` 指针仍可正确继承。虚拟地址相同是 fork 的正常现象，不能用来证明 glibc 缓存 TID 已正确更新；本轮也没有把整个 TLS 系统判定为全部损坏。

#### 4.3 robust mutex 的实际恢复失败

单线程 parent 创建 `MAP_SHARED` 上的 `PTHREAD_PROCESS_SHARED | PTHREAD_MUTEX_ROBUST` mutex，先成功 lock/unlock，确保 fork 前无人持锁。child 成功 lock 后直接退出，不 unlock；parent 先 `waitpid`，再 timedlock。这排除了“把 parent 持有的 mutex 所有权错误地视为继承给 child”这一无效测试方式。

| 方法 | child lock | parent 恢复结果 | kernel robust head |
|---|---|---|---|
| A | 两次均 0 | 两次 `EOWNERDEAD(130)` | child 非零 |
| B | 两次均 0 | 两次 `EOWNERDEAD(130)` | child 非零 |
| C | 两次均 0 | 两次 `ETIMEDOUT(110)` | child 为 NULL |
| B0 | 0 | `EOWNERDEAD(130)` | child 非零 |

**[实测]** 这是实际的 owner-death 语义失败，发生于单线程模板，而不是超时后推测“可能死锁”。直接证据：A robust (`runs/matrix-01/micro/02-os-robust.ndjson`, omitted from this source release)、B robust (`runs/matrix-01/micro/09-libc-robust.ndjson`, omitted from this source release)、C robust (`runs/matrix-01/micro/16-raw-robust.ndjson`, omitted from this source release)、B0 robust (`runs/matrix-01/micro/22-standalone-robust.ndjson`, omitted from this source release)。

**[源码事实 + 实测佐证]** B 的 child 明确调用 `set_robust_list`；C 两代 child 的 `get_robust_list` 都返回 NULL，PyOS child hook 前后均未修复。raw 同时缺少 cached-TID 更新和 robust-list 重注册。本实验没有逐一补丁消融，因而不宣称已经量化这两项对超时各自的贡献；它确定证明原 raw 路径整体不满足该 mutex 合同。B/C syscall 证据 (`runs/verify-01/syscall-traces/index.json`, omitted from this source release)

#### 4.4 libc stdio 内部锁：仅限受控多线程诊断

可信 native helper 线程对一个 `FILE *` 执行 `flockfile`，通过 pipe 确认已持锁后，主线程才 fork。child 执行 `ftrylockfile`，不等待；parent 在 child 退出后释放 helper、join 并清理。helper 不执行 Python。

**[实测]** A/B 各两次 child `ftrylockfile == 0`；C 两次均为 `16`，表示不能取得继承锁。公有 API 只承诺非零表示未取得锁，报告保留数值 16 而不把特定 errno 名称当通用返回合同。A stdio (`runs/matrix-01/micro/04-os-stdio.ndjson`, omitted from this source release)、B stdio (`runs/matrix-01/micro/11-libc-stdio.ndjson`, omitted from this source release)、C stdio (`runs/matrix-01/micro/18-raw-stdio.ndjson`, omitted from this source release)

**[边界]** 该 case 有两条真实线程，明确超出当前生产单线程模板合同；用于揭示 libc fork 的内部 FILE 锁处理差异。A/B 在这个用例成功不代表允许多线程 parent 的 child 执行任意 Python/native 工作，也不代表 malloc、loader、NSS 等所有内部锁已经测试。probe 完成后没有将多线程模板列入支持范围。

### 5. 成功、失败与 errno：不把不同层次混为一谈

资源失败通过将 caller 和 raw target 放在同一个 `pids.max=1` 祖先下实现，未使用 root 可绕过的 `RLIMIT_NPROC`。A/B/C 每项都尝试两次，B0 一次；失败后 parent callbacks 仍执行、没有 child、模板能完成下一次请求。各项 cgroup `pids.events` 与完整记录保存在 matrix 索引 (`runs/matrix-01/micro/index.json`, omitted from this source release)。

| 失败场景 | Python/C 探针看到的 errno | 解释 |
|---|---:|---|
| A，资源限制 | `0, 0` | 实际派生失败；当前 CPython 错误传播未保存 errno |
| B，资源限制 | `11, 11` | wrapper 保存创建返回后的 `EAGAIN` |
| C，资源限制 | `11, 11` | 同样保存 `EAGAIN`，不能据此认定 native 兼容 |
| B0，资源限制 | `11` | glibc 的独立 C 失败返回 |
| C，无效 cgroup FD | `22, 22` | 当前 kernel 对该 `clone_args.cgroup` 值返回 `EINVAL`；不能预设为 EBADF |

**[实测]** strace 在独立 verify 用例中直接观察到 A 的 `clone(...) = -1 EAGAIN`，随后 NDJSON 的 `fork_failed.errno=0`。因此 0 不是内核返回成功或没有触发资源限制。A 失败 strace (`runs/verify-01/syscall-traces/0-os-callbacks-failure.strace`, omitted from this source release)、同次 NDJSON (`runs/verify-01/syscall-traces/0-os-callbacks-failure.ndjson`, omitted from this source release)

**[源码事实]** 该版本 `os_fork_impl` 在 `fork` 失败后执行 `PyOS_AfterFork_Parent`，再构造 `OSError`，没有在这两者之间保护 errno。CPython `Modules/posixmodule.c` 的 `os_fork_impl` (`sources/runtime-source/cpython-3.10.12-ubuntu/Modules/posixmodule.c`, omitted from this source release)

**[分析推导 / 未进一步隔离]** 现象与 parent hook/回调期间 errno 被覆写一致。本轮没有逐条定位是 Python 日志回调的某个 API 还是 hook 内部操作覆写了它；不得把具体覆写指令写成已复现事实。B/C 的 errno 保存是独立、清楚定义的 wrapper 行为，不是 raw 更接近标准 fork 的证据。

**[实测]** 正常退出与退出 `7` 均经真实父进程 `waitpid` 得到正确状态；nested 中第一代确实等待第二代，原模板等待第一代。这里没有把 pidfd 当成改变 wait-parent 关系的能力。A/B/C exit7 原始记录见 matrix 索引 (`runs/matrix-01/micro/index.json`, omitted from this source release)

### 6. 两次派生、内存继承与模板污染能证明什么

**[实测]** A/B/C 的普通 case 在同一模板里生成两个 sibling；nested 每轮执行 `template → child → grandchild`。每代 Python 对象地址、最初 `born_pid`、64 KiB 内容 hash、查表计算结果均与模板一致。子代修改 bytearray 后，上代/模板再次取样仍保持原值。三种方法的全部 Python 内存检查均无不符；native runtime 的 C 差异同时存在。A nested (`runs/matrix-01/micro/03-os-nested.ndjson`, omitted from this source release)、B nested (`runs/matrix-01/micro/10-libc-nested.ndjson`, omitted from this source release)、C nested (`runs/matrix-01/micro/17-raw-nested.ndjson`, omitted from this source release)

**[边界]** 这证明自有有限状态在两轮/两代路径中正确继承和 COW 隔离，不等于任意对象图、外部 FD/连接、数百轮运行、长期回调注册/卸载、信号竞争或 native allocator 状态不会污染模板。比较的是所测对象与 state 摘要，没有比较整个 heap 或测量长期泄漏；hooks、日志与计数器本身会改变 parent 状态。回调在 parent 执行时本来可以主动修改模板；COW 不能隔离发生在 parent 本身的修改。

### 7. 原子 cgroup 出生的证据链

需要同时满足三类证据，而不是把最终 `/proc/self/cgroup` 输出当作单独证明：

1. **[实测] 创建实参：** C 的 strace 两次均为 `CLONE_PIDFD|CLONE_INTO_CGROUP`，目标分别为预先打开的 target/grandchild FD，没有 fork 后 `cgroup.procs` 迁移步骤。C syscall trace (`runs/verify-01/syscall-traces/2-raw-nested.strace`, omitted from this source release)
2. **[源码事实] kernel 顺序：** 实际版本 `cgroup_can_fork` / `cgroup_css_set_fork` / `cgroup_post_fork` 在 child 可运行前完成权限、控制器限制和归属处理，之后才 `wake_up_new_task`。详见 02 第 6 节 (`02-runtime-paths.md`, omitted from this source release)、固定 kernel fork.c (`sources/runtime-source/kernel/fork.c`, omitted from this source release)、cgroup.c (`sources/runtime-source/kernel/cgroup.c`, omitted from this source release)。
3. **[实测] 用户态观测：** C 的首次受控 C snapshot、Python child hook 后 snapshot 和第二代 snapshot 均在指定 target/grandchild 中；A/B/B0 则一直继承 caller，分析器没有错误地要求它们满足 raw 的目标能力。

**[分析推导]** 实际 flags、匹配 kernel 实现及早期观测共同支持当前 raw 路径的原子目标 cgroup 出生合同。没有证据将普通 `fork()` 自动等同于目标 cgroup 创建；本轮也未通过未保护的事后迁移改变 A/B 的定义。

**[测量边界]** `before_PyOS_child` 是 C wrapper 返回后、调用 PyOS child hook 前的可信测量，期间已执行测量 syscall 和 C 指令；A 的第一个 Python 观测更晚。测试没有“在首条用户指令或首个 syscall 之前读 `/proc`”，也没有以直接调度点采样独立证明不存在任何瞬间窗口。原子性归因依赖上述 kernel 源码顺序，而不是声称测量达到了不存在的时间点。cgroup 成员出生归属也不自动等于所有继承页重新计费、所有共享内存成本归属已验证。

### 8. raw 跨域资格仍成立，但不覆盖运行时缺口

在独立副本中保持原 raw bridge/native/policy，顺序创建两次 Bubblewrap 隔离域生命周期，使用同一 Zygote 服务 normal 与 nonzero。没有覆盖 `qualification-02`。运行范围 (`runs/verify-01/cross-domain-raw-c/run-scope.json`, omitted from this source release)、源码 manifest (`runs/verify-01/cross-domain-raw-c/source-manifest.json`, omitted from this source release)

| 观察 | normal | nonzero |
|---|---|---|
| guest 外层 PID 链 | Z `260` → S `263` → W `264` | Z `260` → S `269` → W `270` |
| W 的域内 PID | `2` | `2` |
| S 初始 cgroup | `d0/transition` | `d1/transition` |
| W cgroup | `d0/business` | `d1/business` |
| W wait 退出码 | `0` | `7` |
| 各项业务隔离检查 | 19/19 为 true | 19/19 为 true |
| Z 所测对象/state 摘要 | 请求后未改变 | 请求后未改变 |
| 域资源/进程清理 | drained、移除 | drained、移除 |

**[实测]** W 完成目标 user/mount/PID/net/ipc/uts namespace 进入，五个 capability 集合为零、`NoNewPrivs=1`、`Seccomp=2`、FD 只剩 `0/1/2`；setns/unshare/chroot/exec 测试均被拒绝，根目录、cwd、环境、只读输入与可写工作目录检查全部正确。W 继承原对象 identity/hash/计算结果，修改 COW 内容后，Z 所测对象的相同摘要未改变。normal 全记录 (`runs/verify-01/cross-domain-raw-c/0-normal.json`, omitted from this source release)、nonzero 全记录 (`runs/verify-01/cross-domain-raw-c/1-nonzero.json`, omitted from this source release)

**[实测]** kernel process trace 记录上述两条 `Z→S→W` fork 链；S/W 没有 exec 事件。Z 的初始 exec、Bubblewrap 和 domain-init 的 exec 是设计内的启动步骤，明确与 S/W 的无 exec 继承路径区分。trace 各 CPU 统计 `overrun=0`、`dropped events=0`；这支持所记录区间中的无 exec 证据。process trace (`runs/verify-01/cross-domain-raw-c/process-trace.txt`, omitted from this source release)、trace stats (`runs/verify-01/cross-domain-raw-c/trace-stats.json`, omitted from this source release)

normal 的 W 另生成的后代由域 PID1 回收；S 等待 W，Z 回收 S。controller 最终确认 ECHILD；两个域及 delegation 被移除，外部 observer 没有代替正常清理杀进程。summary (`runs/verify-01/cross-domain-raw-c/summary.json`, omitted from this source release)、external release (`runs/verify-01/cross-domain-raw-c/external-final-release.json`, omitted from this source release)

**[边界]** 微型 runtime 对照未做 namespace 迁移；该跨域资格复测没有把全部 native 探针植入管理期或最终 Worker。因此两组证据互补，不能合并成“所有 runtime 探针已在跨域上下文通过”。跨域 summary 的 `all_passed` 只指原有可信模板资格条目，明确排除完整 runtime 兼容主张。它没有消除第 4 节单线程即可触发的错误。

### 9. 本轮证据边界与后续候选

| 分类 | 本轮已经知道什么 | 不能据此声称什么 |
|---|---|---|
| **实际错误** | C 漏 native callbacks；自有 native owner 不修复；pthread CPU clock 目标错误及实际 EINVAL；robust 恢复超时 | 不能仍称 raw 是通用 glibc fork 兼容实现 |
| **诊断实际错误** | stdio 多线程 case 中 C 保留不可取得的 FILE 锁 | 不把它混入单线程支持合同；不把 A/B 的单例成功放大为多线程安全 |
| **确定源码差异** | raw 绕过 malloc/NSS/loader/unwind/NPTL stack lists、fork generation 等完整维护 | 未逐项故障注入，不能把这些全写成“已实测死锁” |
| **有限正面证据** | 两轮/两代可信内存继承、COW、目标 cgroup、跨域隔离与 wait/清理正确 | 不代表长期稳定、任意 native 库安全或不可信依赖准入 |
| **未验证机制** | 任意线程/信号竞争、pthread_once 进行中状态、callback 动态卸载/递归、设备/连接、复杂 allocator/TLS 组合 | 保持未验证；不能以无崩溃清除风险 |
| **不得捏造的缺口** | 普通 TLS canary 可以继承；kernel `!CLONE_VM` rseq 路径有其继承处理 | 不能写成“raw 丢掉所有 TLS / 必然丢 rseq” |

### 10. 候选 D：有限兼容证据与仍未覆盖的边界

#### 10.1 运行的是哪个候选

D 不是“从 C helper 直接调用几个私有 glibc 函数”。它在精确 Ubuntu glibc 源码的独立构建中保留完整 fork wrapper，并提供新导出入口 `shimos_fork_into_cgroup(int,int*)`，内部使用带 libc TID 地址和目标 cgroup 的 clone3；外层仍执行三个公开 PyOS hooks。实现与维护代价见 候选设计比较 (`04-design-options.md`, omitted from this source release)、[补丁](sources/runtime-source/patches/shimos-fork-into-cgroup.patch)、独立 bridge_d (`prototype/cross_domain/bridge_d.c`, omitted from this source release)。它没有在库存运行时里静默 fallback 到普通 fork。

**[实测]** `candidate-03` 的七个 D 微型 case 各有一条 `runtime_identity`，从本进程 `/proc/self/maps` 取实际映射路径并计算 ELF SHA256。只读核查程序 (`prototype/probes/check_runtime_identity.py`, omitted from this source release) 将这些记录与冻结的包文件实际字节、candidate-runtime-sha (`runs/candidate-03/candidate-runtime-sha.json`, omitted from this source release)、guest 安装记录 (`runs/candidate-03/candidate-runtime-install.json`, omitted from this source release) 逐项比较：

| 映射 | SHA256 |
|---|---|
| `/opt/shimos-glibc/lib/libc.so.6` | `a03b51fe69f36b630ecf7997af05cd36885b1f2f0b52e278391fa6e17047eff4` |
| `/opt/shimos-glibc/lib/ld-linux-x86-64.so.2` | `0682f493d0434391d4ec027d0bcb54dd5f9e46d044dc7810f69abea58fe1398e` |
| 微型探针 `libprobe.so` | `b1d7caedb72522d406117893ec24ee005bcf83bb5ca12dd3c333319f612462d4` |

七项全部一致，maps 中也存在这三个实际路径；探针 DSO 的预期 hash 来自同 guest 的 binary-sha (`runs/candidate-03/micro/binary-sha.json`, omitted from this source release)。这消除了“工具看见版本 2.35，但可能仍调用库存 fork”的歧义。核查不是上游构建可重复性证明，也不把微型进程的 maps 记录冒充每个跨域 Worker 的 maps 取样。

#### 10.2 与原 raw 的同轮对照

**[实测]** `candidate-03` 总共 32 项，外部 harness、逐 PID 回调及关键事件完整性全部完成；matrix/cross-domain/syscall-traces 三个阶段返回值均为 0。阶段结果 (`runs/candidate-03/candidate-phase-results.json`, omitted from this source release)、微型索引 (`runs/candidate-03/micro/index.json`, omitted from this source release)、完整分析 (`evidence/candidate-03-micro-analysis.json`, omitted from this source release)

| 检查 | 同轮 C raw | D 候选 |
|---|---|---|
| Python 回调顺序 | 正确 | 正确 |
| native prepare/parent/child | 缺失 | 与第 3 节标准顺序一致 |
| native owner PID | 14/14 child 不符 | 14/14 正确 |
| pthread CPU clock 目标 TID | 14/14 child 不符 | 14/14 正确 |
| kernel robust head | 14/14 child 为 NULL | 14/14 已注册 |
| robust 所有者死亡恢复 | `110,110`，超时 | `130,130`，EOWNERDEAD |
| stdio 多线程诊断 trylock | `16,16` | `0,0`；仍仅为诊断 |
| 资源拒绝后的 errno / callbacks | `11,11`；只有 Python parent | `11,11`；native 与 Python parent 都执行 |
| 两轮/两代自有 Python 内存、COW | 符合预期 | 符合预期 |
| 目标 cgroup 早期观测 | target / grandchild | target / grandchild |
| 退出 0 / 7 与实际 wait | 正确 | 正确 |

D 原始例子：callbacks (`runs/candidate-03/micro/21-compat-callbacks.ndjson`, omitted from this source release)、state (`runs/candidate-03/micro/22-compat-state.ndjson`, omitted from this source release)、robust (`runs/candidate-03/micro/23-compat-robust.ndjson`, omitted from this source release)、nested (`runs/candidate-03/micro/24-compat-nested.ndjson`, omitted from this source release)、stdio (`runs/candidate-03/micro/25-compat-stdio.ndjson`, omitted from this source release)、exit 7 (`runs/candidate-03/micro/26-compat-callbacks-exit7.ndjson`, omitted from this source release)、失败 (`runs/candidate-03/micro/27-compat-callbacks-failure.ndjson`, omitted from this source release)。D 没有把 C 的无效 FD 用例自动算作自己的测试；D 本轮明确执行的失败场景为 pids controller 拒绝。

**[实测]** D 的独立 trace 中两代创建均为：

```text
clone3(flags = CLONE_PIDFD | CLONE_CHILD_CLEARTID |
               CLONE_CHILD_SETTID | CLONE_INTO_CGROUP,
       child_tid = <glibc descriptor tid address>,
       cgroup = <target FD>, exit_signal = SIGCHLD)
child: set_robust_list(...) = 0
```

第二代改变目标 cgroup FD；两代都明确调用 `set_robust_list`。失败 trace 明确显示该 clone3 返回 `EAGAIN`，对应 native/Python parent 回调和错误返回完整。D nested strace (`runs/candidate-03/syscall-traces/3-compat-nested.strace`, omitted from this source release)、D 失败 strace (`runs/candidate-03/syscall-traces/4-compat-callbacks-failure.strace`, omitted from this source release)

**[源码事实 + 分析推导]** D 的隔离相关 flags 保留 `CLONE_INTO_CGROUP` 和 `CLONE_PIDFD`，额外 TID flags 配合完整 libc 维护，未改成“普通 fork 后移组”。结合第 7 节匹配 kernel 的执行顺序，原子出生归属继续成立；本节对测量时点、共享页计费的限制同样适用。

#### 10.3 D 的独立跨域资格复测

**[实测]** 同一 D 模板 Z `387` 顺序服务两个 Bubblewrap 域：normal `387→390→391`，nonzero `387→395→396`。两个 W 域内 PID 均为 `2`，目标 namespace、transition/business cgroup、自有 Python 对象继承、COW、最终五组 capability 归零、NNP/seccomp、FD、环境/目录/只读输入和 exec 拒绝共 19 项检查各自全部为 true；W 退出码分别为 `0`、`7`，S/Z 的等待与回收、PID1 的后代排空和域资源移除均完成。D normal (`runs/candidate-03/cross-domain-glibc-d/0-normal.json`, omitted from this source release)、D nonzero (`runs/candidate-03/cross-domain-glibc-d/1-nonzero.json`, omitted from this source release)、汇总 (`runs/candidate-03/cross-domain-glibc-d/summary.json`, omitted from this source release)

独立副本选择 `bridge_d.so`，保留原 native/policy，显式以候选 loader 启动 Z，并将候选运行时的相关文件只读覆盖到目标根中；运行范围记录了 bundle、DSO hash、覆盖路径和库存 controller / 候选 Z 的区分。D run-scope (`runs/candidate-03/cross-domain-glibc-d/run-scope.json`, omitted from this source release)

process trace 记录两条 Z→S→W 链且无 S/W exec，各 CPU 无 trace overrun/dropped events；Z 所测对象/state 摘要两次请求后未改变，没有据此声称整个模板 heap 未变或不存在长期泄漏。外部 observer 没有杀进程完成兜底清理，delegation 最终移除。process trace (`runs/candidate-03/cross-domain-glibc-d/process-trace.txt`, omitted from this source release)、trace stats (`runs/candidate-03/cross-domain-glibc-d/trace-stats.json`, omitted from this source release)、external release (`runs/candidate-03/cross-domain-glibc-d/external-final-release.json`, omitted from this source release)

**[边界]** 与 raw 跨域复测相同，这里的 19 项是既有隔离/继承合同，不含跨域上下文中全部 native 微探针。D 的微型 runtime 修复与独立跨域资格分别得到证据；下一步仍需把关键信息组合到更完整准入测试，不应把有限组合覆盖称为任意第三方兼容。

#### 10.4 D 的支持结论没有扩大到哪里

**[有限支持]** 当前证据支持把 D 保留为固定 Linux/Ubuntu glibc/CPython/x86_64、主解释器主线程、持 GIL、可信初始化与可信回调的候选；它修复了本轮实际观察到的 raw 运行时差异，并在独立副本保持资源、隔离和内存继承要求。

**[未覆盖]** 没有完成完整 glibc 测试套件、所有信号/线程/allocator/loader/once 竞争、长时重复派生、跨架构、glibc 版本升级，或真实第三方依赖准入。B/D 的 PyOS wrapper 也没有实现 `os.fork()` 的 `PySys_Audit("os.fork")` 及其 isolated-interpreter 检查，不能称为 `os.fork` 的所有高层 API 语义完全替代。

**[已发现的静态 ABI 缺口，非运行失败记录]** `candidate-03` 包额外提供的旧 glibc `libcrypt.so.1` 只有 `GLIBC_2.2.5`，而 guest 的 `_crypt` 扩展强制要求 `crypt_r@XCRYPT_2.0`；该包的优先搜索与目标域覆盖会选择不满足要求的 provider。现有微型/跨域 case 没有加载这一路径，所以它不推翻已经获得的 fork 数据，却明确阻止把 `candidate-03` 宣称为通用 Python 标准库兼容运行时。本轮此发现来自 ELF 版本需求比对，**没有执行 `_crypt` import 并观察到异常**。readelf 原始记录及文件哈希 (`evidence/libcrypt-static-abi.json`, omitted from this source release)、源码与 ELF 审查 (`evidence/source-review.md`, omitted from this source release)

**[权限与信任限制]** D 正确恢复 native callbacks，也意味着这些 callbacks 会在管理阶段执行。目标 cgroup 出生没有消除 namespace 管理能力；依赖及其 hooks 的可信性仍属于独立准入前提。修复 fork 合同不构成不可信依赖隔离。

### 11. 候选运行的失败历史完整保留

| 运行 | 实际结果 | 能与不能得出的结论 |
|---|---|---|
| `candidate-01` | guest 安装 bundle 时，9p 共享下若干 host symlink alias 触发 `ELOOP`；`shutil.copytree` 抛异常，`complete=false` | 尚未进行任何候选 fork；这是设施打包失败，不能归为 D fork 语义失败，也不能计为一次成功运行 |
| `candidate-02` | alias 实体化后安装成功；D 的七个微型 case 全部 exit `127`，loader 找不到 `libexpat.so.1`；没有 D callback / state 记录。独立 cross-domain 的库搜索路径完整，因此该阶段成功；整个运行 `complete=false` | 此轮 D 微型数据缺失，不能用“没有观察到错误”当 PASS。cross-domain 成功只属于该独立阶段 |
| `candidate-03` | micro / trace 的显式 `--library-path` 补齐库存 multiarch 库目录，32 项、跨域和 trace 完整结束，`complete=true` | 这是原 bundle 的 D 完整对照；之后发现未触达的 libcrypt 静态 ABI 缺口，修包后另跑 04；既有证据不覆盖、不删除 |

`candidate-01` 原始 安装 traceback (`runs/candidate-01/guest-output.log`, omitted from this source release) 与 result (`runs/candidate-01/result.json`, omitted from this source release) 保留。打包修复只把包内 symlink alias 物化为对应目标的相同字节，原链接目标另存；候选 ELF 和 bundle manifest 未改。candidate-02 packaging (`runs/candidate-02/candidate-packaging.json`, omitted from this source release)、candidate-03 packaging (`runs/candidate-03/candidate-packaging.json`, omitted from this source release)

`candidate-02` 的 缺库 stderr (`runs/candidate-02/micro/21-compat-callbacks.stdio`, omitted from this source release)、完整微型索引 (`runs/candidate-02/micro/index.json`, omitted from this source release)、失败分析清单 (`evidence/candidate-02-micro-analysis.json`, omitted from this source release)、阶段状态 (`runs/candidate-02/candidate-phase-results.json`, omitted from this source release) 明确记录七个 D case 的缺测与失败。其独立 跨域汇总 (`runs/candidate-02/cross-domain-glibc-d/summary.json`, omitted from this source release) 可供复核，但没有用来补造缺失的 native callback 结果。

库搜索路径修复为 `/opt/shimos-glibc/lib:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu`，优先使用显式候选 libc/loader，其余 CPython 依赖从同 guest 的库存目录加载。它没有增加 Z 权限、关闭 seccomp、改变原子 cgroup 要求或通过普通 fork 迁移偷偷替换问题定义。candidate-03 完整 argv (`runs/candidate-03/micro/index.json`, omitted from this source release)

### 12. 最终包修正与 candidate-04 复测

#### 12.1 修正内容及归因

**[文件/配置事实]** `candidate-04` 使用打包修订 `exclude-glibc-legacy-libcrypt-v1`，只从候选包排除 `lib/libcrypt.so`、`lib/libcrypt.so.1`，保留 guest 原有 libxcrypt provider。对照两轮冻结 `candidate-runtime-sha.json`，除 manifest 自身更新和上述两项删除外，其余 **283 个运行时成员 hash 相同**；没有重编译，也没有修改 fork 实现。03 冻结 manifest (`runs/candidate-03/candidate-runtime-sha.json`, omitted from this source release)、[04 冻结 manifest](runs/candidate-04/candidate-runtime-sha.json)、04 包元数据 (`runs/candidate-04/candidate-runtime/manifest.json`, omitted from this source release)、[打包脚本](sources/runtime-source/patches/package-no-legacy-crypt.py)

**[实测配置]** guest 安装清单不再包含这两个 libcrypt 文件；D 的目标域只读覆盖清单也不再覆盖 `/lib/x86_64-linux-gnu/libcrypt.so.1`。显式候选 loader 的其余搜索路径保持同 guest 的库存 multiarch 目录，使该 provider 继续由原 guest 文件提供。04 安装记录 (`runs/candidate-04/candidate-runtime-install.json`, omitted from this source release)、04 跨域运行范围及覆盖清单 (`runs/candidate-04/cross-domain-glibc-d/run-scope.json`, omitted from this source release)

**[验证边界]** 这处理了已发现的“用错误同名 provider 遮蔽库存 libxcrypt”的包级问题；静态证据显示库存 provider 具备所需 `XCRYPT_2.0`。本轮没有新增 `_crypt` import 或实际动态绑定测试，没有将它记为业务已通过；包元数据里的该项进一步验证仍然属于待验证范围。也没有声称修复一项闭包问题便完成全部运行时库依赖闭包的兼容验证。

#### 12.2 同范围复测结果

**[实测]** `candidate-04` 完整结束，QEMU 返回 0、无超时；matrix、cross-domain、syscall-traces 三阶段均返回 0。整体结果 (`runs/candidate-04/result.json`, omitted from this source release)、阶段结果 (`runs/candidate-04/candidate-phase-results.json`, omitted from this source release)

| 核查 | candidate-04 结果 | 范围 |
|---|---|---|
| 32 项微型证据完整性 | 全部完整；无超时、各项 cgroup 清空 | 含 A/B/C/B0/D；C 的已知差异仍如实记录 |
| D 七项 / 14 个 child 状态 | callbacks、cached TID、kernel robust head、native owner 均符合受测合同 | 其中两个 child 为独立 stdio 诊断，其余单线程 |
| D robust / stdio | `EOWNERDEAD(130)` 两次；stdio trylock `0` 两次 | stdio 不改变生产单线程限定 |
| D 两次失败 | `EAGAIN(11)` 两次，native/Python parent 序列完整 | 无 child；模板继续第二次请求 |
| D 两轮 / 两代 | Python 所测对象继承、COW、target/grandchild 归属与 wait 0/7 均正确 | 不是长期泄漏或完整 heap 不变证明 |
| D 实际映射身份 | 七项均与冻结 bundle 字节、manifest、guest 安装记录一致 | libc/loader hash 与 03 相同；probe DSO 同 guest 构建 hash 匹配 |

原始与分析：微型索引 (`runs/candidate-04/micro/index.json`, omitted from this source release)、完整微型分析 (`evidence/candidate-04-micro-analysis.json`, omitted from this source release)、ELF 身份核查 (`evidence/candidate-04-runtime-identity.json`, omitted from this source release)。独立 strace 继续记录两代 `CLONE_INTO_CGROUP|CLONE_PIDFD|CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID`、各 child 的 `set_robust_list`，以及资源失败的真实 EAGAIN。两代 trace (`runs/candidate-04/syscall-traces/3-compat-nested.strace`, omitted from this source release)、失败 trace (`runs/candidate-04/syscall-traces/4-compat-callbacks-failure.strace`, omitted from this source release)

**[实测]** 同一 Z `388` 顺序服务 normal `388→391→392` 与 nonzero `388→396→397`，两个 W 的 19 项既有隔离/继承检查各自全部通过，退出分别为 0/7；所测模板对象/state 摘要未改变。两个域均排空、移除资源，真实 wait-parent 链、最终权限/seccomp/FD 限制及内存继承保留。04 normal (`runs/candidate-04/cross-domain-glibc-d/0-normal.json`, omitted from this source release)、04 nonzero (`runs/candidate-04/cross-domain-glibc-d/1-nonzero.json`, omitted from this source release)、04 跨域汇总 (`runs/candidate-04/cross-domain-glibc-d/summary.json`, omitted from this source release)

**[最终证据定位]** 04 是修正已发现包级冲突后的最新有限候选，03 是原包的有效受测记录及静态缺口历史，01/02 是保留的设施失败记录。D 的正面结论仍限于本文明确列出的运行时与隔离合同；主解释器主线程/GIL、可信初始化和可信 callbacks、固定构建及独立依赖准入条件继续成立，没有直接准入 NumPy CPU 或确定最终架构。

## 04 — 兼容实现候选与可维护性边界

**候选 D 可以在 Linux 的创建语义上同时保留 Python heap 与 `CLONE_INTO_CGROUP`，办法是维护一个完整、固定版本的 libc 源码扩展。** 本轮做了独立最小实现和微型验证入口；是否采用它作为 ShimOS 的运行时发行策略，仍需团队基于本轮实测与维护成本选择。它不能把不可信初始化代码从 Z 的 TCB 中移除，也不能把任意多线程/native 运行库变成 fork-safe。

下面把“代码能够构建”“指定 guest 微测试通过”“标准 API 全面等价”“生产支持任意依赖”作为四个不同层级。D 的最终测试范围以主报告和 `runs` 为准。

### 1. 方案对照

| 方案 | Python / native fork 语义 | 创建即进入目标 cgroup | 两次跨域 + heap | 权限/TCB | wait / 故障回收 | 本轮判断 |
|---|---|---|---|---|---|---|
| C 原 raw clone3 + PyOS hooks，限定单线程 | 有 Python hooks；缺 native callbacks、pthread tid、robust 等 | 是 | 原资格测试已跑通自有对象；有 runtime 错误 | 原权限；TCB 仍包括模板代码 | 保留 S 实际等待 W | **不能作为完整 fork 兼容实现**；单线程也不能消除已复现的 tid/robust/native callback 缺口 |
| 原生 `os.fork` / glibc `fork` | 两层正确组合时最贴近标准路径；仍有第三方 fork 限制 | 无目标 FD 参数，只继承父 cgroup | heap 可保留、两次 setns/fork 可做 | 无新增 capability | 原父子关系 | **当前出生归属要求下 BLOCKED**；不能拿事后移动充数 |
| `_Fork` / libc `clone` / 私有 `__clone_internal` | `_Fork` 故意不运行 atfork 与完整 wrapper；clone wrapper也不是fork wrapper | 公共 `_Fork` 无参数；clone3未提供标准同栈fork接口 | 低层内存复制可实现，合同不完整 | 偷调私有函数放大维护依赖 | 可保留父子关系 | **BLOCKED**，不是补齐路径 |
| 外部 C helper + 标准 fork / exec | 干净 helper 可有正确 libc 状态 | helper 自己也需要目标创建机制 | helper 的 child 继承 helper heap；exec 丢失已预加载模板 heap | 地址空间分离有效，但没有免费转移模板内存 | wait-parent 变 helper | 不能声称兼容修复已经保留原跨域模板状态 |
| 普通 fork + 用户态启动门控后迁移 | 完整 callbacks可能在门控前已执行 | 出生仍在源 cgroup | 可保留 heap | 须审计更早的 callbacks/信号/再派生 | 门控失败需杀死并回收 | **与本要求不等价 / BLOCKED**；详见 §4 |
| 父进程先临时迁入目标组，再普通 fork | 两层 hooks 可以保留 | child 可从出生继承目标组；未使用指定 CLONE_INTO_CGROUP | 可保留 heap；两次创建需分别迁移父角色 | Z/S 同时改变预算和 kill 归属，不再保持原资源合同 | 回迁失败、父死亡、并发和目标kill需新状态机 | 本轮未实现/验证；不是现有资源模型的等价替换 |
| **D：固定 glibc 内增公开 vendor API，内部完整 fork wrapper + clone3** | 正确包含 native wrapper，再由 bridge 包 PyOS hooks；高层 os.fork audit仍另论 | **是，保留 CLONE_INTO_CGROUP** | 无 exec、无新地址空间替换；两次调用保留 heap | 无新增 capability；增加自维护 libc 发行/审计责任；native callbacks进入实际执行的管理 TCB | SIGCHLD、pidfd、S wait-parent保持 | **本轮唯一实际实现的完整 wrapper 候选**；限定本架构/版本/可信模板，待团队选择 |
| per-domain / per-worker 模板，隔离后加载 | 可用标准 fork；前提本域 cgroup布局足够 | 默认继承模板所在 cgroup；独立 worker budget仍需设计 | 复用缩小到域内，不能免费跨域共享已初始化 heap | 管理期加载风险更低 | 需按新模板树管理 | 架构替代，不作为本轮原问题已解决 |
| ptrace 改 syscall / 内核扩展 / 恢复快照 | 理论可把完整 wrapper 的底层创建换轨 | 可以设计，但需额外协议和证明 | 可研究 | ptrace/内核/恢复器进入TCB，通常需更多控制能力 | 新停止/恢复/失败状态机 | 本轮不实现；不能用推测覆盖 D 的验证缺口 |

公共 Linux/glibc 文档说明 clone3 无普通 glibc wrapper；glibc `fork` 的实际实现是内部 clone syscall，但不会向调用者开放 clone3 flags 参数。[clone(2)](https://man7.org/linux/man-pages/man2/clone.2.html)、[glibc Process Creation](https://sourceware.org/glibc/manual/latest/html_node/Creating-a-Process.html)、实际发行 fork.c (`sources/runtime-source/patches/fork.c.original`, omitted from this source release)

### 2. D 的最小源码集成

公开 vendor 函数：

```c
pid_t shimos_fork_into_cgroup(int cgroup_fd, int *pidfd);
```

Linux x86_64 的 `pid_t` 为 `int`。这不是上游 glibc 已支持的 API；本原型把自有名字导出到独立 build 的 `GLIBC_2.35` symbol version 节点，仅方便链接/查找，**不表示 stock GLIBC_2.35 提供此函数**。最终产品若采用，应确定自有 ABI namespace、头文件、版本升级策略。接口声明和注释见 [shimos_fork.h](sources/runtime-source/patches/shimos_fork.h)。

源码改动仅三个文件，补丁可审阅：[shimos-fork-into-cgroup.patch](sources/runtime-source/patches/shimos-fork-into-cgroup.patch)。

1. `posix/fork.c` 抽出 `shimos_libc_fork_common(bool into_cgroup, int cgfd, int *pidfd)`。**保留原始 prepare、锁处理、child修复、parent失败解锁、callback次序的完整函数体。** 原 `__libc_fork()` 仍选择原 `_Fork()`，新 API 选择内部 cgroup 路径。
2. `sysdeps/nptl/_Fork.c` 抽出同样参数化的内部公共部分，保留 child robust-list 清理与 `set_robust_list`。新内部 syscall 路径填 `clone_args`：

```text
flags     = CLONE_INTO_CGROUP | CLONE_PIDFD
          | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID
          = 0x201201000
child_tid = &THREAD_SELF->tid
pidfd     = caller output address
cgroup    = caller target FD
exit_signal = SIGCHLD
stack, stack_size, tls, set_tid 等 = 0
```

3. `posix/Versions` 导出自有函数。外部 bridge 只查公开 vendor 函数和公开 PyOS API；新增内部 `__shimos_Fork_into_cgroup` 为 hidden/local，不对外暴露。

**[源码事实]** 没有 `CLONE_VM`、`CLONE_THREAD`、`CLONE_SETTLS`，不另设栈。调用沿相同栈在 child 返回，内核复制 mm 时保留继承的 heap / TLS 基址；child TID 写回指定 TLS 槽，robust-list 由 `_Fork` 共用 child 部分重建。目标 cgroup 选择交给 kernel 在唤醒前完成，不把 child 先放源组再搬迁。`ENOSYS` / `EPERM` / cgroup控制器失败等直接返回失败，**没有普通 fork fallback**。

所有请求参数经函数局部参数传递，没有设置“下次 fork 使用某个 cgroup”的进程全局变量或 TLS 控制开关。因此普通 `fork()` 不会因为残留请求配置误入上一个目标。反过来，若任意 native atfork callback 内主动调用普通 fork，它仍会产生普通 child；本轮可信合同明确不准许回调重入创建/改写管理状态。局部参数避免路由串线，不构成恶意 callback 的隔离机制。

### 3. 为什么源补丁比外部“补几个函数”可验证

**[源码事实]** `pthread_atfork` 没有公开枚举和执行全部已注册回调的 API；glibc fork 还使用 hidden 数据/函数，且有编译配置、线程历史、动态装载器锁、架构分支的组合。只自己执行一次 `set_tid_address` / `set_robust_list`，只能修补部分症状，既不能更新所有 libc 状态，也不能保证第三方 registered handlers 已运行。

**[推导]** 完整源码集成的可审计点是：用版本控制 diff 保证 fork wrapper 原有函数体没有被精简，只参数化创建指令与必要 syscall 参数；使用该版本原来的内部维护实现，而不是在外部 DSO 猜布局/调用 `GLIBC_PRIVATE`。这会承担“维护一个运行时发行版”的成本，但与“长期偷调未导出私有符号”有明确不同。

D 本身仍调用 libc 内部数据和函数，这是 **libc 自己的实现内部**，不是承诺这些内部符号成为跨版本 ABI。升级 glibc 时必须重新审阅 fork、_Fork、arch wrapper、register-atfork、NPTL、loader及kernel接口变更，并重新完成测试。若发行版未来的 `_Fork` 增加信号屏蔽/新线程修复，也必须被共用路径保留，不能冻结本次几行 housekeeping 当成永久合同。

最小可复现构建以 Ubuntu 精确源包为输入，独立 prefix `/opt/shimos-glibc`；启用 `--enable-stack-protector=strong`、CET 和 stackguard randomization，避免默认实验构建无意降低原包的相应编译属性。源包、补丁、configure/build/install日志与 bundle SHA256 一并保存。**编译成功不等于完整 glibc 回归测试通过**；本轮针对 fork 的 guest 微测试及跨域资格测试是明确范围，完整发行打包/全glibc测试仍是采用前条件。

### 4. 门控迁移的证明障碍

普通 `os.fork()` / glibc `fork()` 在返回应用 child 分支前，已经运行 native child callbacks；Python `os.fork()` 还在返回前运行 Python child callbacks。因此在 `if pid == 0: read(pipe)`、`raise(SIGSTOP)` 或 worker main 顶部加门控，不能证明用户代码未在错误 cgroup 内执行；回调还可在门控前创建后代。让 parent 尽快写 `cgroup.procs` 同样存在调度竞态。

一个更严格的门控设计至少需要：在所有可扩展 child 代码之前由受信任运行时进入不可绕过的停止点；创建前阻断异步信号入口；保证所有注册 handler 的先后次序；禁止或控制子进程在门控前再派生；由独立组件确认迁移后再放行；对创建者死亡、目标消失、FD误投、门控超时做终止与回收。把 gate 放在最早**自己**注册的 atfork handler 也须证明没有更早注册的 loader/native handlers；“我们的 handler 排在第一”不能只靠约定。

即便以上用户态执行门控全部成立，child 的 kernel 创建、PID/cgroup controller准入、初始资源记账仍发生在原 cgroup；迁移时的 controller拒绝、父模板组预算、cgroup.kill归属窗口仍不同于 `CLONE_INTO_CGROUP`。所以本任务要求下它只能成为另行论证的资源模型，不能认定等价。本轮没有以此替换原子出生要求。

另一种不同方案是创建**之前先迁移父进程**。Linux 普通 fork 的 child 确实继承父 cgroup，因此该方案不能被笼统否定为“无法出生于目标组”。但 Z 也会临时进入某次任务的 transition 预算/kill 范围，S 的第二次创建同理需要重新定位资源归属；父回调也在该组执行。迁移/回迁失败、控制器并发取消及常驻模板资源归属需要重新证明，而且它没有保留本轮指定的 CLONE_INTO_CGROUP 路径。这里只作为未验证的替代资源模型记录。

### 5. 独立干净派生进程的真实收益与限制

先 exec 一个干净 forkserver，再由它 import 可信库，可以避免从已有多线程业务进程派生，减少状态复杂度；之后从它标准 fork 可以保留**它自己**准备的 heap。这正是专用模板的价值。它不会继承原调用者任意 heap，不能同时把其 native 初始化移到低权限地址空间、又让另一个高权限 helper 任意 fork 出该 heap 的副本。

如果 forkserver 仍需跨域原子出生，那么它仍面对相同的 fork/clone3接口问题；D 可以供它使用。若先为每个域建立独立模板、在隔离内预加载，则可以缩小信任与兼容范围，但会重复 import、常驻内存和域管理成本。共享只读文件/page cache/mmap 可保留某些收益，但不等价于复用 Python对象图、模块状态或原生运行库锁状态。

### 6. D 支持范围与未完成的保证

D 的本轮资格合同应限定：固定 x86_64 guest / libc / CPython；主解释器主线程持GIL；可信模板和callbacks；正常创建前无其他活动线程；不允许callbacks递归创建、修改目标FD/namespace/信号合同；使用相同 runtime 文件树；跨域与最终seccomp/降权流程保持原要求。受控多线程stdio探针仅用于识别差异，不扩大模板支持范围。

采用前仍需解决：完整 libc 发行回归；callback信号/重入与errno合同；动态loader/NSS/TLS/once在声明支持状态内的定向测试；两次派生和长期重复派生；目标cgroup被删/权限被撤销/资源限额/目标PID1死亡的失败回收；bundle覆盖和文件版本核对；安全更新和ABI升级流程。生产实现应在模板启动时验证所需 vendor symbol 与bundle身份，缺失则走独立普通隔离启动路径，不能静默改用不满足出生归属的 fork。

**[安全边界]** 恢复 native callbacks 恢复了标准fork所需行为，也意味着更多模板代码在S/W最终降权之前执行。需要审计所有callbacks与传递依赖；D不会替代依赖可信性准入。任意不可信C扩展与管理代码仍同地址空间、共享控制FD与未来namespace资格，此核心TCB问题没有被本轮runtime兼容修复解决。

## 05 — 支持范围、后续门槛与 Q1–Q5

### 1. 可以确认到哪一层

**当前 raw clone3 路径存在已复现的运行时错误，不能作为“等价于 fork”的依赖准入基础。** 这与原 `qualification-02` 证明的自有 Python 对象可跨域继承不矛盾：内存继承、namespace/cgroup 机制、运行时状态正确性是三个不同验证对象。

**候选 D 证明了一条可实现的修复方向：在固定 glibc 源码内共享完整 fork wrapper，以 clone3 提供目标 cgroup 和 pidfd，再由 bridge 执行 CPython hooks。** 本轮微型数据和独立跨域数据支持它在所测合同内工作；不据此决定 ShimOS 最终采用自维护 libc，也不宣称获得全部 POSIX、glibc 或 `os.fork` API 等价性。

证据入口：源码路径 (`02-runtime-paths.md`, omitted from this source release)、实验及失败历史 (`03-experimental-evidence.md`, omitted from this source release)、候选比较 (`04-design-options.md`, omitted from this source release)。原始日志与机器分析均保留在 `runs/`、`evidence/`。

### 2. 本轮候选的限定合同

| 维度 | 本轮可以支持的范围 | 不能外推的保证 |
|---|---|---|
| 平台 | 固定 Linux x86_64 guest、Ubuntu 2.35 发行源码扩展、CPython 3.10.12 发行构建；产物有 hash | 其他架构、其他 glibc/CPython 版本和任意目标 rootfs |
| 调用上下文 | 主解释器主线程持 GIL；正常模板创建前无其他活动线程 | 多线程父进程后继续复杂 Python/native 工作；stdio 两线程探针仅作故障诊断 |
| 回调 | 测过 Python/native 各两组的顺序、成功和创建失败行为 | 任意回调重入 fork、异步信号处理、注册/注销竞争、异常回调、回调更改凭据/namespace/cgroup FD |
| 内存 | 自有对象图、字节摘要、计算结果、对象地址继承；子进程修改后父模板所测对象保持原值 | 整个 heap 未变化、无所有类型的泄漏、任意 native heap/连接/设备状态可复用 |
| 线程与锁 | 所测 TLS canary、公开 pthread CPU clock、robust owner-death 恢复、stdio 锁诊断 | malloc/NSS/loader/pthread_once 所有竞争和线程历史组合均已验证 |
| 跨域机制 | 同 Z 服务两个 Bubblewrap 域；Z→S→W 两次创建；S/W 无 exec；原权限/seccomp/FD清理合同 | 故障矩阵的全部旧资格结果自动移植到新 libc；各种死亡/并发/长期压力场景已覆盖 |
| 生命周期 | 正常0、非零7、真实 pids controller 拒绝；pidfd、S wait W、controller ECHILD、资源删除 | OOM、信号风暴、控制器崩溃、目标删除竞争和所有失效恢复 |
| 分发 | 显式候选 loader、配套 DSO、目标只读绑定；无候选 API 则 ENOSYS | 任意 libc 混装、全部 Python 标准扩展已验证、完整发行 ABI 回归已完成 |

主线程/可信回调等是研究原型的**使用前提**。当前 C API 本身并不是能抵抗恶意调用者的引用监控器；部分条件由 fixture 检查，部分由自有代码保证。生产准入需要把它们转为可执行的检查、固定初始化过程和明确失败路径。

### 3. Q1：当前 raw clone3 的兼容性缺口具体有哪些？

**[源码事实]** 当前 C 路径只调用 CPython 的三项 hooks，然后直接 `syscall(SYS_clone3)`，绕过 glibc `__libc_fork → _Fork → arch_fork`。具体缺失包括：

- `pthread_atfork` 的 prepare、parent、child 回调链。Python 的 `os.register_at_fork` 回调链仍然执行，两者不能混称。
- `CLONE_CHILD_SETTID/CLEARTID` 及 `&THREAD_SELF->tid`，使 glibc pthread descriptor 的 TID 未随子进程更新。
- `_Fork` 的 robust list 清理与向 kernel 重新注册。
- fork generation、loader/TLS 锁、stack lists 的维护，以及特定线程历史下 malloc、stdio、NSS、线程计数等准备/修复路径。

CPython hooks 修复的是 CPython 自身和它注册的 Python 回调，不能代替 libc/native 的合同。rseq 则必须单独看：实际 kernel 对 `!CLONE_VM` 的 fork 继承注册，**不能把它列作已证明 raw 缺失的事项**。

### 4. Q2：哪些已经导致实际错误，哪些只是源码风险？

**[guest 实测错误]** raw 子进程的公开 pthread CPU clock ID 指向旧 TID、`clock_gettime` 返回 EINVAL；kernel robust head 为0，共享 robust mutex 的 owner-death 恢复得到 ETIMEDOUT，而标准路径得到 EOWNERDEAD；native handlers 完全未被调用，自有模拟 native runtime 的 child owner 状态未修复。两代和连续两轮样本中均可见相应问题。

**[诊断实测]** 自有 helper 线程持 FILE 锁时，raw child 的 `ftrylockfile` 返回16（非零），标准 fork 和 D 返回0；该 API 的判定合同是0/非零，不声称通用 errno 行为。这刻意超出单线程模板合同，不能反过来用通过结果准入任意多线程工作负载。

**[另一个实测异常]** 本发行版 `os.fork` 的受控失败在 kernel 返回 EAGAIN 后，Python exception errno 观测为0；其源码没有跨 `PyOS_AfterFork_Parent` 保存 errno。具体哪个 hook 内调用写入0尚未隔离。B/C/D bridge 保存 errno 后报告11。它是错误传递差异，不能拿来抵消 raw 的其他不兼容。

**[确定源码差异、尚未逐项触发]** malloc/NSS/loader/pthread_once/动态 TLS/stack cache 等不能写成“本轮已全部复现死锁”。异步信号、native callback 异常/竞争、全套第三方库状态和长期稳定性均未验证。

候选 bundle 还出现过两次设施失败和一次静态 ABI 审查发现，均单独记录，不抹掉失败，不把静态缺符号写成已经运行 import 后崩溃。

### 5. Q3：最合理的最小修复或兼容方案是什么？

若坚持**跨域继承同一 Python heap + 创建时进入指定 cgroup + 正确执行两层 fork hooks**，本轮有实际证据支持的候选是 D：维护精确版本的完整 libc 源码扩展，用新 vendor API 参数化最底层创建，同时复用原完整 fork wrapper 和 robust child 处理。

它不要求扩大 Z 的 Linux 能力，不需要外部调用 glibc 私有函数；代价是维护、审计、测试和更新一套 libc/loader/runtime 包。原型中的符号导出在 `GLIBC_2.35` 节点只是实验布局，不代表库存 glibc 提供此 API；产品化前需要正式 vendor ABI/version 策略。

对于现有 raw 路径，最小安全处置是继续把它标成受限机制基线，阻止以“单线程”名义扩展到真实依赖。仅补 TID/robust 两项、手动调用几组回调，仍不能证明等价；普通 fork 后迁移则不满足当前原子出生要求。干净 forkserver 能缩小初始化状态，但不会替换 syscall/interface 问题，也不会自动取得另一个模板的 heap。

**D 也不是完整 `os.fork()` 替身。** `os.fork` 的 audit event、isolated-interpreter guard 等高层 API 行为没有在自有 bridge 中完整实现；本轮承诺的是限定上下文下的 CPython hooks + glibc fork 维护合同。采用前必须决定是否补齐这些高层行为或将 API 明确限定为内部能力。

### 6. Q4：是否仍然保留跨域 Python 内存继承和原子 cgroup 归属？

**在所测合同内，是。** D 的两次创建都使用 `CLONE_INTO_CGROUP | CLONE_PIDFD | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID`，没有 CLONE_VM/CLONE_THREAD，没有在 S/W exec；对象地址、初始化 PID、数据摘要和业务结果与 Z 的预加载状态对应。同一个 Z 完成两个不同域的工作，正常退出和非零退出都被正确回收。

原子归属依据三层证据共同成立：源码的参数传递、strace 记录的真实 flags/目标 FD、实际 kernel 在新任务运行前绑定 cgroup 的路径。探针读 `/proc/self/cgroup` 是用户态观测，不能单独证明出生原子性；源码和 syscall 证据使该推导成立。没有用门控后迁移替换 CLONE_INTO_CGROUP。

**限制：** 目标 cgroup 归属不等于已经进入最终 namespace 或已清除管理能力；native/Python child callbacks 发生在最终 W 清理之前，仍属于 TCB。cgroup 成员关系也不能直接证明继承的共享/COW 内存页的所有历史 charge 已转给 W；若未来以此计算每个 Worker 的完整内存预算，须另外验证资源记账合同。

### 7. Q5：开始 NumPy CPU 预加载准入前还需满足什么条件？

本轮没有 import 或准入 NumPy。下一轮应先完成运行时的阻断项，再对**具体 wheel/build + 具体准备动作**建立依赖资格，而不是对包名授予通用许可。

1. **共同选定运行时方向并冻结支持合同。** 若采用 D，固定源码/补丁/编译器/loader/DSO/kernel/CPython，明确主线程、线程历史、callback、信号与错误传播限制；保持真实创建失败时不降级成普通 fork。
2. **把候选发行包变成可维护产物。** 完成与支持范围相符的 glibc/NPTL/fork/loader 回归和 ABI closure 检查，建立安全更新流程。排除旧 libcrypt 覆盖是本轮发现的一个具体问题，不能代表全部动态库冲突已排除。candidate-04 只复核了去除旧 crypt 提供者后的既有 fork/跨域机制，没有 import `_crypt` 或验证 crypt 业务。
3. **补齐关键未测运行时与失败路径。** 定向覆盖 once、分配器/loader/TLS、支持的线程创建后退出历史、signal/callback 重入拒绝、高层 audit/解释器限制；将目标 PID1 死亡、cgroup删除/权限撤销/限额、Z/S异常退出和控制通道失效等旧机制失败矩阵在新运行时重做。已有正常/非零退出不替代这些场景。
4. **先审计依赖是否可进 TCB。** 固定 NumPy 来源、wheel hash、传递依赖及 OpenBLAS/MKL/OpenMP 实际构建；检查 import 与 atfork/native 初始化代码。版本固定不等于可信；不得在可管理 namespace 的模板里直接执行未知初始化。
5. **区分 import-only 与计算后模板。** 分别记录线程/锁/FD/callback/环境/CPU特性与动态库映射；先用隔离后的普通启动作为正确性对照，再在授权范围内验证 NumPy 的最小准备状态。一次 BLAS 计算后即使线程数回到1，也不能推断所有运行库恢复为未初始化状态。
6. **验证跨域业务正确和长期状态。** 覆盖两代、重复 sibling、异常退出、父模板所测状态、FD/线程/内存趋势、目标文件系统/动态库/环境一致性与资源记账；预先定义数值结果和错误处理的判定标准。此处是正确性准入计划，不是本轮性能 Benchmark。
7. **失败退回普通隔离启动。** 在可信 launcher 已满足目标资源与隔离条件后 exec 新 Python，再在最终 Worker 中 import。该路径放弃 Python heap 预加载收益，但不能放弃权限和资源条件；不要在 D 不可用时静默改成未保护的 fork/迁移。具体恢复路径仍需实现和验证，本轮没有开发 Scheduler。

### 8. 决策边界

本轮支持把 D 作为后续评审候选，**没有替团队确定最终架构**。本轮尚无仅用 stock 公开 API、同时保留现有 Z/S 资源归属和指定 CLONE_INTO_CGROUP 合同的已验证替代；若不接受 libc 分发责任，该组要求仍是 BLOCKED。这不是证明所有“标准 fork 时 child 出生于目标组”的办法都不存在：父进程先迁入目标组再 fork 可以让 child 继承目标组，但父进程也进入目标预算与 kill 范围，且不使用指定 CLONE_INTO_CGROUP。本轮未验证该资源模型。可以共同选择是否改变复用层次，例如域内模板、隔离后加载、只读文件共享，不能隐式放宽条件。

广泛不可信依赖仍面对同地址空间 TCB 的核心限制：fork 修复会执行其 callbacks，回调可在管理阶段访问进程内状态和继承 FD。一个 C helper 函数或更完整的 fork wrapper 不会隔离这类代码。该问题需要单独的权限/内存复用设计，不能由本轮有限正确性结果作答。

## 附录 A — 运行记录和复现入口

### 运行记录

| run | 作用与状态 |
|---|---|
| inventory-01 (`runs/inventory-01`, omitted from this source release) | 实际 guest 版本、构建、配置关联与二进制 hash |
| matrix-01 (`runs/matrix-01`, omitted from this source release) | 25 个 A/B/C/B0 用例；记录完整，raw 的预期语义错误实际复现 |
| verify-01 (`runs/verify-01`, omitted from this source release) | raw 跨域正常/非零退出；三组独立 syscall traces |
| candidate-01 (`runs/candidate-01`, omitted from this source release) | **失败保留**：9p host symlink 打包读取 ELOOP，未运行 D fork |
| candidate-02 (`runs/candidate-02`, omitted from this source release) | **整轮失败保留**：D micro/trace loader 缺 multiarch 搜索路径；本轮跨域部分单独成功 |
| candidate-03 (`runs/candidate-03`, omitted from this source release) | 32 个用例完整、D 运行时探针及跨域通过；后续静态发现包中额外 libcrypt 不满足 `_crypt` 符号版本 |
| [candidate-04](runs/candidate-04) | **最终候选运行**：排除两个额外 libcrypt 成员，其余 ELF 未改；微探针、身份核验、跨域与 syscall 复核完成 |

关键汇总：最终微分析 (`evidence/candidate-04-micro-analysis.json`, omitted from this source release)、实际 runtime 身份 (`evidence/candidate-04-runtime-identity.json`, omitted from this source release)、跨域分析 (`evidence/candidate-04-cross-analysis.json`, omitted from this source release)、包修正核查 (`evidence/candidate-04-closure-check.json`, omitted from this source release)、旧基线未改变 (`evidence/baseline-final-check.json`, omitted from this source release)。32 个 harness 用例完成不等于32项通用兼容保证；D 单独有7个用例、14个子进程运行时观测。旧包的 crypt 问题是静态 ABI 发现，本轮没有执行 `_crypt` import 或 crypt 业务。

最终使用的独立 runtime 包是 glibc-bundle-no-legacy-crypt (`build/glibc-bundle-no-legacy-crypt/opt/shimos-glibc/manifest.json`, omitted from this source release)。之前的 原包 (`build/glibc-bundle/opt/shimos-glibc/manifest.json`, omitted from this source release) 和全部失败运行保留。候选源码、guest 二进制、冻结脚本、bundle hash、实际 maps 和原始 NDJSON 可以交叉追溯。

### 重现入口

从项目根目录执行；必须使用新的 run 名称，脚本拒绝覆盖既有目录。需要同一 lab 的 kernel/initramfs、只读 assets 和可用 QEMU/KVM；运行脚本会校验冻结镜像与配置 hash。源包/编译重现见上方 source README，实验 libc 只能安装到独立 stage。

```sh
python3 research/shimos_worker_pool/fork_runtime_compat/prototype/vm.py repeat-matrix-01 --phase matrix
python3 research/shimos_worker_pool/fork_runtime_compat/prototype/vm.py repeat-verify-01 --phase verify
python3 research/shimos_worker_pool/fork_runtime_compat/prototype/vm.py repeat-candidate-01 \
  --phase candidate --timeout 300 \
  --candidate-bundle research/shimos_worker_pool/fork_runtime_compat/build/glibc-bundle-no-legacy-crypt/opt/shimos-glibc
```

`prototype/vm.py` 每次创建全新 guest、冻结本轮脚本和候选文件，candidate alias 在 host 实体化为同字节普通文件以通过9p传输；原 symlink 关系记录于 `candidate-packaging.json`。guest root 只负责 fixture/观测，实际 Z/微探针 UID/GID=65534；D不增加 capability，不修改最终 seccomp。执行结束清理本次临时磁盘，保留原始日志和冻结源码。

微分析命令示例（输出文件也必须是新名字）：

```sh
python3 research/shimos_worker_pool/fork_runtime_compat/prototype/probes/analyze.py \
  --micro-dir research/shimos_worker_pool/fork_runtime_compat/runs/repeat-candidate-01/micro \
  --output research/shimos_worker_pool/fork_runtime_compat/evidence/repeat-candidate-01-micro.json
python3 research/shimos_worker_pool/fork_runtime_compat/prototype/cross_domain/analyze.py \
  research/shimos_worker_pool/fork_runtime_compat/runs/repeat-candidate-01/cross-domain-glibc-d \
  --output research/shimos_worker_pool/fork_runtime_compat/evidence/repeat-candidate-01-cross.json
```

分析不把 rc=0 当作广泛兼容证明；缺记录和失败运行会显式报告。本目录没有性能 Benchmark、Scheduler、真实大型依赖预加载或飞书操作。旧原型、qualification-02 和旧 B-strict 的86项 hash 收尾检查全部相同。

> 以下审查保留 candidate-03 阶段的发现和 candidate-04 执行前判断。后续04机制复测结果见正文实验第12节；`_crypt`实际装载/业务仍未验证。

## 候选 D 最终源码与运行时边界审查

审查时间：2026-10-19。范围：独立阅读最终源码补丁、公开 API / bridge、冻结 bundle 的 ELF 元数据、`candidate-03` 已有微测试/跨域证据。**本次审查未运行 VM、未执行新增 import、未修改任何原型、bundle 或其他报告。** 审查者参与了候选源码实现；此处是对已冻结产物的再次独立逐项复核，不冒充未参与实现的第三方审计。

**结论：未发现需要撤销“候选 D 在本次固定环境、可信微模板下通过限定机制资格”的源码问题。发现一项必须阻止向完整 runtime / 全部 Python 标准库兼容性扩展的确定静态 ABI 缺口：候选旧 glibc `libcrypt.so.1` 覆盖了 guest 的 libxcrypt，而缺少 guest `_crypt` 扩展要求的符号版本。** 当前实际测试未加载这个库，因此该问题不推翻已完成的 callback/TID/robust/cgroup/跨域内存继承记录；它也绝不能被“本轮通过”掩盖。

### 1. 已检查证据与支持结论

- [冻结源补丁](sources/runtime-source/patches/shimos-fork-into-cgroup.patch)，SHA256 `71901c8bea4702c2833493b41c7f979821575b62fd6f081366eaab285f6555da`。
- [公开 API 声明](sources/runtime-source/patches/shimos_fork.h)、bridge_d.c (`prototype/cross_domain/bridge_d.c`, omitted from this source release)、实际过渡逻辑 (`prototype/cross_domain/zygote.py`, omitted from this source release)。
- candidate-03 微测试分析 (`evidence/candidate-03-micro-analysis.json`, omitted from this source release)：D 7 个 case、14 个 child 观察；native/Python 顺序、线程 ID、robust 注册、模板内存、cgroup 观察无所列差异；robust 恢复返回 130，受控多线程 stdio 诊断返回 0，失败路径 errno 为 11。
- candidate-03 跨域分析 (`evidence/candidate-03-cross-analysis.json`, omitted from this source release)：同一 Z 两域；各 19 个检查、S/W 无 exec、正常退出 0 / 非零 7、对应回收完成。该分析明确 `runtime_compatibility_claim=false`。
- runtime identity (`evidence/candidate-03-runtime-identity.json`, omitted from this source release)：实际微测试映射与冻结 libc/loader 哈希对应。跨域另有 映射文件 (`runs/candidate-03/cross-domain-glibc-d/zygote-0-maps.txt`, omitted from this source release) 和 DSO/overlay 清单 (`runs/candidate-03/cross-domain-glibc-d/candidate-runtime.json`, omitted from this source release)。

这里认可的是上述具体观察与源码机制相符。没有把两个顺序任务改写为长期稳定性，也没有把单个多线程诊断改写为支持多线程模板。

### 2. 必须保留的发现：libcrypt 覆盖造成静态 ABI 不匹配

#### 确认事实

1. 精确 Ubuntu glibc 源包的 `debian/rules:92` 设置 `crypt = no`；`debian/rules.d/build.mk:118` 因而传 `--disable-crypt`。候选独立 configure 没有该选项，构建了 glibc 自带的旧 libcrypt。
2. bundle 包含 `lib/libcrypt.so.1`，SHA256 `59b25a732547c22902d029ef7481ed34626bc822bef85a72c722654930c29a92`。
3. candidate-03 的 `candidate-runtime.json` 记录实际只读覆盖：`/opt/shimos-glibc/lib/libcrypt.so.1` → `/lib/x86_64-linux-gnu/libcrypt.so.1`。显式 loader 的搜索路径也优先查 bundle。
4. 对实际 guest 镜像做只读 `readelf -V/-Ws`：

| 文件 | 确认的 ELF version 信息 |
|---|---|
| stock `runtime/lib/x86_64-linux-gnu/libcrypt.so.1` | 定义 `GLIBC_2.2.5`、`XCRYPT_2.0`、`XCRYPT_4.3`、`XCRYPT_4.4` |
| candidate `lib/libcrypt.so.1` | 只定义 `GLIBC_2.2.5`；没有 `XCRYPT_2.0` |
| guest `runtime/usr/lib/python3.10/lib-dynload/_crypt.cpython-310-x86_64-linux-gnu.so` | `libcrypt.so.1` 的强版本需求 `XCRYPT_2.0`，未定义符号 `crypt_r@XCRYPT_2.0` |

stock libcrypt SHA256：`d8b34ade1d95c6243a48e90f2873d65399dfb0cd3fa4ee2af45afc9e6cb8642b`。guest `_crypt` 扩展 SHA256：`d92ac067b98b3c310f9f34a155888820aa35f48861f3a8eb2c5c3da96b758dec`。这些比对来自 `.build/benchmark-lab/root/runtime` 的只读 ELF，而非宿主默认库版本猜测。

#### 分析与影响

候选库**静态上不能满足**该 `_crypt` 扩展的版本化链接要求。如果 loader 在当前搜索/覆盖条件下为该扩展选择候选 `libcrypt.so.1`，会遇到缺失 `XCRYPT_2.0` 的装载问题。这里未执行 `_crypt` import，因此将它归类为**确定静态 ABI 缺口与对应装载失败推导**，不是新增 guest 已复现失败。

Z 的现有 maps 没有 `libcrypt.so.1`；其中出现的 `libcrypto.so.3` 是另一个库，不应混为 libcrypt 的验证记录。微模板和两域 business 未走 `_crypt` 路径，所以现有受测结论仍成立。

该发现阻止以下声明：候选 bundle 是 stock Ubuntu runtime 的透明替代；全部 Python 标准库已经兼容；候选已具备任意 native extension 装载资格。下一版候选应先明确 DSO 来源边界，例如与发行包装保持 `--disable-crypt` 并保留受验证的 guest libxcrypt，或建立其它经过验证的兼容组合；之后重新冻结与复测。**本轮冻结 bundle 不应静默删库、换库后沿用旧证据。**

### 3. callback 在管理期执行：兼容修复没有隔离不可信代码

**源码事实：** `bridge_d.c:28–29` 先执行 PyOS before，再调用 vendor wrapper；wrapper 包含 native prepare/parent/child handlers，返回后才执行 PyOS parent/child。第二次派生之前，S 已执行 `enter_target`；W 返回到 Python 后，`zygote.py:74–75` 才关闭管理 FD 并 `drop_final`。S 的 parent callbacks 也先于 `zygote.py:88` 的最终降权。

因此第二次派生的 native/Python callbacks 会在仍有 inner user namespace 管理能力、尚持有管理 FD 的 S/W 阶段运行。第一次派生 callbacks 也能利用 Z/S 的目标 owner/委派资格与所持 FD。D 没新增 Linux capability，但恢复了原本被 raw 路径漏掉的模板代码入口。

这不阻止**可信、自有、可控 callback** 的本轮资格结论，却阻止“C helper 已把依赖与管理权限隔离”“可以因 D 修好了 fork 就预加载不可信模块”的结论。版本固定与 callback 按顺序执行均不能证明初始化代码可信。

后续准入合同须明确：callbacks 不再派生、不新建线程、不改写/关闭/复用目标 FD、不改变 namespace/cgroup/安全状态、不重入创建 API；还须控制异步信号入口。当前 bridge 对主线程/主解释器/单线程的要求主要通过受控 fixture 和文档建立，并未变成可抵抗恶意 native 代码的强制边界。尤其 native prepare 中新建线程可使 glibc 在 prepare 之前读取的单线程状态过期；这也是不能任意放宽 callback 行为的具体原因。

### 4. 私有 API 审查：有限表述成立

**确认事实：** 外部 bridge 只 `dlsym` 三个公开 PyOS API 和自有导出 `shimos_fork_into_cgroup`；缺失 vendor symbol 即 `ENOSYS`，没有 raw/fork fallback。最终 libc 的 `readelf -Ws` 显示：

```text
shimos_fork_into_cgroup@@GLIBC_2.35  GLOBAL
__shimos_Fork_into_cgroup          LOCAL
```

补丁使用函数参数传递 cgfd/pidfd，无“下一次 fork”全局/TLS模式开关。原 stock `fork()` 仍选择 `_Fork()` 原路径；新入口共用完整原始 wrapper/child bookkeeping，未通过删除必要回调规避测试。

**允许的结论：** 没有从外部 helper 调用 glibc 私有 fork 入口，也没有在外部猜测 pthread descriptor 布局。

**不允许的扩大：** “完全不依赖 glibc 内部实现”。源补丁本身必须跟随 `posix/fork.c`、`_Fork`、NPTL、loader 的内部实现；同 build libc 家族也自然存在内部 `GLIBC_PRIVATE` 依赖。维护点在固定 libc 源树内，而非一个稳定跨版本私有 ABI。`GLIBC_2.35` 节点下的自有符号并不使 stock glibc 拥有它；产品化仍应定义 vendor ABI/version 策略。

### 5. 创建、内存与 wait 的源码审查

新路径保留 `CLONE_INTO_CGROUP | CLONE_PIDFD`，增加 `CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID` 和 `&THREAD_SELF->tid`；没有 `CLONE_VM`、`CLONE_THREAD`、`CLONE_SETTLS`、替代栈或 exec。kernel 原子放置发生在 child 用户态首次运行前；native child callback 已属于目标 cgroup，而不是 wrapper 返回后迁移。

`_Fork` 公共部分保留 robust-list 清空/重注册；完整 wrapper 保留 native handlers、fork generation、libc 锁与线程维护。`SIGCHLD`、实际 S→W 父子关系和 pidfd 语义未改写；其限定行为与 candidate-03 trace/回收观察相符。

没有发现为通过测试而回避两次跨域、改变原子资源归属问题定义、扩大 Z namespace 权限或移除最终 seccomp 的修改。仍不能从正常/nonzero两例外推所有故障注入与回收竞态均已通过。

### 6. glibc 构建差异与尚未覆盖的合同

候选保留 strong stack protector、CET、stackguard randomization；最终 ELF 也有 RELRO、非执行栈与 IBT/SHSTK 属性。但它是独立配置/路径/工具调用生成的 vendor runtime，**不是** Ubuntu 包的位级复现。具体差异至少含自有 API、`/opt` prefix、独立 configure 参数、优化/打包选项及上面的 libcrypt 来源差异。不能把恢复了几个安全构建选项写成完整发行配置等价。

完整 glibc regression suite 未运行；D 的目标 ABI、loader/NSS/动态TLS/malloc/once/信号/回调重入等全部边界未穷尽。PyOS hooks 也不等于 `os.fork` 所有 API 行为：bridge 没有 `PySys_Audit("os.fork")` 和 isolated-interpreter guard，且其保存 errno 合同与本 guest 旧 `os.fork` 实现不同。报告应维持主解释器主线程持 GIL 的受控合同。

**推荐最终表述：** “在固定 guest 与可信微模板范围，源级候选 D 恢复了本轮检查的 fork 回调/线程/robust 行为，并保留两次跨域 Python 内存继承和创建时 cgroup 归属；它是可继续评审的实验候选，尚非完整运行时兼容认证或依赖准入结果。当前 bundle 另有 libcrypt 静态 ABI 缺口，须在扩展标准库/native 装载范围前处理并重新验证。”

### 7. 审查后的独立打包修正（candidate-04 待验证）

按主任务明确指示，新增了独立目录 glibc-bundle-no-legacy-crypt (`build/glibc-bundle-no-legacy-crypt/opt/shimos-glibc`, omitted from this source release)，没有覆盖 candidate-03 的冻结 bundle 或任何既有 run。它仅排除 `lib/libcrypt.so` 与 `lib/libcrypt.so.1`，保留其余 **283** 个 runtime 成员；逐文件哈希及 symlink 内容复核全部与原包相同。没有重新编译、没有改 fork 实现、没有改 capability/seccomp/namespace 策略。

- 新 manifest (`build/glibc-bundle-no-legacy-crypt/opt/shimos-glibc/manifest.json`, omitted from this source release) SHA256：`8c7a3494339f2400dd8d2ab1e0843be51d435d9c35e47dd2ad61b1ab8ecb5a79`。
- 它记录的原 manifest SHA256：`a5de515d6794886e15b1d662b62e3c56d0fc2ac1f8e7ead4cab909c7db6996a9`。
- 可复现 [packaging script](sources/runtime-source/patches/package-no-legacy-crypt.py) 先核原包，拒绝覆盖已有目标，复制保留项，生成新 manifest，再复核原包未变。
- 精确 readelf 输出与 ELF 哈希见 libcrypt-static-abi.json (`evidence/libcrypt-static-abi.json`, omitted from this source release)。

**修正范围：** 撤掉这个额外 legacy provider，让库存 guest libxcrypt 继续提供 `libcrypt.so.1`；此操作并不声称原 ELF 改用 `--disable-crypt` 重新构建，也不声称已经观察到 `_crypt` import 失败后修复成功。candidate-04 仍需在新的 guest 安装中确认旧文件无残留、实际 `_crypt` 的 `XCRYPT_2.0` 需求由库存库满足，并重跑本轮限定资格检查。最终是否通过以新的运行证据为准；candidate-03 的历史静态缺口与其已完成测试范围应同时保留。

## Runtime source and candidate D build provenance

This directory is confined to task B. The original guest image, kernel tree, qualification-02, and previous experiments are not modified.

### Inputs

- `glibc_2.35-0ubuntu3.15.dsc`, `glibc_2.35.orig.tar.xz`, `glibc_2.35-0ubuntu3.15.debian.tar.xz`: Ubuntu official archive, exact source package matching the guest libc banner. `.dsc` checksums match. Local signature verification could not locate the signing developer's public key; do not interpret hashes as signature-chain verification.
- `python3.10_3.10.12-1~22.04.18.dsc` and archives: exact package attributed through equal guest-image/host-package ELF SHA256 and actual guest inventory. Ubuntu patches are applied; this is not an upstream 3.10.12 tag alone.
- `kernel/`: read-only copies of critical actual kernel source/build-config. Manifest records exact commit and per-file comparisons with Git HEAD; all six critical source copies match.
- `source-manifest.json`: source package, SHA256, critical file and attribution records.

`glibc-2.35-ubuntu/` has all Ubuntu patches plus the task's candidate D patch. For the three changed glibc files, pristine post-Ubuntu originals are retained in `patches/*.original`. `cpython-3.10.12-ubuntu/` has only upstream/distribution patches, no ShimOS Python patch.

### Reviewable implementation

`patches/shimos-fork-into-cgroup.patch` changes only `posix/fork.c`, `sysdeps/nptl/_Fork.c`, `posix/Versions`. It keeps the standard fork path and shares its full wrapper/robust-state handling. Only the extra vendor entry selects clone3 with target cgroup, pidfd, and NPTL child-tid flags. `patches/shimos_fork.h` defines the external research API. No arbitrary glibc private entry point is called from the bridge. Source integration naturally uses libc's own private internals; those do not become external ABI.

`patches/apply-shimos.py` generated the patch, guards exact original bytes and refuses repeat application. For independent reproduction, the ordinary patch command is sufficient.

### Reproduction (new, empty task-local build directories)

Use `/usr/bin` tools, not the environment's Conda Python/toolchain. Fetch fixed archives from the `.dsc` official URLs, verify SHA256 in `source-manifest.json`, and extract with `dpkg-source`. In an empty sibling source directory:

```sh
dpkg-source --no-check -x glibc_2.35-0ubuntu3.15.dsc glibc-reproduction
cd glibc-reproduction
patch -p1 < ../patches/shimos-fork-into-cgroup.patch
```

Configure outside the source tree (replace paths with the task-local extraction/build paths):

```sh
PATH=/usr/bin:/bin ../../sources/runtime-source/glibc-2.35-ubuntu/configure \
  --prefix=/opt/shimos-glibc --disable-werror --enable-kernel=3.2 \
  --enable-stack-protector=strong --enable-stackguard-randomization \
  --enable-cet --enable-multi-arch --enable-static-pie \
  '--with-pkgversion=ShimOS candidate D; Ubuntu source 2.35-0ubuntu3.15' \
  CC=/usr/bin/gcc CXX=/usr/bin/g++
PATH=/usr/bin:/bin make -j24
PATH=/usr/bin:/bin make -j12 install install_root=/absolute/task/build/glibc-stage
```

`install_root` is essential: this writes only the stage tree. Never install this experimental libc over the host/stock guest runtime.

Final configure/build/install all exited 0. Actual logs are in `../../build/glibc/{configure.log,build.log,install.log}`. Initial exploratory configure omitted explicit strong stack protection; it was rebuilt with the above options **before** the bundle was frozen or used for guest candidate tests. Initial logs are retained as `*-initial.log`, not used as the final build specification.

`patches/bundle.py` packages runtime ELF DSOs, internal symlinks, and gconv data into `../../build/glibc-bundle/opt/shimos-glibc`. This excludes headers/static archives/linker scripts. The bundle's `manifest.json` records each artifact hash, ELF build ID, compiler, configure flags, patch hash, and the fact that full glibc regression testing was not run.

Final libc Build ID: `2218522fcaa1ec292c7fbb909f19474d79395d1f`. Build config has `STACK_PROTECTOR_LEVEL=3` and `-fstack-protector-strong`; ELF has GNU_RELRO, nonexecutable GNU_STACK and CET IBT/SHSTK properties. These limited checks do not establish full binary equivalence with Ubuntu's package. Prefix/layout, configuration, build flags and custom API differ; the bundle is an experimental runtime distribution.

### Guest use

Copy the frozen bundle directory to `/opt/shimos-glibc`, execute its own loader with `--library-path /opt/shimos-glibc/lib:...`, and mount the same bundle into each target domain. Do not mix the candidate libc with a different dynamic loader. The cross-domain fixture additionally verifies/overlays corresponding runtime libraries. The source/build environment is the host; runtime evidence comes only from task `runs/` in the actual guest.

No performance benchmark, real third-party dependency initialization, or third-party cross-domain experiment was run here. Passing the task probes is bounded runtime evidence, not NumPy/PyTorch admission or full POSIX/glibc equivalence.

## 中文简要说明

raw clone3 能保留 Python 内存和出生时的资源归属，但这次已经证明它漏掉了必要的原生回调和运行时状态修复；仅要求单线程不能消除这些缺口。

标准 fork 具有完整的 libc 创建路径，但现有接口只继承父 cgroup。事后迁移、先迁父进程、域内模板各有不同的资源与隔离条件，需要单独设计和验证。

候选 D 把完整 fork 路径和 CLONE_INTO_CGROUP 结合，已通过本轮限定验证；代价是维护一套固定的 libc、loader、动态库包和相应回归。本轮顺带发现的 libcrypt 打包问题说明这项成本必须纳入选择。

各种方案都需要可信初始化与可信回调。D 恢复回调后，依赖代码仍可在管理阶段运行；支持更广泛的不可信依赖还要解决权限边界。下一步先共同选择运行时方向并补齐回归门槛，再研究具体 NumPy CPU 准备状态的准入。
