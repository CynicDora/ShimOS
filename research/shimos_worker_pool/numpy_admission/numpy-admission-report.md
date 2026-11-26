# 固定 NumPy CPU 配置：跨域 Zygote 准入报告

日期：2026-10-19。范围：独立实验副本，固定私有 VM、可信单线程模板、串行请求、Supervisor H 正常存活。

## 1. 结论与证据口径

**固定的 NumPy 2.2.6 CPU 配置已在当前 Z→S→W 路径中通过受限准入验证。** 验证级别不仅是 import：可信 Z 已创建 8 MiB ndarray，并执行固定的 128×128 float64 矩阵乘法；其后代在 Bubblewrap 新建的目标域中继承这些初始化状态，完成固定计算、退出及故障回收。

最终资格汇总为 **19 个 VM 会话、65 个执行尝试，按各自场景的验收条件全部 PASS**。其中实际完成独立数值对照的是 **45 次**；14 次为 NOT_EXECUTED，6 次为 NOT_OBSERVED。取消、预算拒绝或失去结果的场景可以正确通过故障验收，但不能计作数值执行成功。19 个 VM 均位于同一物理宿主，不能当作 19 台独立机器。

主依据为 qualification-all-final.json (`analysis/qualification-all-final.json`, omitted from this source release)。它同时绑定生命周期、完整 fork runtime、NumPy 三份验证器及具体原始运行报告的 SHA。报告中的 PASS 不是生产级保证，不是任意 NumPy 代码 fork-safe，也不是跨域方案优于其他 Worker 组织方式的结论。

## 2. 实际接纳的版本、步骤和执行范围

| 项目 | 固定条件与证据 |
|---|---|
| CPython | guest Python 3.10.12，GCC 11.4.0 构建；固定 guest 镜像、实际 loader 命令与 maps，见 environment.json (`runs/qualification-numpy-blas-audit-01-control/environment.json`, omitted from this source release) |
| glibc | candidate-04 D：Ubuntu glibc 2.35-0ubuntu3.15 分发补丁基础上的实验构建；保留完整 fork wrapper，同时通过 `shimos_fork_into_cgroup()` 使用 CLONE_INTO_CGROUP；没有重编译或修改本轮 Kernel |
| D libc / loader SHA256 | libc：`a03b51fe69f36b630ecf7997af05cd36885b1f2f0b52e278391fa6e17047eff4`；loader：`0682f493d0434391d4ec027d0bcb54dd5f9e46d044dc7810f69abea58fe1398e`，完整闭包见 candidate-runtime.json (`runs/qualification-numpy-blas-audit-01-control/candidate-runtime.json`, omitted from this source release) 和 构建 manifest (`runs/qualification-numpy-blas-audit-01-control/candidate-runtime/manifest.json`, omitted from this source release) |
| NumPy | 官方 `numpy-2.2.6-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl`，SHA `fc7b73d02efb0e18c000e9ad8b83480dfcd5dfd11065997ed4c6747470ae8915`；1004 个文件按官方 wheel 冻结，未混入旧目录生成的缓存 |
| BLAS | wheel 自带 OpenBLAS 0.3.29，ILP64、pthread 后端、DYNAMIC_ARCH；实际 getter 选择 SkylakeX，配置线程数为 1；OpenMP/MKL/GPU 不在此资格内 |
| 依赖闭包 | 22 个 wheel ELF 的静态依赖审查；新增支撑库仅 libstdc++.so.6 和 libgcc_s.so.1，独立固定 SHA、只读安装，不替换 D 的 libc/loader |
| 初始化 | import → 固定 1,048,576 个 float64 的 ndarray（8 MiB）→ 固定矩阵乘法；不加载任务提供的插件，不执行任意用户初始化代码 |
| 业务 | float64 数组切片、广播、求和、128×128 matmul；保存 NPZ，与独立冷 Python 同输入结果比较；另有一次错误形状 matmul 的 ValueError 验证 |
| 环境 | Linux `6.18.49-agentic-runtime-opt-v1`，QEMU/KVM、4 vCPU、4 GiB，`-cpu host`；具体命令见 command.json (`runs/qualification-numpy-blas-audit-01-control/command.json`, omitted from this source release)，不是新内核机制实验 |
| 资源预算 | task：512 MiB、pids 256、CPU 400000/100000；S/W 叶域各 256 MiB、pids 128、CPU 200000/100000。预算拒绝用例按原协议将相应 pids.max 设为 0，验证失败处理 |

上述“版本相同”还不够。实际运行使用的源码、原型二进制、wheel、支撑库和 D 运行时均在每个 run 的 manifest 与安装回执中记录；最终 source review v2 (`docs/variant-source-review-v2.json`, omitted from this source release) 限定可继续测量的配置。源码审查本身没有替代运行资格。

来源审计详见 dependency-audit.md (`docs/dependency-audit.md`, omitted from this source release)、官方 wheel URL/SHA (`frozen/numpy-dependency-downloads.json`, omitted from this source release)、[干净资产清单](frozen/numpy-dependency-clean-assets.json)。NumPy 源码固定为 `v2.2.6 / 2b686f659642080e2fc708719385de6e8be0955f`；OpenBLAS 参考源码固定为 `v0.3.29 / 8795fc7985635de1ecf674b87e2008a15097ffab`。这些证据不等于已经重现上游 wheel 的完整构建。

## 3. 本轮怎样接入，哪些机制没有改变

实际流程仍为：

```text
会话开始：H 监督 R；R 创建可信 Z，Z 预加载固定 NumPy CPU recipe
每次请求：R 使用 Bubblewrap 创建新的目标域及 PID1
Z ─完整 CPython/glibc D fork─→ S（原子归属 transition cgroup）
S 进入目标 namespace/root/cwd，提前降权并安装既有策略
S ─完整 CPython/glibc D fork─→ W（原子归属 business cgroup）
W 完成最终 FD/权限约束，等待 RUN_BUSINESS
W 执行固定 NumPy 计算；S wait(W)，Z wait(S)
R/H 完成输出 EOF、PID1 DRAINED、域与目录释放
```

“Bubblewrap 先建域”指目标域先于 S/W 的派生，并非要求先于长期模板 Z 的初始化。

两次派生均经 [bridge_d.c](prototype/bridge_d.c) 的 `py_fork_cgroup()`（20 行）：CPython before hook → D 完整 wrapper/native hooks/clone3 → CPython parent 或 child hook。没有使用已知存在运行时错误的 raw clone 路径，也没有为了导入 NumPy 绕过回调。S 的第二次 fork 仍发生在 [zygote.py](prototype/zygote.py) 的提前 `drop_final()` 之后、业务许可之前（135、150、177–180 行）。

原 runtime 资格也在加入依赖后的同一次运行中重做：两代自有 native/Python callback 顺序、pthread TID 与内核 TID、TLS/owner 状态以及自有 robust mutex 的 owner-death/recovery 检查继续通过。这些证明完整 wrapper 的受测行为，没有替代 OpenBLAS 自身回调的独立观察，也不意味着已经检查全部第三方 native 锁。

相对 architecture_cost，既有产品路径主要修改 `run.py` 与 `zygote.py`，新增 `numpy_workload.py`、`numpy_reference.py`、`numpy_atfork_audit.c`。`common.py`、桥接/策略/PID1、Supervisor H、D runtime 和已有 fork runtime 探针保持原冻结字节。首次 mount 输入布局失败后采用新的运行编号，不改历史运行。具体审查与 SHA 见 independent-source-review.md (`docs/independent-source-review.md`, omitted from this source release) 和每个 run 的 `source-sha.json`。

本轮以未合并 PING 的完整 A+B 路径为基础，没有顺便实施门禁或协议精简。hot 保留同一已初始化 Z，cold 为每请求创建新 Z，并在 W 获业务许可后初始化 NumPy。后者是**相同跨域路径上的初始化复用消融**，不能冒充已经实现了全部四种架构。

## 4. 六项必须保留的安全与正确性边界

| 边界 | 实际要求及验证 | 不能外推的部分 |
|---|---|---|
| 可信模板 | 只加载冻结、审阅过的 CPU recipe；固定线程设置；禁止任意包和任务初始化代码 | Z 虽无有效/许可 capabilities、NNP=1，仍保有进入所拥有后代 namespace 的资格，seccomp=0、bounding set 非零；不是普通业务权限 |
| namespace 与文件视图 | Bubblewrap 先建域；W 六类 namespace 与目标一致；root/cwd 身份、只读 `/src`、可写 `/work`、宿主与其他工作区不可见；固定依赖只读 | 只证明现有受限文件视图，不是通用动态依赖/挂载安全资格 |
| 权限与 syscall 策略 | S 第二次 fork 前降权；W uid/gid=65534，五类 capabilities 为零、NNP=1、seccomp=2；实际拒绝 setns/unshare/chroot/exec 探针 | 既有研究 denylist 不是经过全面审计的生产 allowlist；业务 exec 仍禁止，不具备通用 Shell Worker 能力 |
| 资源归属与真实 wait | 两次 CLONE_INTO_CGROUP、固定预算；S wait W、Z wait S；PID1 清理其后代；H 在 R 死亡后真正收养/回收 | 页继承的 memcg 记账与物理共享不是同一概念；未证明完整内存公平计费模型 |
| 执行许可与失败知识 | SPAWN/PREPARED/COMMIT、START_WORKER、RUN_BUSINESS、取消 seal、nonce、UNKNOWN 均保留；正确数组文件不能替代真实退出回执 | H 自身死亡、宿主 OOM、文件系统故障、并发请求仍不在完整保证范围 |
| 状态、FD 与最终释放 | 检查显式 module/geterr/数组状态、线程、FD 对象、信号/环境；输出 EOF、cgroup 空、目录删除、R/Z/H 收尾分别验收 | 不声称整个 heap 不变；Python signal handler 与 mask 不等于完整 native sigaction 审计；合法库缓存变化不能误判为业务污染 |

固定 NumPy 对象在 W 中可被写入，Z 中原值保持不变，后续域重新继承初始状态。这依赖进程隔离及 COW；`ndarray.flags.writeable=False` 本身不是安全边界，代码也明确在 W 内临时打开它进行验证。

## 5. 原生回调、线程和 DSO 的实际证据

### 5.1 实际 OpenBLAS prepare，不是自有探针代替

该 wheel 的 OpenBLAS 实际动态调用 `__register_atfork`。注册内容为 `prepare=blas_thread_shutdown_`、`parent=NULL`、`child=NULL`。本地 `pthread_atfork` 符号会跳转到动态注册接口，因此只拦截动态 `pthread_atfork` 不足以观察它。二进制、固定源码及调用点见 反汇编 (`frozen/numpy-dependency-openblas-disassembly.txt`, omitted from this source release) 和 静态审计第4节 (`docs/dependency-audit.md`, omitted from this source release)。

`audit=1` 使用独立诊断 DSO 记录真实注册及调用前后，保留原 handler、NULL 位置、DSO handle、返回值与执行顺序；不在 callback 内分配、加锁、格式化或写日志。固定容量溢出/观测错误必须拒绝观测资格，而非当作“没有回调”。`audit=0` 不加载该 DSO，另跑完整相同故障矩阵。

正式诊断矩阵观察到 **49 对完整的 Z/S fork 前后检查点**，每对真实 OpenBLAS prepare 的 enter/exit 各增加 1。另两次预算拒绝没有成功 fork 后的 NP_PHASE，保留为未观测，不能补造回调结果。S 中实际 prepare 在 CapEff=0、NNP=1、seccomp=2 下完成；Z 中为 CapEff=0、NNP=1、seccomp=0。parent/child 原本为 NULL，不能要求 W 产生不存在的 OpenBLAS child callback。

prepare 会清理线程池和内部缓冲。即使已预加载，部分 BLAS 缓存也可能在 fork 前被合法改变，子进程仍可能重新准备内部缓冲。**本轮保留的是可继承的运行时、模块与明确数组状态，不保证所有 native 缓存都免费且原样复用。**

### 5.2 单线程不能只看环境变量

首次导入前设置固定线程环境；实际 OpenBLAS getter 报告线程配置为 1。边界 `/proc/self/task`、动态 `pthread_create` 观察、同 guest 的内核 task trace 相互补充。

两个正式系列各有 12 个 Z 初始化区间、19 个完成的 W NumPy 调用区间，在无丢失 trace 中均未发现新 task；Z/S 的新 task 均与已记录的两次派生吻合。各系列 22 个可完整追踪的 W 出生至退出区间均无成功 exec，支持“真实继承而非重新 exec Python”。旧业务在 NumPy 完成后创建约 40 ms 测试后代，该进程保留在 trace 中，没有错算成 BLAS 线程。

限制：动态 pthread 拦截不能覆盖全部隐藏入口；trace 不记录失败的 clone；冷数值参考在 trace 开启前结束，只有瞬时线程快照。业务后代的普通 fork 发生在最终 NumPy 快照之后，其 callback 明细未再次导出，也没有在那个后代里验证 NumPy。`audit=0` 无逐 callback 观测，不能把正常运行解释为不存在回调。详细判据及原始日志索引见 pilot-dependency-review.md (`docs/pilot-dependency-review.md`, omitted from this source release)。

### 5.3 实际映射与来源

冷参考、Z 和 W 的 candidate D loader/libc/libm/libpthread maps dev/inode，与 guest 已计算 SHA 的对象及冻结 D 清单一致。NumPy/OpenBLAS/支撑库实际 maps 路径与“逐文件哈希校验→只读安装”的清单一致。未额外对每个 NumPy `map_files` 对象独立计算内容哈希，不能把路径检查夸大为全对象内容证明；也未把所有 22 个 wheel ELF 说成已加载。

冷参考是另一普通 Python 进程，使用相同 D loader、固定包、uid=65534、NNP。它提供数值对照，**不具备 W 的相同 namespace/cgroup 合同，不能充当安全等价性能对手**。其计算公式与 W 来源相同，独立进程及离线数组比较能检查继承/运行差异，但不是独立数学实现。

## 6. 正式资格与保留的失败

| 实验集合 | VM / 尝试 | 数值 PASS | NOT_EXECUTED | NOT_OBSERVED | 资格结论 |
|---|---:|---:|---:|---:|---|
| `blas/hot/audit=1` 完整故障矩阵 | 8 / 29 | 19 | 7 | 3 | 全部符合各自验收合同 |
| `blas/hot/audit=0` 完整故障矩阵 | 8 / 29 | 19 | 7 | 3 | 全部符合各自验收合同；第三方 callback 未观测 |
| `blas/cold` 正常/非零对照 | 1 / 3 | 3 | 0 | 0 | PASS；不计跨域预热继承证明 |
| `cow_all` 页触达敏感度 | 1 / 3 | 3 | 0 | 0 | PASS；边界/COW 内容检查 |
| 真实错误形状 matmul | 1 / 1 | 1 | 0 | 0 | 正常计算匹配，实际 ValueError 被捕获，按用例退出 7并释放 |
| **合计** | **19 / 65** | **45** | **14** | **6** | **按场景全 PASS** |

每个 29 次矩阵包含正常/非零、原生 runtime 探针、两级 PID 预算拒绝、CREATED/REAPED/结果回执丢失、取消前/入域中/业务前/重复取消/超时/撤销回执丢失、Z/PID1/控制通道故障，以及 R 两种时点死亡和 H 接管。记录同时检查实际 wait、业务知识、后代、输出 EOF、cgroup、FD 和目录释放，不能用程序返回 0 替代这些条件。最终矩阵分别见 audit (`analysis/qualification-audited-final.json`, omitted from this source release)、plain (`analysis/qualification-plain-final.json`, omitted from this source release)。

独立 NumPy 验证器不 import NumPy，用保存的 NPZ/NPY 数据重新比较数组名称、shape、dtype、有限值及逐元素误差，预先固定 `rtol=1e-12, atol=1e-10`。原始文件及每项证据 SHA 保留在各 `*-numpy-final-v2/v3.json`。数值 PASS 可与业务 UNKNOWN 同时成立：文件证明“观察到正确数组”，不证明丢失的退出回执或完成状态。

探索性的 import/data/blas pilot 各有 3 次请求，证明逐级机制观察可进行，但**没有把 import、data 的 3 次 pilot 冒充各自完整故障矩阵**。正式资格重点固定在 blas recipe。更改依赖、配方或线程数需要重新准入。

必须保留的负记录：

- `pilot-import-hot-01`：目标只读根下缺少挂载目标目录，Bubblewrap 报错；S/W 未创建。H 后续回收成功，不能把原请求改成执行成功。见 失败复核 (`analysis/pilot-level-dependency-review-02/pilot-import-hot-01.json`, omitted from this source release)。
- 初版 NumPy 验证输出 (`analysis/pilot-import-hot-02-numpy-initial.json`, omitted from this source release)：配置匹配及 `/opt/shimos-numpy-deps` 路径识别问题导致 FAIL，并缺少独立报告输入；没有丢弃。后续 parser recheck (`analysis/pilot-import-hot-02-numpy-parser-recheck.json`, omitted from this source release) 仍因缺少明确字段/报告而 BLOCKED，没有补造历史 manifest。
- 初版冷对照检查 (`analysis/qualification-blas-cold-control-01-numpy.json`, omitted from this source release) 与 compute failure v2 (`analysis/qualification-numpy-compute-failure-01-numpy-final-v2.json`, omitted from this source release)：audit=0 被依赖审计入口拒绝为 BLOCKED。最终采用明确 `boundary-only` 范围，保留“回调未观测”，而不是把 audit=0 改成已有 callback 证据；最终文件为独立新版本。

这些修正改进了验证器的口径及输入绑定；没有覆盖原运行、伪造缺项或把不同实现的零散通过拼成一个资格。

## 7. COW 正确性及其成本边界

固定数组为 8,388,608 字节，起始内容 SHA 为 `9d41c910c2a406969cae9d9bbaad83e3e87a0918374b14a2049ffb291a6d493b`。W 保留 Z 的 module/data 对象身份与原始内容，修改后 W 摘要变化；Z 后检查及下一个独立域仍恢复为原始摘要。跨域继承通过真实 fork/no-exec、origin PID、对象身份和内容共同验证，不能仅靠“输出相同”。

具体例子：普通请求只写一个 float64 元素，即 8 字节；`cow_all` 执行 `DATA[::512] += 1`，按 4096 字节步长写 2048 个元素，实际 store 为 16 KiB、触达约 8 MiB 范围。日志中的 `requested_cow_write_bytes=8388608` 是该敏感度的触达范围标签，**不是实际写入 8 MiB 数据**。

首个普通样本的数组跨度覆盖 2049 个页，pagemap exclusive 从 0 增至 1；首个 `cow_all` 样本从 0 增至 2048。若定义 `α_obs=exclusive 标志增量/数组覆盖页数`，两个样本约为 `1/2049` 与 `2048/2049`。它只是已记录的私有页比例变化代理，不能与“实际触达的页比例”或“真正复制的页比例”直接画等号。这说明同样继承 8 MiB 状态，后续写法可能产生非常不同的共享程度；**不是精确的新 COW 页计数，也不能直接算出节省的物理内存**。

PSS、Private_Dirty、minor faults 同时受 Python/native 分配、页表、THP 拆分、快照代码及共享分摊影响。不能把整段 PSS 或缺页增量全部归因于数组 COW。当前没有清零 soft-dirty，也没有 PFN 级逐页复制追踪。证据见 普通样本 (`runs/qualification-numpy-blas-plain-01-control/0-normal-output.log`, omitted from this source release)、页触达样本 (`runs/qualification-numpy-cow-01/0-normal-output.log`, omitted from this source release)、独立资格 (`analysis/qualification-numpy-cow-01-numpy-final-v2.json`, omitted from this source release)。量化收益应另看复用成本报告。

## 8. 当前拒绝预加载的范围

以下项目没有本轮资格，应拒绝直接进入当前可信模板，或另建独立准入验证：

- 任意 pip 包、任务自带扩展、动态插件、未固定 wheel/DSO/CPU 配置；Pandas、SciPy、PyTorch 也不能继承 NumPy 的资格。
- 活跃 Python/native 后台线程、多线程 BLAS/OpenMP/MKL、线程状态无法完整解释的模板。
- GPU/CUDA、设备上下文、外部连接、活跃会话、共享可写 memmap/文件及跨信任主体业务状态。
- 任意 object dtype 回调、未定义 RNG 继承语义、未经审查的 `atfork` handler、DSO 卸载/并发注册。
- 需要业务 exec 或新的 syscall 权限的工具；不能为了运行它们放宽现有策略。
- 没有 H 可靠接管条件、并发派生、长期持续运行、宿主 OOM/存储故障条件下的生产承诺。

固定 profile 的一次成功不是包级永久白名单。安全策略、D/CPython 版本、BLAS 后端、初始化步骤、线程数或业务 API 范围变化，均应建立新的配置身份并重做必要资格。D 尚未运行完整 glibc 回归套件，本轮只增加固定 NumPy 配方的实际兼容证据。

## 9. 对七个问题的回答

**Q1：固定 NumPy CPU 能否在可信 Z 中预加载？** 可以，在上述版本、依赖闭包、线程设置和可信代码边界内已实际验证。不能推广到不可信 import 或任意 NumPy 部署。

**Q2：达到什么初始化级别？** 已达到 import、8 MiB ndarray 与固定 native matmul 初始化。import/data 有各自探索证据；完整故障资格固定在 blas recipe，不将这些等级的证据互换。

**Q3：fork 后数值、native callbacks、生命周期是否符合受测合同？** 是。诊断版观察到真实 OpenBLAS prepare，未插桩版独立通过同矩阵；45 次有独立数值证据，其余正确保留未执行/未观测状态。仍不证明全部内部锁、全部 native 状态或所有依赖行为。

**Q4：能否在多个隔离域间连续复用？** 已证明同一存活 Z 可连续服务多个新域，前一域释放后继续派生，明确数组/geterr/FD/环境等受检状态未被前次 W 写入污染。后续主测量实际完成一次同 Z、100 个新域；关闭额外阶段计时的诊断又独立完成一次 100 请求。相应冷对照触发既有 H 会话期限，没有完整 N=100 配对资格，不能混为性能成功。这里的稳定性是受限运行证据，不等于长期/并发稳定性；详见 主矩阵 (`analysis/paired-numpy-admission-final.json`, omitted from this source release)、独立诊断 (`analysis/paired-numpy-timing0-diagnostic-final.json`, omitted from this source release)。

**Q5：初始化、延迟、CPU、PSS、COW、累计成本变化多少？** 见单独测量的 [numpy-reuse-results.md](numpy-reuse-results.md)：当前配方每次重复初始化约 0.25 秒；N=10/50 完整配对序列有收益，N=1 两次均更慢。Worker PSS 较低，但模板额外常驻，系统净物理内存收益尚不能确定。COW 的正确性观察见第7节，不替代完整资源成本模型；未从资格样本推算性能。

**Q6：哪些操作或依赖必须拒绝？** 第8节所列未固定依赖、多线程/设备/外部状态及任意业务初始化均不在准入范围。进入新范围需要实际证据，不能只添加一个环境变量或更新版本号。

**Q7：是否足够进入正式四架构对照？** 足以把当前固定 NumPy CPU recipe 作为候选工作负载，开始准备公平比较；还不能宣布四种实现都已具备同等资格，更不能宣布跨域胜出。比较前至少需要满足：

| 架构 | 进入对照前仍须成立的条件 |
|---|---|
| 冷启动 | 每次完成同样的初始化与业务、权限/资源/输出/回收合同，完整计费；当前 cold 是同跨域路径的初始化消融，不能自动代表所有冷启动架构 |
| 完整 Worker 复用 | 提供明确持久请求接口，隔离信任主体；规定并验证数组、错误模式、FD、环境、缓存等请求间状态重置；将驻留内存与最终回收计入 |
| 域内 Zygote | 在固定域内使用同样可信配方与完整 fork runtime；验证 PID1、资源归属、取消和后代回收；计入域及模板的保活成本 |
| 跨域 Zygote | 保留本轮可信权限、D/CPython/DSO 闭包、两次派生和 H 合同；同时计入模板、每域准备、过渡进程、回调缓存重建及 COW/回收成本 |

四组必须使用同一实际业务、输出验证和明确安全合同；不能把普通冷参考 Python 当作隔离等价基线，也不能免计某组准备/保活/结束成本。本轮只提供跨域候选及冷/热初始化消融的技术基础，没有替 ShimOS 选定最终架构。

## 10. 复核入口与后续限制

- 总资格：qualification-all-final.json (`analysis/qualification-all-final.json`, omitted from this source release)；两个 29 次矩阵及三项补充均由它定位，包含验证器和报告 SHA。
- 原型：[prototype/](prototype/)，每次真实源码/二进制/命令/环境在对应 runs/ (`runs/`, omitted from this source release) 独立保存。
- 独立验证：[runner/verify_qualification.py](runner/verify_qualification.py)、[runner/verify_runtime.py](runner/verify_runtime.py)、[runner/verify_numpy.py](runner/verify_numpy.py)。不能把 NumPy 自报 checks 替代三份独立验收。
- 依赖及 task 历史复核：audit=1 (`analysis/qualification-audit-dependency-review-01/summary.json`, omitted from this source release)、audit=0 (`analysis/qualification-plain-dependency-review-01/summary.json`, omitted from this source release)、三层 pilot 与失败 (`analysis/pilot-level-dependency-review-02/summary.json`, omitted from this source release)。
- 准入和静态审查：admission-contract.md (`docs/admission-contract.md`, omitted from this source release)、dependency-audit.md (`docs/dependency-audit.md`, omitted from this source release)、independent-source-review.md (`docs/independent-source-review.md`, omitted from this source release)。

当前资格不覆盖任意业务、长期运行、多个并发请求、所有物理宿主/CPU、H 死亡、宿主 OOM 或文件系统失败。模板所在信任边界、定制 glibc 的维护、页记账和不同复用方式的成本仍是后续必须处理的问题。本轮没有新增 Scheduler、Worker Pool 或内核机制，也没有把受限实验资格升级为生产保证。
