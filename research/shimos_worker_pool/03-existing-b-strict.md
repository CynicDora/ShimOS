# 03 — 既有 B-strict 执行底座审计

审计时间：2026-10-16。**B-strict 已经能够创建一次 Bubblewrap 隔离域，在其中多次启动独立资源组，并安全结束每组和整个域。它足以承载本轮 A/B/C 成本实验；不需要重新实现 B-Group，也不需要每请求执行 nsenter。** 它没有 Worker 请求协议、类型匹配、预热、保活选择或调度算法。应用 Worker 复用是本轮新增测量对象，隔离域复用不是本轮新贡献。

本文 Fact/源码指实现可直接确认，Fact/历史实验指已有受控执行结果，Inference 指对本轮复用方式的判断。源文件及历史记录的逐文件 SHA、核验结果在 audit/b-strict-source-audit.json (`audit/b-strict-source-audit.json`, omitted from this source release)。本轮只读旧目录，没有重跑或改写历史基线。

## 1. 实际入口及版本

基线来自 b_group_bwrap_gap_discovery (`../b_group_bwrap_gap_discovery/README.md`, omitted from this source release)，核心是以下真实代码，而非只有设计声明：

| 文件 | 实际职责 | 本轮用法 |
|---|---|---|
| suite.py (`../b_group_bwrap_gap_discovery/minimal-prototypes/suite.py`, omitted from this source release) `Task`、`bwrap`、`spawn` | 隔离域、组、输出、资源及收尾；`Task(strict=True)` 是默认 | 冻结原逻辑，仅在新的私有 VM 实验入口复用 |
| owner.c (`../b_group_bwrap_gap_discovery/minimal-prototypes/owner.c`, omitted from this source release) | PID 1、严格组 guardian、原子 cgroup admission、协议和回收 | 不修改、不重新发明组管理 |
| native.c (`../b_group_bwrap_gap_discovery/minimal-prototypes/native.c`, omitted from this source release) `bg_spawn` | `clone3(CLONE_INTO_CGROUP|CLONE_PIDFD)`、关闭管理 FD、启动 bwrap | A/B/C 保持同一可信启动边界 |
| diagnostics.py (`../b_group_bwrap_gap_discovery/minimal-prototypes/diagnostics.py`, omitted from this source release) `Raw` | 一次性 Bubblewrap 的强基线、完整输出和域结束等待 | A；使用 `release(reap_all=True)` |
| policy.h (`../b_group_bwrap_gap_discovery/minimal-prototypes/policy.h`, omitted from this source release) / `policy.bpf` | 同一实验 seccomp deny-list | 三组保持一致；不冒称生产通用 allow-list |
| nsenter.c (`../b_group_bwrap_gap_discovery/minimal-prototypes/nsenter.c`, omitted from this source release) | base userns→mount/PID/root→inner userns 的有限诊断 | **不用于本轮正常持久 Worker 执行** |
| vm.py (`../b_group_bwrap_gap_discovery/minimal-prototypes/vm.py`, omitted from this source release) | 冻结 KVM 引导、只读源码和 assets、单独 evidence、临时磁盘 | 参考引导方式，新实验只写新目录 |

冻结 bwrap 为 **0.13.1**，commit `362936aea0d5c6e70f7af75d2d44b5a914cb4ba2`，ELF SHA-256 `b4a951a519c1d32e9a47400755366eac8c206118e1fc6897f63041e043f6dca3`。owner ELF SHA-256 `acd8275ce2b43b6c0fa223a5fcb72ddd5472788c72421b15633f092b7612df4b`。来自 build-identity.json (`../b_group_bwrap_gap_discovery/config/build-identity.json`, omitted from this source release)；本次复核 13 个记录文件均与收据相符。

`suite.py` **不是可以在宿主直接 import 的库**：顶层检查私有 VM 标记，创建 cgroup、编译辅助文件，文件末尾立即运行 `main`。新的实验入口必须只在既有私有 VM 内使用冻结定义，并明确记录提取方式/源码 SHA；不能创建假标记绕过保护。`vm.py` 的旧输出固定在旧研究目录，不能直接用它生成本轮数据而污染旧研究。

## 2. 隔离和信任合同

Fact/源码：suite.py 的 `bwrap()` (`../b_group_bwrap_gap_discovery/minimal-prototypes/suite.py`, omitted from this source release)、strong-baselines.md (`../b_group_bwrap_gap_discovery/strong-baselines.md`, omitted from this source release)。

- 固定可信 `/runtime` 只读作为根；只读 `/probe`、`/tools`、`/src`；每 Task 独立可写 `/work`；独立 `/tmp` tmpfs；私有 `/proc`、`/dev`。
- user/PID/net/IPC/UTS 隔离；bwrap 创建独立 mount view。`--disable-userns`、`--cap-drop ALL`、`--die-with-parent`、`--new-session`。持久组由 `--as-pid-1 /probe/owner` 承担 PID 1。
- guest root 只做一次 cgroup 委派及不可变 fixture 准备；之后 controller、bwrap、owner、工具都以 guest UID/GID **65534** 运行。没有委派时不能凭空获得 cgroup 控制权。
- Task 层限额 4 CPU、512 MiB、256 tasks；组可独立指定 `memory.max`/`memory.oom.group`、`pids.max`、`cpu.max`。控制进程独占 control 叶，业务进程在各组叶。
- 策略拒绝额外 namespace/mount/ptrace 等指定调用；这是一份有限研究 deny-list，网络隔离仍由 net namespace 提供。它不是经过全面审计的生产沙箱策略。
- 同 Task 的组共享 UID、mount/PID/net namespace、工作区和 tmpfs，**属于相互合作的同一信任域**。组预算独立不等于组间敌对安全隔离。

Fact/历史实验：supplemental-final-01/checks.json (`../b_group_bwrap_gap_discovery/experiments/supplemental-final-01/checks.json`, omitted from this source release) 中 `same-trust-peer-sighup` 真实证明组 A 可以给组 B 发信号。因此不能把不同信任任务装入同一 Task，也不能将共享可写目录视为独立工作区。不同 trust/workspace/policy 应使用独立隔离域；是否允许同一信任范围内多类型 Worker 共置是后续布局实验问题。

## 3. 创建、执行和完成的真实路径

```text
可信外部 controller / collector（client cgroup）
  │ 私有继承 SOCK_SEQPACKET + SCM_RIGHTS
  ▼
Task cgroup（内部不放进程，统一总预算）
  ├─ control leaf
  │    bwrap monitor → owner PID 1
  │                       ├─ group 1 guardian / subreaper
  │                       └─ group 2 guardian / subreaper
  ├─ group 1 leaf: application leader → descendants
  └─ group 2 leaf: application leader → descendants
```

### 建域

`Task.__init__` 建 task/control cgroup，建 task workspace 和私有 `SOCK_SEQPACKET`。`bg_spawn` 在可信代码执行前原子进入 control cgroup，保留唯一控制 FD 3，exec 冻结 bwrap。owner 设置 `dumpable=0`、subreaper、NNP、seccomp，创建 epoll/signalfd，返回 READY。随后 controller 记录控制进程身份。没有开放的 owner 公共 socket，也没有 Worker 调度服务器。

### 新建组和业务进程

`Task.start(argv, mem=None, pids=None, cpu=None)` 建独立叶 cgroup、设置预算，以 START 消息传递 argv 和 cgroup FD。owner 的 `start()` 只接受严格递增 ID，不复用旧 ID；最多 256 次请求、127 个 argv、8192 字节消息。

严格模式先在 control 叶 clone 一个 guardian；guardian 设置 subreaper，再用 `CLONE_INTO_CGROUP` 在业务组原子创建 leader。guardian 向 owner 确认 admission 后，owner 才返回 STARTED。业务进程 setsid，stdin 指向 `/dev/null`，stdout/stderr 合并到组 pipe，close_range 关闭管理 FD，再 exec。没有先 exec 再补迁移的归属窗口。

**字段陷阱：STARTED 的 pid 是 guardian 的 PID，不是业务 leader 的身份。** B/C 若要证明同一个 Worker，必须增加应用协议的启动身份（PID、启动序号、必要时 starttime）并和实际 cgroup 观察核对，不能使用这个 pid 冒充 Python/clangd PID。

### 输出和退出

owner 将组输出读 FD 用 SCM_RIGHTS 直接交给 collector；控制通道不转运业务日志。`Task.pump()` 非阻塞读取组 pipe，读到 EOF 后关闭并发送 OUTPUT_EOF。业务 leader 原始 wait status 先单独到达，**leader=0 不等于全部后代成功或组已释放**。

严格 DONE 的必要条件同时为：

1. guardian 已 wait 所有被收养后代直到 `ECHILD`，正常退出；
2. owner 已 wait/reap guardian，并拿到 leader status；
3. collector 已观察输出 EOF；
4. 业务 cgroup `populated=0`。

随后 owner 关闭组管理 FD，controller 取 stats、删除叶 cgroup、记录 released 时间。`Task.wait(gid)` 返回时已包含这些条件。`Task.cancel(gid)` 只发取消请求；不能将发送或 `cgroup.kill` 写入成功当最终释放。重复/未知句柄返回错误，不会误报成功。

`Task.groups[g]['status']` 是 **原始 wait status**；A 的 `Raw.release()['rc']` 是解码后的 exit code。比较错误行为时须统一解释，不能直接比任意非零数值。

### 最终销毁

`Task.close()` 停止接纳并取消未结束组，等待所有组 DONE，owner 最后 `ECHILD`，等待 bwrap monitor pidfd，确认 control cgroup 空，关闭 selector/socket/pidfd/log，读取最终 stats，删除 control/task cgroup 和 workspace。删除失败不能作为成功 ACK。controller 退出后，外部实验引导者删除 client cgroup 和委派根；这属于最终回收账本，不是隐形清理。

owner/PID 1 死亡、monitor 死亡、控制 EOF、caller SIGKILL 选择整 Task fail-stop。历史故障夹具的存活外部 manager **等待系统清空进程后清理名称**；它不通过后补 kill 伪造产品清理。生产恢复、断电、任意 LSM/内核状态和外部副作用不在已验证合同内。

## 4. A / B / C 如何复用此底座

| 模式 | 真实入口 | 业务响应与生命周期的区别 |
|---|---|---|
| A：每请求新域、新业务进程 | `Raw(name, argv, work=...)` → `release(reap_all=True)` | 相同 bwrap 配置和 policy；EOF + monitor wait + cgroup 空 +外部 subreaper `ECHILD` 后结束 |
| B：一个域，每请求新业务进程 | `Task(strict=True)`；每次 `start` → `wait`；最后 `close` | 域已预热，但每次重新 exec/import/初始化 |
| C：一个域，一个初始化 Worker | 一次 `Task.start` 启动 Worker；多次应用协议请求；显式 shutdown → `wait` → `close` | 每次有效应用响应**不是** group RELEASED；组/cgroup/guardian 在 Worker 空闲时仍存在并计费 |

Inference：可以在 `/work` 的独立私有 Unix domain socket 上实现明确的业务请求协议，无需修改 owner。这是业务 IPC，不是调度器；A/B/C 均使用相同协议、同一输入与独立正确性 Oracle。loopback 网络属于私有 netns，宿主不能直接按 `127.0.0.1` 连接域内服务。owner 原有 START **不传 stdin**，所以不能直接把 Python JSON stdin 或 clangd LSP stdio接到 controller；应由域内同组协议包装器连接真实工具的正式接口，并完整计入包装器启动、IPC、PSS 和清理。

同组包装器必须显式 shutdown/wait 真实工具并关闭传输。长期 Worker 异常后不能默认复用，应返回错误并结束该组；正常业务错误和传输/进程故障需分别验证。控制器读响应时也要处理组 stdout/stderr，避免未消费日志造成背压。path socket 仅用于同一可信 controller 与该 Task；不能据此声称认证了任意跨租户连接。

## 5. 测量中不可漏计的边界

- `Task.ready_ns` 在收到 READY 后、控制进程 `/proc` 身份/PSS 枚举前记录；旧 `setup_ms` 不包含后者，但旧 `total_ms` 包含。新实验应同时记录构造函数返回及诊断采样跨度，不能把旧 READY 当完整控制器准备时间。
- `Task.close().end_ns` 在审计 JSON 写盘前。必要业务输出已经收集，但研究报告写盘不是业务响应。新输出需明确计时截止点和验证是否计入。
- `Task.wait` 的组 CPU/stat 与 control cgroup 分离；Task 父 cgroup CPU 已包括后代，**不能再加 control/组 CPU 重复计费**。外部 Python controller CPU 另记。
- PSS 是时间点共享页分摊，不能把多进程 RSS相加当独占内存。owner 的受保护 `/proc` 字段可能因 rootless权限不可读，已有self-report；Python Worker可自报，真实工具可由同组包装器读取合法子进程字段，缺失记 Unknown。
- C 空闲时还保留组 guardian 与 cgroup；不能只报 Python/clangd PSS 忽略这些控制成本。Task 共置多个 Worker 也不自动取消每组 guardian。
- 组 `memory.peak` 与全部 sandbox PSS 不同；page cache/kernel内存计费也不等物理页已立即释放。必须区分进程/FD/cgroup名称回收与内核延迟释放。
- 旧 B-event 合同弱于 B-strict；不用于本轮主要性能比较。

## 6. 复核到的历史证据，不计作本轮新收益

直接读取 final-01 (`../b_group_bwrap_gap_discovery/experiments/final-01/checks.json`, omitted from this source release)、final-02 (`../b_group_bwrap_gap_discovery/experiments/final-02/checks.json`, omitted from this source release)、final-03 (`../b_group_bwrap_gap_discovery/experiments/final-03/checks.json`, omitted from this source release) 和 supplemental-final-01 (`../b_group_bwrap_gap_discovery/experiments/supplemental-final-01/checks.json`, omitted from this source release)：主批各 28/28、补充 9/9，共 **93/93 顶层断言**。三次同宿主 VM 不是三个独立硬件样本。四批 `result.json` 均完成且未超时。

每批 `remaining-cgroups.txt` 留有 `/sys/fs/cgroup/bgap/client`，这是 controller 尚活着时的中间状态；后续 **`external-final-release.json`** 均确认 controller 退出、委派根删除，不能仅凭前一个文件称泄漏或仅凭进程空称全部回收。

原始 data/summary.json (`../b_group_bwrap_gap_discovery/data/summary.json`, omitted from this source release)、每批 `benchmarks.json` 和 task JSON 保存了以下历史成本：

| 历史测量 | 结果/范围 | 只能说明什么 |
|---|---|---|
| 100 次 `echo` 完整序列，一次性 / B-strict | 中位 905.594 / 186.841 ms；每组 n=9 | 合成摊销机制已由既有 Bubblewrap 组合实现，不是自然调用率或新 ShimOS 收益 |
| B-strict setup，按10/50/100请求序列 | 中位约 8.540 / 8.238 / 7.756 ms | 特定冻结配置下域 READY 成本，含义如上 |
| B-strict teardown，按10/50/100序列 | 中位约 2.143 / 2.294 / 2.270 ms | 已含同合同 task 收尾，不是业务 Worker专属成本 |
| 初始 monitor+owner PSS | 中位 2896 KiB | 非空闲 Python/clangd Worker PSS；外部 client 另约20MiB |
| 16活跃组的 control进程 | 18个，合计 PSS中位3322 KiB | guardian额外内存可共享；不能RSS乘16估算 |
| HTTP服务 + zlib构建测试 +取消 +重试 | 3VM完整链中位2180.776 ms；取消到strict release中位3.103 ms | 真实工具、受控编排；不是自然 Agent trajectory |

新实验应重新测 Worker初始化、warm response和闲置成本，不把上述机制控制组复制成“Worker Pool提升”。已有证据足以支持最小成本实验；尚不足支持动态布局或调度策略胜出。

## 7. 审计结论

**可直接复用：** 固定受信配置的一次建域、多次新进程、独立组预算/取消、合并stdout/stderr收集、严格组reap和最终域释放。

**需本轮新增而不改底座：** Python/真实代码分析工具的明确业务协议、cold/warm等价输入输出、初始化与每次响应计时、Worker身份和内存观察、正常错误与异常退出探针。

**没有实现：** 通用 Pool Manager、类型匹配、跨信任域共享、动态放置、预测保活、无限任务ID、应用状态正确性证明、透明迁移或恢复。复用 B-strict 能避免重复开发隔离域管理，却不自动解决这些研究问题。
