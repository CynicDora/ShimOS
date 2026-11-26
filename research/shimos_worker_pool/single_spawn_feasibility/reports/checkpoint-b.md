# 检查点 B：原权限负例与独立单次派生诊断

日期：2026-10-20。范围：用户批准的测试包 A、B 和只读内核必要性分析。**现有 ShimOS Z→S→W 保持不变；本轮没有实现完整 Z→W，没有改变 H/R/Z 主协议，没有修改内核或开展性能对照。**

## 1. 本轮回答了什么

**当前 Z 直接选择目标 PID namespace 的权限阻碍已实际复现。具备另一套合法、临时权限关系时，单次完整 fork 到已有目标 PID namespace 也已实际验证。两件事同时成立。**

- **包 A：原权限负例通过。** 在与冻结 Z 一致的凭据下，对两个由原 Bubblewrap 配置创建的目标调用 PID setns，均为 `-1 / EPERM(1)`；调用前后能力集、active PID namespace 和 `pid_for_children` 不变。目标正常停止并回收。
- **包 B：受限机制诊断通过。** 临时管理 userns Uc 拥有管理 PID namespace Pm 和两个子 PID namespace P1/P2。诊断 Z 留在 Pm，选择 P1/P2 后经完整 glibc D/Python fork 创建 W，再恢复 Pm。6 个 W 真正继承内存；两域、重叠存活、pidfd 取消、PID1 死亡、死域派生拒绝和真实 wait 均有原始记录。
- **完整隔离集成没有取得资格。** B 不建立 Bubblewrap 的独立 base/inner userns、mount/root/net/ipc/uts 环境，也没有 H/R 业务协议。其结果不能写成原 ShimOS 合同下的直接 Z→W 已实现。
- **内核必要性尚未得到证明。** 若新接口保留现有双 capability 检查，原 Z 仍被拒绝。它可能消除父进程临时选择/恢复窗口，但不自动赋权或完成其他隔离和回收工作。

固定版运行是 `check-b-a-01`、`check-b-b-01` 两个独立私有 VM；另外保留 `pilot-a-01`、`pilot-b-01` 两个先行运行。四次均来自同一宿主，不是独立硬件重复，也不是性能样本。独立核对见 机器可读验收 (`../analysis/checkpoint-b-independent-verification.json`, omitted from this source release)，原始入口见第 8 节。

独立复核固定 A 的21项、固定 B 的61项断言均通过，结果为 `PASS_DIAGNOSTIC_ONLY`；这些不是21/61个独立场景。完整单次派生 Bubblewrap 合同保持 `NOT_ADMITTED`。

## 2. 环境、身份和证据等级

|项目|实际使用|
|---|---|
|VM|原冻结 KVM fixture，4 vCPU / 4 GiB，一次一个 VM；实验没有 guest 网络|
|Kernel|`6.18.49-agentic-runtime-opt-v1`；冻结源码 commit `1c732c6b94f0faee1526bd375add2fe10cba2e26`|
|Kernel SHA256|`bd303a80ab8fe396ac83d18e2dcd0936143eb0778fbcf6acaf47ea3fba11dd4f`|
|initramfs SHA256|`79505c01cc39cb00dea51d4a8101c1bfea187a84515782520d1b58ef3d4a32f9`|
|Python/runtime|CPython 3.10.12；candidate-04 D 的 glibc 2.35 闭包；284 项 runtime 文件校验一致|
|D libc / loader SHA256|`a03b51fe69f36b630ecf7997af05cd36885b1f2f0b52e278391fa6e17047eff4` / `0682f493d0434391d4ec027d0bcb54dd5f9e46d044dc7810f69abea58fe1398e`|
|fork 路径|冻结 `bridge_d.py_fork_cgroup()` → Python before hook → `shimos_fork_into_cgroup()` 完整 libc wrapper → clone3 → native/Python parent/child hooks|
|资源预算|根委托 512 MiB / 256 pids / 4 CPU；诊断叶组 256 MiB / 128 pids / 2 CPU。没有为负例提高预算或权限|
|计时和追踪|同一 guest 的 CLOCK_MONOTONIC 事件；独立 sched fork/exec/exit 追踪，4 CPU 均无已报告丢失。插桩和审计开启，仅作正确性证据|

包 A 是**使用冻结 Z 凭据、runtime 和目标域配置的独立权限探针**，不是原 Z 主事件循环重跑。UID/GID 65534、空附加组、初始 guest userns/PIDns、CapEff/CapPrm=0、CapBnd=`000001ffffffffff`、NNP=1、seccomp=0、单线程与历史 `ZYGOTE_READY` 一致；FD、日志、父进程和诊断 cgroup 名称不同。原 Z 本来尚未安装业务 seccomp，不能把探针的 seccomp=0 误写成关闭旧安全设置。

包 B 明确使用另一种临时权限诊断合同。guest-root fixture 只负责建立委托、给已降到 UID/GID 65534 的进程写单 UID/GID 映射和最终核查；它没有给正式 Z 增加权限。实际诊断 Z 在 Uc 中拥有完整能力集，NNP=0、seccomp=0；W 在可信回调之后执行原 `drop_final()` 和 no-exec filter，最终 CapEff/CapPrm/CapBnd=0、NNP=1、seccomp=2。**这个构造阶段的权限差异必须保留在结论中。**

证据分为：① 本轮原始运行；② 冻结源码与身份联合解释；③ 未运行的集成假设。不能把②③标成测试通过。623 项所选历史输入前后 SHA 无变化，见 before (`../analysis/checkpoint-b-input-before.json`, omitted from this source release)、after (`../analysis/checkpoint-b-input-after.json`, omitted from this source release)；此声明不覆盖未登记的全部仓库文件。

## 3. 包 A：究竟在哪里被拒绝

权限关系和 PID 层级是两棵不同的树：

```text
userns：U0（Z：UID 65534，CapEff/CapPrm=0）
          ├─ Base A（owner UID=65534）→ Inner A
          └─ Base B（owner UID=65534）→ Inner B

PIDns： P0（Z active；Z pid_for_children=P0）
          ├─ Pd A（owner=Base A；目标 PID1 已存在）
          └─ Pd B（owner=Base B；目标 PID1 已存在）

直接 setns(Pd)：需要目标 owner userns 的资格，也需要自身 U0 的 CAP_SYS_ADMIN。
前一项的 owner 条件成立；后一项在冻结 Z 上不成立。
```

`check-b-a-01` 的两个 attempt：

|attempt|目标 PIDns inode / owner userns inode|rc / errno|前后 CapEff / CapPrm|实际终结|
|---|---|---|---|---|
|`c76915ac3d460eeadd507c586f6ceee4`|4026532243 / 4026532239|−1 / 1 EPERM|0 / 0，未改变|DRAINED、monitor wait=0、EOF、空 cgroup、目录删除|
|`2147ef0611a729297fc84cf506c7b50b`|4026532295 / 4026532240|−1 / 1 EPERM|0 / 0，未改变|同上|

该 VM 中 Z 的 U0 inode 为 4026531837，active PIDns 和前后 children 均为 4026531836。目标 namespace 类型、owner/parent、inner parent 由真实 FD ioctl 查询；两个 Base 的 parent 都是 U0，owner UID 都是 65534。inode 只在相应 run/session 内使用，不把不同 VM 的相同数字当作同一对象。

准确归因是：**观测到 EPERM；冻结 `pidns_install()` 的双权限检查，结合 Z 无自身 U0 capability 的事实，给出了足以拒绝的明确条件。** 目标是 P0 后代，错误不应归因为进入兄弟/祖先 PIDns。目标 owner 资格由 `commoncap` 的父 userns owner 规则解释；本轮没有对内核每个 LSM/capability 分支作动态探针，不能把 EPERM 本身冒称内核分支 trace。

源码：冻结 `kernel/pid_namespace.c:401–424`、`kernel/nsproxy.c:321–332`、`security/commoncap.c:68–103`，见 源码快照 (`../kernel_analysis/source-manifest.json`, omitted from this source release)。接口规则可对照 [setns(2)](https://man7.org/linux/man-pages/man2/setns.2.html)。

A 没有创建试验 W；该拒绝没有通过新增 capability、切换正式 Z 身份或关闭检查绕过。探针正常关闭 namespace/root/pidfd/socket 引用，FD 清单恢复，wait 无剩余孩子，目标和工作目录删除；外层 fixture 另有真实 wait、输出 EOF、根 cgroup 空及空委托删除记录。**VM 最后被销毁不是这些回收条目的替代证据。**

## 4. 包 B：什么条件下单次派生成立

### 4.1 实际拓扑

```text
guest U0 / P0
  └─ 降到 UID/GID 65534 的 mapping client
       └─ 临时 userns Uc（只映射 65534 → 65534）
            └─ 管理 PIDns Pm（owner=Uc；诊断 Z 是此处 PID1）
                 ├─ 目标 PIDns P1（owner=Uc；init 先存在）
                 └─ 目标 PIDns P2（owner=Uc；init 先存在）

真实进程关系（均为诊断 Z 的直接孩子）：
Z(Pm) ──完整 fork──→ init P1 / init P2
Z(Pm) ──一次完整 fork──→ W(P1) 或 W(P2)
Z 始终 active=Pm；pid_for_children 在 Pm、P1、P2 之间选择/恢复。
```

临时 Uc 本身还不够：mapping client 已在 Uc、active PID 仍为外层 P0 时，先 `unshare(NEWPID)` 选中一个尚无 PID1 的 Pm，随后尝试选择原 P0，实际得到 **EPERM**。这时 P0 就是调用者的 active PIDns，**不是 PID 祖先关系拒绝**；问题是 P0 的 owner U0 不归 Uc 凭据管理。

成功路径因此恢复的是**归 Uc 所有的 Pm**。这是运行前登记的诊断拓扑，不是负例失败后偷偷给原 Z 加权，也不是把正式 ShimOS 切换成新架构。一次性的 mapping client/Pm 构造和两个目标 init 都真实存在并被 wait；“一次派生”仅指已就绪诊断 Z 到每个 W，绝不表示整个会话只有一次 fork。

### 4.2 固定版机制结果

`check-b-b-01`：Uc=4026532239，Pm=4026532240，P1=4026532241，P2=4026532242。Pm/P1/P2 的 owner 均为 Uc；P1/P2 的 parent 均为 Pm。真实创建树由 guest sched trace 与事件中的 NSpid、父返回 PID、pidfd 共同关联。

|用例|实际结果|判定范围|
|---|---|---|
|外层 P0 负例|setns=−1，errno=EPERM；原 active 不变|临时 Uc 并不授予 U0 权限|
|P1、P2 顺序直接派生|每个 W 一次 D wrapper；目标内 PID=2，getppid=0；父 Z 真实 wait=0|PID 归属与真实亲缘可以不同；不是目标 init 自动 wait W|
|两个 W 重叠存活|串行派生后分别在 P1/P2 等待 RELEASE，再逐个 wait=0|有两个同时存活的 W；不是多线程并发 fork 或吞吐资格|
|受控取消|pidfd SIGKILL；Z wait W 得到 −9|是诊断私有阻塞点取消，不是原 CANCEL/seal 协议回归|
|P1 的 PID1 死亡|W 被 SIGKILL；Z 先 wait W=−9，再 wait init=−9|实际验证退出传播和重要的 wait 次序|
|再次选择死 P1 并派生|setns 可成功；完整 wrapper 返回 −1/ENOMEM(12)，pidfd=−1，无孩子被虚构|持 FD 不会复活已死 PID1；这里 ENOMEM 不能解释为 RAM 耗尽|
|恢复|2 次 init 创建、6 次 W 创建及1次拒绝之后，共9次恢复 Pm成功|每次回读 active/children；父凭据最终不变|
|正常收尾|P2 init wait=0；所有已知孩子真实 wait；空叶组及委托删除；EOF|没有外部补杀；只确认本实验所持引用关闭|

同一次固定版有 8 次成功 D wrapper（2 个 init + 6 个 W）、1 次拒绝。诊断日志有 10 条真实 wait：Z wait 8 个直接孩子，mapping client wait Z/Pm，外层 package fixture wait mapping client；VM fixture 对 package 根进程的 wait 另在 `fixture-final.json`。不得把 pidfd 可读当成这些 wait 的替代。

### 4.3 运行时和内存证据

- 使用冻结 D libc/loader、`bridge_d`、自有 native runtime 探针；实际映射和 SHA 被记录。没有使用 raw clone3 返回 Python heap 的捷径。
- 9 个派生尝试逐项检查 Python/native callbacks：prepare 逆注册顺序、parent/child 正注册顺序；被拒绝的 fork 仍有 parent callbacks，没有伪造 child callbacks。
- 6 个 W 各有降权前、后的 runtime 快照，共12项：pthread 缓存 TID 探针与内核 TID、robust-list 注册等检查成立。两次 W 持有共享 robust mutex 后退出，Z 在真实 wait 后得到 `EOWNERDEAD=130`，并成功 consistent/unlock。
- Z 内新建随机 128 KiB bytearray 和 nonce；W 继承对象地址、data 地址、nonce、创建者和内容 digest，私有修改一个字节。固定版最终原始 digest 与 READY 一致，Z 未被污染。sched trace 中 W 没有 exec，只有 fixture 最初启动候选 loader 的 exec。
- 每个 W 使用 `CLONE_INTO_CGROUP` 的完整 D 路径；首个记录到的可信 W 身份位于指定 w1/w2 叶组，源码没有 fork 后迁移。**没有逐条 syscall tracing 去测量首条 child callback 的 memcg 事件**；原子出生语义由固定 D 调用源码、实际加载身份与 W 归属共同支持。
- W 的管理 FD 被关闭，保留0/1/2和私有诊断 socket；Z 最终 FD 清单恢复到初始清单减去明确关闭的 Pm 引用。诊断 socket 不符合正式业务仅0/1/2的合同，因此不能据此授予正式 FD 资格。

**native/Python child callbacks 在最终 drop 之前运行，继承 Uc 管理能力。** 这不是未知第三方依赖的准入；只测试可信自有单线程回调。改为单次派生后，旧 S 降权之后的第二次 W 回调时机不再存在，必须重新分析可信面。

### 4.4 明确未验证什么

B 的 W 仍使用 guest 的 mount/root、net、IPC、UTS，并共享管理 Uc；没有进入 Bubblewrap 独立 Base/Inner，也没有文件系统可见性等价检查。没有 Controller SIGKILL/H 接管、Z 突亡、迟到 SPAWN、重复 CANCEL、回执丢失或 UNKNOWN 协议测试。没有新路径 PID预算/OOM资格，没有任意第三方依赖或 NumPy准入，没有性能排名。

私有 `RELEASE` 只用于控制诊断子进程的存活时间；W 在等待前已检查并私有改写测试内存。它**不是**原 RUN_BUSINESS 门禁，不能把这条消息算成正式业务授权验证。

P1 死亡时 P2 的 init 仍存活并正常 STOP；当时 P2 没有同时运行的 W，因而不能声称已经验证“杀 P1 而并发 P2 W 不受影响”。非零业务返回没有另设样本，已测的是正常0和故障信号−9。失败兜底排序修正未独立注入异常分支。

上述完整 ShimOS 集成维度为 **NOT_RUN / NOT_ADMITTED**。这不是对原 Z→S→W 已有资格的否定。

## 5. 哪些阻碍属于什么层面

|问题|证据与分类|当前判断|
|---|---|---|
|Linux 是否普遍要求两次 fork|B 实际一次 D fork 到已有 P1/P2|不普遍要求；不能把 setns 只影响孩子误解为始终需要 S|
|冻结 Z 不能直接 PID setns|A 两域 EPERM，当前 U0 CapEff/Prm=0|现有权限合同与调用顺序的具体阻碍|
|向两个目标选择并恢复|B 在 Uc 管理的 Pm/P1/P2 成功；恢复外层 P0拒绝|合法用户态可解决**特定层级**，不能推广到任意已建域|
|完整 fork 运行时|D hooks、TID、robust、内存继承通过小诊断|继续需要 D/CPython wrapper；不构成省略 runtime 的理由|
|完整 Bubblewrap 身份|B没有做|必须另获准研究，不能从 PID 成功推断|
|谁承担 wait/取消/H接管|B 的 Z是实际父；原协议依赖 S|主要是 ShimOS 生命周期职责调整，单改PID接口不能解决|
|父选择/恢复窗口|B 证明可恢复；未测试信号/callback 重入|用户态需要串行与可信回调约束；按次参数可能减少此窗口|
|是否必须新增内核能力|本轮没有发现仅凭内核扩展才能完成所有目标的证据|保持原权限的新参数不够；改变授权则是独立安全研究|
|端到端/调度价值|没有同合同单次派生实现与成本对照|Unknown；不能从少一次 fork 推导架构交叉点变化|

## 6. 假想内核接口究竟能解决什么

详见 只读内核必要性分析 (`../04_kernel_necessity.md`, omitted from this source release)，包含固定源码、ABI/LSM、PID1、父子关系、cgroup和公开直接先例。

若 `clone3(target_pidns_fd)` 保持现有 PID setns 的双权限与后代条件，它可以把目标绑定到一次创建，避免长期父的 `pid_for_children` 临时变更，以及 prepare/parent callback 或信号处理器重入时选错域的窗口。但它**不会让 A 的 Z 获得 U0 capability**，也不会替 W换其他namespace、root/cwd、FD、权限或完成授权和回收。

若要使原 Z 不改凭据也能使用，需要定义不同授权，例如目标 owner-only 或受限派生授权对象。这不只是添加字段：需要核查 LSM、FD传递、目标/attempt绑定、撤销、PID1消失、失败回滚及恶意调用者。普通 namespace FD 是引用，并非当前就具备任意注入许可。另一方面，原 Z 已可经 S合法进入目标后代 userns；也不能未经分析就断言任何不同授权必然导致宿主提权。

新的 syscall 参数仍须纳入完整 libc/Python wrapper。它不会自动修复或绕过此前 raw clone 的 TID/robust/native-atfork问题。本轮只冻结/阅读内核源码，没有编写、构建或加载补丁；接口价值与上游接受度都未被本实验确认。

## 7. 如果以后移除 S，职责会怎样变化

这是分析，不是已实施方案。

|现有 S 的职责|可能去向|没有自动消失的工作|
|---|---|---|
|取得目标base能力、选PID目标|合法管理层中的Z，或未来按次授权接口|父的权限来源、目标身份和失败恢复|
|mount/user/net/ipc/uts、root/cwd转换|W出生后的可信准备段|必须在业务许可前完成；不能不可逆地把长期Z留在一个目标域|
|降权、NNP、seccomp、FD关闭|W可信准备段|child callbacks已经先运行，可信边界/顺序需新论证|
|第二次完整fork|在合格单次派生中可消除|第一次完整wrapper和其callbacks仍必需|
|START_WORKER及RUN_BUSINESS门禁|新的Z/W控制关系|“W尚未出生”与“已出生但禁止业务”不同；取消封口不能删|
|真实wait W、退出/结果回执|真实父Z|Z事件循环需承担wait、未知结果和死亡次序，不能仅靠pidfd|
|被Z wait 的中间S|可能少一层进程和回执|H/R收养、Controller失败及目标PID1终止必须重做资格|
|transition cgroup中的构造开销|可能转入W业务组|记账移动不是资源消失；模板页/COW仍有责任边界|

因此，B证明的PID机制不能直接作为删除S的补丁。原H/R/Z协议和启动拓扑继续保留；没有以新名字重组旧协议。

## 8. 原始证据、复现和版本变更

|材料|位置|
|---|---|
|固定A：调用前后、目标关系、errno、DRAINED/wait/目录|check-b-a-01/package-a (`../experiments/runs/check-b-a-01/package-a/`, omitted from this source release)、summary (`../experiments/runs/check-b-a-01/package-a/summary.json`, omitted from this source release)|
|固定B：逐事件、callback、TID、namespace、内存、wait|diagnostic-output.log (`../experiments/runs/check-b-b-01/diagnostic-output.log`, omitted from this source release)、summary (`../experiments/runs/check-b-b-01/package-b/summary.json`, omitted from this source release)|
|B真实进程树及exec边界|process-trace.txt (`../experiments/runs/check-b-b-01/process-trace.txt`, omitted from this source release)、trace-stats.json (`../experiments/runs/check-b-b-01/trace-stats.json`, omitted from this source release)|
|外层真实wait/EOF/空组删除|A fixture-final (`../experiments/runs/check-b-a-01/fixture-final.json`, omitted from this source release)、B fixture-final (`../experiments/runs/check-b-b-01/fixture-final.json`, omitted from this source release)|
|运行身份和命令|每个run的 `command.json`、`environment.json`、`build.json`、`source-sha.json`、`candidate-runtime*.json`、冻结 `poc/`|
|预登记及独立检查规则|plan (`../experiments/checkpoint-b-plan.json`, omitted from this source release)、B plan (`../userspace_poc/package_b/plan.json`, omitted from this source release)、verification-contract (`../experiments/verification-contract.md`, omitted from this source release)|
|机器可读提取|setns CSV (`../analysis/checkpoint-b-setns.csv`, omitted from this source release)、关系JSON (`../analysis/checkpoint-b-relations.json`, omitted from this source release)、wait JSON (`../analysis/checkpoint-b-waits.json`, omitted from this source release)、run ledger (`../analysis/checkpoint-b-run-ledger.json`, omitted from this source release)|
|独立验收脚本/结果|verify_results.py (`../experiments/verify_results.py`, omitted from this source release)、verification JSON (`../analysis/checkpoint-b-independent-verification.json`, omitted from this source release)|
|原始pilot及所有版本差异|pilot A (`../experiments/runs/pilot-a-01/`, omitted from this source release)、pilot B (`../experiments/runs/pilot-b-01/`, omitted from this source release)、变更/失败记录 (`../experiments/failure-and-version-record.md`, omitted from this source release)|

pilot 后只改了 B 的异常兜底 wait 顺序和最终模板原始摘要输出；机制、权限和正常路径不变。固定版重新独立跑完整B，不能把pilot的检查拼接到新版本。没有实际运行失败被删除；预期EPERM/ENOMEM全部保存。没有外部observer补杀计作通过。

记录限制：B 的部分 `SETNS_PID` / `TRUE_WAIT` 行的 `attempt` 字段仍是最近一次fork的名称。复核使用 session、角色、`target`/`label`、namespace inode、父可见child、NSpid与事件顺序联合关联，不按该字段单独分组。这个诊断标记不足已保留，不应被误写成正式协议回执串线，也不能将其直接当作生产请求身份协议。

从项目根目录运行，必须换新编号，runner拒绝覆盖：

```bash
python3 -B research/shimos_worker_pool/single_spawn_feasibility/experiments/run_vm.py <新A编号> --package a
python3 -B research/shimos_worker_pool/single_spawn_feasibility/experiments/run_vm.py <新B编号> --package b
```

不要在宿主直接运行 `guest.py`。C辅助件仅在guest编译；源码、命令和实际二进制SHA保存，guest编译产物及可销毁磁盘随会话释放，可按冻结源码重建。程序输出的wrapper wall和VM总wall均是有重诊断的正确性运行，不用于性能比较。

## 9. 交回决策权

本次可确定：**原 Z 的当前权限确实阻止直接 PID 选择；合规的另一套用户态权限/层级可完成一次完整派生及恢复；完整 ShimOS 的环境转换和生命周期责任仍未被替代。**

下一步若考虑完整用户态集成，需要先决定是否允许改变模板所在管理层级及长期权限，并批准相应H/R/Z协议与新资格范围。若考虑新内核接口，需要先决定是否保持原授权；保持则不能解决A，改变则需独立安全论证。也可以继续保留原架构，把本轮结果作为成本与设计约束。

本轮到检查点B停止。没有启动后续集成、性能矩阵或内核原型，没有做项目或路线Go/No-Go判断；最终架构与后续研究选择由项目负责人决定。
