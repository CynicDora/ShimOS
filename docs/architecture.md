# 架构说明：隔离域、Worker 与准备态如何配合

我们在不同阶段保留了不同原型。它们围绕同一个问题展开：隔离环境的寿命，是否可以与程序初始化状态的寿命分开？本页解释主要机制，具体源码入口见[原型导航](../prototypes/README.md)。

## 先看哪份实现？

[integration_ab/prototype](../research/shimos_worker_pool/integration_ab/prototype) 是较紧凑的跨域参考实现，结合了生命周期修复与完整 fork 运行时路径。后来的 [architecture_comparison_full/prototype](../research/shimos_worker_pool/architecture_comparison_full/prototype) 用来比较 G0–G4 和资源竞争，增加了实验分支，并不是新的统一服务接口。

## 持久隔离域中的 Worker

早期 B-strict 把域和域里的业务进程组分开管理。控制器建立 cgroup 和工作区，Bubblewrap 启动域内的 owner/PID 1；业务进程组再由 guardian 监督，并在指定 cgroup 中创建实际执行进程。输出通过私有继承通道传给收集者。

Worker 返回一次业务结果后，可以继续存活处理下一请求；这与整个进程组结束是两件事。严格完成需要真正等待相关进程退出、读到输出 EOF，并确认业务 cgroup 已空。同域 Worker 共享部分环境，只适用于相同信任、工作区和权限要求的任务。

源码见 [baseline](../research/shimos_worker_pool/experiments/baseline)，应用请求协议见 [workers](../research/shimos_worker_pool/experiments/workers)。

## 跨域 Zygote 的实际进程关系

```text
H：独立监督进程
└─ R：控制器
   ├─ Bubblewrap monitor → 目标域 PID 1
   └─ Z：可信、干净、已初始化的 Python 模板
      └─ S：过渡进程，也是 W 的实际父进程
         └─ W：目标域中的业务 Worker
```

目标隔离域先由 Bubblewrap 创建。目标 Namespace（进程看到的系统视图）和根目录的引用通过私有 Unix socket 传递，并与本次执行身份绑定。进入域、加入 cgroup、成为某个进程的孩子，是三个不同操作；W 不会因为进入目标域，就自动成为目标 PID 1 的直接子进程。

S 进入目标域的用户、挂载、网络、IPC 和主机名等环境，切换根目录与工作目录，选择后续孩子使用的 PID Namespace，再永久降权。它自己的活动 PID Namespace 不会随选择改变，因此还需要第二次派生，创建真正具有目标 PID 身份的 W。顺序见 [bridge_d.c](../research/shimos_worker_pool/integration_ab/prototype/bridge_d.c)。

Z 则留在能合法构造后代的位置。将 Z 永久移进某个目标域，或扩大其长期权限，都不是无成本的简化。[单次派生审查](../research/shimos_worker_pool/single_spawn_feasibility/reports/checkpoint-c.md)区分了原权限模型下的阻碍与另一种合法拓扑的诊断结果；后者没有取得完整原合同的集成资格。

## 为什么可以继承初始化内存？

两次派生都通过 fork 保留父进程内存，并依靠写时复制（COW）处理后续写入。Z 最初启动需要 exec，但 S/W 不重新 exec Python。如果业务随后 exec 一个外部工具，原 Python 内存就会被替换，不能再称作 NumPy heap 复用。

我们实际遇到过 raw clone3 绕过完整 libc fork 路径的问题。固定版本的 glibc D 保留了原生回调、线程身份和 robust mutex 等处理，再配合 CPython 的前后置 hooks，让子进程出生在目标 cgroup 中。桥接层在缺少专用接口时直接拒绝，不悄悄退回未经验证的路径。

这个修复只在固定环境中验证。fork 回调在业务门禁前执行，还可能接触管理 FD，所以模板和回调本身必须可信；“只有一个线程”或“能力集已清零”并不足以让任意依赖获准预加载。

## 谁负责取消、等待和回收？

每次执行有独立身份，准备、派生与开始业务分别需要许可。取消先关闭未来的启动许可，再停止已存在的执行；仅调用 cgroup.kill，不能保证稍后不再发生派生。

S 真正 wait W，Z 真正 wait S；R 管理目标域和 monitor。R 异常退出时，H 可以继续运行，停止创建者，等待合法收养的后代，并释放已登记资源。pidfd 提供稳定的观察与发信号对象，不会自动赋予等待任意进程的权限。

我们把业务结果、派生情况和资源释放分开记录。即使清理完成，丢失的业务结果也可能保持 UNKNOWN；清理证据不足时，不能报告 RELEASED。[A+B 报告](../research/shimos_worker_pool/integration_ab/integration-report.md)给出了 29 次受限资格的具体覆盖，前提仍包括 H 存活。后续 Tool Exec 的补充测试不能自动扩大所有历史版本的保证。

## 资源与安全边界

已验证路径使用 CLONE_INTO_CGROUP，让 S/W 出生时就有明确资源归属。不过，共享的旧页面不会因为新建了 Worker，就分别获得一份独立物理记账。父 cgroup 的累计 CPU 也已包含孩子，不能重复相加。

PSS、Private_Dirty 和 cgroup memory.peak 各有不同含义，单独一个指标不能证明净物理内存减少。实验保留了权限下降、NNP、seccomp、FD 清理、授权和真实回收；其中的 seccomp 仍是研究用策略，不是通用生产安全证明。G4 对已知状态的恢复，也不能等同于每次启动一个干净进程。
