# 原型导航：从哪里读源码？

不同阶段保留各自的相对路径，便于和当时的实验对应。它们没有被重新包装成一个不存在的统一生产接口。

| 想了解的机制 | 源码入口 | 阅读时注意 |
|---|---|---|
| B-strict 持久隔离域 | [baseline](../research/shimos_worker_pool/experiments/baseline) | 强生命周期组合，不是任意持久 Shell 的透明替代 |
| NumPy/clangd 请求与结果 | [workers](../research/shimos_worker_pool/experiments/workers) | 固定、可信、串行的应用协议 |
| 最早的跨域实验 | [cross_domain_zygote](../research/shimos_worker_pool/cross_domain_zygote/prototype) | 历史 raw 运行时路径，不用作修正后的合格性能基线 |
| 生命周期修复 A | [reliability_fix](../research/shimos_worker_pool/reliability_fix/prototype) | 保留独立修复历史，运行时另有后续集成 |
| **主要跨域参考实现** | [integration_ab](../research/shimos_worker_pool/integration_ab/prototype) | 生命周期 A + candidate D，29 次受限资格 |
| PING 合并 | [ping_merged](../research/shimos_worker_pool/cost_breakdown/ping_merged) | 将模板检查合入 FORGOTTEN，没有删除检查 |
| 固定 NumPy 准入 | [numpy_admission](../research/shimos_worker_pool/numpy_admission/prototype) | 固定可信 CPU 配方 |
| G0/G1/G2 对照 | [round1](../research/shimos_worker_pool/architecture_comparison_round1/prototype) | 每请求独立新域的比较 |
| G2/G3/G4、并发与压力 | [full](../research/shimos_worker_pool/architecture_comparison_full/prototype) | 有限资格下的研究变体，不是通用调度器 |
| 工具执行后续修复 | [followup](../research/shimos_worker_pool/exec_support_followup/prototype) | 私有退出回执与额外 H 故障合同 |

建议先读 A+B 的 `run.py`、`zygote.py`、`supervisor.py` 和 `bridge_d.c`，再结合[架构说明](../docs/architecture.md)理解分工。需要研究性能分支时，再进入 round1/full。

目录中包含只能在指定私有 VM 内运行的 guest 和故障代码。收录源码不代表已包含完整运行时镜像；执行前请先读[复现说明](../docs/reproduction.md)。实验室根目录的另一套 native MVP 也使用过 G1/G2/G3 名称，本仓库未收录该分支；这里的 G0–G4 始终指 Worker/Zygote 架构模式。
