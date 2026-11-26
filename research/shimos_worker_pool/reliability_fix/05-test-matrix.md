# 最终正确性测试矩阵

2026-10-19。7 个独立初始化的私有 VM，会话仍位于同一物理宿主；同一执行源码版本。26 个 attempt，20 种用例。PASS 表示达到相应故障的预期处理，不表示故障任务业务成功。正式 PASS=26，FAIL=0，BLOCKED=0；未做的扩展故障属于未验证，不计作通过。

| 用例 | 请求结果 / 业务知识 | 资源 | 判定 | 原始证据 |
|---|---|---|---|---|
| 第一次 clone EAGAIN | RESOURCE_REJECTED / NOT_EXECUTED | RELEASED | PASS | 9ac18981 (`runs/qualification-01-budgets/0-pid_budget.json`, omitted from this source release) |
| 正常执行 | SUCCEEDED / KNOWN | RELEASED | PASS | 9aff1626 (`runs/qualification-01-budgets/1-normal.json`, omitted from this source release) |
| 第二次 clone EAGAIN | RESOURCE_REJECTED / NOT_EXECUTED | RELEASED | PASS | 92719906 (`runs/qualification-01-budgets/2-second_budget.json`, omitted from this source release) |
| 正常执行 | SUCCEEDED / KNOWN | RELEASED | PASS | 6d705f8c (`runs/qualification-01-budgets/3-normal.json`, omitted from this source release) |
| Z 已收 SPAWN，取消后迟到 COMMIT | CANCELLED / NOT_EXECUTED | RELEASED | PASS | fdbd2941 (`runs/qualification-01-cancels/0-cancel_queued.json`, omitted from this source release) |
| W 已降权，业务前取消 | CANCELLED / NOT_EXECUTED | RELEASED | PASS | 1e3ad3b0 (`runs/qualification-01-cancels/1-cancel_before_business.json`, omitted from this source release) |
| S 已进入，创建 W 前取消 | CANCELLED / NOT_EXECUTED | RELEASED | PASS | fa0df09e (`runs/qualification-01-cancels/2-cancel_during_entry.json`, omitted from this source release) |
| 执行中两次取消＋终态重复取消 | CANCELLED / KNOWN | RELEASED | PASS | 125ebdee (`runs/qualification-01-cancels/3-double_cancel.json`, omitted from this source release) |
| 超时 | TIMED_OUT / KNOWN | RELEASED | PASS | c165841f (`runs/qualification-01-cancels/4-timeout.json`, omitted from this source release) |
| 撤销确认丢失，保守停止 Z | CANCELLED / NOT_EXECUTED | RELEASED | PASS | 70b35369 (`runs/qualification-01-cancels/5-revoke_ack_loss.json`, omitted from this source release) |
| 正常执行 | SUCCEEDED / KNOWN | RELEASED | PASS | 3476987a (`runs/qualification-01-cancels/6-normal.json`, omitted from this source release) |
| 正常执行 | SUCCEEDED / KNOWN | RELEASED | PASS | c64fb814 (`runs/qualification-01-control/0-normal.json`, omitted from this source release) |
| 正常执行 | SUCCEEDED / KNOWN | RELEASED | PASS | 0299be38 (`runs/qualification-01-control/1-normal.json`, omitted from this source release) |
| 业务非零退出 | NONZERO / KNOWN | RELEASED | PASS | eab3239f (`runs/qualification-01-control/2-nonzero.json`, omitted from this source release) |
| 业务期间 Controller SIGKILL | CONTROLLER_LOST / UNKNOWN | RELEASED | PASS | fd104d52 (`runs/qualification-01-controller-death/supervisor.json`, omitted from this source release) |
| S 派生/进入阶段 Controller SIGKILL | CONTROLLER_LOST / UNKNOWN | RELEASED | PASS | b9b4d5ce (`runs/qualification-01-controller-during-entry/supervisor.json`, omitted from this source release) |
| S 创建后 Z 死亡，CREATED 丢失 | TEMPLATE_CHANNEL_LOST / NOT_EXECUTED | RELEASED | PASS | 90b40bf6 (`runs/qualification-01-failures/0-fork_ack_loss.json`, omitted from this source release) |
| Z wait S 后死亡，REAPED 丢失 | TEMPLATE_LOST / KNOWN | RELEASED | PASS | 1eff06d0 (`runs/qualification-01-failures/1-reap_ack_loss.json`, omitted from this source release) |
| 业务期间 Z 死亡 | TEMPLATE_CHANNEL_LOST / KNOWN | RELEASED | PASS | 113423af (`runs/qualification-01-failures/2-zygote_death.json`, omitted from this source release) |
| 目标 PID1 死亡 | DOMAIN_CHANNEL_LOST / KNOWN | RELEASED | PASS | fa73b859 (`runs/qualification-01-failures/3-pid1_death.json`, omitted from this source release) |
| S 控制通道断开 | STATUS_CHANNEL_LOST / NOT_EXECUTED | RELEASED | PASS | ec62ca36 (`runs/qualification-01-failures/4-control_eof.json`, omitted from this source release) |
| 正常执行 | SUCCEEDED / KNOWN | RELEASED | PASS | bfdf0b55 (`runs/qualification-01-failures/5-normal.json`, omitted from this source release) |
| 只丢 CREATED，Z 健康 | SUCCEEDED / KNOWN | RELEASED | PASS | af61c0fb (`runs/qualification-01-receipts/0-created_drop.json`, omitted from this source release) |
| 只丢 REAPED，Z 健康 | SUCCEEDED / KNOWN | RELEASED | PASS | 67c8084f (`runs/qualification-01-receipts/1-reaped_drop.json`, omitted from this source release) |
| 业务有副作用，丢业务 wait 回执 | RESULT_UNKNOWN / UNKNOWN | RELEASED | PASS | 76c3ce94 (`runs/qualification-01-receipts/2-result_loss_side_effect.json`, omitted from this source release) |
| 正常执行 | SUCCEEDED / KNOWN | RELEASED | PASS | d6a02fb2 (`runs/qualification-01-receipts/3-normal.json`, omitted from this source release) |

KNOWN 仅表示拿到真实进程退出状态，不保证业务无部分副作用。NOT_EXECUTED 由未发业务许可/明确未创建证明；UNKNOWN 不用结果文件代替退出证据。Controller 死亡时保留的 attempt 日志是中途快照，最终资源结论以 Supervisor 为准。

## 按会话的独立证据检查

| 会话 | 请求数 | 检查数 | 判定 |
|---|---:|---:|---|
| qualification-01-budgets (`analysis/qualification-01-budgets.json`, omitted from this source release) | 4 | 117 | PASS |
| qualification-01-cancels (`analysis/qualification-01-cancels.json`, omitted from this source release) | 7 | 178 | PASS |
| qualification-01-control (`analysis/qualification-01-control.json`, omitted from this source release) | 3 | 110 | PASS |
| qualification-01-controller-death (`analysis/qualification-01-controller-death.json`, omitted from this source release) | 1 | 69 | PASS |
| qualification-01-controller-during-entry (`analysis/qualification-01-controller-during-entry.json`, omitted from this source release) | 1 | 61 | PASS |
| qualification-01-failures (`analysis/qualification-01-failures.json`, omitted from this source release) | 6 | 165 | PASS |
| qualification-01-receipts (`analysis/qualification-01-receipts.json`, omitted from this source release) | 4 | 135 | PASS |

共 835 项检查包含大量重复安全/完整性核验，不是 835 个独立故障样本或可靠性概率。全部 trace per-CPU overrun/drop 为 0；136 个产品监督树进程均有 exit 记录，回收另由真实 wait/收养及域空删除证明。

## 开发期失败照实保留

| 批次 | 判定 | 发生了什么 | 后续 |
|---|---|---|---|
| pilot-receipts-01 (`runs/pilot-receipts-01/controller-failure.json`, omitted from this source release) | FAIL | DRAINED 仍在排队，Controller 提前判完整并曾发送 RETIRE/SUCCEEDED，后资格断言失败 | 修正完成条件与确认顺序；pilot-receipts-02、正式 receipts 通过 |
| pilot-failures-01 (`runs/pilot-failures-01/controller-failure.json`, omitted from this source release) | FAIL | QUERY 与 Z 死亡竞争产生 BrokenPipe，Controller 整体异常 | 捕获控制发送失败并转逐请求回收；pilot-failures-02、正式 failures 通过 |

上述两批 Supervisor 的清理成功不能覆盖测试失败。其余 pilot 分析均保留在 analysis/，与最终固定版本分开，不合并成正式通过数。

## 未覆盖

内存 OOM、Supervisor 自身死亡、宿主重启、不可中断睡眠、日志磁盘故障、并发接纳、长期/PID 重用压力：未运行，不给 PASS。参见 剩余风险 (`06-remaining-risks.md`, omitted from this source release)。
