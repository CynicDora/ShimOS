# 最终资格证据索引

自动从冻结结果读取；PASS 表示符合该故障的验收条件，不表示所有业务都成功。

| VM 会话 | 尝试数 | 生命周期检查 | 运行时检查 | 快照 | robust 恢复 | 结果 |
|---|---:|---:|---:|---:|---:|---|
| control (`../runs/qualification-ab-02-control/`, omitted from this source release) | 3 | 185 (`qualification-ab-02-control.json`, omitted from this source release) | 233 (`qualification-ab-02-control-runtime.json`, omitted from this source release) | 28 | 0 | PASS |
| budgets (`../runs/qualification-ab-02-budgets/`, omitted from this source release) | 4 | 194 (`qualification-ab-02-budgets.json`, omitted from this source release) | 222 (`qualification-ab-02-budgets-runtime.json`, omitted from this source release) | 27 | 0 | PASS |
| receipts (`../runs/qualification-ab-02-receipts/`, omitted from this source release) | 4 | 212 (`qualification-ab-02-receipts.json`, omitted from this source release) | 312 (`qualification-ab-02-receipts-runtime.json`, omitted from this source release) | 37 | 0 | PASS |
| cancels (`../runs/qualification-ab-02-cancels/`, omitted from this source release) | 7 | 282 (`qualification-ab-02-cancels.json`, omitted from this source release) | 390 (`qualification-ab-02-cancels-runtime.json`, omitted from this source release) | 49 | 0 | PASS |
| failures (`../runs/qualification-ab-02-failures/`, omitted from this source release) | 6 | 309 (`qualification-ab-02-failures.json`, omitted from this source release) | 374 (`qualification-ab-02-failures-runtime.json`, omitted from this source release) | 47 | 0 | PASS |
| controller_death (`../runs/qualification-ab-02-controller-death/`, omitted from this source release) | 1 | 139 (`qualification-ab-02-controller-death.json`, omitted from this source release) | 78 (`qualification-ab-02-controller-death-runtime.json`, omitted from this source release) | 9 | 0 | PASS |
| controller_during_entry (`../runs/qualification-ab-02-controller-during-entry/`, omitted from this source release) | 1 | 131 (`qualification-ab-02-controller-during-entry.json`, omitted from this source release) | 42 (`qualification-ab-02-controller-during-entry-runtime.json`, omitted from this source release) | 5 | 0 | PASS |
| runtime (`../runs/qualification-ab-02-runtime/`, omitted from this source release) | 3 | 185 (`qualification-ab-02-runtime.json`, omitted from this source release) | 240 (`qualification-ab-02-runtime-runtime.json`, omitted from this source release) | 28 | 3 | PASS |

| 组别/用例 | 结果 | 业务知识 | 资源 | 资格 | 原始证据 |
|---|---|---|---|---|---|
| A_regression / normal | SUCCEEDED | KNOWN | RELEASED | PASS | c347ce9a (`../runs/qualification-ab-02-control/0-normal.json`, omitted from this source release) |
| A_regression / normal | SUCCEEDED | KNOWN | RELEASED | PASS | 7f76b137 (`../runs/qualification-ab-02-control/1-normal.json`, omitted from this source release) |
| A_regression / nonzero | NONZERO | KNOWN | RELEASED | PASS | 19f90ec0 (`../runs/qualification-ab-02-control/2-nonzero.json`, omitted from this source release) |
| A_regression / pid_budget | RESOURCE_REJECTED | NOT_EXECUTED | RELEASED | PASS | bfdaea8c (`../runs/qualification-ab-02-budgets/0-pid_budget.json`, omitted from this source release) |
| A_regression / normal | SUCCEEDED | KNOWN | RELEASED | PASS | dd8a63a7 (`../runs/qualification-ab-02-budgets/1-normal.json`, omitted from this source release) |
| A_regression / second_budget | RESOURCE_REJECTED | NOT_EXECUTED | RELEASED | PASS | 85cda860 (`../runs/qualification-ab-02-budgets/2-second_budget.json`, omitted from this source release) |
| A_regression / normal | SUCCEEDED | KNOWN | RELEASED | PASS | b03c5fcd (`../runs/qualification-ab-02-budgets/3-normal.json`, omitted from this source release) |
| A_regression / created_drop | SUCCEEDED | KNOWN | RELEASED | PASS | 2365ee26 (`../runs/qualification-ab-02-receipts/0-created_drop.json`, omitted from this source release) |
| A_regression / reaped_drop | SUCCEEDED | KNOWN | RELEASED | PASS | 88b50716 (`../runs/qualification-ab-02-receipts/1-reaped_drop.json`, omitted from this source release) |
| A_regression / result_loss_side_effect | RESULT_UNKNOWN | UNKNOWN | RELEASED | PASS | 7314b107 (`../runs/qualification-ab-02-receipts/2-result_loss_side_effect.json`, omitted from this source release) |
| A_regression / normal | SUCCEEDED | KNOWN | RELEASED | PASS | 8fddd6d1 (`../runs/qualification-ab-02-receipts/3-normal.json`, omitted from this source release) |
| A_regression / cancel_queued | CANCELLED | NOT_EXECUTED | RELEASED | PASS | a72593ea (`../runs/qualification-ab-02-cancels/0-cancel_queued.json`, omitted from this source release) |
| A_regression / cancel_before_business | CANCELLED | NOT_EXECUTED | RELEASED | PASS | 6dc42b79 (`../runs/qualification-ab-02-cancels/1-cancel_before_business.json`, omitted from this source release) |
| A_regression / cancel_during_entry | CANCELLED | NOT_EXECUTED | RELEASED | PASS | 83f121bd (`../runs/qualification-ab-02-cancels/2-cancel_during_entry.json`, omitted from this source release) |
| A_regression / double_cancel | CANCELLED | KNOWN | RELEASED | PASS | cff551e1 (`../runs/qualification-ab-02-cancels/3-double_cancel.json`, omitted from this source release) |
| A_regression / timeout | TIMED_OUT | KNOWN | RELEASED | PASS | 964a318f (`../runs/qualification-ab-02-cancels/4-timeout.json`, omitted from this source release) |
| A_regression / revoke_ack_loss | CANCELLED | NOT_EXECUTED | RELEASED | PASS | 5816b3eb (`../runs/qualification-ab-02-cancels/5-revoke_ack_loss.json`, omitted from this source release) |
| A_regression / normal | SUCCEEDED | KNOWN | RELEASED | PASS | c8870c72 (`../runs/qualification-ab-02-cancels/6-normal.json`, omitted from this source release) |
| A_regression / fork_ack_loss | TEMPLATE_CHANNEL_LOST | NOT_EXECUTED | RELEASED | PASS | c22a86d3 (`../runs/qualification-ab-02-failures/0-fork_ack_loss.json`, omitted from this source release) |
| A_regression / reap_ack_loss | TEMPLATE_LOST | KNOWN | RELEASED | PASS | 79dee8c5 (`../runs/qualification-ab-02-failures/1-reap_ack_loss.json`, omitted from this source release) |
| A_regression / zygote_death | TEMPLATE_CHANNEL_LOST | KNOWN | RELEASED | PASS | 4df2c07e (`../runs/qualification-ab-02-failures/2-zygote_death.json`, omitted from this source release) |
| A_regression / pid1_death | DOMAIN_CHANNEL_LOST | KNOWN | RELEASED | PASS | 0ed4152c (`../runs/qualification-ab-02-failures/3-pid1_death.json`, omitted from this source release) |
| A_regression / control_eof | STATUS_CHANNEL_LOST | NOT_EXECUTED | RELEASED | PASS | 7e788737 (`../runs/qualification-ab-02-failures/4-control_eof.json`, omitted from this source release) |
| A_regression / normal | SUCCEEDED | KNOWN | RELEASED | PASS | 09811ccd (`../runs/qualification-ab-02-failures/5-normal.json`, omitted from this source release) |
| A_regression / controller_death | CONTROLLER_LOST | UNKNOWN | RELEASED | PASS | 5c7b19d9 (`../runs/qualification-ab-02-controller-death/supervisor.json`, omitted from this source release) |
| A_regression / controller_during_entry | CONTROLLER_LOST | UNKNOWN | RELEASED | PASS | 2feb9ea8 (`../runs/qualification-ab-02-controller-during-entry/supervisor.json`, omitted from this source release) |
| runtime_combination / normal | SUCCEEDED | KNOWN | RELEASED | PASS | ef8eb170 (`../runs/qualification-ab-02-runtime/0-normal.json`, omitted from this source release) |
| runtime_combination / normal | SUCCEEDED | KNOWN | RELEASED | PASS | 26d5342f (`../runs/qualification-ab-02-runtime/1-normal.json`, omitted from this source release) |
| runtime_combination / nonzero | NONZERO | KNOWN | RELEASED | PASS | 74c08e60 (`../runs/qualification-ab-02-runtime/2-nonzero.json`, omitted from this source release) |
