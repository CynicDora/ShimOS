# 检查点 A：基线职责、单次派生候选与下一步决策材料

日期：2026-10-20。**本轮没有新运行实验。** 已完成真实源码、旧资格/身份、成本 CSV、冻结 Linux 接口的交叉检查。原始输入保持只读，完整研究未到检查点 B/C。

## 已查清的关键事实

1. **S 不只是 setns 工具。** 它是一次性权限转换主体，执行 root/cwd 与 FD 处理，第二次派生前降权；还持有 W 门禁、pidfd，真实 wait W 并回报结果。删除它需要转移这些职责。
2. **Linux 的 PID 规则并不普遍要求两次 fork。** active PID namespace 不变的父，在权限成立时可以选择后代 `pid_for_children`，派生后换目标或恢复；W 自身的 active PID namespace 仍不可迁移。
3. **当前 Z 的权限不满足直接方案。** 旧原始日志中 Z 的 CapEff/Prm=0；单独设置 PID namespace 时，内核同时检查当前与目标 owner userns。仅有后代域管理资格不够。预期 EPERM 是静态推导，尚未运行探针；联合切换 userns 另有检查顺序，但会改变 Z 身份，不能当作保持原身份的替代。
4. **现有完整协议也不能直接删 S。** `s_state`、两级预算拒绝、START_WORKER、WAITED/REAPED 与真实收养责任都会变化。用户明确要求此类变动先提交分析，因此没有实施。
5. **存在局部成本预算，尚无完整净收益。** 旧 NumPy 8/32/128 MiB 的 S 父侧 libc wrapper 中位数约0.565/0.564/0.686ms；含 Python hooks 的完整 bridge 为1.349/1.381/1.458ms，后者包含前者。没有单独消除S的合格对照，不能把这些数相加或预测端到端加速。

完整证据见 基线 (`../01_baseline_audit.md`, omitted from this source release)、用户态条件 (`../02_userspace_feasibility.md`, omitted from this source release)、逐函数职责 (`../baseline_audit/source-responsibilities.md`, omitted from this source release)、成本摘要 (`../baseline_audit/cost-evidence.md`, omitted from this source release)、冻结内核分析 (`../userspace_poc/linux-interface-review.md`, omitted from this source release)。

## 候选及需由用户决定的边界

|路线|已有支持|尚缺什么|本次处理|
|---|---|---|---|
|保留 Z→S→W|已有受限资格，完整派生、门禁、wait 与回收证据|S 可消除净成本仍未知|保留，不改历史|
|原身份直接 Z→W|PID 选择语义支持，但当前权限检查阻碍|需要真实权限负例；不能私加 U0 capability|不实施完整候选|
|共同管理 userns 下的用户态 Z→W|存在清晰的有条件 namespace 关系|启动拓扑、可信能力范围、主协议及新资格|仅提出条件，待批准研究|
|未来 clone3 目标 PID ns FD 接口|可能避免修改父的 children 选择状态|权限仍需解释；没有必要性/性能/上游结论|不写补丁、不切换路线|

## 下一步最小验证建议

优先考虑两个互相独立、不得混为资格的测试包：

- **冻结合同的负例确认**：在原私有 VM、原身份下，记录直接 PID setns 的错误码与前后 namespace/capability，保证目标域正常释放。它可以验证阻碍，不需要新协议或更高 Z 权限。
- **独立权限语义诊断（需明确同意该范围）**：在临时管理 userns 中验证选择两个已有目标 PID namespace、恢复、完整 wrapper、内存继承与真实 wait。它只是机制诊断，不是当前 ShimOS 等价安全通过。

若之后考虑完整用户态 Z→W，还需先同意启动拓扑/协议变更，再补齐六 namespace、root/cwd、FD、callbacks、授权、取消、R/Z/PID1故障、H接管和预算拒绝资格。只有达到声明合同，才进行少量8/32/128MiB与重叠Worker成本对照。没有批准就不进入该实现。

## 对本阶段研究问题的回答

- **RQ1**：S 的职责已逐项查清；一次 wrapper、S 本身及部分中转可能消失，入域、安全、授权、真实退出和回收责任仍存在。
- **RQ2**：一般 Linux 接口有条件可行；冻结 Z 凭据下直接入口被阻碍，完整候选尚未运行。
- **RQ3**：尚不能认定需要内核扩展；若新接口保留同样权限要求，也不会自动解决当前 Z 的问题。完整必要性和 SOCK 审计尚未开展。
- **RQ4**：旧数据给出局部毫秒级预算；端到端净节省、CPU/PSS/COW及吞吐变化均未知。
- **RQ5**：没有证据表明单次派生已改变 G2/G3 交叉点或资源组织选择。旧架构对比不能代替这项消融。

按任务中的检查点 A 和“涉及主协议/不可逆权限变更先停止实现”的约束，下一步验证范围由用户决定。本报告不作整体路线、最终架构或论文贡献的 Go/No-Go 决定。
