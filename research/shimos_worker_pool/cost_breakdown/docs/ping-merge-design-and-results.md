# 最小 PING 合并：设计、资格与反例

2026-10-19。本节仅研究一次完整请求结束时的状态回执合并。没有改变两次派生、隔离配置、资源归属或 Supervisor 责任，也不提出新的 Worker 调度器。

## 改了什么

原路径在 Z 完成 FORGET 后，R 关闭本地 FD、删除 cgroup/目录，再发 PING 获取模板状态。新路径让 Z 在 FORGET 实际关闭请求引用、删除活动条目后，直接把同样的状态信息放入 FORGOTTEN。R 保存这份快照，仍在本地清理之后的原检查位置验证，然后继续原 validate、H RETIRE 和 response-ready。

因此只少一次 PING/PONG 往返。状态指纹、FD 清单、Z 进程身份、session/nonce、active_attempts=0 检查仍存在。当前 v2 还在原最终检查点用已有 pidfd 检查 Z 是否已经退出。没有把 FORGOTTEN 当成资源已释放，没有将清理移到成功响应之后。源码变更仅为 `ping_merged/run.py`、`ping_merged/zygote.py`；v1 差异见 merge-changes.patch (`../analysis/merge-changes.patch`, omitted from this source release)，v2 补充见 merge-v1-to-v2.patch (`../analysis/merge-v1-to-v2.patch`, omitted from this source release)。

两组对称采用相同的身份检查与计时。原固定正常控制骨架为 25 条消息，合并后为 23 条；周期 QUERY/SNAPSHOT 会额外增加消息，实际请求不能硬计为 23。性能部分应以原始 IPC 记录统计，并把固定骨架与查询消息分开。

## 哪些条件下可以合并

当前模板是可信、单线程、串行执行的自有程序。FORGET 后 Z 只等待下一条请求，不会有独立线程或业务回调继续改变模板状态。R 本地清理不会改变 Z 中的 STATE 或 FD 编号，所以这份现场快照可以在稍后的原检查点使用。

源码复查发现 v1 有一项不能忽略的缺口：Z 在 FORGOTTEN 后死亡，旧快照仍可能被接纳。此项是静态发现，尚未通过 v1 注入复现。v1 已保存，不能按同故障合同进入主要比较。v2 加入较晚的非阻塞 pidfd 退出检查，发现退出就失败并交给 H 回收，而不是把 pidfd 当成 wait。

若未来允许 Z 自主异步执行，或要求任意卡死模板的响应性探测，二者仍不能无条件视为相同。当前 v2 检查已退出的进程，不保证未来存活；旧 PONG 之后也可能死亡。资格不能外推为任意运行时健康证明。

状态指纹只覆盖明确的 STATE，FD 校验继承原有“编号集合相同”合同，不证明整个 heap 干净或每个 FD 的底层对象相同。更强状态隔离不属于本次合并成果。

## 回执和失败如何处理

- FORGET 前提仍为派生许可 SEALED 且 S 为 ABSENT/REAPED。nonce 墓碑保留，迟到 COMMIT 不得创建新进程。
- 同一 attempt 的早先通知可能排在回执之前；R 关闭附带 FD，继续等对应 FORGOTTEN。异 nonce 直接拒绝，含额外 FD 的 FORGOTTEN 关闭 FD 后也必须拒绝。
- 回执丢失不推断成功，也不自动重试业务。R 超时失败，H 继续负责收养/真实 wait、UNKNOWN、EOF 和资源删除。
- R 在收到回执后死亡，H 尚未收到 RETIRE，仍需接管。回执不是提前释放 H 责任的许可。

## 运行前审查

baseline-source-review-notes.md (`baseline-source-review-notes.md`, omitted from this source release) 与 merged-source-review-notes.md (`merged-source-review-notes.md`, omitted from this source release) 保存 v1 审查。merged-source-review-notes-v2.md (`merged-source-review-notes-v2.md`, omitted from this source release) 记录存活窗口及修订。基线正式批次绑定原 variant-source-review.json (`variant-source-review.json`, omitted from this source release)；v2 批次绑定 variant-source-review-v2.json (`variant-source-review-v2.json`, omitted from this source release)。两份审查的 baseline 条目相同，历史记录没有被追改。

准入文件仅表示“允许进行受限回归”，不代表运行已通过。正式结果必须分别通过 `verify_qualification.py` 和 `verify_runtime.py`；反例另用 `verify_counterexamples.py`，不能并入原 29 次资格或正常性能样本。

## 正式资格结果

状态：基线及 v2 合并路径均完成正式资格和加强核验。两组各 8 个独立初始化 VM 会话，每组包括 A 原 26 次/20 场景及 runtime 3 次，共 29 次。相同物理宿主的多个 VM 不是多个独立硬件环境。

| 路径 | 生命周期资格 | 运行时组合资格 | 当前结论 |
|---|---|---|---|
| baseline_instrumented | 8/8 组 PASS，29 次 | 8/8 组 PASS | qualification-cost-baseline-01，受限资格通过 |
| ping_merged v2 | 8/8 组 PASS，29 次 | 8/8 组 PASS | qualification-cost-merged-02，受限资格通过 |

完整索引见 资格及反例矩阵 (`../analysis/qualification-and-counterexample-final-matrix.md`, omitted from this source release)，对应 JSON (`../analysis/qualification-and-counterexample-final-matrix.json`, omitted from this source release) 保留逐 run 报告、SHA 和限制。两组各 23 次请求在完成后检查存活模板；发生模板丢失的请求走原真实 wait/UNKNOWN 路径。runtime 组各有 3 次实际 robust 恢复。所有 run 的源码、五个 C 产物及声明审查版本核对一致；H 接管会话保持 UNKNOWN，所有私有资源最终释放，observer 没有补杀或补清理。

加强后的生命周期检查分别为 1908、1931 项，运行时组合检查分别为 1907、1910 项。检查数量不是独立样本量，不能据此宣称概率可靠性。

### 核验器也发现并修正了一个漏查

初版核验器用整个 session 的 Z wait 记录判断“模板已结束”。正常最终 STOP 总会 wait Z，结果意外跳过了正常请求的 post-forget 检查。这是核验器问题，不能用产品程序已 assert 代替独立核验。

原核验器和原结果已保留。新核验改用该请求在 domain_quiescent 时记录的 wait，排除随后正常 STOP，并核对全局真实 wait 日志。对同一完整原始数据重核，16 个 VM 全部 PASS；合并路径的 23 次 FORGOTTEN 状态、身份、FD 和 pidfd 检查有实际记录支持。权威新结果为 `*-qualification-recheck-v2.json`，汇总在 qualification-recheck-v2-matrix.json (`../analysis/qualification-recheck-v2-matrix.json`, omitted from this source release)，不是覆盖原 PASS 文件。

## 六个反例

| 场景 | 实际注入与验收要求 | 状态 |
|---|---|---|
| 状态污染 | 改变 Z 的实际 STATE 字节，快照必须发现，不能提交成功 | PASS |
| FD 泄漏 | 多保留一个真实 pidfd，快照必须发现额外 FD，H 最终清理 | PASS |
| FORGOTTEN 丢失 | Z 已忘记请求，但回执不发；R 有界失败、H UNKNOWN/真实回收 | 初验 FAIL，严格事件链重核 PASS，原失败保留 |
| 外来/迟到样式回执 | 构造错误 nonce，R 必须拒绝；不是实际历史任务发生率证据 | PASS |
| 回执后 R 死亡 | 收到匹配回执、未本地清理时 SIGKILL，H 不能提前 RETIRE | PASS |
| 回执后 Z 死亡 | 正确回执后 Z 自 SIGKILL；R 的产品 pidfd 检查拒绝，H 真正 wait Z=9 | PASS |

每个场景只覆盖一个可复核时序，不是穷举竞态。核验要求真正注入、没有成功响应、H 真实 wait/ECHILD、EOF、私有资源释放及 observer 没有代替产品补杀。

反例使用 `counterexamples-cost-merged-02-*` 六个独立 VM。权威重核见 counterexample-recheck-v2-matrix.json (`../analysis/counterexample-recheck-v2-matrix.json`, omitted from this source release)。原 58 次资格与 6 次反例分别计数，反例不进入性能样本。

### 为什么保留一次原 FAIL，又给出重核 PASS

FORGOTTEN 丢失时，R 实际在 FORGET 的 recv 超时，`controller-failure.json` 保存 TimeoutError。R 的错误处理先关闭 H 通道，再执行诊断输出和 `_exit(1)`；H 在 EOF 后抢先 SIGKILL 了尚在退出期的 R。因此真正 wait_status 是 9，而初版核验器只允许 256（exit 1）。额外诊断 flush 会延长这个竞争窗口，H 原有保守终止策略没有修改。

重核仅对这个实际观察到的 case，要求确切丢回执、对应 FORGET TimeoutError、EOF→恢复→H_STOP_R→真实 wait=9 顺序，以及没有 DONE/RETIRE/提交、UNKNOWN、ECHILD 和完整回收。不是把任意 9/256 都当成通过。原 FAIL 文件保持原样，重核输出另存。

第六反例的关键原始顺序为：Z 268 发回执 → Z 自 SIGKILL → R 确认 pidfd 可读 → R 的正常产品分支在本地资源删除后拒绝 → H 实际 wait Z=9。R 的错误来自 `template exited before final response validation`，不是测试同步等待失败，说明 v2 的产品检查确实发挥作用。

## 性能解释边界

合并减少一个串行往返，但仍采样一次 STATE/identity，并扩大 FORGOTTEN 的内容。IPC、JSON、同步日志写入和 VM 调度都会影响完整 response-ready；不能从消息数直接推导加速比例，也不能将这项常规协议合并包装为新的沙箱架构。

正式性能尝试使用 4 个 VM，其中 2 个配对完成，各 variant 每 VM 5 次热身、35 次计量。另外两个 VM 分别在 merged 第 12 次和 baseline 第 1 次请求等待 DOMAIN_READY 时超时，均在合并之前；H 正确给出 UNKNOWN 并释放资源。它们是实际运行失败，不能因为故障资格通过就写成所有性能请求成功。完整账本为 173 次尝试、171 次成功最终回执、2 次启动失败；主要成功延迟统计使用两个完整配对的 140 个非热身点。

两配对中正常固定消息确认为 25→23，显式 RPC 4→3；较慢请求另有 QUERY/SNAPSHOT。按每请求计算 FORGET+PING 合计跨度后，基线中位数 1.808/1.705 ms，合并版 FORGET 1.544/1.316 ms，局部缩短 0.264/0.389 ms。完整响应中位数却分别为 150.325→150.932 ms、201.150→173.375 ms，第二 VM 候选的 p90 更差。没有稳定的完整延迟或 CPU 优势证据。详见 [成本分解](cost-breakdown-report.md)、计时扰动对照 (`measurement-overhead.md`, omitted from this source release) 与 下一步判断 (`next-architecture-decision.md`, omitted from this source release)。

正常包数来自保存完整的 R 成功收发记录；失败调用、控制 buffer 被 SIGKILL 截断的记录不能补算。状态检查等价、时钟记录和任意卡死健康探测的限制另见 最终只读审查 (`final-correctness-review.md`, omitted from this source release)。

最终资格结论仅限：固定私有 VM、可信单线程自有模板、串行请求、Supervisor H 正常存活。没有扩展到任意依赖、多请求并发、H 死亡、宿主 OOM、文件系统故障或完整生产保证。
