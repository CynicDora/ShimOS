# 05 — Worker 选择、业务语义与验证范围

本轮选择两个真实应用执行接口，测量**稳定输入、单一信任主体、顺序请求**下应用状态保留的成本。请求数是受控摊销变量；不是自然 Agent 轨迹，也不能代表源码在每轮变化的 coding agent。

| Worker | 实际业务请求 | 冷/热等价性 | 可以保留的状态 | 独立 Oracle |
|---|---|---|---|---|
| Python 3.10.12 + NumPy 2.2.6 | 16,384 个确定性整数的分组归约：总和、平方和、64 桶分组和；请求参数 offset 可变 | A/B/C 同一脚本、NumPy版本、输入、单线程设置、数组构造和结果序列化 | interpreter、NumPy模块/库、数值运行时；不缓存业务结果或请求数组 | 纯 Python 整数循环，逐字段精确相等；无浮点容忍带 |
| clangd 14 + zlib 1.3.1 | 对冻结 adler32.c 调用正式 LSP `textDocument/documentSymbol`，验证5个函数定义及位置、同版本无错误诊断 | 同样 initialize/config/didOpen 与同一源码、编译命令；A/B每请求新进程，C保持相同server与open document | clangd 的AST/preamble/native调度状态；background index关闭 | 独立GCC `-O0` 编译和nm确认5个定义；源码定义位置与SHA单独校验；正式请求逐结果验证 |

## 为什么选择这些操作

**Fact**：NumPy实际执行 `arange`、整数向量运算、`add.at`、归约，不能用空循环或sleep代替；所有请求重新构造数组，复用收益来自真实runtime导入/初始化。该工作负载代表受限数值工具的重复计算，不代表所有Python项目或重训练模型。[NumPy ufunc.at文档](https://numpy.org/doc/stable/reference/generated/numpy.ufunc.at.html)。

**Fact**：clangd本来具有长期JSON-RPC接口，TUScheduler管理最新文件版本、AST和preamble；不是将一次性compiler强行伪装成persistent Worker。用native LSP请求可建立冷/热相同操作，解析结果并非仅看进程存活。[clangd设计](https://clangd.llvm.org/design/code)、[LSP documentSymbol规范](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_documentSymbol)。源码输入来自仓库已有真实zlib版本，未增加人工文件修改或编译循环。

**Inference**：这两个类型能够区分解释器/依赖初始化与语言服务初次解析的成本结构，但只有一个翻译单元，不能外推大型C++项目、全量索引、include更新或跨项目迁移。以真实工具为载体，不等于本轮采集到了真实在线Agent轨迹。

## A/B/C 使用同一应用协议

- A：每个业务请求建立新的Bubblewrap隔离域，在域中启动同样的socket Worker，执行一次业务请求，正常shutdown、严格reap并销毁域。
- B：同一B-strict持久域，逐请求建立独立执行组与相同新Worker；其初始化与正常shutdown完整计费。
- C：同一B-strict域、同一执行组与Worker，顺序执行相同请求；初始化只做一次，所有请求结束后正常shutdown并严格回收。保活PSS、初末成本不免费。

所有A/B/C都使用Unix stream JSONL请求、相同JSON/hash验证；没有将A/B改成更重的CLI业务。外部控制器通过host工作区路径连接同一个socket inode。B-strict业务stdin仍是`/dev/null`，无需改owner或为实验添加特殊stdin能力。socket`0600`仅作同UID连接边界，跨不可信主体不得共享域/Worker。

`experiments/workers/protocol.py`是harness入口：`requests(kind,n)`、`Client.call`、`verify`。`server.py`承担有界应用wrapper，不承担namespace/cgroup/身份调度。主报告应直接引用VM原始数据，不将host smoke作为隔离资格或性能成绩。

## 时间与CPU口径

READY只说明请求协议可接受：NumPy已导入；clangd已initialize并发送didOpen，**不代表初次AST已经建好**。因此分别报告launch→READY、首个有效业务响应、后续有效响应、完整序列含shutdown/域销毁。clangd首请求包含未完成的解析，不能把其转移成免费预热。first byte只是诊断时间，不是有效结果。

服务端script-entry初始化计时不包括Python interpreter进入脚本前的时间；外部launch→READY与全序列覆盖它。server `process_time_ns`只有wrapper CPU，不含clangd子进程；子进程ticks与shutdown wait CPU分别记录；全组cgroup CPU用于对应域成本。不得把重叠CPU相加。PSS只在READY/stats/关闭诊断采样，未插入每次业务请求；整个空闲域还要算owner/monitor/guardian，不能只报NumPy或clangd自身。

## 状态正确性与错误合同

Python只提供固定纯计算，不接受任意Python源码。参数校验在操作前；异常参数返回业务/协议错误后，后续有效请求仍与纯Python Oracle相等。每请求业务数组只存在局部引用；wrapper保留已接受request ID去重集合，该协议元数据随调用数增长，不能称为完全无请求状态；`reset`不是通用Python heap回滚，不能证明任意异常无污染。

clangd只允许冻结源码和固定编译命令。首次及每次请求检查adler32.c、zutil.h、zlib.h、zconf.h SHA；目标部署还要求整个输入runtime/headers只读、无不可信写者。哈希不是TOCTOU解法，真正支持范围来自受保护的输入合同；修改源后返回QUARANTINE且后续业务请求拒绝。本轮不研究reload、局部刷新、后台index正确性或配置改变。错误query不会触发LSP业务；正常query在其后仍必须通过独立Oracle。后端/EOF/I/O异常不能默认复用。

shutdown执行LSP shutdown/exit、wait，必要时记录owned-child kill fallback；fallback不是正常退出成功。socket移除和业务子进程reaped仍不等于域释放；必须等B-strict严格组/域回收。当前协议没有增加新的清理保障，也不把B-strict历史收益归为Worker研究新贡献。

## 已完成的准备与非VM检查

- 原始runtime依赖与源码清单：runtime-manifest.json (`experiments/workers/runtime-manifest.json`, omitted from this source release)，缺库修复后1,230文件；补齐正常部署预编译字节码后共2,342文件、325,787,444字节。pilot03发现NumPy依赖缺失libpthread兼容stub；原清单和失败保留，新清单补齐。实际VM runtime和宿主glibc/loader SHA相同；未覆盖其libc/loader。见runtime修复收据 (`experiments/workers/runtime-repair-after-pilot03.json`, omitted from this source release)。
- host-smoke-01 (`experiments/workers/host-smoke-01/events.json`, omitted from this source release)：两个实际应用的valid→error→valid、reset、stats、ping、shutdown均通过；仅host functionality。
- GCC/nm独立Oracle (`experiments/workers/host-smoke-01/compiler-oracle.json`, omitted from this source release)：实际编译成功、5个函数定义匹配。
- 11项最终源码测试 (`experiments/workers/unit-tests-v2.stderr`, omitted from this source release)：含受控源修改后QUARANTINE；该修改不进入性能序列。
- 私有VM正式数据由主harness独立采集：formal01/02主成本108个序列、resources01资源6个、layout01布局6个，共804个业务请求，均通过精确业务Oracle及最终释放校验；见[06](06-benchmark-results.md)和严格分析 (`analysis/final03/summary.json`, omitted from this source release)。qualify02验证参数错误/未知操作后有效请求，以及实际B-strict取消后新Worker正确重试；这不等于任意异常的heap污染已被验证。

## 暂不覆盖

不同信任任务共享heap；并行请求；大型项目索引；不同依赖版本；源变化刷新；NumPy/BLAS任意后台线程；用户定义插件；真实在线Agent自然调用频率；预测keepalive；跨域Worker迁移。缺失这些证据不影响当前固定输入成本测量，但限制未来布局/保活策略的适用范围。

## 源码编译偏差控制

pilot04初始runtime没有stdlib/NumPy pyc，每次fresh进程会重新编译导入源码；不能把这个可避免部署成本包装成保留Worker的必然收益。正式前用相同Python3.10.12生成1112个CHECKED_HASH pyc，所有A/B/C同等使用，并验证实际guest `.py` SHA。`bytecode-preparation.json`完整计费一次准备wall3.913s、CPU2.693s及15.31MB额外字节码。pilot04只作source-only敏感度，后续正常预编译cohort单独统计。主脚本server.py的每次编译仍属于当前wrapper成本，不将其全部归到NumPy或clangd。
