# 06 — 最小成本实验结果（由原始数据生成）

输入分析：`/path/to/research-host/shimos-linux-native-mvp/research/shimos_worker_pool/analysis/final03/summary.json`。共120个完成序列、804个业务请求；cohort分布`{'cost': 108, 'layout': 6, 'resources': 6}`。完整原始记录没有按速度过滤；显式失败run保存在summary.failures，未拼入成功性能分布。

这些是同一物理宿主上的独立VM初始化，非独立硬件、非在线Agent。请求数为受控摊销变量。CPU/缓存/输入合同见run config。无生产p95/p99结论。

## 完整序列与CPU

表中每列先按单个序列计算，再取中位。controller CPU和managed域CPU的列中位数不可直接相加得到合计中位；合计先在各序列内相加，再取中位。阶段与配对表也保留相同计算顺序。

| Worker | 请求数 | 策略 | 序列样本 | VM | 总wall ms | controller CPU ms | managed域CPU ms | 不重叠CPU合计ms |
|---|---|---|---|---|---|---|---|---|
| clangd | 1 | A | 6 | 8,9 | 141.030 | 6.162 | 135.956 | 141.479 |
| clangd | 1 | B | 6 | 8,9 | 148.474 | 8.878 | 139.391 | 147.094 |
| clangd | 1 | C | 6 | 8,9 | 144.278 | 11.177 | 134.193 | 145.354 |
| clangd | 16 | A | 6 | 8,9 | 2331.212 | 86.379 | 2263.138 | 2349.517 |
| clangd | 16 | B | 6 | 8,9 | 2261.728 | 58.194 | 2239.518 | 2292.538 |
| clangd | 16 | C | 6 | 8,9 | 182.166 | 18.257 | 166.046 | 184.302 |
| clangd | 4 | A | 6 | 8,9 | 699.781 | 32.013 | 689.838 | 719.597 |
| clangd | 4 | B | 6 | 8,9 | 643.113 | 22.831 | 635.533 | 656.904 |
| clangd | 4 | C | 6 | 8,9 | 177.554 | 14.174 | 169.471 | 181.792 |
| numpy | 1 | A | 6 | 8,9 | 150.550 | 14.699 | 136.074 | 150.878 |
| numpy | 1 | B | 6 | 8,9 | 142.224 | 18.434 | 126.133 | 140.554 |
| numpy | 1 | C | 6 | 8,9 | 145.303 | 17.002 | 127.157 | 143.368 |
| numpy | 16 | A | 6 | 8,9 | 2204.586 | 217.684 | 1987.271 | 2209.002 |
| numpy | 16 | B | 6 | 8,9 | 2052.968 | 178.210 | 1884.586 | 2057.103 |
| numpy | 16 | C | 6 | 8,9 | 221.782 | 82.126 | 137.846 | 220.000 |
| numpy | 4 | A | 6 | 8,9 | 560.633 | 56.848 | 506.589 | 561.724 |
| numpy | 4 | B | 6 | 8,9 | 555.406 | 51.480 | 502.216 | 554.620 |
| numpy | 4 | C | 6 | 8,9 | 163.325 | 30.342 | 129.856 | 161.708 |

A逐请求新域+新进程；B持久B-strict域+逐请求新进程；C持久域+同Worker。总wall含READY/self-report PSS（主cohort没有root observer）、三次ping、末尾stats、独立Oracle、正常shutdown与严格释放；不含VM启动、runtime分发及最后原始JSON归档。A−B是既有持久域组合的价值，不是本轮新贡献。B−C包含应用状态与减少group/进程生命周期成本，不能全归因于NumPy import或AST。

## 同block配对差值

正值表示后一策略更低的完整耗时；范围保留负样本，按VM分别报告。小样本不支持生产尾延迟或独立机器推广。

| Worker | n | 前−后 | 配对数 | 中位节省ms | 范围ms | 正对数 | 各VM中位ms |
|---|---|---|---|---|---|---|---|
| clangd | 1 | A-B | 6 | -9.766 | [-18.232, -4.431] | 0/6 | VM8: -10.547; VM9: -8.985 |
| clangd | 1 | A-C | 6 | -5.463 | [-9.550, 7.261] | 1/6 | VM8: -8.764; VM9: -3.314 |
| clangd | 1 | B-C | 6 | 4.490 | [-2.850, 16.767] | 5/6 | VM8: 1.782; VM9: 5.671 |
| clangd | 4 | A-B | 6 | 44.513 | [-13.820, 92.020] | 5/6 | VM8: 40.081; VM9: 48.944 |
| clangd | 4 | A-C | 6 | 515.951 | [375.014, 599.168] | 6/6 | VM8: 594.524; VM9: 447.527 |
| clangd | 4 | B-C | 6 | 462.133 | [355.506, 554.443] | 6/6 | VM8: 545.542; VM9: 386.207 |
| clangd | 16 | A-B | 6 | 34.575 | [-78.487, 202.141] | 4/6 | VM8: 26.016; VM9: 43.134 |
| clangd | 16 | A-C | 6 | 2161.439 | [1922.549, 2983.155] | 6/6 | VM8: 2837.275; VM9: 1977.930 |
| clangd | 16 | B-C | 6 | 2094.605 | [1934.797, 2915.763] | 6/6 | VM8: 2781.014; VM9: 1940.934 |
| numpy | 1 | A-B | 6 | -3.652 | [-12.142, 18.973] | 1/6 | VM8: -2.226; VM9: -4.534 |
| numpy | 1 | A-C | 6 | -1.737 | [-12.547, 13.677] | 2/6 | VM8: -0.291; VM9: -4.113 |
| numpy | 1 | B-C | 6 | -0.681 | [-5.296, 7.125] | 2/6 | VM8: -0.957; VM9: -0.405 |
| numpy | 4 | A-B | 6 | 16.691 | [-29.745, 48.980] | 4/6 | VM8: -0.853; VM9: 21.672 |
| numpy | 4 | A-C | 6 | 393.802 | [362.414, 511.323] | 6/6 | VM8: 407.509; VM9: 380.095 |
| numpy | 4 | B-C | 6 | 387.852 | [333.344, 489.650] | 6/6 | VM8: 407.318; VM9: 368.386 |
| numpy | 16 | A-B | 6 | 163.353 | [-451.531, 383.693] | 5/6 | VM8: 202.823; VM9: 96.496 |
| numpy | 16 | A-C | 6 | 1982.245 | [1872.001, 2220.443] | 6/6 | VM8: 2023.617; VM9: 1919.156 |
| numpy | 16 | B-C | 6 | 1829.706 | [1774.624, 2323.532] | 6/6 | VM8: 1836.751; VM9: 1822.660 |


## 阶段诊断

| Worker | n | 策略 | 域constructor ms | launch→READY总ms | script init总ms | dependency init总ms | 首业务响应ms | C后续响应中位ms | 关闭→释放总ms | ping中位ms |
|---|---|---|---|---|---|---|---|---|---|---|
| clangd | 1 | A | Unknown | 80.585 | 53.229 | 25.799 | 40.028 | Unknown | 21.121 | 0.236 |
| clangd | 1 | B | 7.966 | 72.598 | 53.159 | 25.561 | 39.809 | Unknown | 22.901 | 0.211 |
| clangd | 1 | C | 8.611 | 67.813 | 49.098 | 21.894 | 40.060 | Unknown | 19.778 | 0.225 |
| clangd | 16 | A | Unknown | 1278.370 | 848.098 | 399.629 | 43.439 | Unknown | 374.658 | 0.153 |
| clangd | 16 | B | 9.402 | 1229.762 | 887.741 | 437.386 | 41.926 | Unknown | 352.081 | 0.191 |
| clangd | 16 | C | 10.319 | 80.367 | 59.377 | 30.032 | 42.330 | 0.776 | 22.234 | 0.237 |
| clangd | 4 | A | Unknown | 401.055 | 271.071 | 148.370 | 42.808 | Unknown | 102.935 | 0.253 |
| clangd | 4 | B | 10.114 | 354.981 | 268.583 | 144.952 | 45.302 | Unknown | 90.017 | 0.127 |
| clangd | 4 | C | 9.708 | 90.222 | 68.251 | 37.341 | 43.233 | 1.126 | 24.081 | 0.204 |
| numpy | 1 | A | Unknown | 113.536 | 86.949 | 58.485 | 1.254 | Unknown | 23.380 | 0.115 |
| numpy | 1 | B | 9.456 | 98.663 | 80.744 | 54.353 | 1.011 | Unknown | 22.331 | 0.122 |
| numpy | 1 | C | 11.019 | 99.844 | 80.880 | 54.483 | 1.023 | Unknown | 20.562 | 0.117 |
| numpy | 16 | A | Unknown | 1692.062 | 1274.051 | 849.901 | 1.025 | Unknown | 349.032 | 0.132 |
| numpy | 16 | B | 7.980 | 1584.913 | 1293.863 | 865.029 | 1.079 | Unknown | 296.174 | 0.102 |
| numpy | 16 | C | 9.016 | 96.839 | 78.110 | 52.197 | 0.999 | 0.993 | 20.493 | 0.122 |
| numpy | 4 | A | Unknown | 432.428 | 323.622 | 217.986 | 1.004 | Unknown | 87.766 | 0.133 |
| numpy | 4 | B | 9.588 | 417.444 | 333.796 | 224.996 | 0.989 | Unknown | 82.857 | 0.127 |
| numpy | 4 | C | 9.146 | 101.403 | 81.326 | 54.813 | 1.033 | 0.996 | 21.129 | 0.117 |

域constructor与domain-ready嵌套；launch→READY包含script/dependency init；业务请求server时间嵌套于IPC+execution；不能把表格所有列相加。A的launch→READY还包含逐请求域创建，B/C的该字段仅group+Worker。clangd READY尚未保证初次AST结束，初次解析由首业务响应承担。脚本计时不覆盖进入Python脚本前的解释器启动。ping包含Python/json/socket处理，不是纯内核IPC延迟。

## 初始化 CPU、独立验证与归档开销

| Worker | 策略(n=1) | launch→首个Oracle有效响应ms | script init wrapper CPU ms | dependency init wrapper CPU ms | READY业务组/Raw域累计CPU ms |
|---|---|---|---|---|---|
| clangd | A | 116.473 | 27.722 | 0.756 | 81.753 |
| clangd | B | 111.407 | 28.090 | 0.832 | 74.528 |
| clangd | C | 109.996 | 27.853 | 0.735 | 70.582 |
| numpy | A | 124.580 | 86.737 | 58.372 | 111.744 |
| numpy | B | 107.178 | 80.688 | 54.342 | 97.772 |
| numpy | C | 110.497 | 80.820 | 54.455 | 98.657 |

B/C最后一列读取业务叶cgroup，包含wrapper与clangd，guardian在独立control叶；A读取Raw域，含monitor/域准备。它们不是同一个纯应用初始化CPU边界。clangd dependency CPU是wrapper自身，不含clangd child。主CPU总账使用完整受控域递归计数，与controller SELF相加，绝不再叠加本表。

| Worker | n | 策略 | server业务wall总ms | server wrapper CPU总ms | Oracle wall总ms | Oracle CPU总ms | 域释放→close返回审计ms |
|---|---|---|---|---|---|---|---|
| clangd | 1 | A | 39.788 | 0.855 | 1.152 | 1.151 | Unknown |
| clangd | 1 | B | 39.559 | 1.000 | 0.655 | 0.654 | 2.306 |
| clangd | 1 | C | 39.722 | 0.891 | 1.098 | 1.097 | 2.866 |
| clangd | 16 | A | 650.825 | 14.365 | 16.417 | 16.396 | Unknown |
| clangd | 16 | B | 686.858 | 15.334 | 12.187 | 12.168 | 5.217 |
| clangd | 16 | C | 53.052 | 8.537 | 7.638 | 7.635 | 2.767 |
| clangd | 4 | A | 182.052 | 5.133 | 5.090 | 5.085 | Unknown |
| clangd | 4 | B | 168.035 | 4.735 | 3.360 | 3.350 | 3.513 |
| clangd | 4 | C | 44.949 | 3.601 | 2.949 | 2.949 | 2.594 |
| numpy | 1 | A | 0.899 | 0.899 | 7.766 | 7.763 | Unknown |
| numpy | 1 | B | 0.721 | 0.721 | 7.755 | 7.751 | 2.807 |
| numpy | 1 | C | 0.717 | 0.717 | 8.021 | 7.986 | 2.407 |
| numpy | 16 | A | 11.028 | 11.030 | 132.124 | 132.062 | Unknown |
| numpy | 16 | B | 11.422 | 11.424 | 133.049 | 133.001 | 5.484 |
| numpy | 16 | C | 13.847 | 13.850 | 72.489 | 72.486 | 2.422 |
| numpy | 4 | A | 2.925 | 2.925 | 35.176 | 35.164 | Unknown |
| numpy | 4 | B | 3.111 | 3.112 | 32.926 | 32.919 | 3.062 |
| numpy | 4 | C | 3.237 | 3.237 | 20.925 | 20.922 | 2.707 |

独立纯Python Oracle在NumPy热请求中可能高于数值业务本身；它是本轮完整验证合同的真实成本，不是Worker的固有业务成本。所有A/B/C都执行相同Oracle，未从主wall扣除。Task.close在域释放后仍写原基线审计JSON；表中最后一列测到这一返回跨度（含微量调用返回），完整wall保留。A的Raw路径归档方式不同，因此小幅A−B差不能归为纯namespace成本；关闭→释放列只计group release与Task域release；release→return审计另列，仍计入主sequence wall。

## 内存诊断独立cohort

| Worker | n | 策略 | 样本 | 空域PSS KiB | 热域PSS KiB | 末域PSS KiB | app wrapper+worker PSS KiB | worker自身PSS KiB | observer CPU ms |
|---|---|---|---|---|---|---|---|---|---|
| clangd | 4 | A | 1 | Unknown | 106908.000 | 107492.000 | 105272.000 | 92758.000 | 8.095 |
| clangd | 4 | B | 1 | 2896.000 | 107998.000 | 108551.000 | 105631.000 | 93184.000 | 25.667 |
| clangd | 4 | C | 1 | 2900.000 | 107459.000 | 107471.000 | 104543.000 | 92162.000 | 16.744 |
| numpy | 4 | A | 1 | Unknown | 30517.000 | 30819.000 | 28595.000 | 28595.000 | 9.513 |
| numpy | 4 | B | 1 | 2892.000 | 31219.000 | 31361.000 | 28445.000 | 28445.000 | 20.082 |
| numpy | 4 | C | 1 | 2896.000 | 31245.000 | 31249.000 | 28329.000 | 28329.000 | 19.018 |

PSS不是RSS或峰值。任何root observer缺字段/身份不稳定就标Unknown，不把部分和当全量。NumPy wrapper与Worker同一PID只计一次；clangd应用PSS包括wrapper与真实clangd子进程；域PSS还包括控制程序。observer CPU独立披露，没有加到controller+managed域后再重复计数。不同cohort的latency不能与无observer主成绩混排。

### 保留成本的当前截面

| Worker(C,N4,1样本) | 空域MiB | app wrapper+worker MiB | 热完整域MiB | 首业务后→末业务后域PSS变化KiB |
|---|---|---|---|---|
| clangd | 2.832 | 102.093 | 104.940 | 12.000 |
| numpy | 2.828 | 27.665 | 30.513 | 4.000 |

末值差只是四请求截面，不能证明长期无泄漏；A/B首末观测来自不同业务进程，更不能当同一heap增长。PSS反映共享页比例，不能用单独Worker PSS加空域PSS预测混合布局总量。

## 静态布局机制敏感度

| shared域 | 域数 | 样本 | 完整wall ms | 测得CPU ms | 总idle PSS KiB | idle进程数 | observer CPU ms |
|---|---|---|---|---|---|---|---|
| False | 2 | 3 | 419.776 | 406.767 | 129958.000 | 9.000 | 12.330 |
| True | 1 | 3 | 400.996 | 393.702 | 129934.000 | 7.000 | 8.146 |

该布局只在相同信任/工作区策略类下顺序执行NumPy与clangd，无并发争用、动态放置或预测调度；共同外层预算相同。PSS节省若存在，只支持额外域控制成本的实测取舍，不能证明跨信任共享安全或集中布局普遍最优。

### 布局配对与负结果

| 差值(独立域−混合域) | 配对数 | wall中位ms | wall范围ms | CPU中位ms | PSS中位KiB | PSS范围KiB | PSS正对数 |
|---|---|---|---|---|---|---|---|
| False-True | 3 | 20.180 | [18.781, 23.068] | 15.228 | 373.000 | [-1055.000, 609.000] | 2/3 |

布局wall包含独立域额外root快照及Task审计，不能把整段差值都归因于隔离域操作。内存配对保留正反样本；不能声称每多一个域线性增加2.8MiB或混合域稳定降低PSS。这里只测两类Worker各一个、同信任、串行，无资源争用/排队/淘汰/动态调度。

## 失败与可复核文件

- `/path/to/research-host/shimos-linux-native-mvp/research/shimos_worker_pool/experiments/runs/pilot01`：原始failure/result保留于analysis summary.failures；不进入上方主成绩。
- `/path/to/research-host/shimos-linux-native-mvp/research/shimos_worker_pool/experiments/runs/pilot02`：原始failure/result保留于analysis summary.failures；不进入上方主成绩。
- `/path/to/research-host/shimos-linux-native-mvp/research/shimos_worker_pool/experiments/runs/pilot03`：原始failure/result保留于analysis summary.failures；不进入上方主成绩。

分析脚本`analysis/analyze.py`拒绝缺块、重复、源码/合同漂移、Oracle不同、cgroup未释放、FD不平衡；`sequences.csv`、`requests.csv`、`paired.csv`保留原始逐序列/请求/配对指标。`read-only-check.json`复核输入SHA未变。

已测功能通过不等于任意任务状态可复用；本轮仅冻结输入、固定应用协议。协议request ID去重集合会增长，未做长期soak。

## 版本修正与复核入口

pilot01–03是环境/实验harness初始化失败，保留原始ready-failure与错误日志；不将它们作为Worker业务错误率。pilot04完整执行但runtime缺预编译pyc，只能作为source-only敏感度；正式组使用相同CHECKED_HASH字节码，保留一次准备wall/CPU与源码一致性收据。所有策略部署相同runtime，没有免费为热Worker省略初始化。

主输入：formal01 (`experiments/runs/formal01/results.jsonl`, omitted from this source release)、formal02 (`experiments/runs/formal02/results.jsonl`, omitted from this source release)；资源：resources01 (`experiments/runs/resources01/results.jsonl`, omitted from this source release)；布局：layout01 (`experiments/runs/layout01/results.jsonl`, omitted from this source release)。配置/环境/input-snapshot与每个run同目录。资格：qualify02 (`experiments/runs/qualify02/`, omitted from this source release)；Worker功能测试与GCC/nm Oracle见[05](05-workload-selection.md)。

分析器还核对C中实际clangd child的PID/start_ticks从READY到final stats相同；不能只靠wrapper PID。A的PID namespace可重复使用相同数字PID，通过Raw域ID+PID+start_ticks区分不同Worker。B在同域使用新进程身份。初次解析和每次完整源码hash验证均计入C，未将过期输入默认视为可复用。

