# 复现说明：哪些能直接运行，哪些需要准备环境？

建议先从离线检查开始，再决定是否恢复完整 VM。这样能先读懂协议和数字，也能看清缺少哪些实验资产。

## 1. 直接检查源码和历史数据

在仓库根目录，用 Python 3.10+ 运行：

```sh
python3 scripts/check_release.py
python3 benchmarks/reproduce_tables.py
python3 scripts/inspect_protocol.py
```

三个入口分别检查源码语法、收录文件 SHA 和链接，复算历史 CSV 的中位数，以及展示实际应用协议的请求与参考结果。它们不导入 guest 控制器，不启动 Namespace、cgroup、fork 或外部工具。这些命令已经过发布检查，但不代表重新取得实验资格。

## 2. 重跑前先检查外部资产

```sh
python3 scripts/check_vm_inputs.py
```

干净检出时返回 2 / BLOCKED 是预期结果。需要恢复 `.build/benchmark-lab/{manifest.json,bzImage,initramfs.cpio.gz,root/init}`、Bubblewrap/工具资产、guest rootfs、candidate D bundle，以及 NumPy 实验对应的包和支持动态库。发布脚本不会自动换一套环境来代替它们。

原环境为 x86-64 KVM、4 vCPU / 4 GiB，guest Linux 6.18.49-agentic-runtime-opt-v1；Bubblewrap 0.13.1、Ubuntu CPython 3.10.12、基于 Ubuntu glibc 2.35-0ubuntu3.15 的 D、GCC 11.4、NumPy 2.2.6 / OpenBLAS 0.3.29 单线程 CPU。

A+B 记录的 kernel ELF SHA 为 `bd303a80ab8fe396ac83d18e2dcd0936143eb0778fbcf6acaf47ea3fba11dd4f`，initramfs SHA 为 `79505c01cc39cb00dea51d4a8101c1bfea187a84515782520d1b58ef3d4a32f9`。

完整镜像构建夹具不在此次精选快照中。恢复旧资产或独立重建兼容实验室，都需要核对并重新验证；不能只修改期望哈希来让检查通过。后期批次还依赖各自冻结的源码审查和矩阵 JSON，因此保留历史 runner 不等于所有入口都能在新检出中直接运行。

## 3. glibc D 的构建与使用

仓库保留了[构建说明](../research/shimos_worker_pool/fork_runtime_compat/sources/runtime-source/README.md)、固定源包身份和补丁。取得指定 Ubuntu 源包并核验摘要后，在源树外构建，只安装到暂存 `install_root`，再将配套 loader/DSO 打包到可销毁私有 VM。

不要替换宿主或普通系统 libc。原来源记录没有建立完整包签名信任链，也没有完成全量 glibc 回归；换编译器或构建配置后，不能默认产物哈希和旧版本相同。历史桥接代码需要专用接口，缺失时拒绝，不会退回未验证的 raw clone3。

## 4. 已有跨域 Demo 的实际入口

在**相对路径下恢复完整且匹配的私有 VM 夹具后**，A+B 的宿主驱动为：

```sh
python3 -B research/shimos_worker_pool/integration_ab/prototype/vm.py \
  demo-local-01 --case control
python3 -B research/shimos_worker_pool/integration_ab/prototype/verify.py demo-local-01
python3 -B research/shimos_worker_pool/integration_ab/prototype/verify_runtime.py demo-local-01
```

每次使用新的输出 ID。驱动核验镜像和运行时身份，在无网络私有 VM 中执行，并导出结果；control 场景包含多个独立目标域与内存继承。guest 失败就保留失败，外部补杀不能算产品资格通过。

**整理仓库时未重跑这些 VM 命令；缺少资产时仍为 BLOCKED。**不要在宿主直接执行 `prototype/run.py`、`install_runtime.py` 或 `baseline/suite.py`。

完整八会话资格驱动为 `integration_ab/prototype/qualify.py PREFIX`。它是正确性矩阵，不是性能 Benchmark，也不适合作为入门冒烟测试。

## 5. 早期 Worker 实验入口

恢复对应 Worker runtime additions 和基线资产后：

```sh
python3 research/shimos_worker_pool/experiments/vm.py local-pool-01 \
  --session 1 --mode cost --counts 1,4 --repeats 1
```

这是小型 pilot，不是原正式重复矩阵。`--mode layout`、`--mode qualify` 也是实际存在的模式。准备脚本复制固定本地依赖，不是通用安装器；更换 NumPy/clangd 版本需要重新验证。

round1/full 的脚本保留供研究，完整冻结计划、审查记录、原始 runs 和二进制并未全部分发。精确设置以最终报告为准，新失败也应保留。源码语法通过、旧数字复算成功，都不能当成新的安全或性能结果。
