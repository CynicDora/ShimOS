# 第三方材料与来源说明

## 随仓库收录的材料

- **zlib 1.3.1 测试文件**：`research/shimos_worker_pool/experiments/workers/fixture/{adler32.c,zutil.h,zlib.h,zconf.h}`。保留原版权和 zlib 许可，完整条款在 `zlib.h` 中。来源：https://zlib.net/fossils/zlib-1.3.1.tar.gz 。这些未修改的小型文件用于代码查询正确性验证，不为 ShimOS 授予统一许可。
- **glibc 衍生研究补丁**：`research/shimos_worker_pool/fork_runtime_compat/sources/runtime-source/patches/shimos-fork-into-cgroup.patch`，对应 Ubuntu glibc `2.35-0ubuntu3.15`，保留完整 fork 路径并增加实验接口。相关材料继续受原版权与 GNU 条款约束；许可原文见 `third_party/glibc/COPYING`、`COPYING.LIB`，固定源包 URL 和哈希在对应 manifest 中。未分发 libc/loader 二进制和完整厂商源树；该补丁不是受支持的上游 ABI。

精选的原型 C/Python 文件来自本地研究项目，其最终权属和项目许可仍需作者确认，未擅自赋予统一许可证。每个文件的来源和发布摘要记录在 `docs/source-manifest.json`。

## 作为外部前提、未打包的材料

Bubblewrap、CPython、NumPy、OpenBLAS、clangd/LLVM、Linux、QEMU 和 GNU 工具遵循各自的许可及捆绑组件声明。提到它们不代表重新授权或分发了其二进制；重建资产时应保留实际发行版的声明，并履行相应源码义务。

下载的 Agent 仓库、Benchmark 任务快照、轨迹、wheel、VM 镜像和论文 PDF 均未收录。公开访问不能替代分发授权。报告中的先例链接仅作引用，不代表随仓库提供了对应实现。

本页是来源说明；第三方许可原文保留原语言，未改写其法律条款。
