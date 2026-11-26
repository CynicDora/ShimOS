# 实验数据与复核入口

想先确认 README 数字从哪里来，可以运行：

```sh
python3 benchmarks/reproduce_tables.py
```

它读取已经收录的 CSV，复算早期 Worker 与 N=100 对照的中位数，不会启动新实验、清缓存或执行 Agent 命令。具体口径见[实验汇总](../docs/experiments.md)。

实际 VM 实验需要未随仓库分发的固定资产，请按[复现说明](../docs/reproduction.md)准备。本目录不会自动启动 VM。G4、外部工具和 Agent 回放各有不同的状态与安全要求，不能放到一个不加条件的排行榜中。

如需重新绘图，可在单独的 Python 环境安装 `matplotlib`，然后运行：

```sh
python3 benchmarks/plot_results.py
```

图表已经以 SVG/PNG 收录。基础表格复算只用标准库，不依赖绘图库；图中保留了与原始数据对应的英文模式名和计量标签。
