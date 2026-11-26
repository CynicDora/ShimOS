# Benchmark entry points

- `python3 benchmarks/reproduce_tables.py`: safe offline reproduction of selected historical medians, using included sequence/session CSVs.
- Actual private-VM benchmarks: see [reproduction](../docs/reproduction.md). They require omitted pinned fixtures and runtime assets. No automatic VM launch occurs from this directory.
- [Experimental definitions and results](../docs/experiments.md).

The result table script does not flush caches, execute agent commands or warm a template. It recomputes already-measured data. G4, native tools and Agent replay use different stated contracts and must not be added to one unconditional leaderboard.

Optional figure regeneration: install `matplotlib` in a separate Python environment, then run `python3 benchmarks/plot_results.py`. The SVGs are already included; basic result reproduction has no plotting dependency.
