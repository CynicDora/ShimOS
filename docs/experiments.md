# Experimental results and their boundaries

## Reading order

1. [Early Worker experiments](../research/shimos_worker_pool/06-benchmark-results.md).
2. [A+B integration](../research/shimos_worker_pool/integration_ab/integration-report.md) and [qualification matrix](../research/shimos_worker_pool/integration_ab/analysis/qualification-ab-02-matrix.md).
3. [NumPy admission](../research/shimos_worker_pool/numpy_admission/numpy-admission-report.md).
4. [G0/G1/G2 final report](../research/shimos_worker_pool/architecture_comparison_round1/round1-final-report.md).
5. [Full G0–G4 synthesis](../research/shimos_worker_pool/architecture_comparison_full/reports/shimos-round3-complete-report.md).
6. [Real-agent workload study](../research/real_agent_workload/reports/real_agent_workload_and_benchmark_final.md) and [later dependency evidence](../research/shimos_next_architecture/reports/03_dependency_and_state_reuse.md).

## Environment

The architecture experiments used KVM, x86-64, 4 vCPU / 4 GiB on one physical host; frozen Linux 6.18.49-agentic-runtime-opt-v1, Bubblewrap 0.13.1, CPython 3.10.12, Ubuntu glibc 2.35-based candidate D, and fixed NumPy 2.2.6 / OpenBLAS 0.3.29 single-thread CPU recipe. Exact package revisions, artifact hashes and build configuration are in the A+B/runtime reports and included source manifests. The kernel was a pre-existing frozen experimental-lab asset; this release neither builds nor certifies an upstream-equivalent replacement.

## Persistent Workers

Both fresh/reused columns below keep the same domain. Each sample is four requests including preparation, result validation and final cleanup.

| Workload | Fresh median | Reused median | Samples/cell |
|---|---:|---:|---:|
| NumPy fixed integer reduction | 555.406 ms | 163.325 ms | 6 |
| clangd fixed C symbol query | 643.113 ms | 177.554 ms | 6 |

Independent single snapshots showed retained whole-domain PSS of about 30.5 MiB / 104.9 MiB respectively. These are not peaks or long-run averages. Static same-/separate-domain layout tests do not establish a dynamic placement policy.

## Independent new domains, N=100

| Mode | Complete sequence median | Root-accounted CPU median |
|---|---:|---:|
| G0 cold Python | 53.793 s | 49.679 s |
| G1 cold cross-domain template | 61.759 s | 55.805 s |
| G2 warm shared template | 22.503 s | 16.904 s |

Three paired VM blocks. The 8 MiB float64 array / 128×128 matrix recipe differs from the early integer reduction. Initial warming and final H/Z wait are included. G2 was slower at N=1; the tested early break-even is not a general property. Root memcg peak at N=100 was about 61.27 MiB for G2 versus 45.46 MiB for G0. Lower time does not imply lower peak or net physical memory.

## Shared versus domain-local templates, N=50

| Requests/domain K | G2 median | G3 median |
|---:|---:|---:|
| 1 | 11.644 s | 30.608 s |
| 2 | 10.651 s | 18.623 s |
| 5 | 10.065 s | 11.331 s |
| 10 | 9.791 s | 8.979 s |
| 25 | 9.337 s | 7.697 s |
| 50 | 9.797 s | 7.016 s |

Same D/K and domain-retention policy; domains were sequentially created/used/released in this experiment, not all retained simultaneously. The crossing is observed between K=5 and 10 for this recipe. The detailed report preserves paired differences and resource coverage limits.

![Measured G2/G3 density crossover](figures/reuse-density.svg)

## State, COW, concurrency and failure

G4's K=100 read-only sequence took 8.604 s versus G3's 14.022 s; known-state reset (about 14.5–14.9 ms/request) is included. This weaker persistent-state contract cannot replace fresh process isolation.

G2 C=4→8 did not improve complete light-workload latency (2.513→2.529 s) on four vCPUs and raised root-accounted peak memory. Both G2/G3 failed to complete tested 96 MiB root-budget sequences; cleanup PASS is separate from business FAIL. A single-slot two-profile experiment took 4.645 s grouped versus 11.198 s alternating, including switching and shutdown; no cache algorithm improvement is claimed.

Tool Exec T1/T2 has a separate safety contract. T2 avoids routing an eventual exec through Python heap; it was more direct in most tested scenarios, with reverse/noisy ELF samples retained. Do not merge it into a NumPy ranking.

## Real-agent evidence and negative results

The public corpus contained 122 real runs, 108 task IDs and 5,288 tool actions. Separate VM fixed-trajectory observations covered 13 tasks, 414 actions and 102 Python executions. These do not establish K_heap or K_template. Later B0/B1 qualification did not support an unconditional fair speed ranking; persisting workspaces and background-process semantics matter.

Separate fresh-Python mpmath import probes fell from roughly 231–233 ms to 70 ms with ordinary bytecode caching. Some apparent initialization opportunity is already addressed by mature caching. This is not a live Agent E2E speedup or automatic dependency admission.

## Recomputing included results

`python3 benchmarks/reproduce_tables.py` reads the included numeric exports and prints the two headline medians. The curated CSVs preserve all their original rows, including diagnostic cohorts; the script selects the explicitly documented performance cohorts. It is not a fresh benchmark. Run-level unredacted logs are not distributed, so this checkout alone cannot independently recertify all historical qualification judgments.
