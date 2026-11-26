# Reproduction: what runs from a checkout

## 1. Portable source/result inspection

From the repository root, with Python 3.10+:

```sh
python3 scripts/check_release.py
python3 benchmarks/reproduce_tables.py
python3 scripts/inspect_protocol.py
```

The first command parses Python without importing guest controllers and verifies imported-file SHA values and local links. The second reproduces result medians from included CSV exports, and the third uses the actual application's pure-Python reference protocol. No namespace, cgroup, native fork or external tool is started. These commands are validated for this release. They provide an executable research-reading entry point, not a new qualification run.

## 2. Understand external assets first

```sh
python3 scripts/check_vm_inputs.py
```

Exit 2 / BLOCKED is expected in a fresh source-only checkout. Required assets include a frozen `.build/benchmark-lab/{manifest.json,bzImage,initramfs.cpio.gz,root/init}`, the Bubblewrap/tool asset tree, a guest rootfs, candidate D bundle, and the NumPy support package for NumPy studies. These are not downloads silently substituted by the release scripts.

Historical environment: x86-64 KVM with 4 vCPU / 4 GiB; guest Linux 6.18.49-agentic-runtime-opt-v1; Bubblewrap 0.13.1; Ubuntu CPython 3.10.12; candidate D based on Ubuntu glibc 2.35-0ubuntu3.15; GCC 11.4; NumPy 2.2.6 and OpenBLAS 0.3.29 single-thread CPU. Kernel ELF SHA in the A+B record is `bd303a80ab8fe396ac83d18e2dcd0936143eb0778fbcf6acaf47ea3fba11dd4f`; initramfs SHA is `79505c01cc39cb00dea51d4a8101c1bfea187a84515782520d1b58ef3d4a32f9`.

The underlying lab kernel/initramfs are not automatically reproducible from this checkout: their complete fixture build is outside this curated snapshot. Restoring a local copy or independently rebuilding a compatible lab requires a new qualification, not changing expected hashes until something runs. Later studies also require their frozen source-review JSONs and matrices, deliberately excluded from automatic launch here. Their historical scripts are implementation evidence, not all turnkey entry points.

## 3. Runtime D build is experimental

The [source/build recipe](../research/shimos_worker_pool/fork_runtime_compat/sources/runtime-source/README.md), fixed source-package manifest and vendor patch are included. Fetch the specified Ubuntu source package, verify its recorded checksums, apply the patch and use an out-of-tree build. Install only into a staging `install_root`, package the matching loader and DSOs, then copy to a disposable private VM. Never replace host or ordinary system libc. The original source attribution did not establish a complete package-signature trust chain or full glibc regression qualification.

A rebuild's identity must be independently recorded and tested; a different compiler/build does not necessarily yield the recorded binary hashes. The fixed historical bridge expects the vendor API, not stock fork or an unchecked raw clone3 fallback.

## 4. Actual historical VM demo / qualification

Once the full matching private fixture is restored **at the expected relative paths**, the A+B host runner is:

```sh
python3 -B research/shimos_worker_pool/integration_ab/prototype/vm.py \
  demo-local-01 --case control
python3 -B research/shimos_worker_pool/integration_ab/prototype/verify.py demo-local-01
python3 -B research/shimos_worker_pool/integration_ab/prototype/verify_runtime.py demo-local-01
```

Use a new output ID. The runner verifies kernel/initramfs and candidate identities, starts a networkless private VM and exports new results. The control case exercises multiple independent target domains and inherited state. A guest failure remains failure; external emergency cleanup cannot count as product qualification. **These VM commands were not rerun during packaging and are BLOCKED without the omitted fixture.** Do not execute `prototype/run.py`, `install_runtime.py`, or `baseline/suite.py` directly on the host.

The full eight-session restricted correctness driver is `integration_ab/prototype/qualify.py PREFIX`; it is not a performance benchmark. Do not run it as a getting-started smoke test.

## 5. Early Worker benchmark

With its separate, matching Worker runtime additions and baseline assets restored:

```sh
python3 research/shimos_worker_pool/experiments/vm.py local-pool-01 \
  --session 1 --mode cost --counts 1,4 --repeats 1
```

This is a small pilot, not the original formal repeat matrix. `--mode layout` and `--mode qualify` are actual historical modes. The runtime preparation scripts copy pinned local packages; they are not a general dependency installer. Replacing NumPy/clangd versions requires requalification.

Round1/full runners and analyzers are retained for study: their frozen plans, reviewers, raw run trees and binary assets are not all included, so their launch commands are not advertised as working in a fresh checkout. Start from the final reports for exact historical configurations and retain new failures. Never treat source syntax checks or offline numeric reproduction as a new security/performance result.
