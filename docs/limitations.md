# Qualification and limitations

| Capability | Status | Scope |
|---|---|---|
| Persistent Bubblewrap domain | Implemented and tested | Frozen B-strict profile; same-domain Workers share trust/workspace |
| NumPy/clangd Worker reuse | Implemented and measured | Fixed inputs and application protocols; no general daemon pool |
| Z → S → W inheritance | Implemented and tested | Trusted single-threaded template, legal namespace hierarchy, private VM |
| Lifecycle A + runtime B | 29 restricted attempts PASS | Eight VM sessions on one host; expected failure/UNKNOWN outcomes included |
| NumPy CPU preload | Separately admitted | NumPy 2.2.6/OpenBLAS 0.3.29 fixed single-thread recipe and tested profiles |
| G2/G3/G4, concurrency/pressure | Implemented research variants | Each has its own qualification and response/state contract |
| Native Tool Exec | Implemented research variants | Separate tool policy, private receipts, limited tool/failure matrix |
| One-fork direct cross-domain path | Permission diagnostics/review only | Alternative topology is not full original-contract qualification |
| Automatic joint scheduler / general pool | Not implemented | Static experimental policies are not a scheduler |
| Arbitrary dependency admission | Not implemented | Package-name equality and environment flags do not prove fork safety |
| Transparent CLI classifier/converter | Concept/prior-art analysis only | No new transparent execution prototype or performance result |
| General real-agent E2E speedup | Not established | Public trajectory analysis and fixed replay are separate from live E2E |

## Security and runtime

Do not use this repository as a production untrusted multitenant service. Cross-domain construction retains sensitive namespace/FD authority. Unknown Python/native callbacks can run before the business gate. Threads, locks, signals, plugins, device state and DSO identity require runtime-specific review. The full glibc regression suite and arbitrary Python extension compatibility were not established.

H survival, fixed fixtures and finite fault scenarios are explicit assumptions in the A+B and NumPy results. Host OOM/reboot, inaccessible filesystems, uninterruptible processes, long-lived state growth and all fault interleavings are not comprehensively covered. Later follow-up qualification has narrower named cases and is not a global guarantee.

## Measurement

Headline performance is from controlled work on the same physical host, not independent hardware or production distributions. VM boot/distribution preparation lies outside product session timing and is separately scoped in the reports. Initialization and final product release are included. Diagnostic probes, fingerprints and result validation have cost; historical cohorts with different instrumentation are not interchangeable.

G4 permits persistent state with enumerated reset. Docker/B-strict agent adapters did not obtain a shared complete qualification contract, so no strict B0/B1 speedup is claimed. The observed count of Bash actions is not a count of safe heap/template reuse opportunities.

## Distribution

Images, pinned runtime binaries, vendor source trees, third-party trajectories, private Feishu records, and raw logs were deliberately omitted. Historical source paths and dependency manifests are retained, but a source-only checkout cannot replay all experiments without reconstructing external assets. Sanitized reports label omitted links. No SPDX license has been invented for the project's own code; see [license status](../LICENSE-STATUS.md).
