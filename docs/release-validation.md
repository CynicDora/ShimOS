# Packaging validation

This source release was checked without launching a new VM or performance campaign.

- Source provenance: 557 imported files checked against their released SHA256 manifest; 515 remain byte-identical to the selected originals, 42 are sanitized snapshots (mostly reports/paths/omitted-artifact links).
- Python source parsing and local Markdown link checks: PASS.
- Offline result reproduction: PASS, including both headline table medians and sample counts.
- Existing `test_workers.Oracles`: 8 pure protocol/reference tests PASS. Worker integration tests were not run on the host.
- GCC `-fsyntax-only` on A+B `bridge_d.c` and `domain_init.c`: PASS. Syntax checks do not establish kernel, ABI or runtime correctness.
- Figure generation: two descriptive plots from the included numeric exports, visually reviewed; no new measurements.
- Exact VM asset preflight: BLOCKED as expected in this curated checkout. The fixture and vendor runtime payloads are intentionally absent.
- Filesystem credential scan: gitleaks v8.30.1, redacted reporting, no leaks detected. Staged-file review also checked size, file type, private home paths, private service links, private-network addresses and forbidden artifact paths.
- Imported historical whitespace, CSV line endings and patch context are preserved with `.gitattributes`; new documentation passes staged whitespace checking.

The original working tree has no Git history. This release initializes its own repository, uses a GitHub noreply author identity, and contains no inherited private commits. Before pushing, the committed history is scanned separately with gitleaks. Detailed machine-local packaging receipts are not included because they can contain host paths. This report describes packaging checks, not renewed experimental qualification or a comprehensive security audit.

No blanket open-source license has been selected. The target publication mode is Private; permission to make it Public and to license first-party material remains with the owner.

The first GitHub checkout exposed one packaging omission: a blanket `runs/` ignore excluded the reviewed candidate-runtime SHA metadata. A follow-up commit admits only that named JSON file, preserves the failed CI run, and adds a tracked-file check to prevent working-tree-only inputs from passing validation. No experimental results or raw runs were added/changed.
