# Third-party material and provenance

## Included

- **zlib 1.3.1 fixture**: `research/shimos_worker_pool/experiments/workers/fixture/{adler32.c,zutil.h,zlib.h,zconf.h}`. Copyright and permissive zlib notice are preserved, including the full license in `zlib.h`. Origin: https://zlib.net/fossils/zlib-1.3.1.tar.gz . This is a small unmodified source fixture used for code-query correctness, not a ShimOS license grant.
- **glibc-derived research patch**: `research/shimos_worker_pool/fork_runtime_compat/sources/runtime-source/patches/shimos-fork-into-cgroup.patch`. Applies to Ubuntu glibc `2.35-0ubuntu3.15`; preserves the full fork wrapper and adds a vendor API. Upstream notices and GNU license terms continue to apply to covered material. GNU license texts are in `third_party/glibc/COPYING` and `COPYING.LIB`; exact source-package URL and hashes are in the accompanying source manifest. No libc/loader binary or full vendor source tree is distributed. The patch is not a supported upstream ABI.

The selected prototype C/Python sources were taken from the local research project. Their ownership and final licensing still require author confirmation; no new blanket license has been assigned. Source/release hashes are recorded in `docs/source-manifest.json`.

## Not bundled

Bubblewrap (LGPL), CPython (PSF terms), NumPy (BSD and bundled notices), OpenBLAS (BSD and bundled components), clangd/LLVM (Apache-2.0 with LLVM exceptions), Linux (GPL and per-file terms), QEMU and GNU tools are external prerequisites. Their mention does not relicense or redistribute their binaries. Users rebuilding assets must retain the actual distribution notices and satisfy its source obligations.

Downloaded Agent repositories, benchmark task snapshots, public trajectories, vendor wheels, VM images and article PDFs are omitted. Licensing and privacy were not inferred from public accessibility. Related-work source citations in reports are references, not bundled implementations or claims of permission.
