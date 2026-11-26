# Runtime source and candidate D build provenance

This directory is confined to task B. The original guest image, kernel tree, qualification-02, and previous experiments are not modified.

## Inputs

- `glibc_2.35-0ubuntu3.15.dsc`, `glibc_2.35.orig.tar.xz`, `glibc_2.35-0ubuntu3.15.debian.tar.xz`: Ubuntu official archive, exact source package matching the guest libc banner. `.dsc` checksums match. Local signature verification could not locate the signing developer's public key; do not interpret hashes as signature-chain verification.
- `python3.10_3.10.12-1~22.04.18.dsc` and archives: exact package attributed through equal guest-image/host-package ELF SHA256 and actual guest inventory. Ubuntu patches are applied; this is not an upstream 3.10.12 tag alone.
- `kernel/`: read-only copies of critical actual kernel source/build-config. Manifest records exact commit and per-file comparisons with Git HEAD; all six critical source copies match.
- `source-manifest.json`: source package, SHA256, critical file and attribution records.

`glibc-2.35-ubuntu/` has all Ubuntu patches plus the task's candidate D patch. For the three changed glibc files, pristine post-Ubuntu originals are retained in `patches/*.original`. `cpython-3.10.12-ubuntu/` has only upstream/distribution patches, no ShimOS Python patch.

## Reviewable implementation

`patches/shimos-fork-into-cgroup.patch` changes only `posix/fork.c`, `sysdeps/nptl/_Fork.c`, `posix/Versions`. It keeps the standard fork path and shares its full wrapper/robust-state handling. Only the extra vendor entry selects clone3 with target cgroup, pidfd, and NPTL child-tid flags. `patches/shimos_fork.h` defines the external research API. No arbitrary glibc private entry point is called from the bridge. Source integration naturally uses libc's own private internals; those do not become external ABI.

`patches/apply-shimos.py` generated the patch, guards exact original bytes and refuses repeat application. For independent reproduction, the ordinary patch command is sufficient.

## Reproduction (new, empty task-local build directories)

Use `/usr/bin` tools, not the environment's Conda Python/toolchain. Fetch fixed archives from the `.dsc` official URLs, verify SHA256 in `source-manifest.json`, and extract with `dpkg-source`. In an empty sibling source directory:

```sh
dpkg-source --no-check -x glibc_2.35-0ubuntu3.15.dsc glibc-reproduction
cd glibc-reproduction
patch -p1 < ../patches/shimos-fork-into-cgroup.patch
```

Configure outside the source tree (replace paths with the task-local extraction/build paths):

```sh
PATH=/usr/bin:/bin ../../sources/runtime-source/glibc-2.35-ubuntu/configure \
  --prefix=/opt/shimos-glibc --disable-werror --enable-kernel=3.2 \
  --enable-stack-protector=strong --enable-stackguard-randomization \
  --enable-cet --enable-multi-arch --enable-static-pie \
  '--with-pkgversion=ShimOS candidate D; Ubuntu source 2.35-0ubuntu3.15' \
  CC=/usr/bin/gcc CXX=/usr/bin/g++
PATH=/usr/bin:/bin make -j24
PATH=/usr/bin:/bin make -j12 install install_root=/absolute/task/build/glibc-stage
```

`install_root` is essential: this writes only the stage tree. Never install this experimental libc over the host/stock guest runtime.

Final configure/build/install all exited 0. Actual logs are in `../../build/glibc/{configure.log,build.log,install.log}`. Initial exploratory configure omitted explicit strong stack protection; it was rebuilt with the above options **before** the bundle was frozen or used for guest candidate tests. Initial logs are retained as `*-initial.log`, not used as the final build specification.

`patches/bundle.py` packages runtime ELF DSOs, internal symlinks, and gconv data into `../../build/glibc-bundle/opt/shimos-glibc`. This excludes headers/static archives/linker scripts. The bundle's `manifest.json` records each artifact hash, ELF build ID, compiler, configure flags, patch hash, and the fact that full glibc regression testing was not run.

Final libc Build ID: `2218522fcaa1ec292c7fbb909f19474d79395d1f`. Build config has `STACK_PROTECTOR_LEVEL=3` and `-fstack-protector-strong`; ELF has GNU_RELRO, nonexecutable GNU_STACK and CET IBT/SHSTK properties. These limited checks do not establish full binary equivalence with Ubuntu's package. Prefix/layout, configuration, build flags and custom API differ; the bundle is an experimental runtime distribution.

## Guest use

Copy the frozen bundle directory to `/opt/shimos-glibc`, execute its own loader with `--library-path /opt/shimos-glibc/lib:...`, and mount the same bundle into each target domain. Do not mix the candidate libc with a different dynamic loader. The cross-domain fixture additionally verifies/overlays corresponding runtime libraries. The source/build environment is the host; runtime evidence comes only from task `runs/` in the actual guest.

No performance benchmark, real third-party dependency initialization, or third-party cross-domain experiment was run here. Passing the task probes is bounded runtime evidence, not NumPy/PyTorch admission or full POSIX/glibc equivalence.
