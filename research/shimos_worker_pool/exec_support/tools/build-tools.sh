#!/bin/sh
# Run only inside the private VM, before binding the tool tree read-only.
set -eu
test "$(cat /run/native-benchmark-lab)" = private-stock-linux-benchmark-vm
tool_root=${1:?absolute guest copy of tools required}
fixture_build=${2:?private guest build directory outside visible tool root required}
case "$tool_root" in /state/*) ;; *) echo 'tools must be copied into private /state' >&2; exit 64 ;; esac
case "$fixture_build" in /state/*) ;; *) echo 'build must be private /state' >&2; exit 64 ;; esac
mkdir -p "$tool_root/bin" "$fixture_build"
/usr/bin/gcc -Wall -Wextra -O2 -static "$tool_root/probe.c" -o "$tool_root/bin/probe-static"
/usr/bin/gcc -Wall -Wextra -O2 "$tool_root/probe.c" -o "$tool_root/bin/probe-dynamic"
/usr/bin/gcc -Wall -Wextra -O2 -shared -fPIC "$tool_root/missing_dep.c" -Wl,-soname,libexec_missing_fixture.so -o "$fixture_build/libexec_missing_fixture.so"
/usr/bin/gcc -Wall -Wextra -O2 "$tool_root/loader_target.c" -L"$fixture_build" -lexec_missing_fixture -o "$tool_root/bin/linked-missing"
# No RPATH is embedded, and the dependency directory is never bound into a domain.
test ! -e "$tool_root/bin/libexec_missing_fixture.so"
