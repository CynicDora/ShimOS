#!/bin/sh
# All inputs are fixed fixtures. The shell still runs as untrusted tool workload.
set -eu
/workloads/bin/probe-static identity
case "${1:-pipeline}" in
  pipeline)
    printf 'gamma\nalpha\nbeta\n' | sort | tr 'a-z' 'A-Z' > /work/pipeline.txt
    cat /work/pipeline.txt
    test "$(wc -l < /work/pipeline.txt)" -eq 3
    echo SHELL_PIPELINE_OK
    ;;
  children)
    /workloads/bin/probe-static child & first=$!
    /workloads/bin/probe-static grandchild & second=$!
    wait "$first"
    wait "$second"
    echo SHELL_CHILDREN_OK
    ;;
  failure)
    # POSIX sh pipeline status is the last command; propagate explicitly.
    if /workloads/bin/probe-static nonzero; then exit 82; else rc=$?; fi
    echo "SHELL_PROPAGATED_EXIT=$rc" >&2
    exit "$rc"
    ;;
  background)
    /workloads/bin/probe-static hang &
    echo "SHELL_BACKGROUND_PID=$!"
    exit 0
    ;;
  cancel)
    /workloads/bin/probe-static holdio &
    /workloads/bin/probe-static hang &
    echo SHELL_CANCEL_TREE_READY
    wait
    ;;
  *) echo 'unknown fixed shell case' >&2; exit 64 ;;
esac
