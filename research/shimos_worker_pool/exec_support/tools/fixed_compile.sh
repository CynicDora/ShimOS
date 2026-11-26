#!/bin/sh
set -eu
/workloads/bin/probe-static identity
case "${1:-success}" in
  success)
    /usr/bin/gcc -Wall -Wextra -O1 -I/workloads/c_project -c /workloads/c_project/answer.c -o /work/answer.o
    /usr/bin/gcc -Wall -Wextra -O1 -I/workloads/c_project -c /workloads/c_project/main.c -o /work/main.o
    /usr/bin/gcc /work/main.o /work/answer.o -o /work/compiled-result
    echo COMPILER_LINK_OK
    /work/compiled-result
    ;;
  failure)
    /usr/bin/gcc -Wall -Wextra /workloads/c_project/broken.c -o /work/should-not-exist
    echo UNEXPECTED_COMPILER_SUCCESS
    exit 84
    ;;
  *) echo 'unknown fixed compiler case' >&2; exit 64 ;;
esac
