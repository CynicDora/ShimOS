#ifndef SHIMOS_FORK_H
#define SHIMOS_FORK_H
#include <sys/types.h>
/* Research-only API from the accompanying pinned libc source build.
 * Same-thread/main-interpreter contract must be enforced by the Python caller.
 * pidfd must point to writable int; caller initializes it to -1.
 * Return child PID / 0 / -1 and errno as with fork. No fallback or migration.
 * On success only the parent receives the newly allocated CLONE_PIDFD handle.
 * FD ownership and namespace/cgroup authorization remain the caller's job.
 */
pid_t shimos_fork_into_cgroup(int cgroup_fd, int *pidfd);
#endif
