#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

/* Trusted static, short-lived launcher; NEVER privileged and never a daemon.
 * argv = [launcher, absolute_tool_path, arg1, ...]. The Controller's immutable
 * workload catalog chooses this argv. Script contents remain untrusted work.
 * The W branch must have passed its business gate BEFORE execing this file.
 * No control/gate/error-report FD is accepted or retained by this interface. */

static void fail(const char *stage, int error, int code)
{
    /* stage is always a literal, not a tool-supplied JSON string. */
    dprintf(STDERR_FILENO,
            "{\"event\":\"TOOL_LAUNCHER_ERROR\",\"stage\":\"%s\",\"errno\":%d}\n",
            stage, error);
    _exit(code);
}

static void verify_security(void)
{
    struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct data[2] = {{0}};
    if (syscall(SYS_capget, &header, data) < 0) fail("capget", errno, 125);
    for (unsigned i = 0; i < 2; i++)
        if (data[i].effective || data[i].permitted || data[i].inheritable)
            fail("capabilities_not_zero", EPERM, 125);
    for (int capability = 0; capability < 64; capability++) {
        errno = 0;
        int bounded = prctl(PR_CAPBSET_READ, capability, 0, 0, 0);
        if (bounded < 0 && errno == EINVAL) break;
        if (bounded < 0) fail("capability_bound_read", errno, 125);
        if (bounded != 0) fail("capability_bound_not_zero", EPERM, 125);
        int ambient = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, capability, 0, 0);
        if (ambient < 0) fail("capability_ambient_read", errno, 125);
        if (ambient != 0) fail("capability_ambient_not_zero", EPERM, 125);
    }
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
        fail("no_new_privs", EPERM, 125);
    if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != SECCOMP_MODE_FILTER)
        fail("seccomp_filter", EPERM, 125);
    /* A successful exec has destroyed any other caller threads. This launcher
     * creates none. The filter's exact identity remains a pre-gate W check;
     * PR_GET_SECCOMP=2 alone does not identify which filter is installed. */
}

static void reset_signals(void)
{
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask)) fail("empty_signal_set", errno, 125);
    for (int sig = 1; sig < NSIG; sig++) {
        if (sig == SIGKILL || sig == SIGSTOP) continue;
        /* glibc reserves signal numbers 32 and 33 on this qualified ABI. */
        if (sigaction(sig, &action, NULL) && errno != EINVAL)
            fail("signal_default", errno, 125);
    }
    sigset_t empty;
    if (sigemptyset(&empty) || sigprocmask(SIG_SETMASK, &empty, NULL))
        fail("signal_unblock", errno, 125);
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 130 || argv[1][0] != '/') fail("arguments", EINVAL, 126);
    size_t bytes = 0;
    for (int i = 1; i < argc; i++) {
        size_t length = strnlen(argv[i], 65537);
        if (length > 65536 || bytes > 65536 - length) fail("arguments_size", E2BIG, 126);
        bytes += length;
    }
    verify_security();
    if (syscall(SYS_close_range, 3U, UINT_MAX, 0) < 0)
        fail("close_range", errno, 125);
    reset_signals();
    umask(0077);
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) fail("clock", errno, 125);
    uint64_t ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
    if (dprintf(STDOUT_FILENO,
                "{\"event\":\"TOOL_LAUNCHER_PRE_EXEC\",\"pid\":%ld,\"monotonic_ns\":%llu}\n",
                (long)getpid(), (unsigned long long)ns) < 0)
        fail("diagnostic_output", errno, 125);
    execve(argv[1], argv + 1, environ);
    fail("target_execve", errno, 127);
}
