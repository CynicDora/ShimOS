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
 * argv = [launcher, --receipt-fd, N, --fault, MODE, --, /target, arg1, ...].
 * Only the trusted immutable catalogue selects MODE and the initial target.
 * G was consumed before the first exec. The one private pipe write FD survives
 * that exec, is immediately made CLOEXEC here, and MUST NOT reach the target.
 * Native startup before main is trusted too. No target dependencies are loaded
 * by this static image. This channel reports attempts/errors, never success. */

enum receipt_stage { LAUNCHER_READY = 3, TARGET_EXEC_ATTEMPT = 4,
                     EXEC_FAILED = 5, LAUNCHER_SETUP_FAILED = 6 };
enum setup_detail { ARGUMENTS = 1, ARGUMENTS_SIZE = 2, RECEIPT_CLOEXEC = 3,
                    RECEIPT_PIPE = 4, RECEIPT_FLAGS = 5, CAPABILITIES = 6,
                    NO_NEW_PRIVS = 7, SECCOMP_FILTER = 8, CLOSE_RANGE = 9,
                    SIGNALS = 10, CLOCK = 11, DIAGNOSTIC_OUTPUT = 12 };
enum fault_mode { FAULT_NONE, EXIT_BEFORE_READY, EXIT_AFTER_READY,
                  EXIT_AFTER_ATTEMPT, DROP_EXEC_FAILED, KILL_BEFORE_EXEC,
                  PAUSE_AFTER_ATTEMPT };
static int receipt_fd = -1;

static void put32(unsigned char *out, uint32_t value)
{
    for (unsigned i = 0; i < 4; i++) out[i] = (unsigned char)(value >> (i * 8));
}

static void put64(unsigned char *out, uint64_t value)
{
    for (unsigned i = 0; i < 8; i++) out[i] = (unsigned char)(value >> (i * 8));
}

static void emit_receipt(unsigned stage, int error, unsigned detail)
{
    unsigned char frame[24] = {'S', 'X', 'R', 'C', 1, 0, 0, 0};
    struct timespec now;
    uint64_t ns = 0;
    if (!clock_gettime(CLOCK_MONOTONIC, &now))
        ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
    frame[5] = (unsigned char)stage;
    put32(frame + 8, (uint32_t)error); put32(frame + 12, detail); put64(frame + 16, ns);
    /* < PIPE_BUF, one nonblocking write. No partial-frame retry or stdio buffer.
     * A channel failure forbids continuing into the untrusted target. */
    ssize_t count;
    do { count = write(receipt_fd, frame, sizeof(frame)); } while (count < 0 && errno == EINTR);
    if (count != (ssize_t)sizeof(frame)) _exit(125);
}

static _Noreturn void fail(const char *stage, unsigned detail, int error, int code)
{
    if (receipt_fd >= 0) emit_receipt(LAUNCHER_SETUP_FAILED, error, detail);
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
    if (syscall(SYS_capget, &header, data) < 0) fail("capget", CAPABILITIES, errno, 125);
    for (unsigned i = 0; i < 2; i++)
        if (data[i].effective || data[i].permitted || data[i].inheritable)
            fail("capabilities_not_zero", CAPABILITIES, EPERM, 125);
    for (int capability = 0; capability < 64; capability++) {
        errno = 0;
        int bounded = prctl(PR_CAPBSET_READ, capability, 0, 0, 0);
        if (bounded < 0 && errno == EINVAL) break;
        if (bounded < 0) fail("capability_bound_read", CAPABILITIES, errno, 125);
        if (bounded != 0) fail("capability_bound_not_zero", CAPABILITIES, EPERM, 125);
        int ambient = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, capability, 0, 0);
        if (ambient < 0) fail("capability_ambient_read", CAPABILITIES, errno, 125);
        if (ambient != 0) fail("capability_ambient_not_zero", CAPABILITIES, EPERM, 125);
    }
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
        fail("no_new_privs", NO_NEW_PRIVS, EPERM, 125);
    if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != SECCOMP_MODE_FILTER)
        fail("seccomp_filter", SECCOMP_FILTER, EPERM, 125);
    /* A successful exec has destroyed any other caller threads. This launcher
     * creates none. The filter's exact identity remains a pre-gate W check;
     * PR_GET_SECCOMP=2 alone does not identify which filter is installed. */
}

static void reset_signals(void)
{
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask)) fail("empty_signal_set", SIGNALS, errno, 125);
    for (int sig = 1; sig < NSIG; sig++) {
        if (sig == SIGKILL || sig == SIGSTOP) continue;
        /* glibc reserves signal numbers 32 and 33 on this qualified ABI. */
        if (sigaction(sig, &action, NULL) && errno != EINVAL)
            fail("signal_default", SIGNALS, errno, 125);
    }
    sigset_t empty;
    if (sigemptyset(&empty) || sigprocmask(SIG_SETMASK, &empty, NULL))
        fail("signal_unblock", SIGNALS, errno, 125);
}

int main(int argc, char **argv)
{
    /* Parse only enough trusted ABI to locate the pipe; make it CLOEXEC before
     * any optional work. Invalid initial ABI has no usable private channel. */
    if (argc < 7 || argc > 135 || strcmp(argv[1], "--receipt-fd"))
        fail("arguments", ARGUMENTS, EINVAL, 126);
    unsigned long fd_number = 0;
    size_t fd_digits = strnlen(argv[2], 11);
    if (!fd_digits || fd_digits > 10) fail("receipt_number", ARGUMENTS, EINVAL, 126);
    for (size_t i = 0; i < fd_digits; i++) {
        if (argv[2][i] < '0' || argv[2][i] > '9')
            fail("receipt_number", ARGUMENTS, EINVAL, 126);
        fd_number = fd_number * 10 + (unsigned)(argv[2][i] - '0');
        if (fd_number > INT_MAX - 1UL) fail("receipt_number", ARGUMENTS, EINVAL, 126);
    }
    if (fd_number < 3) fail("receipt_number", ARGUMENTS, EINVAL, 126);
    int fd = (int)fd_number;
    int fd_flags = fcntl(fd, F_GETFD);
    if (fd_flags < 0 || fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC) < 0)
        fail("receipt_cloexec", RECEIPT_CLOEXEC, errno, 125);
    struct stat receipt_stat;
    int open_flags = fcntl(fd, F_GETFL);
    if (fstat(fd, &receipt_stat) < 0 || !S_ISFIFO(receipt_stat.st_mode) ||
        open_flags < 0 || (open_flags & O_ACCMODE) != O_WRONLY)
        fail("receipt_pipe", RECEIPT_PIPE, EINVAL, 125);
    if (fcntl(fd, F_SETFL, open_flags | O_NONBLOCK) < 0)
        fail("receipt_flags", RECEIPT_FLAGS, errno, 125);
    receipt_fd = fd;
    if (strcmp(argv[3], "--fault") || strcmp(argv[5], "--") || argv[6][0] != '/')
        fail("arguments", ARGUMENTS, EINVAL, 126);
    enum fault_mode fault;
    if (!strcmp(argv[4], "none")) fault = FAULT_NONE;
    else if (!strcmp(argv[4], "exit_before_ready")) fault = EXIT_BEFORE_READY;
    else if (!strcmp(argv[4], "exit_after_ready")) fault = EXIT_AFTER_READY;
    else if (!strcmp(argv[4], "exit_after_attempt")) fault = EXIT_AFTER_ATTEMPT;
    else if (!strcmp(argv[4], "drop_exec_failed")) fault = DROP_EXEC_FAILED;
    else if (!strcmp(argv[4], "kill_before_exec")) fault = KILL_BEFORE_EXEC;
    else if (!strcmp(argv[4], "pause_after_attempt")) fault = PAUSE_AFTER_ATTEMPT;
    else fail("unknown_fault", ARGUMENTS, EINVAL, 126);
    size_t bytes = 0;
    for (int i = 6; i < argc; i++) {
        size_t length = strnlen(argv[i], 65537);
        if (length > 65535 || bytes > 65536 - length - 1)
            fail("arguments_size", ARGUMENTS_SIZE, E2BIG, 126);
        bytes += length + 1;
    }
    verify_security();
    /* Keep only this CLOEXEC receipt FD in addition to stdio. Both range calls
     * must succeed; no compatibility fallback that leaves management FDs. */
    if (fd > 3 && syscall(SYS_close_range, 3U, (unsigned)fd - 1, 0) < 0)
        fail("close_range_low", CLOSE_RANGE, errno, 125);
    if (syscall(SYS_close_range, (unsigned)fd + 1, UINT_MAX, 0) < 0)
        fail("close_range_high", CLOSE_RANGE, errno, 125);
    reset_signals();
    umask(0077);
    if (fault == EXIT_BEFORE_READY) _exit(124);
    emit_receipt(LAUNCHER_READY, 0, 0);
    if (fault == EXIT_AFTER_READY) _exit(124);
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) fail("clock", CLOCK, errno, 125);
    uint64_t ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
    if (dprintf(STDOUT_FILENO,
                "{\"event\":\"TOOL_LAUNCHER_PRE_EXEC\",\"pid\":%ld,\"monotonic_ns\":%llu}\n",
                (long)getpid(), (unsigned long long)ns) < 0)
        fail("diagnostic_output", DIAGNOSTIC_OUTPUT, errno, 125);
    emit_receipt(TARGET_EXEC_ATTEMPT, 0, 0);
    if (fault == EXIT_AFTER_ATTEMPT) _exit(124);
    if (fault == KILL_BEFORE_EXEC) {
        raise(SIGKILL);
        _exit(125);  /* Signal delivery unexpectedly failed: still never exec. */
    }
    if (fault == PAUSE_AFTER_ATTEMPT) for (;;) pause();
    execve(argv[6], argv + 6, environ);
    int saved_errno = errno;
    if (fault != DROP_EXEC_FAILED) emit_receipt(EXEC_FAILED, saved_errno, 0);
    dprintf(STDERR_FILENO,
            "{\"event\":\"TOOL_LAUNCHER_ERROR\",\"stage\":\"target_execve\",\"errno\":%d}\n",
            saved_errno);
    _exit(127);
}
