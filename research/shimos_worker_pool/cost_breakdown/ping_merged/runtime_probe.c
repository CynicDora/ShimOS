#define _GNU_SOURCE
/* Trusted correctness instrumentation, not a runtime compatibility shim.
 * Based on task B probe.c's public pthread/robust probes. No private glibc
 * structure is accessed. Callback logging uses FD 1 and never opens a FD. */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/capability.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static int installed;
static char attempt[129] = "session";
static pid_t initial_pid, native_owner;
static unsigned int generation, prepares[2], parents[2], children[2];
static __thread unsigned long tls_cookie = 0x51a7c0deUL;
static pthread_mutex_t *shared_mutex;
static int recover_consistent = -1, recover_unlock = -1;

static char *literal(char *p, const char *s) { while (*s) *p++ = *s++; return p; }
static char *number(char *p, long value) {
    char rev[32]; size_t n = 0; unsigned long u;
    if (value < 0) { *p++ = '-'; u = (unsigned long)(-(value + 1)) + 1; }
    else u = (unsigned long)value;
    do { rev[n++] = '0' + u % 10; u /= 10; } while (u);
    while (n) *p++ = rev[--n];
    return p;
}
static uint64_t caps(struct __user_cap_data_struct d[2], int which) {
    uint32_t lo = which == 0 ? d[0].effective : which == 1 ? d[0].permitted : d[0].inheritable;
    uint32_t hi = which == 0 ? d[1].effective : which == 1 ? d[1].permitted : d[1].inheritable;
    return ((uint64_t)hi << 32) | lo;
}
static void callback_record(const char *name) {
    /* Stack-only formatting; no allocator, Python, FD discovery or lock here. */
    struct __user_cap_header_struct h = {.version = _LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct d[2] = {{0}};
    long caprc = syscall(SYS_capget, &h, d);
    long nnp = syscall(SYS_prctl, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    long seccomp = syscall(SYS_prctl, PR_GET_SECCOMP, 0, 0, 0, 0);
    char b[1024], *p = b;
    p = literal(p, "{\"event\":\"AB_NATIVE_FORK_CALLBACK\",\"trusted_instrumentation\":true,\"nonce\":\"");
    p = literal(p, attempt); p = literal(p, "\",\"name\":\"");
    p = literal(p, name); p = literal(p, "\",\"pid\":");
    p = number(p, syscall(SYS_getpid)); p = literal(p, ",\"tid\":");
    p = number(p, syscall(SYS_gettid)); p = literal(p, ",\"generation\":");
    p = number(p, generation); p = literal(p, ",\"capget_rc\":");
    p = number(p, caprc); p = literal(p, ",\"cap_eff\":");
    p = number(p, (long)caps(d, 0)); p = literal(p, ",\"cap_prm\":");
    p = number(p, (long)caps(d, 1)); p = literal(p, ",\"nnp\":");
    p = number(p, nnp); p = literal(p, ",\"seccomp\":");
    p = number(p, seccomp); p = literal(p, "}\n");
    if (write(STDOUT_FILENO, b, (size_t)(p - b)) != p - b) _exit(126);
}
static void prepare1(void) { prepares[0]++; callback_record("prepare1"); }
static void parent1(void) { parents[0]++; callback_record("parent1"); }
static void child1(void) { children[0]++; callback_record("child1"); }
static void prepare2(void) { prepares[1]++; callback_record("prepare2"); }
static void parent2(void) { parents[1]++; callback_record("parent2"); }
static void child2(void) {
    children[1]++; generation++; native_owner = (pid_t)syscall(SYS_getpid);
    callback_record("child2");
}

int rp_install(void) {
    if (installed) return EALREADY;
    initial_pid = native_owner = (pid_t)syscall(SYS_getpid);
    int e = pthread_atfork(prepare1, parent1, child1);
    if (!e) e = pthread_atfork(prepare2, parent2, child2);
    if (!e) installed = 1;
    return e;
}
int rp_context(const char *nonce) {
    if (!nonce) return EINVAL;
    size_t n = strlen(nonce);
    if (!n || n > 128) return EINVAL;
    for (size_t i = 0; i < n; i++) {
        char c = nonce[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) return EINVAL;
    }
    memcpy(attempt, nonce, n + 1);
    return 0;
}

/* This snapshot is outside atfork callbacks. It works even when S's adopted
 * target /proc cannot represent S (whose active PID namespace is still outer). */
int rp_snapshot(char *buffer, size_t size) {
    struct robust_list_head *head = NULL; size_t length = 0;
    errno = 0; long rr = syscall(SYS_get_robust_list, 0, &head, &length); int re = errno;
    clockid_t clock = 0; int ce = pthread_getcpuclockid(pthread_self(), &clock);
    struct timespec ts; errno = 0; int cr = ce ? -1 : clock_gettime(clock, &ts); int cre = errno;
    struct __user_cap_header_struct h = {.version = _LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct d[2] = {{0}};
    long caprc = syscall(SYS_capget, &h, d);
    uint64_t bound = 0, ambient = 0;
    for (int c = 0; c < 64; c++) {
        long r = syscall(SYS_prctl, PR_CAPBSET_READ, c, 0, 0, 0);
        if (r < 0) break;
        if (r) bound |= 1ULL << c;
        r = syscall(SYS_prctl, PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, c, 0, 0);
        if (r > 0) ambient |= 1ULL << c;
    }
    sigset_t blocked; int sigrc = sigprocmask(SIG_SETMASK, NULL, &blocked);
    uint64_t blocked_bits = 0;
    if (!sigrc) for (int s = 1; s < 65; s++) if (sigismember(&blocked, s) == 1) blocked_bits |= 1ULL << (s - 1);
    int n = snprintf(buffer, size,
        "{\"pid\":%ld,\"tid\":%ld,\"uid\":%ld,\"gid\":%ld,"
        "\"generation\":%u,\"initial_pid\":%d,\"native_owner\":%d,\"native_owner_matches\":%s,"
        "\"native_counts\":{\"prepare1\":%u,\"prepare2\":%u,\"parent1\":%u,\"parent2\":%u,\"child1\":%u,\"child2\":%u},"
        "\"pthread_self\":%" PRIuPTR ",\"tls_address\":%" PRIuPTR ",\"tls_cookie\":%lu,"
        "\"robust_rc\":%ld,\"robust_errno\":%d,\"robust_head\":%" PRIuPTR ",\"robust_length\":%zu,"
        "\"cpuclock_rc\":%d,\"cpuclock_tid\":%ld,\"clock_gettime_rc\":%d,\"clock_errno\":%d,"
        "\"capget_rc\":%ld,\"cap_eff\":%" PRIu64 ",\"cap_prm\":%" PRIu64 ",\"cap_inh\":%" PRIu64 ","
        "\"cap_bnd\":%" PRIu64 ",\"cap_amb\":%" PRIu64 ",\"nnp\":%ld,\"seccomp\":%ld,"
        "\"signal_mask_rc\":%d,\"blocked_signal_bits\":%" PRIu64 ",\"robust_test_mapping\":%" PRIuPTR "}",
        syscall(SYS_getpid), syscall(SYS_gettid), syscall(SYS_getuid), syscall(SYS_getgid),
        generation, initial_pid, native_owner, native_owner == syscall(SYS_getpid) ? "true" : "false",
        prepares[0], prepares[1], parents[0], parents[1], children[0], children[1],
        (uintptr_t)pthread_self(), (uintptr_t)&tls_cookie, tls_cookie,
        rr, re, (uintptr_t)head, length, ce, ~(long)(clock >> 3), cr, cre,
        caprc, caps(d, 0), caps(d, 1), caps(d, 2), bound, ambient,
        syscall(SYS_prctl, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0),
        syscall(SYS_prctl, PR_GET_SECCOMP, 0, 0, 0, 0), sigrc, blocked_bits, (uintptr_t)shared_mutex);
    return n < 0 || (size_t)n >= size ? ENOSPC : 0;
}

/* One shared page established in trusted Z before forks, with no mutex held at
 * fork. It is diagnostic shared state, not claimed to be a COW-only template. */
int rp_robust_prepare(void) {
    if (shared_mutex) return EALREADY;
    pthread_mutexattr_t a; int e = pthread_mutexattr_init(&a);
    if (e) return e;
    if ((e = pthread_mutexattr_setpshared(&a, PTHREAD_PROCESS_SHARED))) { pthread_mutexattr_destroy(&a); return e; }
    if ((e = pthread_mutexattr_setrobust(&a, PTHREAD_MUTEX_ROBUST))) { pthread_mutexattr_destroy(&a); return e; }
    shared_mutex = mmap(NULL, sizeof(*shared_mutex), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (shared_mutex == MAP_FAILED) { shared_mutex = NULL; pthread_mutexattr_destroy(&a); return errno; }
    e = pthread_mutex_init(shared_mutex, &a); pthread_mutexattr_destroy(&a);
    if (!e) e = pthread_mutex_lock(shared_mutex);
    if (!e) e = pthread_mutex_unlock(shared_mutex);
    return e;
}
int rp_robust_lock(void) { return shared_mutex ? pthread_mutex_lock(shared_mutex) : EINVAL; }
int rp_robust_recover(void) {
    if (!shared_mutex) return EINVAL;
    recover_consistent = recover_unlock = -1;
    struct timespec end; if (clock_gettime(CLOCK_REALTIME, &end)) return errno;
    end.tv_nsec += 300000000;
    if (end.tv_nsec >= 1000000000) { end.tv_sec++; end.tv_nsec -= 1000000000; }
    int e = pthread_mutex_timedlock(shared_mutex, &end);
    if (e == EOWNERDEAD) {
        recover_consistent = pthread_mutex_consistent(shared_mutex);
        recover_unlock = pthread_mutex_unlock(shared_mutex);
    } else if (!e) recover_unlock = pthread_mutex_unlock(shared_mutex);
    return e;
}
int rp_robust_consistent_result(void) { return recover_consistent; }
int rp_robust_unlock_result(void) { return recover_unlock; }
