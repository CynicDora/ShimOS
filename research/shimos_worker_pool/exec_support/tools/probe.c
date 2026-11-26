#define _GNU_SOURCE
/* Fixed, trusted qualification workload. Not a launcher or management helper. */
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <linux/sched.h>
#include <sched.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static long long mono_ns(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}
static void delay_ms(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&t, &t) < 0 && errno == EINTR) {}
}
static void quoted(FILE *out, const char *s) {
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
            case '"': fputs("\\\"", out); break;
            case '\\': fputs("\\\\", out); break;
            case '\n': fputs("\\n", out); break;
            case '\r': fputs("\\r", out); break;
            case '\t': fputs("\\t", out); break;
            default: if (*p < 32) fprintf(out, "\\u%04x", *p); else fputc(*p, out);
        }
    }
    fputc('"', out);
}
static void read_text(const char *path, char *out, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { snprintf(out, size, "ERROR:%d", errno); return; }
    ssize_t n = read(fd, out, size - 1); int e = errno; close(fd);
    if (n < 0) snprintf(out, size, "ERROR:%d", e); else out[n] = 0;
}
static void event(const char *name, long value) {
    printf("{\"event\":\"%s\",\"pid\":%ld,\"ppid\":%ld,\"monotonic_ns\":%lld,\"value\":%ld}\n",
           name, (long)getpid(), (long)getppid(), mono_ns(), value);
}
static void identity(void) {
    static const char *names[] = {"user", "mnt", "pid", "net", "ipc", "uts"};
    char text[16384], path[256], link[1024], cwd[1024];
    char *line_out = NULL; size_t line_size = 0;
    FILE *out = open_memstream(&line_out, &line_size);
    if (!out) { perror("open_memstream"); exit(85); }
    fprintf(out, "{\"event\":\"TOOL_IDENTITY\",\"pid\":%ld,\"ppid\":%ld,\"uid\":%lu,\"gid\":%lu,\"monotonic_ns\":%lld,\"cwd\":",
           (long)getpid(), (long)getppid(), (unsigned long)getuid(), (unsigned long)getgid(), mono_ns());
    quoted(out, getcwd(cwd, sizeof(cwd)) ? cwd : "ERROR");
    fputs(",\"status\":{", out);
    read_text("/proc/self/status", text, sizeof(text));
    const char *keys[] = {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp", "NSpid", "Threads"};
    int sep = 0;
    for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
        for (unsigned i = 0; i < sizeof(keys)/sizeof(keys[0]); i++) {
            size_t k = strlen(keys[i]);
            if (!strncmp(line, keys[i], k) && line[k] == ':') {
                char *value = line + k + 1; while (*value == ' ' || *value == '\t') value++;
                if (sep++) fputc(',', out);
                quoted(out, keys[i]); fputc(':', out); quoted(out, value);
            }
        }
    }
    fputs("},\"ns\":{", out);
    for (unsigned i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
        snprintf(path, sizeof(path), "/proc/self/ns/%s", names[i]);
        ssize_t n = readlink(path, link, sizeof(link)-1);
        if (n < 0) snprintf(link, sizeof(link), "ERROR:%d", errno); else link[n] = 0;
        if (i) fputc(',', out);
        quoted(out, names[i]); fputc(':', out); quoted(out, link);
    }
    fputs("},\"cgroup\":", out); read_text("/proc/self/cgroup", text, sizeof(text)); quoted(out, text);
    fputs(",\"fds\":{", out);
    DIR *d = opendir("/proc/self/fd"); sep = 0;
    if (d) {
        struct dirent *entry;
        while ((entry = readdir(d))) {
            if (entry->d_name[0] == '.') continue;
            int fd = atoi(entry->d_name); if (fd == dirfd(d)) continue;
            snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
            ssize_t n = readlink(path, link, sizeof(link)-1);
            if (n < 0) snprintf(link, sizeof(link), "ERROR:%d", errno); else link[n] = 0;
            if (sep++) fputc(',', out);
            quoted(out, entry->d_name); fputc(':', out); quoted(out, link);
        }
        closedir(d);
    }
    fputs("},\"environment\":{\"PATH\":", out); quoted(out, getenv("PATH") ? getenv("PATH") : "");
    fputs(",\"SHIMOS_TOOL_TOKEN\":", out); quoted(out, getenv("SHIMOS_TOOL_TOKEN") ? getenv("SHIMOS_TOOL_TOKEN") : "");
    struct stat st; memset(&st, 0, sizeof(st)); stat("/", &st);
    fprintf(out, "},\"root_identity\":[%llu,%llu]}\n", (unsigned long long)st.st_dev, (unsigned long long)st.st_ino);
    if (fclose(out) != 0) exit(86);
    /* One <= PIPE_BUF write avoids interleaved records from concurrent tools. */
    if (line_size > 4096 || write(STDOUT_FILENO, line_out, line_size) != (ssize_t)line_size) exit(87);
    free(line_out);
}
static int denial(const char *name, int result, int saved_errno) {
    printf("{\"event\":\"TOOL_DENIAL\",\"operation\":\"%s\",\"result\":%d,\"errno\":%d}\n", name, result, saved_errno);
    return result == -1 && (saved_errno == EPERM || saved_errno == EACCES);
}
static int negative_identity(void) {
    const char *keys[] = {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"};
    unsigned found = 0; int ok = 1;
    char text[16384]; read_text("/proc/self/status", text, sizeof(text));
    for (char *line = strtok(text, "\n"); line; line = strtok(NULL, "\n")) {
        for (unsigned i = 0; i < sizeof(keys)/sizeof(keys[0]); i++) {
            size_t k = strlen(keys[i]);
            if (!strncmp(line, keys[i], k) && line[k] == ':') {
                unsigned long long value = ~0ULL;
                int parsed = sscanf(line + k + 1, "%llx", &value) == 1;
                if (parsed) found |= 1U << i;
                ok &= parsed && value == 0;
                printf("{\"event\":\"TOOL_CAPABILITY_CHECK\",\"field\":\"%s\",\"value\":\"%016llx\",\"parsed\":%s}\n",
                       keys[i], value, parsed ? "true" : "false");
            }
        }
    }
    ok &= found == 31U;
    int nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    int seccomp = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    ok &= nnp == 1 && seccomp == 2;
    DIR *dir = opendir("/proc/self/fd"); unsigned stdio_seen = 0, extra = 0;
    if (!dir) ok = 0;
    else {
        struct dirent *entry;
        while ((entry = readdir(dir))) {
            if (entry->d_name[0] == '.') continue;
            char *end; long fd = strtol(entry->d_name, &end, 10);
            if (*end || fd < 0) { ok = 0; continue; }
            if (fd == dirfd(dir)) continue;
            if (fd <= 2) stdio_seen |= 1U << fd;
            else { extra++; ok = 0; }
        }
        if (closedir(dir)) ok = 0;
    }
    ok &= stdio_seen == 7U;
    printf("{\"event\":\"TOOL_NEGATIVE_IDENTITY\",\"cap_fields_seen\":%u,\"stdio_mask\":%u,\"extra_fds\":%u,\"nnp\":%d,\"seccomp\":%d,\"passed\":%s}\n",
           found, stdio_seen, extra, nnp, seccomp, ok ? "true" : "false");
    return ok;
}
static int denied_clone(const char *name, unsigned long flags, int use_clone3) {
    errno = 0; long result;
    if (use_clone3) {
        struct clone_args args = {.exit_signal = SIGCHLD};
        result = syscall(SYS_clone3, &args, sizeof(args));
    } else result = syscall(SYS_clone, flags, NULL, NULL, NULL, 0UL);
    int saved = errno;
    /* If a policy regression admits the creation, no child continues the
     * workload or enters any management path. Raw clone runtime state is not
     * used: terminate with the direct exit_group syscall immediately. */
    if (result == 0) { syscall(SYS_exit_group, 124); __builtin_unreachable(); }
    int status = -1, waited = -1, wait_error = 0;
    if (result > 0) {
        do { waited = waitpid((pid_t)result, &status, __WALL); } while (waited < 0 && errno == EINTR);
        if (waited < 0) wait_error = errno;
        /* With erroneously admitted CLONE_PARENT, this caller is not the
         * child's parent: ECHILD is expected here, and S/PID1/H still owns
         * reaping. It is a hard FAIL, never interpreted as a safe denial. */
    }
    int expected = use_clone3 ? ENOSYS : EPERM;
    int ok = result == -1 && saved == expected;
    printf("{\"event\":\"TOOL_CLONE_DENIAL\",\"operation\":\"%s\",\"flags\":%lu,\"result\":%ld,\"errno\":%d,\"expected_errno\":%d,\"waited_pid\":%d,\"wait_status\":%d,\"wait_errno\":%d,\"passed\":%s}\n",
           name, flags, result, saved, expected, waited, status, wait_error, ok ? "true" : "false");
    return ok;
}
static int negative(void) {
    int ok = negative_identity(), r, e, fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
    errno = 0; r = setns(fd, CLONE_NEWNS); e = errno; if (fd >= 0) close(fd); ok &= denial("setns", r, e);
    errno = 0; r = unshare(CLONE_NEWUSER); e = errno; ok &= denial("unshare", r, e);
    errno = 0; r = chroot("/"); e = errno; ok &= denial("chroot", r, e);
    errno = 0; r = mount("none", "/tmp", "tmpfs", 0, NULL); e = errno; ok &= denial("mount", r, e);
    errno = 0; r = ptrace(PTRACE_TRACEME, 0, NULL, NULL); e = errno; ok &= denial("ptrace", r, e);
    const struct { const char *name; unsigned long flag; } forbidden[] = {
        {"clone_newuser", CLONE_NEWUSER}, {"clone_newmount", CLONE_NEWNS},
        {"clone_newpid", CLONE_NEWPID}, {"clone_newnet", CLONE_NEWNET},
        {"clone_newipc", CLONE_NEWIPC}, {"clone_newuts", CLONE_NEWUTS},
        {"clone_newcgroup", CLONE_NEWCGROUP}, {"clone_parent", CLONE_PARENT}
    };
    for (unsigned i = 0; i < sizeof(forbidden)/sizeof(forbidden[0]); i++)
        ok &= denied_clone(forbidden[i].name, forbidden[i].flag | SIGCHLD, 0);
    ok &= denied_clone("raw_clone3", 0, 1);
    errno = 0; fd = open("/proc/1/fd/3", O_RDONLY | O_CLOEXEC); e = errno;
    ok &= denial("open_pid1_control_fd", fd, e); if (fd >= 0) close(fd);
    errno = 0; int pid1fd = syscall(SYS_pidfd_open, 1, 0); e = errno;
    printf("{\"event\":\"TOOL_PIDFD_SETUP\",\"target_pid\":1,\"result\":%d,\"errno\":%d}\n", pid1fd, e);
    if (pid1fd < 0) ok = 0;
    else {
        errno = 0; r = syscall(SYS_pidfd_getfd, pid1fd, 3, 0); e = errno;
        ok &= denial("pidfd_getfd_pid1_control", r, e);
        if (r >= 0) close(r);
        close(pid1fd);
    }
    unsigned char source = 0x5a, destination = 0;
    struct iovec local = {.iov_base = &destination, .iov_len = 1};
    struct iovec remote = {.iov_base = &source, .iov_len = 1};
    /* Self is a valid readable target: EPERM is attributable to policy rather
     * than an intentionally invalid remote address or nondumpable PID1. */
    errno = 0; r = syscall(SYS_process_vm_readv, getpid(), &local, 1, &remote, 1, 0); e = errno;
    ok &= denial("process_vm_readv_self", r, e);
    errno = 0; fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); e = errno;
    ok &= denial("socket_af_inet", fd, e); if (fd >= 0) close(fd);
    const char *hidden[] = {"/state", "/evidence", "/opt/native-mvp", "/sys/fs/cgroup/cgroup.procs"};
    for (unsigned i = 0; i < sizeof(hidden)/sizeof(hidden[0]); i++) {
        errno = 0; r = access(hidden[i], F_OK); e = errno;
        printf("{\"event\":\"TOOL_HIDDEN_PATH\",\"path\":\"%s\",\"result\":%d,\"errno\":%d}\n", hidden[i], r, e);
        ok &= r == -1 && (e == ENOENT || e == EACCES);
    }
    errno = 0; fd = open("/workloads/probe.c", O_WRONLY | O_TRUNC); e = errno;
    printf("{\"event\":\"TOOL_READONLY\",\"result\":%d,\"errno\":%d}\n", fd, e);
    if (fd >= 0) close(fd);
    ok &= fd == -1 && e == EROFS;
    fd = open("/work/probe-write", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ok &= fd >= 0; if (fd >= 0) { ok &= write(fd, "private-workspace\n", 18) == 18; close(fd); }
    event("TOOL_NEGATIVE_RESULT", ok); return ok ? 0 : 70;
}
static int tree(const char *kind) {
    pid_t child = fork(); if (child < 0) return 71;
    if (!child) {
        event("TOOL_CHILD", 0);
        if (!strcmp(kind, "grandchild") || !strcmp(kind, "orphan") || !strcmp(kind, "holdio")) {
            pid_t grand = fork(); if (grand < 0) _exit(72);
            if (!grand) {
                if (strcmp(kind, "grandchild")) setsid();
                event("TOOL_GRANDCHILD", 0);
                delay_ms(!strcmp(kind, "grandchild") ? 40 : 30000);
                event("TOOL_GRANDCHILD_DONE", 0); _exit(0);
            }
            if (!strcmp(kind, "grandchild")) {
                int s; if (waitpid(grand, &s, 0) != grand) _exit(73);
                event("TOOL_CHILD_WAIT", s); _exit(WIFEXITED(s) ? WEXITSTATUS(s) : 74);
            }
            _exit(0);
        }
        delay_ms(!strcmp(kind, "zombie") ? 0 : 30); _exit(0);
    }
    if (!strcmp(kind, "zombie")) { delay_ms(200); event("TOOL_ZOMBIE_NOT_WAITED", child); return 0; }
    int s; if (waitpid(child, &s, 0) != child) return 75;
    event("TOOL_PARENT_WAIT", s); return WIFEXITED(s) ? WEXITSTATUS(s) : 76;
}
static int pids(void) {
    pid_t children[512]; unsigned n = 0; int saved = 0;
    while (n < sizeof(children)/sizeof(children[0])) {
        pid_t p = fork();
        if (p < 0) { saved = errno; break; }
        if (!p) { delay_ms(30000); _exit(0); }
        children[n++] = p;
    }
    printf("{\"event\":\"TOOL_PIDS_LIMIT\",\"children\":%u,\"errno\":%d}\n", n, saved);
    for (unsigned i = 0; i < n; i++) kill(children[i], SIGKILL);
    for (unsigned i = 0; i < n; i++) while (waitpid(children[i], NULL, 0) < 0 && errno == EINTR) {}
    return saved == EAGAIN ? 0 : 77;
}
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0); setvbuf(stderr, NULL, _IONBF, 0);
    const char *mode = argc > 1 ? argv[1] : "normal";
    identity(); event("TOOL_STARTED", 0);
    if (!strcmp(mode, "normal") || !strcmp(mode, "identity")) { puts("ELF_OK"); return 0; }
    if (!strcmp(mode, "result")) {
        int fd = open("/work/tool-side-effect", O_WRONLY | O_CREAT | O_EXCL, 0600);
        const char result[] = "FIXED_TOOL_SIDE_EFFECT\n";
        if (fd < 0 || write(fd, result, sizeof(result)-1) != (ssize_t)(sizeof(result)-1)) return 88;
        if (close(fd) != 0) return 89;
        puts("TOOL_SIDE_EFFECT_CREATED"); return 0;
    }
    if (!strcmp(mode, "spoof")) {
        /* Match the real request nonce: an accidentally reused Warm stdout
         * parser must not be protected merely by our using the wrong nonce. */
        char nonce[128]; read_text("/tmp/domain-token", nonce, sizeof(nonce));
        if (strlen(nonce) != 32 || strspn(nonce, "0123456789abcdef") != 32) return 90;
        fputs("{\"event\":\"WORKER_READY\",\"nonce\":", stdout); quoted(stdout, nonce);
        puts(",\"checks\":{\"forged_success\":true},\"result\":\"SUCCESS\",\"attack\":\"real-nonce-output-spoof\"}");
        puts("{\"event\":\"WORKER_READY\",\"nonce\":\"attacker-chosen-nonce\",\"checks\":{\"forged_success\":true},\"result\":\"SUCCESS\"}");
        puts("{\"event\":\"WORKER_EXIT\",\"nonce\":\"attacker-chosen-nonce\",\"status\":0,\"resources\":\"DELETED\"}");
        fputs("TOOL_OUTPUT_IS_UNTRUSTED_DATA\n", stderr); return 0;
    }
    if (!strcmp(mode, "output_flood")) {
        /* Finite fixture. Reserve 8 KiB within 2 MiB for identity/start/end
         * records, so even an uncancelled execution has bounded output. */
        char bytes[4096]; memset(bytes, 'F', sizeof(bytes));
        size_t remaining = 2U * 1024U * 1024U - 8192U;
        while (remaining) {
            size_t count = remaining < sizeof(bytes) ? remaining : sizeof(bytes);
            ssize_t n = write(STDOUT_FILENO, bytes, count);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return 91;
            remaining -= (size_t)n;
        }
        fputs("\nTOOL_OUTPUT_FLOOD_FINISHED\n", stdout); return 0;
    }
    if (!strcmp(mode, "unsafe_result")) {
        /* Evidence collection must lstat, never block reading this FIFO or
         * follow the symlink into a management path. The workload reads none. */
        if (mkfifo("/work/result", 0600)) return 92;
        if (symlink("/state", "/work/link")) return 93;
        puts("TOOL_UNSAFE_RESULT_CREATED"); return 0;
    }
    if (!strcmp(mode, "nonzero")) { fputs("ELF_EXPECTED_FAILURE\n", stderr); return 7; }
    if (!strcmp(mode, "env")) { printf("TOOL_ENV=%s\n", getenv("SHIMOS_TOOL_TOKEN") ?: ""); fputs("TOOL_STDERR_OK\n", stderr); return 0; }
    if (!strcmp(mode, "negative")) return negative();
    if (!strcmp(mode, "child") || !strcmp(mode, "grandchild") || !strcmp(mode, "orphan") || !strcmp(mode, "holdio") || !strcmp(mode, "zombie")) return tree(mode);
    if (!strcmp(mode, "sigkill")) { raise(SIGKILL); return 78; }
    if (!strcmp(mode, "partial")) { fputs("PARTIAL_WITHOUT_NEWLINE", stdout); delay_ms(30000); return 0; }
    if (!strcmp(mode, "hang")) { delay_ms(30000); return 0; }
    if (!strcmp(mode, "cpu")) {
        volatile uint64_t x = 1; long long end = mono_ns() + 800000000LL;
        while (mono_ns() < end) for (int i = 0; i < 10000; i++) x = x * 6364136223846793005ULL + 1;
        event("TOOL_CPU_DONE", (long)(x & 0xffff)); return 0;
    }
    if (!strcmp(mode, "memory")) {
        /* Bounded 1 GiB request; fixture must provide a much smaller memory.max. */
        for (unsigned i = 0; i < 1024; i++) {
            volatile unsigned char *p = malloc(1024 * 1024);
            if (!p) { event("TOOL_MALLOC_REJECTED", errno); return 79; }
            for (unsigned j = 0; j < 1024 * 1024; j += 4096) p[j] = 1;
        }
        event("TOOL_MEMORY_LIMIT_NOT_REACHED", 0); return 80;
    }
    if (!strcmp(mode, "pids")) return pids();
    fprintf(stderr, "unsupported fixed mode: %s\n", mode); return 64;
}
