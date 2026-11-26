#define _GNU_SOURCE
/* Fixed recovery fixtures, run only as an authorized Tool in the private VM.
 * This is workload code, never a launcher or a management helper. It grants no
 * authority to its marker or stdout. R's explicit fixture code observes them.
 */
#include <sys/prctl.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define STREAM_BYTES (1536U * 1024U)
#define CHUNK_BYTES 16384U
#define SPARSE_BYTES (64LL * 1024LL * 1024LL)

static void fail(const char *operation) {
    perror(operation);
    _exit(79);
}

static void write_all(int fd, const void *data, size_t length) {
    const unsigned char *p = data;
    while (length) {
        ssize_t n = write(fd, p, length);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) fail("fixture write");
        p += n;
        length -= (size_t)n;
    }
}

static int create(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) fail(path);
    return fd;
}

static void small_file(const char *path, const char *content) {
    int fd = create(path);
    write_all(fd, content, strlen(content));
    if (close(fd)) fail("fixture close");
}

static void marker(const char *mode, const char *phase) {
    char data[256];
    int n = snprintf(data, sizeof(data), "mode=%s\nphase=%s\n", mode, phase);
    if (n < 0 || (size_t)n >= sizeof(data)) _exit(79);
    small_file("/work/fixture-ready.tmp", data);
    if (rename("/work/fixture-ready.tmp", "/work/fixture-ready")) fail("fixture marker rename");
}

static void forever(void) {
    for (;;) pause();
}

static void flood(void) {
    unsigned char out[CHUNK_BYTES], err[CHUNK_BYTES];
    memset(out, 'O', sizeof(out));
    memset(err, 'E', sizeof(err));
    for (size_t written = 0; written < STREAM_BYTES; written += CHUNK_BYTES) {
        write_all(STDOUT_FILENO, out, sizeof(out));
        write_all(STDERR_FILENO, err, sizeof(err));
    }
    /* Without an active reader, this point requires each fixture pipe to hold
     * > 1.5 MiB. Only the VM's privileged test fixture changes pipe capacity;
     * this unprivileged workload neither requests nor changes it. */
    marker("flood", "both-stream-writes-completed");
    forever();
}

static void hostile(void) {
    if (mkfifo("/work/fifo", 0600)) fail("fixture mkfifo");
    if (symlink("/state", "/work/host-link")) fail("fixture symlink");
    int fd = create("/work/sparse");
    if (ftruncate(fd, SPARSE_BYTES)) fail("fixture sparse ftruncate");
    if (close(fd)) fail("fixture sparse close");
    for (unsigned i = 0; i < 140; i++) {
        char path[64];
        int n = snprintf(path, sizeof(path), "/work/entry-%03u", i);
        if (n < 0 || (size_t)n >= sizeof(path)) _exit(79);
        small_file(path, "fixed bounded hostile-directory entry\n");
    }
    marker("hostile", "all-objects-created");
    forever();
}

static void permissions(const char *mode) {
    const char *target;
    if (!strcmp(mode, "unreadable_file")) {
        target = "/work/unreadable";
        small_file(target, "fixed file unreadable by the recovery UID\n");
    } else if (!strcmp(mode, "unreadable_dir")) {
        target = "/work";
        small_file("/work/ordinary", "directory traversal must fail after chmod\n");
    } else {
        target = "/work/locked";
        if (mkdir(target, 0700)) fail("fixture locked mkdir");
        small_file("/work/locked/entry", "cannot recursively remove without directory access\n");
    }
    /* Marker creation deliberately precedes permission removal. The Controller
     * MUST corroborate target mode==000 via its private parent path, or wait a
     * documented fixture interval, before SIGKILL. Marker alone is not evidence
     * that chmod has happened. For unreadable_dir the marker becomes unreadable
     * afterward, so polling mode on the private workspace path is preferable. */
    marker(mode, "permission-change-pending");
    if (chmod(target, 0000)) fail("fixture chmod");
    forever();
}

int main(int argc, char **argv) {
    char cwd[64];
    /* Accident prevention only, not a security boundary. */
    if (!getcwd(cwd, sizeof(cwd)) || strcmp(cwd, "/work") ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 2) {
        fputs("recovery_probe requires the authorized /work Tool environment\n", stderr);
        return 78;
    }
    if (argc != 2) return 64;
    if (!strcmp(argv[1], "flood")) flood();
    else if (!strcmp(argv[1], "hostile")) hostile();
    else if (!strcmp(argv[1], "unreadable_file") ||
             !strcmp(argv[1], "unreadable_dir") ||
             !strcmp(argv[1], "undeletable")) permissions(argv[1]);
    else return 64;
    return 0;
}
