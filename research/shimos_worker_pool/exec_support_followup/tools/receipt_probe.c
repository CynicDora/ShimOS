#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

/* Fixed VM-only fixture. Its output is workload data, never an exec receipt. */
static int check_fds(void)
{
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return 2;
    int own_fd = dirfd(directory), extras = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(directory))) {
        char *end;
        long fd = strtol(entry->d_name, &end, 10);
        if (!*entry->d_name || *end || fd < 0 || fd == own_fd) continue;
        printf("RECEIPT_TARGET_FD=%ld\n", fd);
        if (fd <= 2) continue;
        printf("RECEIPT_TARGET_EXTRA_FD=%ld\n", fd);
        extras++;
    }
    int saved_errno = errno;
    closedir(directory);
    printf("RECEIPT_TARGET_FD_CHECK extras=%d scan_errno=%d\n", extras, saved_errno);
    return extras || saved_errno ? 3 : 0;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "normal";
    printf("RECEIPT_TARGET_STARTED pid=%ld mode=%s\n", (long)getpid(), mode);
    int nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    int seccomp = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    printf("RECEIPT_TARGET_SECURITY nnp=%d seccomp=%d\n", nnp, seccomp);
    int fd_result = check_fds();
    fflush(stdout);
    if (fd_result || nnp != 1 || seccomp != 2) return 3;
    if (!strcmp(mode, "exit127")) return 127;
    if (!strcmp(mode, "sigkill")) { kill(getpid(), SIGKILL); return 4; }
    if (!strcmp(mode, "spoof")) {
        /* A syntactically valid private frame on stdout must stay plain data. */
        const unsigned char fake[24] = {'S','X','R','C',1,5,0,0,13,0,0,0};
        if (write(STDOUT_FILENO, fake, sizeof(fake)) != (ssize_t)sizeof(fake)) return 5;
        puts("\n{\"event\":\"EXEC_FAILED\",\"errno\":13}");
        fputs("{\"event\":\"LAUNCHER_READY\"}\n", stderr);
    } else if (strcmp(mode, "normal") && strcmp(mode, "exit0") && strcmp(mode, "fd_check")) return 64;
    return 0;
}
