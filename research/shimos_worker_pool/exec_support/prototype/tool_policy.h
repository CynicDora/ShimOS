#ifndef SHIMOS_EXEC_SUPPORT_TOOL_POLICY_H
#define SHIMOS_EXEC_SUPPORT_TOOL_POLICY_H

/* Separate, inherited Tool Worker policy. This never replaces B-strict and
 * never changes Python Warm's additional execve/execveat prohibition.
 * Research deny-list for the frozen x86-64 guest, not a production allow-list.
 * Install only AFTER the second D fork: S still needs clone3 INTO_CGROUP. */
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#if !defined(__x86_64__)
#error "Tool policy is qualified only for the frozen Linux x86-64 guest"
#endif

#define TOOL_ERRNO(e) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (e))
#define TOOL_DENY(n) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (n), 0, 1), TOOL_ERRNO(EPERM)
#define TOOL_CLONE_FORBIDDEN ((uint32_t)(CLONE_NEWUSER | CLONE_NEWNS | \
    CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | \
    CLONE_NEWCGROUP | CLONE_NEWTIME | CLONE_PARENT | CLONE_PTRACE | CLONE_UNTRACED))

static const struct sock_filter shimos_tool_filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000U, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

    /* Classic BPF cannot inspect the pointed-to clone_args. ENOSYS allows
     * the frozen glibc __clone_internal's documented-in-source clone fallback;
     * direct clone3-only tools remain unsupported, with a recorded refusal. */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1),
    TOOL_ERRNO(ENOSYS),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 15),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, TOOL_CLONE_FORBIDDEN, 0, 1),
    TOOL_ERRNO(EPERM),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]) + 4),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
    TOOL_ERRNO(EPERM),
    /* Keep ordinary waitpid semantics: non-thread children notify SIGCHLD;
     * CLONE_THREAD tasks have no separate waitable exit signal. */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_THREAD, 4, 0),
    BPF_STMT(BPF_ALU | BPF_AND | BPF_K, CSIGNAL),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGCHLD, 1, 0),
    TOOL_ERRNO(EPERM),
    BPF_STMT(BPF_JMP | BPF_JA, 3),
    BPF_STMT(BPF_ALU | BPF_AND | BPF_K, CSIGNAL),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
    TOOL_ERRNO(EPERM),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

    /* Local UNIX IPC is available inside the private mount/network views.
     * This mode supplies no IP, netlink or packet sockets. */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 0, 3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 1, 0),
    TOOL_ERRNO(EPERM),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socketpair, 0, 3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 1, 0),
    TOOL_ERRNO(EPERM),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

    TOOL_DENY(SYS_unshare), TOOL_DENY(SYS_setns),
    TOOL_DENY(SYS_mount), TOOL_DENY(SYS_umount2), TOOL_DENY(SYS_pivot_root), TOOL_DENY(SYS_chroot),
    TOOL_DENY(SYS_fsopen), TOOL_DENY(SYS_fsconfig), TOOL_DENY(SYS_fsmount), TOOL_DENY(SYS_fspick),
    TOOL_DENY(SYS_move_mount), TOOL_DENY(SYS_open_tree), TOOL_DENY(SYS_mount_setattr),
    TOOL_DENY(SYS_ptrace), TOOL_DENY(SYS_process_vm_readv), TOOL_DENY(SYS_process_vm_writev),
    TOOL_DENY(SYS_pidfd_getfd), TOOL_DENY(SYS_kcmp),
    TOOL_DENY(SYS_process_madvise), TOOL_DENY(SYS_process_mrelease),
    TOOL_DENY(SYS_open_by_handle_at), TOOL_DENY(SYS_name_to_handle_at),
    TOOL_DENY(SYS_bpf), TOOL_DENY(SYS_perf_event_open), TOOL_DENY(SYS_userfaultfd),
    TOOL_DENY(SYS_io_uring_setup), TOOL_DENY(SYS_io_uring_enter), TOOL_DENY(SYS_io_uring_register),
    TOOL_DENY(SYS_keyctl), TOOL_DENY(SYS_add_key), TOOL_DENY(SYS_request_key),
    TOOL_DENY(SYS_fanotify_init), TOOL_DENY(SYS_fanotify_mark),
    TOOL_DENY(SYS_init_module), TOOL_DENY(SYS_finit_module), TOOL_DENY(SYS_delete_module),
    TOOL_DENY(SYS_kexec_load), TOOL_DENY(SYS_kexec_file_load), TOOL_DENY(SYS_reboot),
    TOOL_DENY(SYS_swapon), TOOL_DENY(SYS_swapoff), TOOL_DENY(SYS_acct), TOOL_DENY(SYS_syslog),
    TOOL_DENY(SYS_sethostname), TOOL_DENY(SYS_setdomainname), TOOL_DENY(SYS_iopl), TOOL_DENY(SYS_ioperm),
    TOOL_DENY(SYS_modify_ldt),

    /* In particular execve/execveat, fork/vfork, ordinary clone, wait, pipe,
     * file IO, mmap and futex remain available under inherited restrictions.
     * Executable authority comes from the controlled rootfs and launcher,
     * not from pretending this filter can compare pathname strings. */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
};

static int shimos_apply_tool_policy(void)
{
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != SECCOMP_MODE_FILTER) {
        errno = EPERM;
        return -1;
    }
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(shimos_tool_filter) / sizeof(shimos_tool_filter[0])),
        .filter = (struct sock_filter *)shimos_tool_filter
    };
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

#undef TOOL_ERRNO
#undef TOOL_DENY
#undef TOOL_CLONE_FORBIDDEN
#endif
