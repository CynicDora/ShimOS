#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <errno.h>
#define DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(n),0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
/* Explicit research contract, not a general production allow-list. */
static struct sock_filter policy[]={
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
 BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
 BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,0x40000000,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
 DENY(SYS_unshare),DENY(SYS_setns),DENY(SYS_mount),DENY(SYS_umount2),DENY(SYS_ptrace),DENY(SYS_process_vm_writev),
 DENY(SYS_fsopen),DENY(SYS_fsmount),DENY(SYS_move_mount),DENY(SYS_open_tree),DENY(SYS_mount_setattr),
 BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
};
static int apply_policy(void){struct sock_fprog p={.len=sizeof(policy)/sizeof(policy[0]),.filter=policy};return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p);}
