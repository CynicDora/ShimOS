#define _GNU_SOURCE
#include <sched.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include "policy.h"

/* Must be called through ctypes.PyDLL: GIL held, single trusted Python thread.
 * No CLONE_VM/CLONE_FS/CLONE_THREAD. CPython hooks bracket both clone3 forks. */
int py_fork_cgroup(int cgfd, int *pidfd) {
 void (*before)(void)=dlsym(RTLD_DEFAULT,"PyOS_BeforeFork");
 void (*parent)(void)=dlsym(RTLD_DEFAULT,"PyOS_AfterFork_Parent");
 void (*child)(void)=dlsym(RTLD_DEFAULT,"PyOS_AfterFork_Child");
 if(!before||!parent||!child){errno=ENOSYS;return -1;}
 struct clone_args a={.flags=CLONE_INTO_CGROUP|CLONE_PIDFD,
   .cgroup=cgfd,.pidfd=(uint64_t)(uintptr_t)pidfd,.exit_signal=SIGCHLD};
 before(); int p=syscall(SYS_clone3,&a,sizeof(a)); int e=errno;
 if(p==0) child(); else parent(); errno=e; return p;
}

/* slots: base user, inner user, mount, pid, net, ipc, uts, root. */
int enter_target(int *f) {
 if(setns(f[0],CLONE_NEWUSER))return 1;
 if(setns(f[2],CLONE_NEWNS))return 2;
 if(setns(f[4],CLONE_NEWNET))return 3;
 if(setns(f[5],CLONE_NEWIPC))return 4;
 if(setns(f[6],CLONE_NEWUTS))return 5;
 if(setns(f[3],CLONE_NEWPID))return 6;
 if(fchdir(f[7])||chroot(".")||chdir("/work"))return 7;
 if(setns(f[1],CLONE_NEWUSER))return 8;
 return 0;
}
int drop_final(void) {
 /* Joining inner userns grants new caps: drop bounding set HERE, not earlier. */
 for(int c=0;;c++){
  int r=prctl(PR_CAPBSET_READ,c,0,0,0);
  if(r<0){if(errno==EINVAL)break;return 1;}
  if(r&&prctl(PR_CAPBSET_DROP,c,0,0,0))return 2;
 }
 if(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0))return 3;
 struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3};
 struct __user_cap_data_struct d[2]={{0}};
 if(syscall(SYS_capset,&h,d))return 4;
 if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_DUMPABLE,1,0,0,0))return 5;
 if(apply_policy())return 6;
 return 0;
}
int forbid_exec(void) {
 /* Extra test-only restriction. Original B-strict filter retained unchanged. */
 struct sock_filter f[]={
  BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
  DENY(SYS_execve),DENY(SYS_execveat),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
 struct sock_fprog p={.len=sizeof(f)/sizeof(f[0]),.filter=f};
 return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p);
}
int set_base_safety(void){return prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);}
int subreaper(void){return prctl(PR_SET_CHILD_SUBREAPER,1,0,0,0);}
int install_policy(void){return apply_policy();}
int close_from(int start){return syscall(SYS_close_range,start,~0U,0);}
