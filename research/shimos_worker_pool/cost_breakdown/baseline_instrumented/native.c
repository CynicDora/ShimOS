#define _GNU_SOURCE
#include <linux/sched.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
/* Single-threaded trusted caller only; no fallback to post-exec migration. */
int bg_spawn(int cgfd, int outfd, char *const argv[], int *pidfd, int unprivileged, int keepfd) {
 struct clone_args a={0};
 a.flags=CLONE_INTO_CGROUP|CLONE_PIDFD; a.cgroup=cgfd;
 a.pidfd=(uint64_t)(uintptr_t)pidfd; a.exit_signal=SIGCHLD;
 int p=syscall(SYS_clone3,&a,sizeof(a));
 if(p!=0) return p;
 if(setsid()<0) _exit(121);
 if(dup2(outfd,1)<0 || dup2(outfd,2)<0) _exit(122);
 int n=open("/dev/null",O_RDONLY); if(n>=0){dup2(n,0);close(n);}
 if(keepfd>=0){if(dup2(keepfd,3)<0)_exit(124);fcntl(3,F_SETFD,0);syscall(SYS_close_range,4,~0U,0);}
 else syscall(SYS_close_range,3,~0U,0);
 if(unprivileged && geteuid()==0 && (setgroups(0,NULL)<0 || setgid(65534)<0 || setuid(65534)<0)) _exit(123);
 prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
 execv(argv[0],argv);_exit(127);
}
