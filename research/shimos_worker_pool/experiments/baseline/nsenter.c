#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <linux/capability.h>
#include <sched.h>
#include <signal.h>
#include "policy.h"
/* Diagnostic only. The trusted caller supplies user,mnt,pid,root FDs.
 * It must separately reinstate any per-exec LSM/seccomp policy. */
static void ck(int r,const char*s){if(r<0){perror(s);exit(121);}}
int main(int ac,char**av){if(ac<7)return 2;ck(setns(atoi(av[1]),CLONE_NEWUSER),"userns");ck(setns(atoi(av[2]),CLONE_NEWNS),"mntns");ck(setns(atoi(av[3]),CLONE_NEWPID),"pidns");ck(fchdir(atoi(av[4])),"rootfd");ck(chroot("."),"chroot");ck(chdir("/work"),"cwd");
 ck(setns(atoi(av[5]),CLONE_NEWUSER),"inner-userns");
 int p=fork();ck(p,"fork");if(!p){struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3};struct __user_cap_data_struct d[2]={{0}};ck(syscall(SYS_capset,&h,d),"capset");ck(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0),"nnp");ck(apply_policy(),"seccomp");syscall(SYS_close_range,3,~0U,0);execvp(av[6],av+6);perror("exec");_exit(127);}int s;ck(waitpid(p,&s,0),"wait");return WIFEXITED(s)?WEXITSTATUS(s):128+WTERMSIG(s);}
