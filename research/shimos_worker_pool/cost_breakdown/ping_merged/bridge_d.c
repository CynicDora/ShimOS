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
#include "bridge_timing.h"

/* Must be called through ctypes.PyDLL: GIL held, single trusted Python thread.
 * Candidate libc wrapper performs both clone3 forks and its native hooks.
 * CPython hooks remain outside the full candidate libc fork wrapper. */
int py_fork_cgroup(int cgfd, int *pidfd) {
 uint64_t t0=timing_now_ns();
 void (*before)(void)=dlsym(RTLD_DEFAULT,"PyOS_BeforeFork");
 void (*parent)(void)=dlsym(RTLD_DEFAULT,"PyOS_AfterFork_Parent");
 void (*child)(void)=dlsym(RTLD_DEFAULT,"PyOS_AfterFork_Child");
 if(!before||!parent||!child){timing_finish("fork_symbols",t0,-1,ENOSYS);errno=ENOSYS;return -1;}
 /* This symbol belongs to the explicitly built candidate libc. It is not
  * a call into a private glibc implementation symbol or a stock-libc fallback. */
 int (*fork_into_cgroup)(int,int*)=dlsym(RTLD_DEFAULT,"shimos_fork_into_cgroup");
 if(!fork_into_cgroup){timing_finish("fork_symbols",t0,-1,ENOSYS);errno=ENOSYS;return -1;}
 uint64_t t1=timing_now_ns();
 before();uint64_t t2=timing_now_ns();
 int p=fork_into_cgroup(cgfd,pidfd);int e=errno;
 uint64_t t3=timing_now_ns();
 if(p==0) child(); else parent();
 uint64_t t4=timing_now_ns();
 if(p==0){
  /* Do not duplicate the parent's prior setup or samples inherited at fork.
   * These child elapsed intervals overlap the parent's intervals, include
   * first scheduling/native callbacks, and are NOT exclusive clone3 cost. */
  timing_reset();
  timing_add("fork_vendor_call_to_child_return","child",t2,t3,0,0);
  timing_add("fork_python_after_child","child",t3,t4,0,0);
  timing_add("fork_entry_to_child_return","child",t0,t4,0,0);
 }else{
  timing_add("fork_symbols","parent",t0,t1,0,0);
  timing_add("fork_python_before","parent",t1,t2,0,0);
  timing_add("fork_vendor_call_parent","parent",t2,t3,p,p<0?e:0);
  timing_add("fork_python_after_parent","parent",t3,t4,0,0);
  timing_add("fork_entry_to_parent_return","parent",t0,t4,p,p<0?e:0);
 }
 errno=e;return p;
}

/* slots: base user, inner user, mount, pid, net, ipc, uts, root. */
int enter_target(int *f) {
 uint64_t t;int r,e;
#define TIMED_ENTER(name,expression,failure) do { t=timing_now_ns();r=(expression);e=errno;timing_finish((name),t,r,r?e:0);errno=e;if(r)return (failure); } while(0)
 TIMED_ENTER("enter_base_userns",setns(f[0],CLONE_NEWUSER),1);
 TIMED_ENTER("enter_mountns",setns(f[2],CLONE_NEWNS),2);
 TIMED_ENTER("enter_networkns",setns(f[4],CLONE_NEWNET),3);
 TIMED_ENTER("enter_ipcns",setns(f[5],CLONE_NEWIPC),4);
 TIMED_ENTER("enter_utsns",setns(f[6],CLONE_NEWUTS),5);
 TIMED_ENTER("enter_pidns_for_children",setns(f[3],CLONE_NEWPID),6);
 TIMED_ENTER("enter_root_fchdir",fchdir(f[7]),7);
 TIMED_ENTER("enter_root_chroot",chroot("."),7);
 TIMED_ENTER("enter_work_chdir",chdir("/work"),7);
 TIMED_ENTER("enter_inner_userns",setns(f[1],CLONE_NEWUSER),8);
#undef TIMED_ENTER
 return 0;
}
int drop_final(void) {
 /* Joining inner userns grants new caps: drop bounding set HERE, not earlier. */
 uint64_t t=timing_now_ns();int e,r;
 for(int c=0;;c++){
  r=prctl(PR_CAPBSET_READ,c,0,0,0);
  if(r<0){if(errno==EINVAL)break;e=errno;timing_finish("drop_bounding_set",t,1,e);errno=e;return 1;}
  if(r&&prctl(PR_CAPBSET_DROP,c,0,0,0)){e=errno;timing_finish("drop_bounding_set",t,2,e);errno=e;return 2;}
 }
 timing_finish("drop_bounding_set",t,0,0);
#define TIMED_DROP(name,expression,failure) do { t=timing_now_ns();r=(expression);e=errno;timing_finish((name),t,r,r?e:0);errno=e;if(r)return (failure); } while(0)
 TIMED_DROP("drop_ambient_set",prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0),3);
 struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3};
 struct __user_cap_data_struct d[2]={{0}};
 TIMED_DROP("drop_capset",syscall(SYS_capset,&h,d),4);
 TIMED_DROP("drop_no_new_privs",prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0),5);
 TIMED_DROP("drop_dumpable",prctl(PR_SET_DUMPABLE,1,0,0,0),5);
 TIMED_DROP("drop_seccomp_policy",apply_policy(),6);
#undef TIMED_DROP
 return 0;
}
int forbid_exec(void) {
 /* Extra test-only restriction. Original B-strict filter retained unchanged. */
 struct sock_filter f[]={
  BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
  DENY(SYS_execve),DENY(SYS_execveat),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
 struct sock_fprog p={.len=sizeof(f)/sizeof(f[0]),.filter=f};
 uint64_t t=timing_now_ns();int r=prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p),e=errno;
 timing_finish("worker_forbid_exec",t,r,r?e:0);errno=e;return r;
}
int set_base_safety(void){return prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);}
int subreaper(void){return prctl(PR_SET_CHILD_SUBREAPER,1,0,0,0);}
int install_policy(void){return apply_policy();}
int close_from(int start){return syscall(SYS_close_range,start,~0U,0);}
