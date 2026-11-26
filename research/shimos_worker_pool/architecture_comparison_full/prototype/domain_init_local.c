#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include "policy.h"

/* The local-domain trusted process creator is this trusted, single-threaded C PID1. It does
 * not hold initialized Python/library state. The child immediately execs the
 * fixed D loader/Python, before any request business or NumPy import. The
 * existing policy is unchanged; final no-exec is installed by local_zygote.py.
 * One nonce, at most one creation. CANCEL permanently closes START admission.
 * No pathname cgroup migration, external observer, or wait-by-pidfd shortcut. */
static const char *nonce, *fault;
static pid_t worker;
static int sealed, started, worker_reaped, worker_status, reaped, wait_echild;
static uint64_t ns(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
static int emit(const char *data,int fd){
 struct iovec v={.iov_base=(void*)data,.iov_len=strlen(data)};
 char control[CMSG_SPACE(sizeof(int))]={0};struct msghdr m={.msg_iov=&v,.msg_iovlen=1};
 if(fd>=0){m.msg_control=control;m.msg_controllen=sizeof(control);struct cmsghdr*c=CMSG_FIRSTHDR(&m);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));memcpy(CMSG_DATA(c),&fd,sizeof(fd));}
 return sendmsg(3,&m,MSG_NOSIGNAL)<0?-1:0;
}
static int code(int s){return WIFEXITED(s)?WEXITSTATUS(s):(WIFSIGNALED(s)?-WTERMSIG(s):255);}
static int hidden_result(void){return !strcmp(fault,"result_loss_side_effect");}
static void snapshot(const char *event){
 char m[1024];
 snprintf(m,sizeof(m),"{\"event\":\"%s\",\"nonce\":\"%s\",\"monotonic_ns\":%llu,\"sealed\":%s,\"worker_local_pid\":%d,\"w_state\":\"%s\",\"wait_known\":%s,\"wait_status\":%d,\"exit_code\":%d}",event,nonce,(unsigned long long)ns(),sealed?"true":"false",worker,!started?"ABSENT":(worker_reaped?"REAPED":"CREATED"),(worker_reaped&&!hidden_result())?"true":"false",hidden_result()?0:worker_status,hidden_result()?255:code(worker_status));
 emit(m,-1);
}
static int reap_ready(void){
 int s;pid_t q;wait_echild=0;
 while((q=waitpid(-1,&s,WNOHANG))>0){
  reaped++;char m[1024];uint64_t t=ns();
  snprintf(m,sizeof(m),"{\"event\":\"PID1_LOCAL_WAIT\",\"nonce\":\"%s\",\"pid_local\":%d,\"wait_status\":%d,\"exit_code\":%d,\"monotonic_ns\":%llu}",nonce,q,s,code(s),(unsigned long long)t);puts(m);fflush(stdout);
  if(q==worker){worker_reaped=1;worker_status=s;
   if(!strcmp(fault,"reap_ack_loss"))_exit(131);
   if(strcmp(fault,"reaped_drop")&&!hidden_result()){
    snprintf(m,sizeof(m),"{\"event\":\"LOCAL_WAITED\",\"nonce\":\"%s\",\"worker_local_pid\":%d,\"wait_status\":%d,\"exit_code\":%d,\"monotonic_ns\":%llu,\"source\":\"PID1_REAL_WAIT\"}",nonce,q,s,code(s),(unsigned long long)t);emit(m,-1);
   }
  }
 }
 if(q<0&&errno==ECHILD)wait_echild=1;
 return q<0&&errno!=ECHILD?-1:0;
}
static void stop_children(void){sealed=1;kill(-1,SIGKILL);}
static void close_fds(int*f,int n){for(int i=0;i<n;i++)close(f[i]);}
static int receive(char *buf,size_t size,int*f,int*count){
 char control[CMSG_SPACE(sizeof(int)*16)]={0};struct iovec v={.iov_base=buf,.iov_len=size-1};
 struct msghdr m={.msg_iov=&v,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
 int n=recvmsg(3,&m,MSG_CMSG_CLOEXEC);*count=0;
 if(n<=0)return n;
 for(struct cmsghdr*c=CMSG_FIRSTHDR(&m);c;c=CMSG_NXTHDR(&m,c)){
  if(c->cmsg_level!=SOL_SOCKET||c->cmsg_type!=SCM_RIGHTS)continue;
  size_t bytes=c->cmsg_len-CMSG_LEN(0);int k=(int)(bytes/sizeof(int));
  int *p=(int*)CMSG_DATA(c);for(int i=0;i<k;i++){if(*count<16)f[(*count)++]=p[i];else close(p[i]);}
 }
 if(m.msg_flags&(MSG_TRUNC|MSG_CTRUNC)){close_fds(f,*count);*count=0;errno=EMSGSIZE;return -1;}
 buf[n]=0;return n;
}
static int export_domain(void){
 const char *names[]={"user","mnt","pid","net","ipc","uts"};int f[7];char p[128],m[1024];
 for(int i=0;i<6;i++){snprintf(p,sizeof(p),"/proc/self/ns/%s",names[i]);f[i]=open(p,O_RDONLY|O_CLOEXEC);if(f[i]<0)return -1;}
 f[6]=open("/",O_PATH|O_DIRECTORY|O_CLOEXEC);if(f[6]<0)return -1;
 int mark=open("/tmp/domain-token",O_CREAT|O_EXCL|O_WRONLY,0600);if(mark<0)return -1;
 if(write(mark,nonce,strlen(nonce))!=(ssize_t)strlen(nonce))return -1;
 close(mark);
 snprintf(m,sizeof(m),"{\"event\":\"DOMAIN_READY\",\"nonce\":\"%s\",\"pid\":1,\"uid\":%u,\"group\":\"LOCAL\",\"monotonic_ns\":%llu}",nonce,getuid(),(unsigned long long)ns());
 struct iovec v={.iov_base=m,.iov_len=strlen(m)};char cb[CMSG_SPACE(sizeof(f))]={0};struct msghdr h={.msg_iov=&v,.msg_iovlen=1,.msg_control=cb,.msg_controllen=sizeof(cb)};
 struct cmsghdr*c=CMSG_FIRSTHDR(&h);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(f));memcpy(CMSG_DATA(c),f,sizeof(f));
 int rc=sendmsg(3,&h,MSG_NOSIGNAL);close_fds(f,7);return rc<0?-1:0;
}
static void start_worker(int *f){
 struct stat s;if(fstat(f[0],&s)||!S_ISDIR(s.st_mode)){sealed=1;snapshot("PROTOCOL_ERROR");return;}
 struct clone_args a={0};int pidfd=-1;
 a.flags=CLONE_INTO_CGROUP|CLONE_PIDFD;a.cgroup=f[0];a.pidfd=(uint64_t)(uintptr_t)&pidfd;a.exit_signal=SIGCHLD;
 uint64_t begin=ns();pid_t p=syscall(SYS_clone3,&a,sizeof(a));int error=errno;uint64_t end=ns();
 if(p==0){
  /* recv FDs are CLOEXEC. Keep only worker control and its output; no cgroup,
   * namespace, host-root or PID1 controller channel reaches Python. */
  if(dup2(f[2],1)<0||dup2(f[2],2)<0||dup2(f[1],3)<0)_exit(122);
  if(fcntl(3,F_SETFD,0)<0||syscall(SYS_close_range,4,~0U,0)<0)_exit(123);
  char *argv[]={"/opt/shimos-glibc/lib/ld-linux-x86-64.so.2","--library-path","/opt/shimos-glibc/lib:/opt/shimos-numpy-deps:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu","/usr/bin/python3","-B","/probe/local_zygote.py",(char*)nonce,(char*)fault,NULL};
  execv(argv[0],argv);_exit(127);
 }
 char m[1024];
 if(p<0){sealed=1;snprintf(m,sizeof(m),"{\"event\":\"LOCAL_REJECTED\",\"nonce\":\"%s\",\"errno\":%d,\"w_state\":\"ABSENT\",\"sealed\":true,\"clone_begin_ns\":%llu,\"clone_end_ns\":%llu}",nonce,error,(unsigned long long)begin,(unsigned long long)end);emit(m,-1);return;}
 worker=p;started=1;
 snprintf(m,sizeof(m),"{\"event\":\"PID1_LOCAL_CLONE\",\"nonce\":\"%s\",\"worker_local_pid\":%d,\"clone_flags\":%llu,\"clone_begin_ns\":%llu,\"clone_end_ns\":%llu}",nonce,p,(unsigned long long)a.flags,(unsigned long long)begin,(unsigned long long)end);puts(m);fflush(stdout);
 if(!strcmp(fault,"fork_ack_loss"))_exit(130);
 if(strcmp(fault,"created_drop")){
  snprintf(m,sizeof(m),"{\"event\":\"LOCAL_CREATED\",\"nonce\":\"%s\",\"worker_local_pid\":%d,\"clone_flags\":%llu,\"clone_begin_ns\":%llu,\"clone_end_ns\":%llu}",nonce,p,(unsigned long long)a.flags,(unsigned long long)begin,(unsigned long long)end);emit(m,pidfd);
 }
 close(pidfd);
}
int main(int argc,char**argv){
 if(argc!=3||getpid()!=1||strlen(argv[1])!=32||strspn(argv[1],"0123456789abcdef")!=32|| (strcmp(argv[2],"G3")&&strcmp(argv[2],"G4")))return 120;
 nonce=argv[1];fault=argv[2];
 if(prctl(PR_SET_DUMPABLE,0,0,0,0)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||apply_policy())return 121;
 if(export_domain())return 122;
 for(;;){
  if(reap_ready())return 123;
  struct pollfd p={.fd=3,.events=POLLIN|POLLHUP};int rc=poll(&p,1,10);
  if(rc<0&&errno==EINTR)continue;
  if(rc<0)return 124;
  if(!rc)continue;
  char cmd[256],wanted[128];int f[16],nf=0,n=receive(cmd,sizeof(cmd),f,&nf);
  if(n<=0){stop_children();while(waitpid(-1,NULL,0)>0||errno==EINTR){}return 125;}
  snprintf(wanted,sizeof(wanted),"START_LOCAL %s",nonce);
  if(!strcmp(cmd,wanted)){
   if(sealed||started){snapshot("START_REJECTED");}
   else if(nf!=3){sealed=1;snapshot("PROTOCOL_ERROR");}
   else start_worker(f);
   close_fds(f,nf);continue;
  }
  close_fds(f,nf);if(nf){stop_children();return 126;}
  snprintf(wanted,sizeof(wanted),"CANCEL %s",nonce);
  if(!strcmp(cmd,wanted)){stop_children();reap_ready();if(strcmp(fault,"revoke_ack_loss"))snapshot("CANCEL_ACK");continue;}
  snprintf(wanted,sizeof(wanted),"QUERY %s",nonce);
  if(!strcmp(cmd,wanted)){snapshot("SNAPSHOT");continue;}
  snprintf(wanted,sizeof(wanted),"STOP %s",nonce);
  if(!strcmp(cmd,wanted)){
   reap_ready();if(!sealed||!wait_echild){snapshot("STOP_REJECTED");continue;}
   char m[512];snprintf(m,sizeof(m),"{\"event\":\"DRAINED\",\"nonce\":\"%s\",\"echild\":true,\"reaped\":%d,\"monotonic_ns\":%llu}",nonce,reaped,(unsigned long long)ns());emit(m,-1);close(3);return 0;
  }
  stop_children();snapshot("PROTOCOL_ERROR");return 127;
 }
}
