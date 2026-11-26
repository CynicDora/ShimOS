#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <errno.h>
#include "policy.h"

/* Optional same-guest monotonic observations, carried in the two existing
 * protocol messages. No extra FD/message, wait, permission or policy change.
 * Errors/missing final messages invalidate timing, not the lifecycle protocol. */
static int timing_on;
static unsigned timing_errors, wait_calls;
static uint64_t wait_total_ns, wait_max_ns, wait_last_begin_ns, wait_last_end_ns;
static uint64_t now_ns(void) {
 if(!timing_on)return 0;
 int saved=errno;struct timespec ts;int rc=clock_gettime(CLOCK_MONOTONIC,&ts);
 if(rc)timing_errors++;
 errno=saved;return rc?0:(uint64_t)ts.tv_sec*UINT64_C(1000000000)+(uint64_t)ts.tv_nsec;
}
static int observed_wait(int *status,int options) {
 uint64_t start=now_ns();int r=waitpid(-1,status,options),saved=errno;uint64_t end=now_ns();
 if(timing_on){
  wait_calls++;wait_last_begin_ns=start;wait_last_end_ns=end;
  if(start&&end>=start){uint64_t d=end-start;wait_total_ns+=d;if(d>wait_max_ns)wait_max_ns=d;}
 }
 errno=saved;return r;
}

/* Trusted PID1: export self-owned objects over one inherited private channel.
 * No /proc/<protected-owner> lookup by the caller, no public listener. */
int main(int argc,char **argv){
 timing_on=argc==3&&!strcmp(argv[2],"cost-on");
 uint64_t entry_ns=now_ns();
 if((argc!=2&&!timing_on)||getpid()!=1)return 120;
 uint64_t policy_begin_ns=now_ns();
 if(prctl(PR_SET_DUMPABLE,0,0,0,0))return 121;
 uint64_t dumpable_done_ns=now_ns();
 if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))return 121;
 uint64_t nnp_done_ns=now_ns();
 if(apply_policy())return 121;
 uint64_t policy_end_ns=now_ns(),export_begin_ns=now_ns();
 const char *names[]={"user","mnt","pid","net","ipc","uts"};
 int fds[7];char path[128],msg[4096];
 for(int i=0;i<6;i++){snprintf(path,sizeof(path),"/proc/self/ns/%s",names[i]);fds[i]=open(path,O_RDONLY|O_CLOEXEC);if(fds[i]<0)return 122;}
 fds[6]=open("/",O_PATH|O_DIRECTORY|O_CLOEXEC);if(fds[6]<0)return 123;
 uint64_t export_end_ns=now_ns(),marker_begin_ns=now_ns();
 int marker=open("/tmp/domain-token",O_CREAT|O_WRONLY|O_EXCL,0600);
 if(marker<0||write(marker,argv[1],strlen(argv[1]))!=(ssize_t)strlen(argv[1]))return 124;
 close(marker);
 uint64_t marker_end_ns=now_ns(),ready_ns=now_ns();
 if(timing_on){
  /* entry is C main, after the ELF loader. READY is local setup complete;
   * sendmsg return appears later in DRAINED, never confused with R receipt. */
  snprintf(msg,sizeof(msg),"{\"event\":\"DOMAIN_READY\",\"nonce\":\"%s\",\"pid\":1,\"uid\":%d,\"monotonic_ns\":%" PRIu64 ",\"timing_error\":%u,"
   "\"timing\":{\"clock\":\"CLOCK_MONOTONIC\",\"unit\":\"ns\",\"entry_ns\":%" PRIu64 ",\"policy_begin_ns\":%" PRIu64 ",\"dumpable_done_ns\":%" PRIu64 ",\"nnp_done_ns\":%" PRIu64 ",\"policy_end_ns\":%" PRIu64 ",\"export_begin_ns\":%" PRIu64 ",\"export_end_ns\":%" PRIu64 ",\"marker_begin_ns\":%" PRIu64 ",\"marker_end_ns\":%" PRIu64 ",\"ready_ns\":%" PRIu64 "}}",
   argv[1],getuid(),ready_ns,timing_errors,entry_ns,policy_begin_ns,dumpable_done_ns,nnp_done_ns,policy_end_ns,export_begin_ns,export_end_ns,marker_begin_ns,marker_end_ns,ready_ns);
 }else snprintf(msg,sizeof(msg),"{\"event\":\"DOMAIN_READY\",\"nonce\":\"%s\",\"pid\":1,\"uid\":%d}",argv[1],getuid());
 struct iovec v={.iov_base=msg,.iov_len=strlen(msg)};char cb[CMSG_SPACE(sizeof(fds))]={0};
 struct msghdr m={.msg_iov=&v,.msg_iovlen=1,.msg_control=cb,.msg_controllen=sizeof(cb)};
 struct cmsghdr*c=CMSG_FIRSTHDR(&m);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(fds));memcpy(CMSG_DATA(c),fds,sizeof(fds));
 uint64_t ready_send_begin_ns=now_ns();
 if(sendmsg(3,&m,MSG_NOSIGNAL)<0)return 125;
 uint64_t ready_send_end_ns=now_ns();
 for(int i=0;i<7;i++)close(fds[i]);
 uint64_t exports_closed_ns=now_ns();
 unsigned reaped=0;int s;
 for(;;){
  while(observed_wait(&s,WNOHANG)>0)reaped++;
  struct pollfd p={.fd=3,.events=POLLIN|POLLHUP};int r=poll(&p,1,10);if(r<0&&errno==EINTR)continue;if(r<0)return 126;
  if(!r)continue;
  char cmd[32];int n=recv(3,cmd,sizeof(cmd),0);if(n<=0)return 125;
  if(n==4&&!memcmp(cmd,"STOP",4)){
   uint64_t stop_received_ns=now_ns();
   int q;while((q=observed_wait(&s,WNOHANG))>0)reaped++;
   if(q==0){send(3,"BUSY",4,MSG_NOSIGNAL);continue;}
   if(errno!=ECHILD)return 127;
   if(timing_on){
    uint64_t drained_ns=now_ns();
    snprintf(msg,sizeof(msg),"{\"event\":\"DRAINED\",\"nonce\":\"%s\",\"reaped\":%u,\"echild\":true,\"timing\":{\"clock\":\"CLOCK_MONOTONIC\",\"unit\":\"ns\",\"clock_errors\":%u,\"ready_send_begin_ns\":%" PRIu64 ",\"ready_send_end_ns\":%" PRIu64 ",\"exports_closed_ns\":%" PRIu64 ",\"stop_received_ns\":%" PRIu64 ",\"drained_record_ns\":%" PRIu64 ",\"wait_calls\":%u,\"wait_total_wall_ns\":%" PRIu64 ",\"wait_max_wall_ns\":%" PRIu64 ",\"wait_last_begin_ns\":%" PRIu64 ",\"wait_last_end_ns\":%" PRIu64 "}}",
     argv[1],reaped,timing_errors,ready_send_begin_ns,ready_send_end_ns,exports_closed_ns,stop_received_ns,drained_ns,wait_calls,wait_total_ns,wait_max_ns,wait_last_begin_ns,wait_last_end_ns);
   }else snprintf(msg,sizeof(msg),"{\"event\":\"DRAINED\",\"reaped\":%u,\"echild\":true}",reaped);
   send(3,msg,strlen(msg),MSG_NOSIGNAL);close(3);return 0;
  }
 }
}
