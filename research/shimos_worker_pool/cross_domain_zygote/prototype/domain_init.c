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
#include "policy.h"

/* Trusted PID1: export self-owned objects over one inherited private channel.
 * No /proc/<protected-owner> lookup by the caller, no public listener. */
int main(int argc,char **argv){
 if(argc!=2||getpid()!=1)return 120;
 if(prctl(PR_SET_DUMPABLE,0,0,0,0)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||apply_policy())return 121;
 const char *names[]={"user","mnt","pid","net","ipc","uts"};
 int fds[7];char path[128],msg[1024];
 for(int i=0;i<6;i++){snprintf(path,sizeof(path),"/proc/self/ns/%s",names[i]);fds[i]=open(path,O_RDONLY|O_CLOEXEC);if(fds[i]<0)return 122;}
 fds[6]=open("/",O_PATH|O_DIRECTORY|O_CLOEXEC);if(fds[6]<0)return 123;
 int marker=open("/tmp/domain-token",O_CREAT|O_WRONLY|O_EXCL,0600);
 if(marker<0||write(marker,argv[1],strlen(argv[1]))!=(ssize_t)strlen(argv[1]))return 124;
 close(marker);
 snprintf(msg,sizeof(msg),"{\"event\":\"DOMAIN_READY\",\"nonce\":\"%s\",\"pid\":1,\"uid\":%d}",argv[1],getuid());
 struct iovec v={.iov_base=msg,.iov_len=strlen(msg)};char cb[CMSG_SPACE(sizeof(fds))]={0};
 struct msghdr m={.msg_iov=&v,.msg_iovlen=1,.msg_control=cb,.msg_controllen=sizeof(cb)};
 struct cmsghdr*c=CMSG_FIRSTHDR(&m);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(fds));memcpy(CMSG_DATA(c),fds,sizeof(fds));
 if(sendmsg(3,&m,MSG_NOSIGNAL)<0)return 125;
 for(int i=0;i<7;i++)close(fds[i]);
 unsigned reaped=0;int s;
 for(;;){
  while(waitpid(-1,&s,WNOHANG)>0)reaped++;
  struct pollfd p={.fd=3,.events=POLLIN|POLLHUP};int r=poll(&p,1,10);if(r<0&&errno==EINTR)continue;if(r<0)return 126;
  if(!r)continue;
  char cmd[32];int n=recv(3,cmd,sizeof(cmd),0);if(n<=0)return 125;
  if(n==4&&!memcmp(cmd,"STOP",4)){
   int q;while((q=waitpid(-1,&s,WNOHANG))>0)reaped++;
   if(q==0){send(3,"BUSY",4,MSG_NOSIGNAL);continue;}
   if(errno!=ECHILD)return 127;
   snprintf(msg,sizeof(msg),"{\"event\":\"DRAINED\",\"reaped\":%u,\"echild\":true}",reaped);
   send(3,msg,strlen(msg),MSG_NOSIGNAL);close(3);return 0;
  }
 }
}
