#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <linux/sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include "policy.h"
/* Research baseline. Private inherited SOCK_SEQPACKET, no public listener.
 * One trusted, single-threaded PID1; no runtime or scheduling API.
 * Wire: four native uint32_t (op,id,a,b), followed by <=8192 payload bytes.
 * START=1 payload argv NULs + one delegated cgroup directory SCM_RIGHTS.
 * CANCEL=2, SHUTDOWN=3, INSPECT=4, OUTPUT_EOF=5 (trusted collector). Replies READY=10 STARTED=11 DATA=12
 * LEADER=13 DONE=14 ERROR=15 BYE=16 INSPECT=17. Ids strictly increase.
 */
#define MAXG 256
#define SZ 8192
struct msg { uint32_t op,id,a,b; char data[SZ]; };
struct group { int used,cg,ev,pfd,out,pid,status,reaped,eof,cancel,lfd,leader_seen; uint32_t id; uint64_t bytes; };
static struct group gs[MAXG];
static int ctrl,ep,sfd,stopping; static int strict_reap=1; static uint32_t lastid; static unsigned long reaps;
static void fatal(const char *s){perror(s);_exit(120);}
static void sendm(uint32_t op,uint32_t id,uint32_t a,uint32_t b,const void*data,size_t n){
 struct msg m={.op=op,.id=id,.a=a,.b=b}; if(n>SZ)fatal("message overflow"); if(n)memcpy(m.data,data,n);
 if(send(ctrl,&m,16+n,MSG_NOSIGNAL)!=(ssize_t)(16+n))fatal("control send");
}
static void add(int fd,uint32_t key,uint32_t events){struct epoll_event e={.events=events,.data.u32=key};if(epoll_ctl(ep,EPOLL_CTL_ADD,fd,&e))fatal("epoll add");}
static void delclose(int *fd){if(*fd>=0){epoll_ctl(ep,EPOLL_CTL_DEL,*fd,0);close(*fd);*fd=-1;}}
static int populated(struct group*g){char b[256];ssize_t n=pread(g->ev,b,sizeof(b)-1,0);if(n<0)fatal("events");b[n]=0;return strstr(b,"populated 1")!=NULL;}
static void killg(struct group*g){int f=openat(g->cg,"cgroup.kill",O_WRONLY|O_CLOEXEC);if(f<0)fatal("kill open");if(write(f,"1",1)!=1)fatal("kill write");close(f);g->cancel=1;}
static void reap(void){int s,p;while((p=waitpid(-1,&s,WNOHANG))>0){reaps++;for(int i=0;i<MAXG;i++)if(gs[i].used&&gs[i].pid==p){gs[i].reaped=1;if(strict_reap){if(s!=0)fatal("group reaper died");}else{gs[i].status=s;gs[i].leader_seen=1;sendm(13,gs[i].id,s,0,0,0);}}}}
static int finish(void){int active=0;reap();for(int i=0;i<MAXG;i++){struct group*g=&gs[i];if(!g->used)continue;
 if(g->reaped&&g->leader_seen&&g->eof&&!populated(g)){delclose(&g->ev);delclose(&g->pfd);close(g->cg);g->used=0;sendm(14,g->id,g->status,g->cancel,&g->bytes,sizeof(g->bytes));}
 else active++;
 }return active;}
static void start(struct msg*m,ssize_t len,int cg){
 if(cg<0||m->id<=lastid||stopping){if(cg>=0)close(cg);sendm(15,m->id,EINVAL,0,0,0);return;}lastid=m->id;
 int i;for(i=0;i<MAXG&&gs[i].id;i++);if(i==MAXG){close(cg);sendm(15,m->id,ENOSPC,0,0,0);return;}
 if(len<=16||m->data[len-17]!=0){close(cg);sendm(15,m->id,EINVAL,0,0,0);return;}
 char*av[128];int ac=0;for(ssize_t o=0;o<len-16&&ac<127;){av[ac++]=m->data+o;o+=strlen(m->data+o)+1;}av[ac]=0;
 int pp[2],lp[2]={-1,-1};if(pipe2(pp,O_CLOEXEC))fatal("pipe");if(strict_reap&&pipe2(lp,O_CLOEXEC))fatal("leader pipe");
 struct group*g=&gs[i];memset(g,0,sizeof(*g));g->id=m->id;g->cg=cg;g->ev=openat(cg,"cgroup.events",O_RDONLY|O_CLOEXEC);g->pfd=-1;g->out=pp[0];g->lfd=lp[0];
 if(g->ev<0)fatal("events open");
 struct clone_args ca={.flags=CLONE_PIDFD|(strict_reap?0:CLONE_INTO_CGROUP),.cgroup=(uint64_t)cg,.pidfd=(uint64_t)(uintptr_t)&g->pfd,.exit_signal=SIGCHLD};
 int p=syscall(SYS_clone3,&ca,sizeof(ca));
 if(p==0){
  if(strict_reap){
   if(prctl(PR_SET_CHILD_SUBREAPER,1,0,0,0))_exit(120);
   struct clone_args child={.flags=CLONE_INTO_CGROUP,.cgroup=(uint64_t)cg,.exit_signal=SIGCHLD};
   int leader=syscall(SYS_clone3,&child,sizeof(child));
   if(leader!=0){
    int saved=errno;close(pp[0]);close(pp[1]);close(lp[0]);
    if(dup2(lp[1],3)<0)_exit(120);
    syscall(SYS_close_range,4,~0U,0);
    int admitted=leader<0?-saved:leader;
    if(write(3,&admitted,sizeof(admitted))!=sizeof(admitted)||leader<0)_exit(120);
    int status,q;for(;;){q=waitpid(-1,&status,0);if(q==leader&&write(3,&status,sizeof(status))!=sizeof(status))_exit(120);if(q<0){if(errno==EINTR)continue;if(errno!=ECHILD)_exit(120);break;}}
    _exit(0);
   }
  }
  sigset_t empty;sigemptyset(&empty);sigprocmask(SIG_SETMASK,&empty,0);signal(SIGPIPE,SIG_DFL);
  if(setsid()<0)_exit(121);
  int nil=open("/dev/null",O_RDONLY);if(nil<0||dup2(nil,0)<0||dup2(pp[1],1)<0||dup2(pp[1],2)<0)_exit(122);
  if(syscall(SYS_close_range,3,~0U,0))_exit(123);
  if(prctl(PR_SET_DUMPABLE,1,0,0,0)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))_exit(124);
  execvp(av[0],av);dprintf(2,"exec failure: %s\n",strerror(errno));_exit(127);
 }
 int spawn_errno=errno;close(pp[1]);if(strict_reap)close(lp[1]);if(p<0){int e=spawn_errno;close(pp[0]);close(g->ev);close(cg);sendm(15,m->id,e,0,0,0);return;}
 if(strict_reap){int admitted=0;ssize_t n;do{n=read(lp[0],&admitted,sizeof(admitted));}while(n<0&&errno==EINTR);if(n!=sizeof(admitted)||admitted<=0)fatal("group admission");add(g->lfd,10+3*i,EPOLLIN|EPOLLHUP);}
 g->used=1;g->pid=p;add(g->ev,11+3*i,EPOLLPRI|EPOLLERR);add(g->pfd,12+3*i,EPOLLIN);
 struct msg reply={.op=11,.id=m->id,.a=p};struct iovec v={&reply,16};char cb[CMSG_SPACE(sizeof(int))]={0};struct msghdr mh={.msg_iov=&v,.msg_iovlen=1,.msg_control=cb,.msg_controllen=sizeof(cb)};
 struct cmsghdr*c=CMSG_FIRSTHDR(&mh);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));memcpy(CMSG_DATA(c),&g->out,sizeof(int));
 if(sendmsg(ctrl,&mh,MSG_NOSIGNAL)!=16)fatal("output fd send");
 close(g->out);g->out=-1;
}
static void command(void){struct msg m;char ancillary[CMSG_SPACE(sizeof(int)*4)];struct iovec v={&m,sizeof(m)};struct msghdr h={.msg_iov=&v,.msg_iovlen=1,.msg_control=ancillary,.msg_controllen=sizeof(ancillary)};
 ssize_t n=recvmsg(ctrl,&h,MSG_CMSG_CLOEXEC);if(n<=0){for(int i=0;i<MAXG;i++)if(gs[i].used)killg(&gs[i]);_exit(125);}int cg=-1;
 if(n<16||h.msg_flags&(MSG_TRUNC|MSG_CTRUNC))fatal("truncated command");
 for(struct cmsghdr*c=CMSG_FIRSTHDR(&h);c;c=CMSG_NXTHDR(&h,c))if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_RIGHTS){size_t k=(c->cmsg_len-CMSG_LEN(0))/sizeof(int);int*fs=(int*)CMSG_DATA(c);for(size_t j=0;j<k;j++){if(cg<0)cg=fs[j];else close(fs[j]);}}
 if(m.op==1){start(&m,n,cg);return;}if(cg>=0)close(cg);
 if(m.op==2){int found=0;for(int i=0;i<MAXG;i++)if(gs[i].used&&gs[i].id==m.id){killg(&gs[i]);found=1;}if(!found)sendm(15,m.id,ESRCH,0,0,0);}
 else if(m.op==5){for(int i=0;i<MAXG;i++)if(gs[i].used&&gs[i].id==m.id){gs[i].eof=1;gs[i].bytes=(uint64_t)m.a|((uint64_t)m.b<<32);}}
 else if(m.op==3){stopping=1;for(int i=0;i<MAXG;i++)if(gs[i].used)killg(&gs[i]);}
 else if(m.op==4){char b[256];int n=snprintf(b,sizeof(b),"pid=%d uid=%d dumpable=%d reaps=%lu",getpid(),getuid(),prctl(PR_GET_DUMPABLE),reaps);sendm(17,m.id,0,0,b,n);}
 else sendm(15,m.id,EINVAL,0,0,0);
}
int main(int ac,char**av){if(ac<2||ac>3)return 2;ctrl=atoi(av[1]);if(ac==3)strict_reap=atoi(av[2]);
 if(prctl(PR_SET_DUMPABLE,0,0,0,0)||prctl(PR_SET_CHILD_SUBREAPER,1,0,0,0)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))fatal("prctl");
 if(apply_policy())fatal("seccomp");
 signal(SIGPIPE,SIG_IGN);sigset_t set;sigemptyset(&set);sigaddset(&set,SIGCHLD);sigprocmask(SIG_BLOCK,&set,0);
 ep=epoll_create1(EPOLL_CLOEXEC);sfd=signalfd(-1,&set,SFD_CLOEXEC|SFD_NONBLOCK);add(ctrl,1,EPOLLIN|EPOLLHUP);add(sfd,2,EPOLLIN);
 char diag[4096]={0},line[512];int used=0;FILE*f=fopen("/proc/self/smaps_rollup","r");if(f){while(fgets(line,sizeof(line),f))if(!strncmp(line,"Pss:",4))used+=snprintf(diag+used,sizeof(diag)-used,"%s",line);fclose(f);}
 f=fopen("/proc/self/status","r");if(f){while(fgets(line,sizeof(line),f))if(!strncmp(line,"Cap",3)||!strncmp(line,"NoNewPrivs:",11)||!strncmp(line,"Seccomp",7))used+=snprintf(diag+used,sizeof(diag)-used,"%s",line);fclose(f);}
 const char*names[]={"mnt","pid","user","net","ipc"};for(int i=0;i<5;i++){char path[128],dest[128];snprintf(path,sizeof(path),"/proc/self/ns/%s",names[i]);int n=readlink(path,dest,127);if(n>=0){dest[n]=0;used+=snprintf(diag+used,sizeof(diag)-used,"%s=%s\n",names[i],dest);}}
 DIR*d=opendir("/proc/self/fd");int count=-1;struct dirent*e;while((e=readdir(d)))if(e->d_name[0]!='.')count++;closedir(d);used+=snprintf(diag+used,sizeof(diag)-used,"fds=%d\n",count);
 sendm(10,0,getpid(),getuid(),diag,used);
 for(;;){int active=finish();if(stopping&&!active){int s;pid_t p;do{p=waitpid(-1,&s,0);if(p>0)reaps++;}while(p>0||(p<0&&errno==EINTR));if(errno!=ECHILD)fatal("final wait");struct rusage a,b;getrusage(RUSAGE_SELF,&a);getrusage(RUSAGE_CHILDREN,&b);char data[1024];int n=snprintf(data,sizeof(data),"{\"reaps\":%lu,\"owner_user_us\":%ld,\"owner_system_us\":%ld,\"children_user_us\":%ld,\"children_system_us\":%ld,\"owner_nvcsw\":%ld,\"owner_nivcsw\":%ld,\"children_nvcsw\":%ld,\"children_nivcsw\":%ld}",reaps,a.ru_utime.tv_sec*1000000+a.ru_utime.tv_usec,a.ru_stime.tv_sec*1000000+a.ru_stime.tv_usec,b.ru_utime.tv_sec*1000000+b.ru_utime.tv_usec,b.ru_stime.tv_sec*1000000+b.ru_stime.tv_usec,a.ru_nvcsw,a.ru_nivcsw,b.ru_nvcsw,b.ru_nivcsw);sendm(16,0,0,0,data,n);return 0;}
 struct epoll_event es[64];int n=epoll_wait(ep,es,64,-1);if(n<0){if(errno==EINTR)continue;fatal("epoll wait");}
 for(int j=0;j<n;j++){uint32_t k=es[j].data.u32;if(k==1)command();else if(k==2){struct signalfd_siginfo s;while(read(sfd,&s,sizeof(s))>0);reap();}else{int i=(k-10)/3,typ=(k-10)%3;struct group*g=&gs[i];if(!g->used)continue;if(typ==0){int status;ssize_t z=read(g->lfd,&status,sizeof(status));if(z!=sizeof(status))fatal("leader status");g->status=status;g->leader_seen=1;delclose(&g->lfd);sendm(13,g->id,status,0,0,0);}else if(typ==2){delclose(&g->pfd);reap();}else (void)populated(g);}}
 }
}
