#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
static void event(const char *s){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);dprintf(1,"%s pid=%d ppid=%d sid=%d t=%ld.%09ld\n",s,getpid(),getppid(),getsid(0),t.tv_sec,t.tv_nsec);}
int main(int argc,char **v){
 if(argc<2)return 2;
 if(!strcmp(v[1],"tree")){
  event("leader");pid_t p=fork();if(p<0)return 3;
  if(p>0){usleep(30000);event("leader_exit");return 0;}
  if(setsid()<0)return 4;
  event("session_child");p=fork();if(p<0)return 3;
  if(p>0){event("middle_exit");return 0;}
  event("orphan_ready");for(;;)pause();
 }
 if(!strcmp(v[1],"hold")){event("ready");usleep(argc>2?atoi(v[2])*1000:100000);event("done");return 0;}
 if(!strcmp(v[1],"forkrace")){
  event("ready");for(int i=0;i<64;i++){pid_t p=fork();if(!p){setsid();event("fork_child");usleep(5000000);_exit(0);}usleep(1000);}pause();return 0;
 }
 if(!strcmp(v[1],"pids")){
  int count=0;while(1){pid_t p=fork();if(p<0){dprintf(1,"fork_denied errno=%d count=%d\n",errno,count);break;}if(!p){pause();_exit(0);}count++;}event("ready");pause();return 0;
 }
 if(!strcmp(v[1],"memory")){event("ready");for(int i=0;i<128;i++){char *p=malloc(1024*1024);if(!p)return 5;memset(p,1,1024*1024);asm volatile(""::"r"(p):"memory");usleep(1000);}pause();}
 if(!strcmp(v[1],"escape")){int f=open(v[2],O_WRONLY);dprintf(1,"cgroup_open fd=%d errno=%d\n",f,errno);return f<0?0:9;}
 if(!strcmp(v[1],"failchild")){pid_t p=fork();if(!p){raise(SIGSEGV);_exit(9);}int s;waitpid(p,&s,0);dprintf(1,"child_status=%d\n",s);return 0;}
 if(!strcmp(v[1],"produce")){
  char tmp[4096];snprintf(tmp,sizeof(tmp),"%s.tmp",v[2]);int f=open(tmp,O_CREAT|O_TRUNC|O_WRONLY,0644);if(f<0)return 5;
  if(write(f,"immutable intermediate\n",23)!=23)return 6;
  close(f);event("temp_ready");
  if(argc>3)usleep(atoi(v[3])*1000);
  if(rename(tmp,v[2])<0)return 7;
  event("published");for(;;)pause();
 }
 if(!strcmp(v[1],"readfd")){int f=open(v[2],O_RDONLY);if(f<0)return 5;event("opened");usleep(150000);char b[256];int n=read(f,b,sizeof(b));dprintf(1,"read_bytes=%d\n",n);close(f);return n>0?0:6;}
 return 2;
}
