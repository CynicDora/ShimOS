#define _GNU_SOURCE
/* Diagnostic interposer, NOT an alternative fork implementation.
 * Intended contract: one trusted importing/forking thread; no dlclose/unloading.
 * Real callbacks, non-NULL positions, dso_handle and registration result remain.
 * No allocation, locks, dlsym, formatting or IO in callback trampolines.
 * PID/TID below are namespace-local. The external controller maps host identity.
 */
#include <dlfcn.h>
#include <errno.h>
#include <linux/capability.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define SLOTS 16
#define EVENTS 128
typedef void (*callback_t)(void);
typedef int (*register_t)(callback_t,callback_t,callback_t,void *);
typedef int (*create_t)(pthread_t *,const pthread_attr_t *,void *(*)(void *),void *);
static register_t real_register;
static create_t real_create;
static _Atomic int resolve_errors, registering, registration_overlap;
static _Atomic unsigned long registration_attempts, registration_successes;
static _Atomic unsigned long registration_failures, registration_overflow;
static __thread int resolving;
struct slot {
  _Atomic int state; /* 0 free; 1 being registered; 2 successful; 3 failed */
  callback_t callback[3];
  void *dso_handle;
  int rc;
};
static struct slot registry[SLOTS];
struct event {
  unsigned long seq;
  int slot, phase, edge;
  pid_t pid,tid;
  uint64_t monotonic_ns, cap_eff, cap_prm;
  int capget_rc,nnp,seccomp,clock_errno;
};
static struct event events[EVENTS];
static _Atomic pid_t observation_pid;
static _Atomic unsigned long event_total, event_overwritten, observation_errors;
static _Atomic unsigned long callback_enter[SLOTS][3],callback_exit[SLOTS][3];
static _Atomic unsigned long create_attempts,create_successes,create_failures;
static _Atomic int create_last_rc;

static void resolve_next(void) {
  int saved=errno;
  if (resolving) {atomic_fetch_add(&resolve_errors,1);errno=saved;return;}
  resolving=1;
  if(!real_register) real_register=(register_t)dlsym(RTLD_NEXT,"__register_atfork");
  if(!real_create) real_create=(create_t)dlsym(RTLD_NEXT,"pthread_create");
  if(!real_register || !real_create) atomic_fetch_add(&resolve_errors,1);
  resolving=0;errno=saved;
}

/* Called first by the sole surviving thread after fork. Registry is inherited;
 * only observations/counters are reset. No callback execution is fabricated. */
static pid_t ensure_pid(void) {
  pid_t pid=(pid_t)syscall(SYS_getpid);
  if(atomic_load(&observation_pid)!=pid) {
    for(int i=0;i<SLOTS;i++)for(int j=0;j<3;j++) {
      atomic_store(&callback_enter[i][j],0);atomic_store(&callback_exit[i][j],0);
    }
    atomic_store(&event_total,0);atomic_store(&event_overwritten,0);
    atomic_store(&observation_errors,0);
    atomic_store(&create_attempts,0);atomic_store(&create_successes,0);
    atomic_store(&create_failures,0);atomic_store(&create_last_rc,0);
    atomic_store(&observation_pid,pid);
  }
  return pid;
}

static void record_event(int slot,int phase,int edge) {
  int saved=errno;
  pid_t pid=ensure_pid();
  unsigned long seq=atomic_fetch_add(&event_total,1);
  if(seq>=EVENTS) atomic_fetch_add(&event_overwritten,1);
  struct event e={.seq=seq,.slot=slot,.phase=phase,.edge=edge,.pid=pid,
                  .tid=(pid_t)syscall(SYS_gettid)};
  struct timespec ts;
  if(clock_gettime(CLOCK_MONOTONIC,&ts)==0)
    e.monotonic_ns=(uint64_t)ts.tv_sec*1000000000ULL+(uint64_t)ts.tv_nsec;
  else {e.clock_errno=errno;atomic_fetch_add(&observation_errors,1);}
  struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};
  struct __user_cap_data_struct d[2]={{0},{0}};
  e.capget_rc=(int)syscall(SYS_capget,&h,d);
  if(e.capget_rc==0) {
    e.cap_eff=((uint64_t)d[1].effective<<32)|d[0].effective;
    e.cap_prm=((uint64_t)d[1].permitted<<32)|d[0].permitted;
  } else atomic_fetch_add(&observation_errors,1);
  e.nnp=prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0);
  e.seccomp=prctl(PR_GET_SECCOMP,0,0,0,0);
  if(e.nnp<0 || e.seccomp<0)atomic_fetch_add(&observation_errors,1);
  events[seq%EVENTS]=e;
  if(edge==0)atomic_fetch_add(&callback_enter[slot][phase],1);
  else atomic_fetch_add(&callback_exit[slot][phase],1);
  errno=saved;
}

static void invoke(int slot,int phase) {
  callback_t f=registry[slot].callback[phase];
  record_event(slot,phase,0);
  f(); /* original callback: preserving changes to errno made by that callback */
  record_event(slot,phase,1);
}
#define WRAPS(N) static void pre##N(void){invoke(N,0);} \
 static void par##N(void){invoke(N,1);} static void chi##N(void){invoke(N,2);}
WRAPS(0) WRAPS(1) WRAPS(2) WRAPS(3) WRAPS(4) WRAPS(5) WRAPS(6) WRAPS(7)
WRAPS(8) WRAPS(9) WRAPS(10) WRAPS(11) WRAPS(12) WRAPS(13) WRAPS(14) WRAPS(15)
#define ROW(N) {pre##N,par##N,chi##N}
static callback_t wrappers[SLOTS][3]={ROW(0),ROW(1),ROW(2),ROW(3),ROW(4),ROW(5),
 ROW(6),ROW(7),ROW(8),ROW(9),ROW(10),ROW(11),ROW(12),ROW(13),ROW(14),ROW(15)};

__attribute__((constructor)) static void audit_init(void) {
  int saved=errno;resolve_next();ensure_pid();errno=saved;
}

int __register_atfork(callback_t prepare,callback_t parent,callback_t child,void *handle) {
  int saved=errno;
  if(!real_register)resolve_next();
  if(!real_register) {errno=saved;return ENOSYS;}
  atomic_fetch_add(&registration_attempts,1);
  if(atomic_fetch_add(&registering,1)!=0)atomic_fetch_add(&registration_overlap,1);
  int selected=-1;
  for(int i=0;i<SLOTS;i++) {
    int expected=0;
    if(atomic_compare_exchange_strong(&registry[i].state,&expected,1)){selected=i;break;}
  }
  int rc;
  errno=saved;
  if(selected<0) {
    /* Never alter libc's registration result or drop a real handler. Missing
     * instrumentation is explicit and disqualifies the diagnostic profile. */
    atomic_fetch_add(&registration_overflow,1);
    rc=real_register(prepare,parent,child,handle);
  } else {
    struct slot *s=&registry[selected];
    s->callback[0]=prepare;s->callback[1]=parent;s->callback[2]=child;s->dso_handle=handle;
    rc=real_register(prepare?wrappers[selected][0]:NULL,
                     parent?wrappers[selected][1]:NULL,
                     child?wrappers[selected][2]:NULL,handle);
    s->rc=rc;atomic_store(&s->state,rc==0?2:3);
  }
  int after=errno;
  if(rc==0)atomic_fetch_add(&registration_successes,1);
  else atomic_fetch_add(&registration_failures,1);
  atomic_fetch_sub(&registering,1);errno=after;return rc;
}

int pthread_create(pthread_t *thread,const pthread_attr_t *attr,
                   void *(*start)(void *),void *arg) {
  int saved=errno;
  if(!real_create)resolve_next();
  if(!real_create){errno=saved;return ENOSYS;}
  ensure_pid();atomic_fetch_add(&create_attempts,1);errno=saved;
  int rc=real_create(thread,attr,start,arg),after=errno;
  atomic_store(&create_last_rc,rc);
  if(rc==0)atomic_fetch_add(&create_successes,1);
  else atomic_fetch_add(&create_failures,1);
  errno=after;return rc;
}

struct output {char *buf;size_t size,used;int error;};
static void append(struct output *o,const char *fmt,...) {
  if(o->error)return;
  va_list ap;va_start(ap,fmt);
  int n=vsnprintf(o->buf+o->used,o->size-o->used,fmt,ap);va_end(ap);
  if(n<0 || (size_t)n>=o->size-o->used){o->error=ENOSPC;return;}
  o->used+=(size_t)n;
}
static void json_string(struct output *o,const char *s) {
  append(o,"\"");
  if(s)for(const unsigned char *p=(const unsigned char *)s;*p;p++) {
    if(*p=='"'||*p=='\\')append(o,"\\%c",*p);
    else if(*p<32)append(o,"\\u%04x",*p);
    else append(o,"%c",*p);
  }
  append(o,"\"");
}
static const char *phases[3]={"prepare","parent","child"};

/* Snapshot is outside all fork callbacks. Counts/ring are NOT drained.
 * Caller must be the sole thread and must reject concurrent registration,
 * observation loss, lookup errors, overflow or ENOSPC. */
int shimos_numpy_audit_snapshot(char *buffer,size_t size) {
  int saved=errno;
  if(!buffer || size<2){errno=saved;return EINVAL;}
  pid_t pid=ensure_pid();struct output o={.buf=buffer,.size=size};
  unsigned long total=atomic_load(&event_total);
  append(&o,"{\"schema\":1,\"diagnostic_interposer\":true,\"pid\":%d,\"tid\":%ld,"
    "\"pid_scope\":\"current_pid_namespace\",\"clock\":\"CLOCK_MONOTONIC\","
    "\"event_capacity\":%d,\"event_total\":%lu,\"event_overwritten\":%lu,"
    "\"observation_errors\":%lu,\"resolve_errors\":%d,\"registration_overlap\":%d,"
    "\"registration_in_progress\":%d,\"registration_attempts_inherited_or_local\":%lu,"
    "\"registration_successes_inherited_or_local\":%lu,\"registration_failures_inherited_or_local\":%lu,"
    "\"registration_overflow_inherited_or_local\":%lu,\"pthread_create\":{"
    "\"attempts\":%lu,\"successes\":%lu,\"failures\":%lu,\"last_rc\":%d},\"registry\":[",
    pid,syscall(SYS_gettid),EVENTS,total,atomic_load(&event_overwritten),
    atomic_load(&observation_errors),atomic_load(&resolve_errors),atomic_load(&registration_overlap),
    atomic_load(&registering),atomic_load(&registration_attempts),atomic_load(&registration_successes),
    atomic_load(&registration_failures),atomic_load(&registration_overflow),
    atomic_load(&create_attempts),atomic_load(&create_successes),atomic_load(&create_failures),atomic_load(&create_last_rc));
  int comma=0;
  for(int i=0;i<SLOTS;i++) {
    struct slot *s=&registry[i];int state=atomic_load(&s->state);if(!state)continue;
    append(&o,"%s{\"slot\":%d,\"state\":%d,\"registration_rc\":%d,\"dso_handle\":\"%p\",\"callbacks\":{",
      comma++?",":"",i,state,s->rc,s->dso_handle);
    for(int k=0;k<3;k++) {
      Dl_info info={0};if(s->callback[k])dladdr((void *)s->callback[k],&info);
      append(&o,"%s\"%s\":{\"present\":%s,\"address\":\"%p\",\"dso\":",
        k?",":"",phases[k],s->callback[k]?"true":"false",(void *)s->callback[k]);
      json_string(&o,info.dli_fname);append(&o,",\"symbol\":");json_string(&o,info.dli_sname);
      append(&o,",\"enter\":%lu,\"exit\":%lu}",atomic_load(&callback_enter[i][k]),atomic_load(&callback_exit[i][k]));
    }
    append(&o,"}}");
  }
  append(&o,"],\"events\":[");comma=0;
  for(unsigned long seq=total>EVENTS?total-EVENTS:0;seq<total;seq++) {
    struct event *e=&events[seq%EVENTS];
    append(&o,"%s{\"seq\":%lu,\"slot\":%d,\"phase\":\"%s\",\"edge\":\"%s\","
      "\"pid\":%d,\"tid\":%d,\"monotonic_ns\":%llu,\"capget_rc\":%d,"
      "\"cap_eff\":\"%016llx\",\"cap_prm\":\"%016llx\",\"nnp\":%d,\"seccomp\":%d,\"clock_errno\":%d}",
      comma++?",":"",e->seq,e->slot,phases[e->phase],e->edge?"exit":"enter",e->pid,e->tid,
      (unsigned long long)e->monotonic_ns,e->capget_rc,(unsigned long long)e->cap_eff,
      (unsigned long long)e->cap_prm,e->nnp,e->seccomp,e->clock_errno);
  }
  append(&o,"]}");errno=saved;return o.error;
}
