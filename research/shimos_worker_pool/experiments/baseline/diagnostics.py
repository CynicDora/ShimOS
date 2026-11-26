# Loaded into suite globals after private-VM guard and unprivileged transition.
import errno,signal,pty,termios,fcntl
class NativeProcess:
 def __init__(self,pid,readfd):self.pid=pid;self.returncode=None;self.stdout=os.fdopen(readfd,'rb',buffering=0)
 def poll(self):
  if self.returncode is None:
   p,s=os.waitpid(self.pid,os.WNOHANG)
   if p:self.returncode=os.waitstatus_to_exitcode(s)
  return self.returncode
 def wait(self):
  if self.returncode is None:self.returncode=os.waitstatus_to_exitcode(os.waitpid(self.pid,0)[1])
  return self.returncode

class Raw:
 seq=0
 def __init__(self,name,argv=None,work=None,die=True,newsession=True,keep=(),modify=None,stdio=None):
  Raw.seq+=1;self.name=f'raw{Raw.seq}-{name}';self.t0=now();self.cpu0=time.process_time_ns();self.cg=CG/self.name;self.cg.mkdir();delegate(self.cg);(self.cg/'pids.max').write_text('256');(self.cg/'memory.max').write_text(str(512*1024**2));(self.cg/'cpu.max').write_text('400000 100000');self.ownwork=work is None;self.work=work or R/self.name
  if self.ownwork:self.work.mkdir()
  cmd=bwrap(self.work,argv or ['/bin/true'],asinit=False,die=die,newsession=newsession)
  if modify:cmd=modify(cmd)
  policyfd=None
  if cmd[0].endswith('ld-linux-x86-64.so.2'):
   policyfd=os.open(P/'policy.bpf',os.O_RDONLY);keep=tuple(keep)+(policyfd,);cmd=cmd[:4]+['--seccomp',str(policyfd)]+cmd[4:]
  def gate():
   (self.cg/'cgroup.procs').write_text(str(os.getpid()))
  if modify is None and stdio is None and len(keep)==1 and policyfd is not None:
   cmd[cmd.index('--seccomp')+1]='3';rr,ww=os.pipe2(os.O_CLOEXEC);pid,self.pfd=spawn(cmd,self.cg,ww,keepfd=policyfd);os.close(ww);self.p=NativeProcess(pid,rr);self.launch='native-atomic'
  else:
   self.p=subprocess.Popen(cmd,stdin=subprocess.DEVNULL if stdio is None else stdio,stdout=subprocess.PIPE if stdio is None else stdio,stderr=subprocess.STDOUT,pass_fds=keep,preexec_fn=gate,start_new_session=(stdio is None),env=os.environ.copy());self.pfd=os.pidfd_open(self.p.pid);self.launch='python-trusted-gate'
  if policyfd is not None:os.close(policyfd)
  self.buf=b'';self.eof=stdio is not None;self.first=None;self.ep=select.epoll();self.cfd=os.open(self.cg/'cgroup.events',os.O_RDONLY);self.ep.register(self.cfd,select.EPOLLPRI|select.EPOLLERR);self.ep.register(self.pfd,select.EPOLLIN)
  if self.p.stdout:os.set_blocking(self.p.stdout.fileno(),False);self.ep.register(self.p.stdout.fileno(),select.EPOLLIN|select.EPOLLHUP)
 def pump(self,timeout=5):
  for fd,e in self.ep.poll(timeout):
   if self.p.stdout and fd==self.p.stdout.fileno():
    while True:
     try:d=os.read(fd,65536)
     except BlockingIOError:break
     if not d:self.eof=True;self.ep.unregister(fd);break
     if self.first is None:self.first=now()
     self.buf+=d
   elif fd==self.cfd:os.pread(fd,256,0)
   elif fd==self.pfd:self.ep.unregister(fd);self.p.poll()
 def until(self,token):
  end=time.monotonic()+15
  while token not in self.buf:
   if time.monotonic()>end:raise TimeoutError((self.name,self.buf))
   self.pump()
 def kill(self): (self.cg/'cgroup.kill').write_text('1')
 def release(self,kill=False,reap_all=False):
  if kill:self.kill()
  end=time.monotonic()+15
  while not (self.eof and self.p.poll() is not None and b'populated 0' in os.pread(self.cfd,256,0)):
   if time.monotonic()>end:raise TimeoutError((self.name,self.buf,self.p.returncode))
   self.pump()
  self.p.wait();os.close(self.pfd);os.close(self.cfd);self.ep.close()
  if self.p.stdout:self.p.stdout.close()
  while True:
   try:p,s=os.waitpid(-1,0 if reap_all else os.WNOHANG)
   except ChildProcessError:break
   if not p:break
  st=stats(self.cg);self.cg.rmdir()
  if self.ownwork:shutil.rmtree(self.work)
  self.t1=now();r=dict(name=self.name,launch=self.launch,ms=(self.t1-self.t0)/1e6,first_ms=None if self.first is None else (self.first-self.t0)/1e6,client_cpu_ms=(time.process_time_ns()-self.cpu0)/1e6,rc=self.p.returncode,stats=st,output=self.buf.decode(errors='replace'))
  emit({'raw':r});return r

def namespaces():
 # Standard initial program is dumpable, unlike protected persistent PID1.
 source=Raw('ns-source',['/usr/bin/python3','-u','-c',"import os,time,json;open('/tmp/marker','w').write('same-object');print(json.dumps({'mnt':os.readlink('/proc/self/ns/mnt'),'pid':os.readlink('/proc/self/ns/pid'),'user':os.readlink('/proc/self/ns/user'),'inode':os.stat('/tmp/marker').st_ino}),flush=True);print('READY',flush=True);time.sleep(60)"])
 source.until(b'READY');origin=json.loads(source.buf.splitlines()[0]);target=next(int(p) for p in (source.cg/'cgroup.procs').read_text().split() if Path(f'/proc/{p}/comm').read_text().strip()=='python3')
 fds=[os.open(f'/proc/{target}/ns/{n}',os.O_RDONLY) for n in ['user','mnt','pid']]+[os.open(f'/proc/{target}/root',os.O_RDONLY|os.O_DIRECTORY)]
 query="import os,json; print(json.dumps({'mnt':os.readlink('/proc/self/ns/mnt'),'pid':os.readlink('/proc/self/ns/pid'),'user':os.readlink('/proc/self/ns/user'),'marker':os.path.exists('/tmp/marker')}))"
 def partial(cmd):
  for opt in ['--unshare-user','--disable-userns','--unshare-pid']:cmd.remove(opt)
  return cmd[:4]+['--userns',str(fds[0]),'--pidns',str(fds[2])]+cmd[4:]
 second=Raw('partial-ns',['/usr/bin/python3','-c',query],work=source.work,keep=fds,modify=partial);r=second.release()
 check('inner-userns-cannot-enter-ancestor-owned-pidns',r['rc']!=0 and 'Operation not permitted' in r['output'],failure=r['output'])
 baseuser=fcntl.ioctl(fds[1],0xb701);fds.append(baseuser) # NS_GET_USERNS
 def partial_correct(cmd):
  for opt in ['--unshare-user','--disable-userns','--unshare-pid']:cmd.remove(opt)
  return cmd[:4]+['--userns',str(baseuser),'--userns2',str(fds[0]),'--pidns',str(fds[2])]+cmd[4:]
 second=Raw('partial-correct',['/usr/bin/python3','-c',query],work=source.work,keep=fds,modify=partial_correct);r=second.release();assert r['rc']==0,r;v=json.loads(r['output'])
 check('partial-namespace-reuse-does-not-reuse-mount',r['rc']==0 and v['pid']==origin['pid'] and v['user']==origin['user'] and v['mnt']!=origin['mnt'] and not v['marker'],origin=origin,partial=v)
 third=Raw('setns',['/bin/true'],work=source.work,keep=fds,modify=lambda cmd:[str(P/'nsenter')]+list(map(str,[baseuser,fds[1],fds[2],fds[3],fds[0]]))+['/usr/bin/python3','-c',query]);r=third.release();v=json.loads(r['output'])
 check('rootless-explicit-setns-preserves-view',r['rc']==0 and v['mnt']==origin['mnt'] and v['pid']==origin['pid'] and v['marker'],joined=v)
 source.release(kill=True)
 # Namespace descriptors keep kernel namespace objects referenced, despite all processes gone.
 check('namespace-fd-outlives-processes',all(os.fstat(f).st_ino>0 for f in fds),identities=[os.fstat(f).st_ino for f in fds]);[os.close(f) for f in fds]

def signals():
 # Issue726 operational equivalent: actual terminal line discipline injects Ctrl-C.
 for new in [False,True]:
  for die in [False,True]:
   w=R/f'pty-{new}-{die}';w.mkdir();cg=CG/f'pty-{new}-{die}';cg.mkdir();delegate(cg)
   pid,master=pty.fork()
   if pid==0:
    (cg/'cgroup.procs').write_text(str(os.getpid()));argv=bwrap(w,['/bin/sh','-c','echo READY; exec /bin/sleep 60'],asinit=False,die=die,newsession=new);os.execv(argv[0],argv)
   os.set_blocking(master,False);buf=b'';end=time.monotonic()+10
   while b'READY' not in buf:
    assert time.monotonic()<end
    if select.select([master],[],[],1)[0]:buf+=os.read(master,4096)
   os.write(master,b'\x03');_,status=os.waitpid(pid,0)
   # Observe readiness then cleanup; timer is observation grace, not race correctness.
   fd=os.open(cg/'cgroup.events',os.O_RDONLY);ep=select.epoll();ep.register(fd,select.EPOLLPRI|select.EPOLLERR);deadline=time.monotonic()+.1
   while b'populated 1' in os.pread(fd,256,0) and time.monotonic()<deadline:ep.poll(max(0,deadline-time.monotonic()))
   left=b'populated 1' in os.pread(fd,256,0);check(f'pty-newsession-{new}-die-{die}',left==(new and not die),monitor_wait_status=status,populated_after_ctrl_c=left)
   (cg/'cgroup.kill').write_text('1')
   while b'populated 1' in os.pread(fd,256,0):ep.poll(5)
   os.close(master);os.close(fd);ep.close()
   while True:
    try:q,s=os.waitpid(-1,os.WNOHANG)
    except ChildProcessError:break
    if not q:break
   cg.rmdir();shutil.rmtree(w)
 # Correct PTY within a group: child's session owns slave, monitor stays outside.
 t=Task('pty-owner')
 code="""import pty,os,signal,select,time
p,m=pty.fork()
if not p:
 os.execl('/bin/sh','sh','-c','trap "echo INTERRUPTED; exit 0" INT; echo READY; while :; do sleep 1; done')
b=b''
while b'READY' not in b:b+=os.read(m,4096)
os.write(m,b'\\x03')
while True:
 try:d=os.read(m,4096)
 except OSError:break
 if not d:break
 b+=d
q,s=os.waitpid(p,0);os.close(m);assert b'INTERRUPTED' in b;print('PTY_OK',s)
"""
 g=t.start(['/usr/bin/python3','-c',code]);r=t.wait(g);check('group-owned-pty-ctrl-c',r['status']==0 and b'PTY_OK' in r['output']);t.close()

def faults():
 for role in ['pid1','monitor','control-eof']:
  t=Task('fault-'+role);a=t.start(['/probe/payload','tree']);t.until_output(a,b'orphan_ready')
  group=t.groups[a];captured=(group['cg']/'cgroup.procs').read_text().split();pid1=next(int(p) for p in (t.control/'cgroup.procs').read_text().split() if Path(f'/proc/{p}/comm').read_text().strip()=='owner')
  if role=='pid1':os.kill(pid1,signal.SIGKILL)
  elif role=='monitor':os.kill(t.pid,signal.SIGKILL)
  else:t.sock.shutdown(socket.SHUT_RDWR)
  # Independent manager recovers explicitly, without relying on the dead owner.
  os.waitid(os.P_PIDFD,t.pfd,os.WEXITED);os.close(t.pfd)
  fd=os.open(t.cg/'cgroup.events',os.O_RDONLY);ep=select.epoll();ep.register(fd,select.EPOLLPRI|select.EPOLLERR);deadline=time.monotonic()+10
  while b'populated 1' in os.pread(fd,256,0):
   assert time.monotonic()<deadline;ep.poll(1)
  ep.close();os.close(fd)
  for key in list(t.sel.get_map().values()):
   if key.data[0]=='output':
    while True:
     try:d=os.read(key.fd,65536)
     except BlockingIOError:continue
     if not d:break
    os.close(key.fd)
  t.sel.close();t.sock.close();t.log.close()
  while True:
   try:p,s=os.waitpid(-1,os.WNOHANG)
   except ChildProcessError:break
   if not p:break
  (group['cg']).rmdir();t.control.rmdir();t.cg.rmdir();shutil.rmtree(t.work)
  check('failure-'+role+'-domain-recovery',not t.cg.exists() and all(not Path('/proc/'+p).exists() for p in captured),captured=captured)


def caller_and_cleanup():
 # Actual caller death with a separate surviving manager, handshake before SIGKILL.
 r,w=os.pipe();pid=os.fork()
 if pid==0:
  os.close(r);t=Task('caller-death');g=t.start(['/probe/payload','tree']);t.until_output(g,b'orphan_ready')
  record={'cg':str(t.cg),'work':str(t.work),'members':(t.groups[g]['cg']/'cgroup.procs').read_text().split()}
  os.write(w,json.dumps(record).encode()+b'\n');os.close(w)
  while True:signal.pause()
 os.close(w);data=b''
 while not data.endswith(b'\n'):data+=os.read(r,8192)
 os.close(r);d=json.loads(data);cg=Path(d['cg']);start=now();os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)
 fd=os.open(cg/'cgroup.events',os.O_RDONLY);ep=select.epoll();ep.register(fd,select.EPOLLPRI|select.EPOLLERR);deadline=time.monotonic()+10
 while b'populated 1' in os.pread(fd,256,0):
  assert time.monotonic()<deadline;ep.poll(1)
 ep.close();os.close(fd)
 while True:
  try:q,s=os.waitpid(-1,os.WNOHANG)
  except ChildProcessError:break
  if not q:break
 for leaf in cg.iterdir():
  if leaf.is_dir():leaf.rmdir()
 cg.rmdir();shutil.rmtree(d['work']);check('actual-caller-sigkill-external-recovery',all(not Path('/proc/'+p).exists() for p in d['members']),release_ms=(now()-start)/1e6)
 t=Task('cleanup-failure');g=t.start(['/bin/sh','-c','mkdir sealed; echo diagnostic > sealed/file; chmod 000 sealed']);t.wait(g)
 try:t.close();failed=False
 except PermissionError:failed=True
 check('filesystem-release-failure-not-acknowledged',failed and t.work.exists() and not t.cg.exists())
 os.chmod(t.work/'sealed',0o700);shutil.rmtree(t.work);check('filesystem-release-explicit-retry',not t.work.exists())


def benches():
 import random
 seed=731;cases=[(m,n) for m in ['oneshot','persistent'] for n in [10,50,100] for _ in range(3)];random.Random(seed).shuffle(cases);bench=[]
 for mode,n in cases:
  start=now();cpu=time.process_time_ns();ru0=resource.getrusage(resource.RUSAGE_CHILDREN)
  if mode=='persistent':
   t=Task(f'bench-{n}');fd0=len(list(Path('/proc/self/fd').iterdir()))
   for _ in range(n):g=t.start(['/bin/echo','benchmark']);r=t.wait(g);assert r['status']==0 and r['output']==b'benchmark\n'
   fd1=len(list(Path('/proc/self/fd').iterdir()));row=t.close();details={'task_file':t.name+'.json','fd_start':fd0,'fd_end':fd1,'owner':row['owner'],'setup_ms':row['setup_ms'],'teardown_ms':row['teardown_ms']}
  else:
   work=R/f'sequence-{Raw.seq}';work.mkdir();items=[]
   for _ in range(n):
    r=Raw('bench',['/bin/echo','benchmark'],work=work).release(reap_all=True);assert r['rc']==0 and r['output']=='benchmark\n';items.append(r['ms'])
   shutil.rmtree(work);details={'per_request_ms':items}
  ru1=resource.getrusage(resource.RUSAGE_CHILDREN);bench.append(dict(mode=mode,n=n,total_ms=(now()-start)/1e6,client_cpu_ms=(time.process_time_ns()-cpu)/1e6,children_cpu_ms=1000*((ru1.ru_utime+ru1.ru_stime)-(ru0.ru_utime+ru0.ru_stime)),vcsw=ru1.ru_nvcsw-ru0.ru_nvcsw,ivcsw=ru1.ru_nivcsw-ru0.ru_nivcsw,details=details))
 for n in [2,4,8,16]:
  for rep in range(3):
   t=Task(f'scale-{n}');ids=[t.start(['/probe/payload','hold','20']) for _ in range(n)]
   for g in ids:t.until_output(g,b'ready')
   active_snapshot=[]
   for p in (t.control/'cgroup.procs').read_text().split():
    try:active_snapshot.append({'pid':int(p),'comm':Path('/proc/'+p+'/comm').read_text().strip(),'pss_kib':pss(int(p))})
    except FileNotFoundError:pass
   emit({'scale_active_control':{'n':n,'processes':active_snapshot}})
   for g in ids:t.wait(g)
   row=t.close();bench.append(dict(mode='concurrent',n=n,total_ms=row['total_ms'],task_file=t.name+'.json'))
 (O/'benchmarks.json').write_text(json.dumps(bench,indent=2));check('benchmark-completion',True,samples=len(bench),seed=seed)

def supplement():
 t=Task('mount-view');view="import os,json;print(json.dumps({'mnt':os.readlink('/proc/self/ns/mnt'),'sub':open('/extra/sub/marker').read(),'source':[os.stat('/src/zlib.h').st_dev,os.stat('/src/zlib.h').st_ino]}))"
 a=t.start(['/usr/bin/python3','-c',view]);va=json.loads(t.wait(a)['output']);b=t.start(['/usr/bin/python3','-c',view]);vb=json.loads(t.wait(b)['output']);check('recursive-submount-shared-view',va==vb and va['sub']=='trusted-submount')
 r1=Raw('ro-input',['/usr/bin/python3','-c',view]).release();r2=Raw('ro-input',['/usr/bin/python3','-c',view]).release();v1=json.loads(r1['output']);v2=json.loads(r2['output']);check('independent-bwrap-same-source-object',va['source']==v1['source']==v2['source'] and v1['mnt']!=v2['mnt'],views=[va,v1,v2]);t.close()
 t=Task('cpu-limit');a=t.start(['/usr/bin/python3','-c',"import time;end=time.monotonic()+.4;exec('while time.monotonic()<end: pass')"],cpu='5000 100000');b=t.start(['/bin/echo','sibling']);rb=t.wait(b);ra=t.wait(a);cs=dict(x.split() for x in ra['stats']['cpu.stat'].splitlines());check('cpu-quota-sibling-progress',int(cs['nr_throttled'])>0 and rb['status']==0,cpu_stat=cs);t.close()
 # Protocol negative tests are explicit errors, not successful cancellation receipts.
 t=Task('handles');t.send(2,9000)
 try:
  while True:t.pump()
 except OSError as e:check('cancel-before-admission-not-false-success',e.errno==errno.ESRCH)
 a=t.start(['/bin/true']);t.wait(a);b=t.start(['/bin/sleep','60']);t.cancel(a)
 try:
  while True:t.pump()
 except OSError as e:check('retired-cancel-does-not-target-sibling',e.errno==errno.ESRCH and not t.groups[b]['done'])
 cg=t.cg/'duplicate';cg.mkdir();fd=os.open(cg,os.O_RDONLY);t.send(1,a,payload=b'/bin/echo\0BAD\0',fd=fd);os.close(fd)
 try:
  while True:t.pump()
 except OSError as e:check('duplicate-generation-rejected',e.errno==errno.EINVAL and 'populated 0' in (cg/'cgroup.events').read_text())
 cg.rmdir();t.cancel(b);t.wait(b);t.close()
 # Application handshake, no sleep assumption: reader opens, producer cancelled,
 # name removed, then reader released to demonstrate FD ownership.
 t=Task('producer-consumer');os.mkfifo(t.work/'gate');a=t.start(['/probe/payload','produce','/work/published']);t.until_output(a,b'published')
 code="f=open('/work/published','rb');print('OPENED',flush=True);g=open('/work/gate','rb',buffering=0);g.read(1);print(f.read().decode(),flush=True)"
 b=t.start(['/usr/bin/python3','-c',code]);t.until_output(b,b'OPENED');t.cancel(a);t.wait(a);os.unlink(t.work/'published')
 with (t.work/'gate').open('wb',buffering=0) as f:f.write(b'!')
 r=t.wait(b);check('producer-cancel-unlink-open-reader-preserved',r['status']==0 and b'immutable intermediate' in r['output']);t.close()
 # A cgroup is not a peer-security boundary, demonstrated inside sandbox only.
 t=Task('peer-trust');b=t.start(['/usr/bin/python3','-u','-c',"import os,time;print('PID='+str(os.getpid()));time.sleep(60)"]);t.until_output(b,b'PID=');target=int(t.groups[b]['output'].split(b'PID=')[1].splitlines()[0]);a=t.start(['/usr/bin/python3','-c',f'import os,signal;os.kill({target},signal.SIGHUP)']);ra=t.wait(a);rb=t.wait(b);check('same-trust-peer-sighup',ra['status']==0 and os.WIFSIGNALED(rb['status']) and os.WTERMSIG(rb['status'])==signal.SIGHUP);t.close()
 # Event-only alternative measured under its explicitly weaker per-group reaping contract.
 rows=[]
 for n in [10,50,100]:
  for _ in range(3):
   t=Task(f'event-{n}',strict=False)
   for i in range(n):g=t.start(['/bin/echo','benchmark']);t.wait(g)
   row=t.close();rows.append({'mode':'persistent-event','n':n,'task_file':t.name+'.json','total_ms':row['total_ms']})
 (O/'event-alternative.json').write_text(json.dumps(rows,indent=2));check('event-only-alternative-complete',True,samples=len(rows))
