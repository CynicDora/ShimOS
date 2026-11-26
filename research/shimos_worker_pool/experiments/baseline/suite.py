#!/usr/bin/env python3
"""Private-VM-only strong Bubblewrap composition; no host process tests."""
import os,sys,json,time,stat,socket,struct,array,select,selectors,ctypes,subprocess,hashlib,shutil,resource,traceback
from pathlib import Path
assert Path('/run/native-benchmark-lab').read_text().strip()=='private-stock-linux-benchmark-vm'
R=Path(os.environ['BG_ROOT']); O=Path(os.environ['BG_OUT']); P=R/'prototype'; A=R/'assets'
ROOTCG=Path('/sys/fs/cgroup')
HAS_IO='io' in (ROOTCG/'cgroup.controllers').read_text().split()
if HAS_IO:(ROOTCG/'cgroup.subtree_control').write_text('+io')
CONTROLLERS='+cpu +memory +pids'+(' +io' if HAS_IO else '')
CG=ROOTCG/'bgap';CG.mkdir();(CG/'cgroup.subtree_control').write_text(CONTROLLERS)
for n in ['work','probe','src','extra','tools']: (Path('/runtime')/n).mkdir(exist_ok=True)
subprocess.run(['gcc','-shared','-fPIC','-O2',str(P/'native.c'),'-o',str(P/'native.so')],check=True)
subprocess.run(['gcc','-static','-O2',str(P/'payload.c'),'-o',str(P/'payload')],check=True)
lib=ctypes.CDLL(str(P/'native.so'),use_errno=True);lib.bg_spawn.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.POINTER(ctypes.c_char_p),ctypes.POINTER(ctypes.c_int),ctypes.c_int,ctypes.c_int]
ctypes.CDLL(None).prctl(36,1,0,0,0)
logs=[];results=[]
def now():return time.monotonic_ns()
def emit(obj):
 logs.append(obj)
 with (O/'events.jsonl').open('a') as f:f.write(json.dumps(obj)+'\n')
def check(name,ok,**kw):
 r=dict(check=name,ok=bool(ok),**kw);results.append(r);emit(r)
 if not ok:raise AssertionError(r)
def stats(path):
 r={}
 for k in ['cpu.stat','memory.peak','memory.current','memory.events','pids.peak','pids.events','cgroup.events','io.stat']:
  r[k]=(path/k).read_text() if (path/k).exists() else None
 return r
def pss(pid):
 try:return int(next(l.split()[1] for l in Path(f'/proc/{pid}/smaps_rollup').read_text().splitlines() if l.startswith('Pss:')))
 except (FileNotFoundError,StopIteration,PermissionError):return None
def delegate(path):
 os.chown(path,65534,65534)
 for n in ['cgroup.procs','cgroup.threads','cgroup.subtree_control']:os.chown(path/n,65534,65534)
def spawn(argv,cg,out,unpriv=1,keepfd=-1):
 fd=os.open(cg,os.O_RDONLY|os.O_DIRECTORY);pf=ctypes.c_int(-1);args=(ctypes.c_char_p*(len(argv)+1))(*[str(x).encode() for x in argv],None)
 p=lib.bg_spawn(fd,out,args,ctypes.byref(pf),unpriv,keepfd);os.close(fd)
 if p<0:raise OSError(ctypes.get_errno(),'clone3')
 return p,pf.value
def bwrap(work,tail,asinit=True,die=True,newsession=True,extra=None):
 a=[str(A/'bwrap/lib/ld-linux-x86-64.so.2'),'--library-path',str(A/'bwrap/lib'),str(A/'bwrap/bwrap'),'--unshare-user','--disable-userns','--unshare-pid','--unshare-net','--unshare-ipc','--unshare-uts','--cap-drop','ALL']
 if asinit:a+=['--as-pid-1']
 if die:a+=['--die-with-parent']
 if newsession:a+=['--new-session']
 a+=['--ro-bind','/runtime','/','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--ro-bind',str(P),'/probe','--ro-bind',str(A),'/tools','--ro-bind',str(A/'zlib-1.3.1'),'/src','--bind',str(work),'/work','--chdir','/work','--setenv','PATH','/tools/bin:/usr/bin:/bin','--unsetenv','LD_LIBRARY_PATH','--unsetenv','PYTHONPATH']
 if extra:a+=extra
 return a+list(map(str,tail))
class Task:
 seq=0
 def __init__(self,name,strict=True):
  Task.seq+=1; self.name=f't{Task.seq}-{name}';self.start_ns=now();self.client_cpu0=time.process_time_ns();self.cg=CG/self.name;self.cg.mkdir();delegate(self.cg);(self.cg/'cgroup.subtree_control').write_text(CONTROLLERS)
  (self.cg/'pids.max').write_text('256');(self.cg/'memory.max').write_text(str(512*1024**2));(self.cg/'cpu.max').write_text('400000 100000')
  self.control=self.cg/'control';self.control.mkdir();delegate(self.control)
  self.work=R/self.name;self.work.mkdir();os.chown(self.work,65534,65534)
  self.sock,cs=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);cs.set_inheritable(True);self.sock.settimeout(10)
  self.sel=selectors.DefaultSelector();self.sel.register(self.sock,selectors.EVENT_READ,('control',0));self.groups={};self.gid=0;self.bye=None
  self.log=(O/(self.name+'-bwrap.log')).open('wb');self.pid,self.pfd=spawn(bwrap(self.work,['/probe/owner','3',str(int(strict))]),self.control,self.log.fileno(),keepfd=cs.fileno());cs.close()
  # native spawn closes 3+; special launch below replaces helper for owner socket inheritance.
  self.ready=False
  while not self.ready:self.pump()
  self.ready_ns=now();self.owner_host=int(next(x.split()[0] for x in [])) if False else None
  hostpids=[int(x) for x in (self.control/'cgroup.procs').read_text().split()];self.identity={}
  for pid in hostpids:
   try:self.identity[pid]={'cmd':Path(f'/proc/{pid}/comm').read_text().strip(),'pss_kib':pss(pid),'fds':len(list(Path(f'/proc/{pid}/fd').iterdir())),'status':Path(f'/proc/{pid}/status').read_text(),'namespaces':{n:os.readlink(f'/proc/{pid}/ns/{n}') for n in ['mnt','pid','user','net','ipc']}}
   except (FileNotFoundError,PermissionError):self.identity[pid]={'cmd':Path(f'/proc/{pid}/comm').read_text().strip(),'pss_kib':pss(pid),'inspection':'permission denied'}
  self.snapshot=self.identity
 def send(self,op,gid=0,a=0,b=0,payload=b'',fd=None):
  anc=[] if fd is None else [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))]
  self.sock.sendmsg([struct.pack('IIII',op,gid,a,b)+payload],anc)
 def pump(self,timeout=10):
  events=self.sel.select(timeout)
  if not events:raise TimeoutError((self.name,{k:{a:v for a,v in g.items() if a in ['pid','done','eof','leader']} for k,g in self.groups.items()}))
  for key,_ in events:
   typ,gid=key.data
   if typ=='control':
    data,anc,flags,_=self.sock.recvmsg(16384,socket.CMSG_SPACE(16));assert data,(self.name,'owner eof',self.log.name)
    op,gid,a,b=struct.unpack('IIII',data[:16]);payload=data[16:];fds=[]
    for level,kind,val in anc:
     if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
      ar=array.array('i');ar.frombytes(val);fds+=ar.tolist()
    if op==10:self.ready=True;self.ready_info={'ns_pid':a,'uid':b,'self_report':payload.decode()}
    elif op==11:
     g=self.groups[gid];g.update(pid=a,started_ns=now());assert len(fds)==1;fd=fds[0];os.set_blocking(fd,False);self.sel.register(fd,selectors.EVENT_READ,('output',gid));g['outfd']=fd
    elif op==13:self.groups[gid].update(leader=a,leader_ns=now())
    elif op==14:
     g=self.groups[gid];g.update(done=True,status=a,cancelled=b,done_ns=now(),stats=stats(g['cg']));g['cg'].rmdir();g['released_ns']=now()
    elif op==15:raise OSError(a,f'owner error gid={gid}')
    elif op==16:self.bye=json.loads(payload)
    elif op==17:self.inspect=payload.decode()
    else:raise ValueError(op)
   else:
    g=self.groups[gid]
    try:data=os.read(key.fd,65536)
    except BlockingIOError:continue
    if data:
     if not g['first_ns']:g['first_ns']=now()
     g['bytes']+=len(data);g['output']+=data
    else:
     self.sel.unregister(key.fd);os.close(key.fd);g['outfd']=None;g['eof']=True;self.send(5,gid,g['bytes']&0xffffffff,g['bytes']>>32)
 def start(self,argv,mem=None,pids=None,cpu=None):
  self.gid+=1;gid=self.gid;cg=self.cg/f'g{gid}';t=now();cg.mkdir();delegate(cg)
  if mem:(cg/'memory.max').write_text(str(mem));(cg/'memory.oom.group').write_text('1')
  if pids:(cg/'pids.max').write_text(str(pids))
  if cpu:(cg/'cpu.max').write_text(cpu)
  g=dict(cg=cg,argv=argv,start_ns=t,done=False,eof=False,first_ns=None,bytes=0,output=b'');self.groups[gid]=g;fd=os.open(cg,os.O_RDONLY|os.O_DIRECTORY)
  self.send(1,gid,payload=b'\0'.join(str(x).encode() for x in argv)+b'\0',fd=fd);os.close(fd);return gid
 def wait(self,gid,timeout=20):
  end=time.monotonic()+timeout
  while not self.groups[gid]['done']:
   if time.monotonic()>end:raise TimeoutError(('wait',gid))
   self.pump(min(5,end-time.monotonic()))
  return self.groups[gid]
 def until_output(self,gid,token,timeout=20):
  end=time.monotonic()+timeout
  while token not in self.groups[gid]['output']:
   if time.monotonic()>end:raise TimeoutError(('output',gid,self.groups[gid]['output'][-2000:]))
   self.pump(min(5,end-time.monotonic()))
 def cancel(self,gid):self.groups[gid]['cancel_ns']=now();self.send(2,gid)
 def close(self):
  self.stop_ns=now();file_bytes=0;file_count=0
  for root,dirs,files in os.walk(self.work,followlinks=False):
   for f in files:
    st=(Path(root)/f).lstat()
    if stat.S_ISREG(st.st_mode):file_count+=1;file_bytes+=st.st_size
  self.send(3)
  while self.bye is None:self.pump()
  os.waitid(os.P_PIDFD,self.pfd,os.WEXITED);os.close(self.pfd);self.sel.close();self.sock.close();self.log.close()
  # monitor exit is followed by actual control cgroup emptiness; no early ACK.
  fd=os.open(self.control/'cgroup.events',os.O_RDONLY);ep=select.epoll();ep.register(fd,select.EPOLLPRI|select.EPOLLERR)
  while b'populated 1' in os.pread(fd,256,0):ep.poll(5)
  ep.close();os.close(fd);self.final_stats=stats(self.cg);control_stats=stats(self.control);self.control.rmdir();self.cg.rmdir();shutil.rmtree(self.work);self.end_ns=now()
  row=dict(name=self.name,setup_ms=(self.ready_ns-self.start_ns)/1e6,teardown_ms=(self.end_ns-self.stop_ns)/1e6,total_ms=(self.end_ns-self.start_ns)/1e6,client_cpu_ms=(time.process_time_ns()-self.client_cpu0)/1e6,owner=self.bye,initial_processes=self.snapshot,task_stats=self.final_stats,control_stats=control_stats,workspace_final_bytes=file_bytes,workspace_final_files=file_count,client_pss_end_kib=pss(os.getpid()),owner_ready=self.ready_info,groups=[])
  for gid,g in self.groups.items():row['groups'].append({k:(str(v) if isinstance(v,Path) else v.decode(errors='replace') if isinstance(v,bytes) else v) for k,v in g.items() if k!='outfd'})
  (O/(self.name+'.json')).write_text(json.dumps(row,indent=2));return row

def core():
 t=Task('core')
 a=t.start(['/usr/bin/python3','-u','-m','http.server','8123','--bind','127.0.0.1','--directory','/work'])
 t.until_output(a,b'Serving HTTP')
 b=t.start(['/bin/sh','-c','cp -R /src /work/zlib && cd /work/zlib && ./configure --static && make -j4 && make test && printf published-v1 > /work/result.tmp && mv /work/result.tmp /work/result'])
 rb=t.wait(b,60);check('real-zlib-build',rb['status']==0,output_tail=rb['output'][-800:].decode(errors='replace'))
 test="import urllib.request,time; d=urllib.request.urlopen('http://127.0.0.1:8123/result').read(); assert d==b'published-v1'; print('C_READY',flush=True); time.sleep(60)"
 c=t.start(['/usr/bin/python3','-c',test]);t.until_output(c,b'C_READY');t.cancel(c);rc=t.wait(c)
 check('independent-cancel-keeps-service',rc['cancelled']==1 and not t.groups[a]['done'],cancel_ms=(rc['released_ns']-rc['cancel_ns'])/1e6)
 d=t.start(['/usr/bin/python3','-c',"import urllib.request; assert urllib.request.urlopen('http://127.0.0.1:8123/result').read()==b'published-v1'; print('D_OK')"])
 rd=t.wait(d);check('restart-test-shared-artifact',rd['status']==0 and b'D_OK' in rd['output'])
 t.cancel(a);t.wait(a);row=t.close();check('core-complete-release',not t.cg.exists() and not t.work.exists(),total_ms=row['total_ms'])

def correctness():
 t=Task('correctness')
 # Same namespace/object view for independent argv, private tmpfs survives producer.
 view="import os,json; print(json.dumps({'ns':{n:os.readlink('/proc/self/ns/'+n) for n in ['mnt','pid','user','net','ipc']},'source':list(os.stat('/src/zlib.h')[i] for i in [1,2]),'tmp':open('/tmp/keep').read()}))"
 g=t.start(['/bin/sh','-c','printf retained > /tmp/keep']);t.wait(g)
 a=t.start(['/usr/bin/python3','-c',view]);ra=t.wait(a);b=t.start(['/usr/bin/python3','-c',view]);rb=t.wait(b)
 check('identical-namespaces-and-file-objects',ra['status']==rb['status']==0 and ra['output']==rb['output'],view=ra['output'].decode())
 # No control/cgroup FD inheritance, no opening owner's private descriptors.
 sec="""import os,json
r={}
for x in ['/proc/1/fd/3','/sys/fs/cgroup/cgroup.procs']:
 try: f=os.open(x,os.O_RDONLY);os.close(f);r[x]='OPEN'
 except OSError as e:r[x]=e.errno
r['fds']=[x for x in os.listdir('/proc/self/fd') if int(x)>2 and os.path.exists('/proc/self/fd/'+x)]
r['status']=[s for s in open('/proc/self/status') if s.startswith(('Cap','NoNewPrivs','Seccomp'))]
print(json.dumps(r))
"""
 s=t.start(['/usr/bin/python3','-c',sec]);rs=t.wait(s);d=json.loads(rs['output']);check('control-fds-not-inherited-or-reopened',d['/proc/1/fd/3'] in [1,13] and not d['fds'] and d['/sys/fs/cgroup/cgroup.procs']!= 'OPEN',details=d)
 g=t.start(['/probe/payload','tree']);t.until_output(g,b'orphan_ready');
 while 'leader' not in t.groups[g]:t.pump()
 check('leader-exit-is-not-group-complete',not t.groups[g]['done'] and not t.groups[g]['eof'])
 t.cancel(g);t.wait(g)
 # Group limits; OOM must leave sibling live.
 sibling=t.start(['/bin/sleep','60']);oom=t.start(['/probe/payload','memory'],mem=16*1024**2);rr=t.wait(oom)
 check('leaf-oom-keeps-sibling',rr['status']!=0 and int(dict(x.split() for x in rr['stats']['memory.events'].splitlines())['oom_kill'])>=1 and not t.groups[sibling]['done'],events=rr['stats']['memory.events'])
 p=t.start(['/probe/payload','pids'],pids=8);t.until_output(p,b'fork_denied');t.cancel(p);rp=t.wait(p);check('leaf-pids-bound',int(rp['stats']['pids.peak'])<=8,events=rp['stats']['pids.events'])
 # Cancellation queued immediately after START: ordered owner admission, no sleeps.
 for i in range(20):
  g=t.start(['/probe/payload','forkrace'],pids=32)
  if i>=10:t.until_output(g,b'fork_child')
  t.cancel(g);r=t.wait(g);assert r['cancelled'] and 'populated 0' in r['stats']['cgroup.events']
 check('twenty-start-cancel-races',True)
 # Backpressure: stop reading one output while keep control plane and sibling active.
 noisy=t.start(['/usr/bin/python3','-c',"import os; print('NOISY',flush=True); [os.write(1,b'x'*65536) for _ in range(1024)]"])
 while 'outfd' not in t.groups[noisy]:t.pump()
 fd=t.groups[noisy]['outfd'];t.sel.unregister(fd)
 import fcntl,termios
 capacity=fcntl.fcntl(fd,fcntl.F_GETPIPE_SZ);deadline=time.monotonic()+10
 while True:
  count=array.array('i',[0]);fcntl.ioctl(fd,termios.FIONREAD,count,True)
  if count[0]>=min(capacity//2,4096):break
  assert time.monotonic()<deadline
  select.select([fd],[],[],.01)
 emit({'backpressure':{'capacity':capacity,'unread':count[0]}})
 t.cancel(noisy)
 # Leader receipt is on private control socket even though data pipe was not drained.
 while 'leader' not in t.groups[noisy]:t.pump()
 check('cancel-not-blocked-by-output-backpressure',not t.groups[noisy]['done'] and not t.groups[sibling]['done'])
 t.sel.register(fd,selectors.EVENT_READ,('output',noisy));r=t.wait(noisy);check('cancel-drains-retained-output',r['bytes']>0,bytes=r['bytes'])
 t.cancel(sibling);t.wait(sibling);t.close()

def main(mode):
 # Fixture administrator delegates once; all controllers/launches below run nonroot.
 if mode=='supplement':
  sub=Path('/runtime/extra/sub');sub.mkdir(exist_ok=True);mount=ctypes.CDLL(None,use_errno=True).mount
  assert mount(b'tmpfs',str(sub).encode(),b'tmpfs',0,b'mode=0755')==0
  (sub/'marker').write_text('trusted-submount')
 delegate(CG);client=CG/'client';client.mkdir();delegate(client);(client/'cgroup.procs').write_text(str(os.getpid()))
 os.chown(R,65534,65534);os.chown(O,65534,65534);os.setgroups([]);os.setgid(65534);os.setuid(65534)
 emit({'environment':{'uid':os.getuid(),'kernel':os.uname().release,'client_pss_kib':pss(os.getpid()),'controllers':(CG/'cgroup.controllers').read_text()}})
 if mode=='pilot':
  t=Task('pilot');g=t.start(['/bin/echo','hello']);r=t.wait(g);check('rootless-persistent-exec',r['status']==0 and r['output']==b'hello\n',ready=t.ready_info);t.close()
 elif mode=='core':core();correctness()
 else:
  exec((P/'diagnostics.py').read_text(),globals())
  if mode in ['diagnostics','all']:namespaces();signals();faults();caller_and_cleanup()
  if mode in ['bench','all']:benches()
  if mode=='all':core();correctness()
  if mode=='supplement':supplement()

try:main(sys.argv[1] if len(sys.argv)>1 else 'pilot')
except Exception:
 traceback.print_exc();emit({'fatal':traceback.format_exc()});raise
finally:
 (O/'checks.json').write_text(json.dumps(results,indent=2));(O/'remaining-cgroups.txt').write_text('\n'.join(str(x) for x in CG.rglob('*') if x.is_dir()))
