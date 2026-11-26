import os,socket,array,json,struct,ctypes,time
from pathlib import Path
import cost
NS=['user','mnt','pid','net','ipc','uts']
def send(sock,obj,fds=()):
    started=cost.now()
    processing=cost.mark()
    anc=[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))] if fds else []
    raw=json.dumps(obj,separators=(',',':')).encode()
    cost.finish('ipc_encode',processing,nonce=obj.get('nonce',cost.NONCE),message=obj.get('op',obj.get('event')),bytes=len(raw),fd_count=len(fds))
    syscall=cost.mark()
    try:sock.sendmsg([raw],anc)
    finally:cost.finish('ipc_sendmsg',syscall,nonce=obj.get('nonce',cost.NONCE),message=obj.get('op',obj.get('event')))
    cost.ipc('send',obj,started,sock.fileno())
def recv(sock):
    started=cost.now()
    syscall=cost.mark()
    try:data,anc,flags,_=sock.recvmsg(65536,socket.CMSG_SPACE(64*4)+socket.CMSG_SPACE(12),socket.MSG_CMSG_CLOEXEC)
    except BaseException:
        cost.finish('ipc_recvmsg',syscall,message='receive_failed');raise
    syscall_end=cost.mark()
    processing=cost.mark()
    fds=[];creds=None
    for lev,typ,val in anc:
        if lev==socket.SOL_SOCKET and typ==socket.SCM_RIGHTS:
            a=array.array('i');a.frombytes(val);fds+=list(a)
        if lev==socket.SOL_SOCKET and typ==socket.SCM_CREDENTIALS:creds=struct.unpack('iii',val)
    try:
        if not data:raise EOFError('channel closed')
        if flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC):raise RuntimeError('truncated protocol')
        obj=json.loads(data)
        cost.record('ipc_recvmsg','span',start_ns=syscall[0],end_ns=syscall_end[0],
                    thread_cpu_ns=syscall_end[1]-syscall[1],cpu_clock='CLOCK_THREAD_CPUTIME_ID',
                    nonce=obj.get('nonce',cost.NONCE),message=obj.get('op',obj.get('event')))
        cost.finish('ipc_decode',processing,nonce=obj.get('nonce',cost.NONCE),message=obj.get('op',obj.get('event')),bytes=len(data),fd_count=len(fds));cost.ipc('recv',obj,started,sock.fileno())
        return obj,fds,creds
    except BaseException:
        cost.record('ipc_recvmsg','span',start_ns=syscall[0],end_ns=syscall_end[0],
                    thread_cpu_ns=syscall_end[1]-syscall[1],cpu_clock='CLOCK_THREAD_CPUTIME_ID',message='EOF_or_decode_failed')
        for f in fds:os.close(f)
        raise
def bridge(path):
    b=ctypes.PyDLL(path,use_errno=True)
    b.py_fork_cgroup.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_int)]
    b.enter_target.argtypes=[ctypes.POINTER(ctypes.c_int)]
    cost.configure_bridge(b)
    return b
def fork_cg(b,fd):
    pf=ctypes.c_int(-1);p=b.py_fork_cgroup(fd,ctypes.byref(pf));saved_errno=ctypes.get_errno()
    if p==0:
        # Python child callbacks may already have established S/W identity.
        if os.getpid()!=cost.PID:cost.context('S' if cost.ROLE=='Z' else 'W',cost.NONCE)
        cost.record('fork_child_first_python_point',point='after full C fork bridge return, before timing drain')
    try:cost.drain_bridge(b)
    finally:ctypes.set_errno(saved_errno)
    if p<0:raise OSError(ctypes.get_errno(),'clone3 INTO_CGROUP')
    return p,pf.value
def identity():
    status=Path('/proc/self/status').read_text()
    fields={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in status.splitlines()}
    return {'pid':os.getpid(),'ppid':os.getppid(),'uid':os.getuid(),'gid':os.getgid(),
      'ns':{n:os.readlink('/proc/self/ns/'+n) for n in NS},
      'status':{k:fields.get(k) for k in ['NSpid','Uid','Gid','Groups','CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs','Seccomp','Threads']},
      'uid_map':Path('/proc/self/uid_map').read_text(),'gid_map':Path('/proc/self/gid_map').read_text(),
      'cgroup':Path('/proc/self/cgroup').read_text(),
      'fds':{str(f):os.readlink('/proc/self/fd/'+f) for f in os.listdir('/proc/self/fd') if os.path.exists('/proc/self/fd/'+f)}}
def close_except(keep):
    started=cost.mark();closed=0;scanned=0
    for x in os.listdir('/proc/self/fd'):
        scanned+=1
        f=int(x)
        if f>2 and f not in keep:
            try:os.close(f);closed+=1
            except OSError:pass
    cost.finish('close_except_fds',started,closed=closed,scanned=scanned,
                classification='required allowlist enforcement, not RP diagnostic scan')
