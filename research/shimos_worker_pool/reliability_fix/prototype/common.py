import os,socket,array,json,struct,ctypes,time
from pathlib import Path
NS=['user','mnt','pid','net','ipc','uts']
def send(sock,obj,fds=()):
    anc=[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))] if fds else []
    sock.sendmsg([json.dumps(obj,separators=(',',':')).encode()],anc)
def recv(sock):
    data,anc,flags,_=sock.recvmsg(65536,socket.CMSG_SPACE(64*4)+socket.CMSG_SPACE(12),socket.MSG_CMSG_CLOEXEC)
    fds=[];creds=None
    for lev,typ,val in anc:
        if lev==socket.SOL_SOCKET and typ==socket.SCM_RIGHTS:
            a=array.array('i');a.frombytes(val);fds+=list(a)
        if lev==socket.SOL_SOCKET and typ==socket.SCM_CREDENTIALS:creds=struct.unpack('iii',val)
    try:
        if not data:raise EOFError('channel closed')
        if flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC):raise RuntimeError('truncated protocol')
        return json.loads(data),fds,creds
    except BaseException:
        for f in fds:os.close(f)
        raise
def bridge(path):
    b=ctypes.PyDLL(path,use_errno=True)
    b.py_fork_cgroup.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_int)]
    b.enter_target.argtypes=[ctypes.POINTER(ctypes.c_int)]
    return b
def fork_cg(b,fd):
    pf=ctypes.c_int(-1);p=b.py_fork_cgroup(fd,ctypes.byref(pf))
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
    for x in os.listdir('/proc/self/fd'):
        f=int(x)
        if f>2 and f not in keep:
            try:os.close(f)
            except OSError:pass
