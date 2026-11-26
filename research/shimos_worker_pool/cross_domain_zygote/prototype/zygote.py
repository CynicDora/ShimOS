"""Trusted single-threaded test template. No third-party import, no user code loader."""
import os,sys,socket,time,json,ctypes,hashlib,traceback,select,signal,errno
from pathlib import Path
from common import send,recv,bridge,fork_cg,identity,close_except
LIB=bridge(sys.argv[1]);assert LIB.set_base_safety()==0
class MemoryState:
    def __init__(self):
        self.born_pid=os.getpid();self.bytes=bytearray(os.urandom(65536));self.lookup={i:i*i+17 for i in range(200)}
STATE=MemoryState()
def fingerprint():
    return {'object_id':id(STATE),'born_pid':STATE.born_pid,'sha256':hashlib.sha256(STATE.bytes).hexdigest(),'answer':sum(STATE.lookup.values())}
BASE=fingerprint()
CTRL=socket.socket(fileno=3)

def business(req):
    # All Python business code starts AFTER final drop/FD close/filter.
    ident=identity();checks={}
    checks['marker']=Path('/tmp/domain-token').read_text()==req['nonce']
    checks['inherited']=fingerprint()==BASE
    checks['not_recreated']=STATE.born_pid!=os.getpid() and id(STATE)==BASE['object_id']
    checks['no_host_path']=not Path('/state').exists() and not Path('/evidence').exists()
    checks['no_other_workspace']=not Path('/work/other-domain-secret').exists()
    try:Path('/src/input').write_text('bad');checks['readonly']=False
    except OSError as e:checks['readonly']=e.errno==errno.EROFS
    Path('/work/result').write_text(str(sum(STATE.lookup.values())))
    checks['writable']=Path('/work/result').read_text()==str(sum(i*i+17 for i in range(200)))
    libc=ctypes.CDLL(None,use_errno=True)
    sf=os.open('/proc/self/ns/mnt',os.O_RDONLY);ret=libc.setns(sf,0);checks['setns_denied']=ret==-1 and ctypes.get_errno()==errno.EPERM;os.close(sf)
    ret=libc.unshare(0x10000000);checks['unshare_denied']=ret==-1 and ctypes.get_errno()==errno.EPERM
    try:os.chroot('/');checks['chroot_denied']=False
    except PermissionError:checks['chroot_denied']=True
    try:os.execv('/usr/bin/python3',['python3','-c','raise SystemExit(99)']);checks['exec_denied']=False
    except PermissionError:checks['exec_denied']=True
    checks['caps_zero']=all(int(ident['status'][k],16)==0 for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])
    checks['nnp_seccomp']=ident['status']['NoNewPrivs']=='1' and ident['status']['Seccomp']=='2'
    checks['fd_allowlist']=set(ident['fds'])<=set(['0','1','2'])
    checks['namespaces']=ident['ns']==req['target_ns']
    checks['cgroup']=req['business_cgroup'] in ident['cgroup']
    checks['environment']=dict(os.environ)=={'PATH':'/usr/bin:/bin'}
    checks['cwd']=os.getcwd()=='/work'
    checks['root_identity']=[os.stat('/').st_dev,os.stat('/').st_ino]==req['root_identity']
    STATE.bytes[0]^=255
    print(json.dumps({'event':'WORKER_READY','nonce':req['nonce'],'identity':ident,'inherited':BASE,'checks':checks,'after_cow':fingerprint()}),flush=True)
    if not all(checks.values()):os._exit(91)
    if req['mode']=='nonzero':os._exit(7)
    if req['mode'] in ('normal','waiter_failure'):
        p=os.fork()
        if p==0:
            time.sleep(.04);print(json.dumps({'event':'DESCENDANT_DONE','pid':os.getpid()}),flush=True);os._exit(0)
        os._exit(0)
    p=os.fork()
    if p==0:os.setsid()
    while True:time.sleep(1)

def transition(req,fds):
    # fds: base,inner,mnt,pid,net,ipc,uts,root,transitioncg,businesscg,
    #       request status channel, stdout writer, target PID1 pidfd.
    c=socket.socket(fileno=fds[10]);keep=set(fds)
    close_except(keep)
    try:
        send(c,{'event':'TRANSITION_BORN','pid':os.getpid(),'identity':identity()})
        if req['mode']=='target_during_entry':
            send(c,{'event':'TRANSITION_PAUSED'});m,extra,_=recv(c);assert m['op']=='GO' and not extra
        if select.select([fds[12]],[],[],0)[0]:raise RuntimeError('target PID1 already exited')
        arr=(ctypes.c_int*8)(*fds[:8]);r=LIB.enter_target(arr)
        if r:raise OSError(ctypes.get_errno(),'enter_target stage '+str(r))
        if Path('/tmp/domain-token').read_text()!=req['nonce']:raise RuntimeError('target nonce mismatch')
        os.environ.clear();os.environ['PATH']='/usr/bin:/bin'
        sys.path[:]=[p for p in sys.path if p.startswith(('/usr/lib/','/lib/'))]
        if select.select([fds[12]],[],[],0)[0]:raise RuntimeError('target died before clone')
        p,pfd=fork_cg(LIB,fds[9])
        if p==0:
            nil=os.open('/dev/null',os.O_RDONLY);os.dup2(nil,0);os.dup2(fds[11],1);os.dup2(fds[11],2)
            if LIB.close_from(3):os._exit(122)
            r=LIB.drop_final()
            if r:print(json.dumps({'event':'DROP_ERROR','stage':r,'errno':ctypes.get_errno()}),flush=True);os._exit(123)
            if LIB.forbid_exec():os._exit(124)
            os.setsid()
            try:business(req)
            except BaseException:traceback.print_exc();os._exit(90)
        # S is the actual wait parent; it has no retained construction caps.
        keep={c.fileno(),pfd}
        # target /proc excludes S; enumerate FDs numerically rather than /proc/self.
        for f in fds:
            if f not in keep:
                try:os.close(f)
                except OSError:pass
        r=LIB.drop_final()
        if r:raise OSError(ctypes.get_errno(),'transition drop '+str(r))
        send(c,{'event':'WORKER_CREATED','worker_host_pid':p,'waiter_host_pid':os.getpid()},[pfd]);os.close(pfd)
        q,status=os.waitpid(p,0)
        send(c,{'event':'WORKER_WAITED','worker_host_pid':q,'wait_status':status,'exit_code':os.waitstatus_to_exitcode(status)})
        c.close();os._exit(17 if req['mode']=='waiter_failure' else 0)
    except BaseException as e:
        try:send(c,{'event':'TRANSITION_ERROR','error':repr(e),'traceback':traceback.format_exc()})
        except OSError:pass
        os._exit(125)

send(CTRL,{'event':'ZYGOTE_READY','identity':identity(),'state':BASE,'threads':len(os.listdir('/proc/self/task'))})
children={}
while True:
    for p in list(children):
        q,status=os.waitpid(p,os.WNOHANG)
        if q:
            send(CTRL,{'event':'TRANSITION_REAPED','pid':p,'nonce':children.pop(p),'wait_status':status})
    ready,_,_=select.select([CTRL],[],[],.01)
    if not ready:continue
    try:req,fds,_=recv(CTRL)
    except EOFError:break
    if req['op']=='STOP':
        assert not children
        send(CTRL,{'event':'ZYGOTE_STOP','state_unchanged':fingerprint()==BASE,'state':fingerprint()});break
    if req['op']=='PING':send(CTRL,{'event':'PONG','state_unchanged':fingerprint()==BASE,'identity':identity()});continue
    assert req['op']=='SPAWN' and len(fds)==13
    try:
        p,pfd=fork_cg(LIB,fds[8])
        if p==0:transition(req,fds)
        children[p]=req['nonce']
        send(CTRL,{'event':'TRANSITION_CREATED','pid':p,'nonce':req['nonce']},[pfd]);os.close(pfd)
    except BaseException as e:send(CTRL,{'event':'SPAWN_ERROR','error':repr(e)})
    finally:
        for f in fds:
            try:os.close(f)
            except OSError:pass
CTRL.close()
