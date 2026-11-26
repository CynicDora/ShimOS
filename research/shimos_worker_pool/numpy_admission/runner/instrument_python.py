"""Reproducible instrumentation of the frozen integration Python sources only."""
from pathlib import Path
p=Path(__file__).resolve().parents[1]/'baseline_instrumented'
def edit(name,changes):
 s=(p/name).read_text()
 for a,b in changes:
  assert a in s,(name,a);s=s.replace(a,b)
 (p/name).write_text(s)
edit('common.py',[
 ('from pathlib import Path','from pathlib import Path\nimport cost'),
 ('    anc=[','    started=cost.now()\n    anc=['),
 ('    sock.sendmsg([json.dumps(obj,separators=(\',\',\':\')).encode()],anc)','    sock.sendmsg([json.dumps(obj,separators=(\',\',\':\')).encode()],anc)\n    cost.ipc(\'send\',obj,started,sock.fileno())'),
 ('    data,anc,flags,_=','    started=cost.now()\n    data,anc,flags,_='),
 ('        return json.loads(data),fds,creds','        obj=json.loads(data);cost.ipc(\'recv\',obj,started,sock.fileno())\n        return obj,fds,creds'),
 ('    return b','    cost.configure_bridge(b)\n    return b'),
 ('    pf=ctypes.c_int(-1);p=b.py_fork_cgroup(fd,ctypes.byref(pf))','    pf=ctypes.c_int(-1);p=b.py_fork_cgroup(fd,ctypes.byref(pf))\n    if p==0:cost.context(\'S\' if cost.ROLE==\'Z\' else \'W\',cost.NONCE)\n    cost.drain_bridge(b)')])
edit('zygote.py',[
 ('import runtime_probe as RP','import runtime_probe as RP\nimport cost\ncost.context(\'Z\');cost.record(\'zygote_python_enter\')'),
 ('def business(req):','def business(req):\n    cost.record(\'business_enter\')'),
 ('os._exit(','cost.exit('),
 ("if req['mode']=='nonzero':cost.exit(7)","if req['mode']=='nonzero':cost.record('business_end');cost.exit(7)"),
 ("        cost.exit(0)\n    p=os.fork()","        cost.record('business_end');cost.exit(0)\n    p=os.fork()"),
 ("r = LIB.enter_target(arr)","r = LIB.enter_target(arr);cost.drain_bridge(LIB)"),
 ('r = LIB.drop_final()','r = LIB.drop_final();cost.drain_bridge(LIB)'),
 ("if LIB.forbid_exec(): cost.exit(124)","if LIB.forbid_exec(): cost.exit(124)\n                cost.drain_bridge(LIB)"),
 ('        q, status = os.waitpid(p, 0)','        wait_begin=cost.now();q, status = os.waitpid(p, 0)\n        cost.span(\'wait_worker\',wait_begin);cost.record(\'worker_waited\')'),
 ("'threads': len(os.listdir('/proc/self/task')),'runtime':RP.snapshot('Z_ready')}","'threads': len(os.listdir('/proc/self/task')),'runtime':RP.snapshot('Z_ready'),'session':cost.SESSION}"),
 ('attempts = {}',"cost.record('zygote_ready');cost.usage('zygote_ready_usage')\nattempts = {}"),
 ("            nonce = children.pop(p); entry = attempts[nonce]","            nonce = children.pop(p);cost.context('Z',nonce);cost.record('transition_waited');entry = attempts[nonce]"),
 ("            op = req.get('op'); nonce = req.get('nonce')","            op = req.get('op'); nonce = req.get('nonce');cost.context('Z',nonce)"),
 ("'identity': identity(), 'active_attempts': len(attempts)}","'identity': identity(), 'active_attempts': len(attempts),'session':cost.SESSION,'nonce':nonce}"),
 ('    CTRL.close()',"    CTRL.close();cost.usage('zygote_final_usage');cost.flush()")])
edit('supervisor.py',[
 ('import traceback','import traceback\nimport cost'),
 ('    CG, R, O = Path(CG), Path(R), Path(O)',"    cost.context('H');cost.record('supervisor_enter');cost.usage('supervisor_initial_usage')\n    CG, R, O = Path(CG), Path(R), Path(O)"),
 ('    if controller_pid == 0:\n        parent.close()',"    if controller_pid == 0:\n        cost.context('R');cost.record('controller_forked')\n        parent.close()"),
 ('            os._exit(int(result or 0))','            cost.exit(int(result or 0))'),
 ('            os._exit(1)','            cost.exit(1)'),
 ("    return 0 if released else 1","    cost.record('supervisor_released',released=released);cost.usage('supervisor_final_usage');cost.flush()\n    return 0 if released else 1")])
edit('run.py',[
 ('import runtime_support as runtime','import runtime_support as runtime\nimport cost'),
 ("          '/probe/domain_init',nonce]","          '/probe/domain_init',nonce]+(['cost-on'] if cost.ENABLED else [])"),
 ('    def __init__(self,supervisor):',"    def __init__(self,supervisor):\n        cost.context('R');cost.record('session_begin',force=True);cost.usage('controller_initial_usage')"),
 ('    def rpc_supervisor(self,obj,fds=()):','    def rpc_supervisor(self,obj,fds=()):\n        started=cost.now()'),
 ('        return m\n    def reap',"        cost.span('rpc_'+obj['op'].lower(),started);cost.record({'REGISTER':'registered','RETIRE':'retire_done','DONE':'done_ack'}[obj['op']])\n        return m\n    def reap"),
 ('    def start_z(self):',"    def start_z(self):\n        cost.record('zygote_create_begin')"),
 ("        event(m);self.z=", "        cost.record('zygote_ready_received');event(m);self.z="),
 ("        n=len(self.rows);nonce=os.urandom(16).hex();cg=", "        n=len(self.rows);nonce=os.urandom(16).hex();cost.context('R',nonce,repeat=n,warmup=n<int(os.environ.get('COST_WARMUP','0')));cost.record('request_begin',force=True);cg="),
 ("        def journal():dump(f'attempt-{nonce}.json',row)","        def journal():\n            t=cost.now();dump(f'attempt-{nonce}.json',row);cost.span('controller_journal',t)"),
 ("        cg.mkdir();", "        cost.record('domain_build_begin');cg.mkdir();"),
 ("        log=(O/f'{n}-{case}-bwrap.log')", "        cost.record('bwrap_spawn_begin');log=(O/f'{n}-{case}-bwrap.log')"),
 ("        ready,export,cred=recv(ds);", "        cost.record('bwrap_spawn_return');ready,export,cred=recv(ds);cost.record('domain_fd_received',domain_ready_ns=ready.get('monotonic_ns'));"),
 ("        st,sc=socket.socketpair", "        cost.record('domain_ready');st,sc=socket.socketpair"),
 ("                    if typ=='PREPARED':", "                    if typ=='PREPARED':\n                        cost.record('prepared')"),
 ("                    elif typ=='ENTERED':", "                    elif typ=='ENTERED':\n                        cost.record('entered')"),
 ("                        if typ=='WORKER_GATED':", "                        if typ=='WORKER_GATED':\n                            cost.record('worker_gated')"),
 ("if sealed and not stopped:ds.send(b'STOP');stopped=True", "if sealed and not stopped:\n                    t=cost.now();ds.send(b'STOP');cost.ipc('send',{'op':'STOP','nonce':nonce},t,ds.fileno());stopped=True"),
 ("        row['monitor_wait']=", "        cost.record('domain_quiescent');row['monitor_wait']="),
 ("            send(self.z['sock'],{'op':'FORGET','nonce':nonce})", "            forget_start=cost.now();cost.record('forget_begin');send(self.z['sock'],{'op':'FORGET','nonce':nonce})"),
 ("                if m['event']=='FORGOTTEN':break", "                if m['event']=='FORGOTTEN':break\n            cost.span('rpc_forget',forget_start);cost.record('forget_done')"),
 ("        row['resources']='RELEASED';", "        cost.record('resources_deleted');row['resources']='RELEASED';"),
 ("            send(self.z['sock'],{'op':'PING'});", "            ping_start=cost.now();send(self.z['sock'],{'op':'PING','nonce':nonce});"),
 ("            row['zygote_post']=m", "            cost.span('rpc_ping',ping_start);row['zygote_post']=m\n            assert m['nonce']==nonce and m['session']==self.z['ready']['session'] and m['identity']['pid']==self.z['pid'] and m['active_attempts']==0,m"),
 ("        journal();self.validate(row)", "        journal();self.validate(row);cost.record('validation_done')"),
 ("self.rows.append(row);return row", "self.rows.append(row);cost.record('response_ready',force=True);return row"),
 ("        self.start_z()\n        for c", "        if case=='performance':suites[case]=['normal']*(int(os.environ.get('COST_REQUESTS','35'))+int(os.environ.get('COST_WARMUP','5')))\n        self.start_z()\n        for c"),
 ("        self.rpc_supervisor({'op':'DONE'})", "        self.rpc_supervisor({'op':'DONE'});cost.record('session_end',force=True);cost.usage('controller_final_usage')"),
 ("    (trace/'tracing_on').write_text('1')", "    (trace/'trace_clock').write_text('mono')\n    if os.environ.get('COST_SYSCALL_TRACE')=='1':\n        for name in ['sys_enter_clone3','sys_exit_clone3']:(trace/'events/syscalls'/name/'enable').write_text('1')\n    (trace/'tracing_on').write_text('1' if os.environ.get('COST_TRACE','1')=='1' else '0')\n    cost.record('fixture_session_start',force=True)"),
 ("        def execute(sock):", "        cost.context('H');cost.record('supervisor_forked')\n        def execute(sock):"),
 ("    _,status=os.waitpid(p,0)", "    _,status=os.waitpid(p,0);cost.record('session_supervisor_waited',force=True)"),
 ("    return 0 if status==0 and released else 1", "    cost.record('fixture_release',force=True,released=released);cost.flush()\n    return 0 if status==0 and released else 1")])
# Existing runtime snapshot logging/security checks are not disabled or cached.
f=p/'runtime_probe.py';s=f.read_text();s+='''\n# Diagnostic envelope only; original snapshot contents and I/O are unchanged.\n_snapshot_original=snapshot\ndef snapshot(*args,**kwargs):\n    import cost\n    t=cost.now()\n    try:return _snapshot_original(*args,**kwargs)\n    finally:cost.span('runtime_snapshot_'+str(args[0] if args else 'unknown'),t)\n''';f.write_text(s)
print('instrumented Python copies')
