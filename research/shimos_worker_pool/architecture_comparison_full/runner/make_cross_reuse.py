from pathlib import Path
S=Path(__file__).resolve().parents[1]
s=(S/'prototype/run.py').read_text()
d=s[s.index('    def domain(self,case):'):s.index('    def validate(self,r):')]
d=d.replace("row={'case':case", "row={'release_scope':'REQUEST_GROUP','workspace_scope':'same-trust retained /work; request taskwork is registration directory','persistent_domain_nonce':self.d['nonce'],'case':case")
a=d.index("        cost.record('domain_build_begin')");b=d.index("        row['domain_ready_record']=ready",a)
d=d[:a]+'''        cost.record('request_group_begin');cg.mkdir();(cg/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        for key,value in [('memory.max',str(512*1024**2)),('pids.max','256'),('cpu.max','400000 100000')]:(cg/key).write_text(value)
        trans=writecg(cg/'transition');business=writecg(cg/'business');control=self.d['control'];work.mkdir()
        taskwork=work;work=self.d['work']
        if case=='pid_budget':(trans/'pids.max').write_text('0')
        if case=='second_budget':(business/'pids.max').write_text('0')
        ds=self.d['sock'];log=self.d['log'];argv=self.d['argv'];mon=self.d['pid'];monfd=None
        ready=self.d['ready'];export=[os.dup(f) for f in self.d['export']];cred=self.d['cred']
'''+d[b:]
d=d.replace("'workspace':str(work)},[rd]", "'workspace':str(taskwork)},[rd]")
d=d.replace("req={'op':'SPAWN','nonce':nonce,", "req={'op':'SPAWN','nonce':nonce,'domain_nonce':self.d['nonce'],'full_profile':os.environ.get('FULL_PROFILE','legacy'),")
d=d.replace("row['drained']=m;cost.record", "self.d['drained']=m;row['drained']=m;cost.record")
d=d.replace("if sealed and not stopped:\n                    t=cost.now();ds.send(b'STOP');cost.ipc('send',{'op':'STOP','nonce':nonce},t,ds.fileno());stopped=True", "if sealed:stopped=True")
d=d.replace("if mon in self.waited and empty(cg) and sdone and sealed and row['output_eof'] and not status_open and (case!='cancel_queued' or row.get('late_commit_rejected')) and (row['failure'] or row.get('drained')):", "if empty(cg) and sdone and sealed and row['output_eof'] and not status_open and (case!='cancel_queued' or row.get('late_commit_rejected')):")
d=d.replace("if self.nochildren and empty(cg):", "if sorted(int(p) for p in Path(f'/proc/self/task/{os.getpid()}/children').read_text().split())==([mon] if mon not in self.waited else []) and empty(cg):")
d=d.replace("expected_children=[self.z['pid']] if self.z['alive'] else []", "expected_children=([self.z['pid']] if self.z['alive'] else [])+([mon] if mon not in self.waited else [])")
d=d.replace("cost.record('domain_quiescent');", "self.request_quiesce(nonce);cost.record('request_group_quiescent');")
d=d.replace("row['monitor_wait']=self.waited[mon]", "row['monitor_wait']=self.waited.get(mon);row['domain_retained']=mon not in self.waited")
d=d.replace("st.close();ds.close();log.close()", "st.close();ds.setblocking(True)")
d=d.replace("for p in [business,trans,control,cg]:p.rmdir()", "for p in [business,trans,cg]:p.rmdir()")
d=d.replace("shutil.rmtree(work);cost.finish", "shutil.rmtree(taskwork);cost.finish")
d=d.replace("not cg.exists() and not work.exists()", "not cg.exists() and not taskwork.exists()")
# Copy/remove only known outputs in the retained same-trust workspace.
d=d.replace("row['controller_fd_after']=fdcount();", "\n        for name in ('numpy-output.npz','result'):\n            f=work/name\n            if f.exists():f.unlink()\n        row['controller_fd_after']=fdcount();")
header=s[:s.index('class Controller:')]+"\nfrom run import Controller as BaseController\nclass Controller(BaseController):\n"
extra='''    def __init__(self,supervisor):
        super().__init__(supervisor);self.d=None;self.domains=[]
    def open_domain(self):
        assert self.d is None
        nonce=os.urandom(16).hex();cg=CG/('d-'+nonce);work=R/('work-'+nonce)
        started=time.monotonic_ns();cost.record('retained_domain_begin',domain_nonce=nonce,force=True)
        cg.mkdir();(cg/'cgroup.subtree_control').write_text('+cpu +memory +pids')
        (cg/'memory.max').write_text(str(512*1024**2));(cg/'pids.max').write_text('256');(cg/'cpu.max').write_text('400000 100000')
        control=writecg(cg/'control');work.mkdir()
        ds,ch=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);ds.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);ds.settimeout(10)
        rd,wr=os.pipe2(os.O_CLOEXEC);os.set_blocking(rd,False)
        self.rpc_supervisor({'op':'REGISTER','nonce':nonce,'cgroup':str(cg),'workspace':str(work)},[rd])
        log=(O/('domain-'+nonce+'.log')).open('wb');argv=self.bwrap(work,nonce)
        mon,pfd=self.spawn(argv,control,wr,ch.fileno());ch.close();os.close(wr);self.waited.pop(mon,None)
        ready,export,cred=recv(ds)
        assert ready['event']=='DOMAIN_READY' and ready['nonce']==nonce and len(export)==7 and cred[1:]==(65534,65534)
        assert str(cred[0]) in (control/'cgroup.procs').read_text().split()
        self.d={'nonce':nonce,'cg':cg,'work':work,'control':control,'sock':ds,'log':log,'argv':argv,'pid':mon,'pidfd':pfd,'ready':ready,'export':export,'cred':cred,'hold_read':rd,'begin_ns':started,'ready_ns':time.monotonic_ns()}
        cost.record('retained_domain_ready',domain_nonce=nonce,force=True)
    def request_quiesce(self,nonce):
        d=self.d
        if d['pid'] in self.waited:return
        d['sock'].settimeout(8);d['sock'].send(('QUIESCE '+nonce).encode());m,f,_=recv(d['sock'])
        assert not f and m.get('event')=='QUIESCENT' and m.get('nonce')==nonce and m.get('echild'),m
        event(m);d.setdefault('quiescence',[]).append(m)
    def close_domain(self):
        d=self.d;assert d is not None
        if d['pid'] not in self.waited:
            d['sock'].settimeout(8);d['sock'].send(b'STOP');m,f,_=recv(d['sock']);assert not f and m.get('event')=='DRAINED' and m.get('echild') and m.get('nonce',d['nonce'])==d['nonce'];d['drained']=m
        until=time.monotonic()+8
        while d['pid'] not in self.waited:
            self.reap();assert time.monotonic()<until;time.sleep(.002)
        assert empty(d['cg']);state=stats(d['cg']);wait=self.waited[d['pid']]
        while True:
            chunk=os.read(d['hold_read'],65536)
            if not chunk:break
            d['log'].write(chunk)
        os.close(d['hold_read'])
        for f in d['export']+[d['pidfd']]:os.close(f)
        d['sock'].close();d['log'].close();d['control'].rmdir();d['cg'].rmdir();shutil.rmtree(d['work'])
        self.rpc_supervisor({'op':'RETIRE','nonce':d['nonce'],'outcome':'DOMAIN_CLOSED','output_eof':True})
        row={'nonce':d['nonce'],'output_eof':True,'output_channel_role':'real monitor/PID1 output','quiescence':d.get('quiescence',[]),'monitor_wait':wait,'drained':d.get('drained'),'begin_ns':d['begin_ns'],'ready_ns':d['ready_ns'],'released_ns':time.monotonic_ns(),'stats':state,'resources_removed':not d['cg'].exists() and not d['work'].exists()}
        self.domains.append(row);dump('persistent-domains.json',self.domains);self.d=None
        cost.record('retained_domain_released',domain_nonce=d['nonce'],force=True)
    def validate(self,r):
        assert r['resources_removed'] and r['output_eof'] and r['domain_empty'] and r['admission'].startswith('SEALED'),r
        if r['worker']:
            assert all(r['worker']['checks'].values()) and r['worker']['inherited']==r['expected_state'],r
            assert all(r['worker']['numpy']['checks'].values()),r
            assert r.get('numpy_output',{}).get('sha256')==r['worker']['numpy']['output_sha256'],r
        if r['case'] in ('normal','nonzero','created_drop','reaped_drop'):
            assert not r['failure'] and r['s_wait']==0 and r['result']['exit_code']==(7 if r['case']=='nonzero' else 0) and r['worker'],r
        else:
            assert r['outcome']!='SUCCEEDED' and r['failure'],r
        if r['case']=='double_cancel':assert r.get('terminal_duplicate_ack',{}).get('sealed'),r
    def run(self):
        D=int(os.environ.get('FULL_DOMAINS','1'));K=int(os.environ.get('FULL_PER_DOMAIN','2'))
        case=os.environ.get('RELIABILITY_CASE','performance');cases=['normal']*K if case=='performance' else case.split(',')
        assert D>0 and K>0
        for di in range(D):
            if self.z is None:self.start_z()
            self.open_domain()
            for c in cases:
                cost.record('numpy_call_begin',force=True,call_index=len(self.rows));self.domain(c);cost.record('numpy_call_complete',force=True,call_index=len(self.rows)-1)
                if not self.z['alive']:break
            self.close_domain()
            if not self.z['alive']:self.stop_z()
        if self.z is not None:self.stop_z()
        self.reap();assert self.nochildren
        dump('summary.json',{'all_passed':True,'case':case,'rows':self.rows,'persistent_domains':self.domains,'controller_echild':True,'wait_records':self.wait_records,'full_mode':'G2_REUSE'})
        self.rpc_supervisor({'op':'DONE'});cost.record('session_end',force=True)
'''
(S/'prototype/run_cross_reuse.py').write_text(header+extra+'\n'+d)
