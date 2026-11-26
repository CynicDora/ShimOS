#!/usr/bin/env python3
"""Private-VM measurement driver; frozen B-strict owns execution and cleanup.

No pool policy. Single trust/workspace, deterministic serial request sequences.
Root observer reads only this run's cgroups; it never kills or cleans workers.
"""
import argparse,os,sys,json,time,socket,hashlib,resource,random,traceback,shutil
from pathlib import Path

def ns():return time.monotonic_ns()
def dump(p,data):p.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')
def cpu(st):return int(dict(x.split() for x in st['cpu.stat'].splitlines())['usage_usec'])*1000
def recvline(f):
    line=f.readline(8*1024*1024)
    if not line:raise EOFError('Worker/observer closed without response')
    return json.loads(line)

class Client:
    def __init__(self,path):
        self.s=socket.socket(socket.AF_UNIX);self.s.settimeout(30);self.s.connect(str(path));self.f=self.s.makefile('rb')
    def call(self,obj):self.s.sendall(json.dumps(obj,separators=(',',':')).encode()+b'\n');return recvline(self.f)
    def close(self):self.f.close();self.s.close()

def snapshot(root):
    t=ns();c0=time.process_time_ns();pids=set();records=[]
    for cg in [root,*root.rglob('*')]:
        if cg.is_dir() and (cg/'cgroup.procs').exists():
            try:pids.update(map(int,(cg/'cgroup.procs').read_text().split()))
            except FileNotFoundError:pass
    for pid in sorted(pids):
        p=Path('/proc')/str(pid);r={'pid':pid}
        try:
            before=(p/'stat').read_text();r['comm']=(p/'comm').read_text().strip();r['status']=(p/'status').read_text();r['cgroup']=(p/'cgroup').read_text()
            r['starttime']=int(before.rsplit(')',1)[1].split()[19]);r['fds']=len(list((p/'fd').iterdir()))
            mem=(p/'smaps_rollup').read_text();r['pss_kib']=int(next(x.split()[1] for x in mem.splitlines() if x.startswith('Pss:')));r['rss_kib']=int(next(x.split()[1] for x in mem.splitlines() if x.startswith('Rss:')))
            r['stable_identity']=r['starttime']==int((p/'stat').read_text().rsplit(')',1)[1].split()[19])
        except (OSError,StopIteration,ValueError) as e:r['error']=repr(e)
        records.append(r)
    return {'processes':records,'pss_sum_kib':sum(x.get('pss_kib',0) for x in records),'rss_sum_kib':sum(x.get('rss_kib',0) for x in records),'missing':sum('error' in x or not x.get('stable_identity') for x in records),'wall_ns':ns()-t,'observer_cpu_ns':time.process_time_ns()-c0,'not_peak':True}

def foundation():
    r=Path(os.environ['BG_ROOT']);o=Path(os.environ['BG_OUT']);p=r/'prototype'
    src=(p/'suite.py').read_text();marker='\ntry:main('
    assert src.count(marker)==1
    g={'__name__':'frozen_b_strict','__file__':str(p/'suite.py')}
    exec(compile(src.split(marker)[0],str(p/'suite.py'),'exec'),g)
    exec(compile((p/'diagnostics.py').read_text(),str(p/'diagnostics.py'),'exec'),g)
    return g

def main_child(a,b,obs):
    o=b['O'];r=b['R'];cg=b['CG'];of=obs.makefile('rb');measurements=[]
    # PR_SET_CHILD_SUBREAPER is NOT inherited by fork. Re-establish the frozen
    # Raw baseline's strict reap contract in the actual executing controller.
    libc=b['ctypes'].CDLL(None,use_errno=True);assert libc.prctl(36,1,0,0,0)==0
    sub=b['ctypes'].c_int();assert libc.prctl(37,b['ctypes'].byref(sub),0,0,0)==0 and sub.value==1
    sys.path.insert(0,'/runtime/pool-workers');import protocol
    b['delegate'](cg);clientcg=cg/'client';clientcg.mkdir();b['delegate'](clientcg);(clientcg/'cgroup.procs').write_text(str(os.getpid()))
    # One aggregate budget regardless of how many task domains layout uses.
    (cg/'memory.max').write_text(str(1024**3));(cg/'pids.max').write_text('512');(cg/'cpu.max').write_text('400000 100000')
    os.chown(r,65534,65534);os.chown(o,65534,65534);os.setgroups([]);os.setgid(65534);os.setuid(65534)
    os.environ.update(OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1',MKL_NUM_THREADS='1',LD_LIBRARY_PATH='/usr/local/lib/worker-deps',LANG='C.UTF-8',PYTHONHASHSEED='0')
    fd_initial=len(list(Path('/proc/self/fd').iterdir()))
    def observe(path):
        if not a.resources and a.mode!='layout':return None
        t=ns();obs.sendall(json.dumps({'path':str(path)}).encode()+b'\n');d=recvline(of);d['client_roundtrip_ns']=ns()-t;return d
    def argv(kind,sock):return ['/bin/env','LD_LIBRARY_PATH=/usr/local/lib/worker-deps','OPENBLAS_NUM_THREADS=1','OMP_NUM_THREADS=1','/usr/bin/python3','-B','/pool-workers/server.py','--kind',kind,'--socket','/work/'+sock,'--workspace','/src','--clangd','/usr/bin/clangd']
    def wait_ready(holder,gid=None):
        if gid is None:holder.until(b'\n');raw=holder.buf
        else:holder.until_output(gid,b'\n');raw=holder.groups[gid]['output']
        try:row=json.loads(raw.splitlines()[0]);assert row['event']=='ready',row
        except Exception:
            dump(o/'ready-failure.json',{'output':raw.decode(errors='replace'),'holder':holder.name,'gid':gid});raise
        return row
    def start_worker(kind,task,mode,label,sock='worker.sock'):
        t=ns()
        if mode=='A':
            work=r/label;work.mkdir();raw=b['Raw'](label,argv(kind,sock),work=work);ready=wait_ready(raw);return {'start_ns':t,'ready_ns':ns(),'ready':ready,'raw':raw,'work':work,'socket_name':sock,'client':Client(work/sock),'mode':mode}
        gid=task.start(argv(kind,sock));ready=wait_ready(task,gid);return {'start_ns':t,'ready_ns':ns(),'ready':ready,'task':task,'gid':gid,'work':task.work,'socket_name':sock,'client':Client(task.work/sock),'mode':mode}
    def stop_worker(w,request_shutdown=True):
        t=ns();c=w['client'];reply=None
        if request_shutdown:
            reply=c.call({'id':'shutdown','op':'shutdown'});assert reply['status']=='ok' and reply['result']['worker_shutdown']=='normal' and reply['result']['child_reaped'] and reply['result']['child_exit_code'] in (None,0),reply
        c.close()
        log=w['work']/(w['socket_name']+'.clangd.stderr');stderr={log.name:log.read_text(errors='replace')} if log.exists() else {}
        if w['mode']=='A':
            row=w['raw'].release(reap_all=True);assert row['rc']==0,row
            shutil.rmtree(w['work']);st=row['stats'];status=row['rc'];release=ns()
        else:
            row=w['task'].wait(w['gid'],30);st=row['stats'];status=os.waitstatus_to_exitcode(row['status']);assert status==0 or not request_shutdown,row
            release=row['released_ns']
        assert 'populated 0' in st['cgroup.events']
        output=row.get('output');output=output.decode(errors='replace') if isinstance(output,bytes) else output
        return {'shutdown':reply,'stop_to_release_ns':release-t,'release_ns':release,'stats':st,'status':status,'output':output,'clangd_stderr':stderr,'domain_removed':not (w['raw'].cg if w['mode']=='A' else row['cg']).exists()}
    def call(w,request,verify=True):
        t=ns();response=w['client'].call(request);responded=ns()
        vc=time.process_time_ns()
        if verify:protocol.verify(w['ready']['identity']['kind'],request,response)
        return {'request':request,'response':response,'submit_ns':t,'received_ns':responded,'verified_ns':ns(),'verify_cpu_ns':time.process_time_ns()-vc,'ipc_plus_execution_ns':responded-t}
    def serial(kind,mode,n,rep,block):
        label=f's{a.session}-b{block}-{kind}-{mode}-n{n}-r{rep}'
        t0=ns();c0=time.process_time_ns();task=None;rows=[];managed_cpu=0;teardown=0;idle=None;init_idle=None
        if mode!='A':
            t=ns();task=b['Task'](label,strict=True);domain_constructor=ns()-t;domain_ready=task.ready_ns-task.start_ns
            init_idle=observe(task.cg)
        else:domain_constructor=None;domain_ready=None
        w=None;pings=[];final_stats=None;last_idle=None
        for i,request in enumerate(protocol.requests(kind,n)):
            t=ns()
            if w is None:w=start_worker(kind,task,mode,f'{label}-q{i}',sock=f'worker-{i}.sock')
            first=(i==0)
            if first:
                init_stats=b['stats'](w['raw'].cg if mode=='A' else task.groups[w['gid']]['cg'])
            r0=call(w,request)
            r0['worker_start_ns']=w['start_ns'];r0['worker_ready_ns']=w['ready_ns'];r0['launch_to_valid_response_ns']=r0['verified_ns']-w['start_ns']
            if first:
                r0['initialization']={'ready':w['ready'],'launch_to_ready_ns':w['ready_ns']-w['start_ns'],'group_stats_at_ready':init_stats}
                idle=observe(w['raw'].cg if mode=='A' else task.cg)
                for pi in range(3):pings.append(call(w,{'id':'ping'+str(pi),'op':'ping'},False))
            elif mode!='C':r0['initialization']={'ready':w['ready'],'launch_to_ready_ns':w['ready_ns']-w['start_ns']}
            if i==n-1:
                final_stats=call(w,{'id':'stats','op':'stats'},False)
                last_idle=idle if first else observe(w['raw'].cg if mode=='A' else task.cg)
            if mode in ['A','B']:
                stop=stop_worker(w);r0['release']=stop
                if mode=='A':managed_cpu+=cpu(stop['stats'])
                w=None
            r0['active_request_ns']=ns()-t;rows.append(r0)
        if w:
            stop=stop_worker(w);teardown=stop['stop_to_release_ns']
        else:stop=None
        close=None;close_return_overhead=None
        if task:
            close=task.close();close_return_overhead=ns()-task.end_ns;managed_cpu=cpu(close['task_stats']);teardown+=int(close['teardown_ms']*1e6)
        t1=ns();result={'session':a.session,'block':block,'repeat':rep,'kind':kind,'mode':mode,'n':n,'label':label,'sequence_total_ns':t1-t0,'controller_cpu_ns':time.process_time_ns()-c0,'managed_cgroup_cpu_ns':managed_cpu,'domain_constructor_ns':domain_constructor,'domain_ready_ns':domain_ready,'empty_domain_idle':init_idle,'initialized_idle':idle,'last_idle':last_idle,'requests':rows,'pings':pings,'final_stats':final_stats,'worker_final_release':stop,'domain_final_release':close,'final_teardown_ns':teardown,'fd_after':len(list(Path('/proc/self/fd').iterdir())),'fd_initial':fd_initial,'passed':True,'timing_note':'Total includes measurement probes; their explicit intervals remain charged. Persistent request response is not group RELEASED.'}
        result['domain_release_to_close_return_ns']=close_return_overhead
        assert result['fd_after']==fd_initial,(label,'FD imbalance',result['fd_after'],fd_initial)
        measurements.append(result)
        with (o/'results.jsonl').open('a') as f:f.write(json.dumps(result,default=str)+'\n')
    def qualify(kind):
        task=b['Task']('qualify-'+kind);w=start_worker(kind,task,'C','unused')
        good=protocol.requests(kind,1)[0];first=call(w,good)
        bad=call(w,protocol.invalid_request(kind),False);protocol.verify_error(bad['response'])
        unknown=call(w,{'id':'bad-op','op':'unknown-operation'},False);assert unknown['response'].get('status')=='error' and unknown['response'].get('state')=='ready',unknown
        again={**good,'id':'after-error'};second=call(w,again);assert first['response']['result']==second['response']['result']
        # Real cancellation through unchanged B-strict; no observer process kill.
        task.cancel(w['gid']);stop=stop_worker(w,False);assert stop['status']!=0
        w=start_worker(kind,task,'C','unused',sock='retry.sock');retry=call(w,good);assert retry['response']['result']==first['response']['result'];stop2=stop_worker(w);close=task.close()
        q={'kind':kind,'passed':True,'first':first,'error':bad,'unknown_operation':unknown,'next':second,'cancel':stop,'retry':retry,'retry_release':stop2,'task_release':close};dump(o/('qualification-'+kind+'.json'),q)
    def layout(shared,rep):
        t0=ns();c0=time.process_time_ns();tasks=[];ws=[];rows=[];label=f'layout-{shared}-r{rep}';kinds=['numpy','clangd']
        for i,kind in enumerate(kinds):
            if i==0 or not shared:
                tasks.append(b['Task'](label+'-'+kind))
                if shared:
                    (tasks[-1].cg/'memory.max').write_text(str(1024**3));(tasks[-1].cg/'pids.max').write_text('512')
            w=start_worker(kind,tasks[-1],'C',label,sock=kind+'.sock');ws.append(w)
            rows.append(call(w,protocol.requests(kind,1)[0]))
        idle=[observe(t.cg) for t in tasks]
        for w in ws:rows.append(call(w,{**protocol.requests(w['ready']['identity']['kind'],1)[0],'id':'second'}))
        stops=[stop_worker(w) for w in ws];closes=[t.close() for t in tasks]
        result={'session':a.session,'mode':'layout','shared':shared,'repeat':rep,'sequence_total_ns':ns()-t0,'controller_cpu_ns':time.process_time_ns()-c0,'managed_cgroup_cpu_ns':sum(cpu(x['task_stats']) for x in closes),'idle_domains':idle,'ready':[w['ready'] for w in ws],'requests':rows,'stops':stops,'closes':closes,'passed':True,'note':'Same trust/workspace policy class; sequential requests, not contention/isolation proof; aggregate study cgroup budget fixed'}
        measurements.append(result)
        with (o/'results.jsonl').open('a') as f:f.write(json.dumps(result,default=str)+'\n')
    dump(o/'environment.json',{'kernel':os.uname().release,'uid':os.getuid(),'cpuinfo':Path('/proc/cpuinfo').read_text(),'loadavg':Path('/proc/loadavg').read_text(),'meminfo':Path('/proc/meminfo').read_text(),'baseline_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in b['P'].iterdir() if p.is_file()},'kind':'controlled mechanism sensitivity, no online Agent','same_physical_host':True,'controller_cgroup':str(clientcg),'worker_protocol':'private AF_UNIX JSONL within same trust/workspace','fd_initial':fd_initial,'controller_subreaper_verified':sub.value==1})
    seed=20261016+a.session;rng=random.Random(seed)
    plan=[]
    if a.mode=='cost':
        blocks=[(kind,n,rep) for kind in ['numpy','clangd'] for n in map(int,a.counts.split(',')) for rep in range(a.repeats)];rng.shuffle(blocks)
        for block,(kind,n,rep) in enumerate(blocks):
            modes=list('ABC');rng.shuffle(modes)
            for mode in modes:plan.append((kind,mode,n,rep,block))
    dump(o/'config.json',{'arguments':vars(a),'seed':seed,'plan':plan,'contract':'B-strict frozen same-trust rootless namespace and policy; aggregate 4CPU/1GiB/512tasks; cost task/Raw domain 4CPU/512MiB/256tasks, Worker group inherits task cap. Layout shared task1GiB/512tasks or two512MiB/256tasks, common outer4CPU/1GiB/512tasks; no contention claim.','cpu_accounting':'controller SELF plus recursive domain cgroup cpu; never add children rusage. Observer diagnostic CPU separate.','cold_meaning':'fresh processes/domains with natural page cache, not flushed disk cache','source_runtime_additions_manifest':json.loads(Path('/runtime/pool-workers/runtime-manifest.json').read_text())})
    if a.mode=='cost':
        for row in plan:serial(*row)
    elif a.mode=='qualify':
        for kind in ['numpy','clangd']:qualify(kind)
    else:
        plan=[(shared,rep) for rep in range(a.repeats) for shared in [False,True]];rng.shuffle(plan)
        for row in plan:layout(*row)
    assert len(list(Path('/proc/self/fd').iterdir()))==fd_initial
    remaining=[str(x) for x in cg.iterdir() if x.is_dir()];assert remaining==[str(clientcg)],remaining
    dump(o/'summary.json',{'passed':True,'rows':len(measurements),'mode':a.mode,'remaining_cgroups':remaining,'fd_final':len(list(Path('/proc/self/fd').iterdir())),'fd_initial':fd_initial})
    of.close();obs.close()

def main():
    assert Path('/run/native-benchmark-lab').read_text().strip()=='private-stock-linux-benchmark-vm'
    p=argparse.ArgumentParser();p.add_argument('--session',type=int,required=True);p.add_argument('--repeats',type=int,default=1);p.add_argument('--counts',default='1,4');p.add_argument('--mode',choices=['cost','layout','qualify'],default='cost');p.add_argument('--resources',action='store_true');a=p.parse_args()
    b=foundation();outer,inner=socket.socketpair();child=os.fork()
    if child==0:
        outer.close()
        try:main_child(a,b,inner)
        except BaseException:
            err=traceback.format_exc();print(err,flush=True);dump(b['O']/'failure.json',{'error':err});os._exit(1)
        os._exit(0)
    inner.close();f=outer.makefile('rb');observer=[]
    while True:
        line=f.readline()
        if not line:break
        msg=json.loads(line);path=Path(msg['path']);assert path.is_relative_to(b['CG']) and path!=b['CG']
        reply=snapshot(path);observer.append({'path':str(path),'wall_ns':reply['wall_ns'],'cpu_ns':reply['observer_cpu_ns']});outer.sendall(json.dumps(reply).encode()+b'\n')
    f.close();outer.close();_,status=os.waitpid(child,0)
    # Read-only failure observation: never kill or reap workers on child's behalf.
    remaining=[str(x) for x in b['CG'].rglob('*') if x.is_dir()];dump(b['O']/'observer-cost.json',observer)
    if os.waitstatus_to_exitcode(status)==0:
        assert remaining==[str(b['CG']/'client')],remaining
        assert 'populated 0' in (b['CG']/'cgroup.events').read_text()
        (b['CG']/'client').rmdir();b['CG'].rmdir()
        dump(b['O']/'external-final-release.json',{'private_cgroup_root_removed':True,'controller_exited':True,'observer_killed_workers':False})
        assert not Path(f'/proc/self/task/{os.getpid()}/children').read_text().strip(),'observer unexpectedly inherited workers'
    else:
        dump(b['O']/'remaining-after-failure.json',remaining)
        dump(b['O']/'failure-worker-logs.json',{str(x.relative_to(b['R'])):x.read_text(errors='replace') for x in b['R'].glob('t*/*.clangd.stderr')})
    return os.waitstatus_to_exitcode(status)
if __name__=='__main__':raise SystemExit(main())
