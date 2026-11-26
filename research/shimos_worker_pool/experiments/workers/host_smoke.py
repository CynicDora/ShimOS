"""Trusted host-only protocol smoke; not an isolation or performance experiment."""
import hashlib,json,os,pathlib,shutil,subprocess,sys,tempfile,time
P=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(P))
import protocol

def main():
 out=P/'host-smoke-01';out.mkdir(exist_ok=False)
 events=[]
 for kind in ('numpy','clangd'):
  with tempfile.TemporaryDirectory(prefix='worker-protocol-') as tmp:
   d=pathlib.Path(tmp);sock=d/'worker.sock'
   env=dict(os.environ,OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1',PYTHONDONTWRITEBYTECODE='1')
   log=(out/(kind+'.stderr')).open('wb')
   proc=subprocess.Popen(['/usr/bin/python3','-B',str(P/'server.py'),'--kind',kind,'--socket',str(sock),'--workspace',str(P/'fixture'),'--stderr',str(d/'clangd.stderr')],stdout=subprocess.PIPE,stderr=log,env=env,text=True)
   try:
    ready=json.loads(proc.stdout.readline());assert ready['event']=='ready';events.append({'kind':kind,'ready':ready})
    with protocol.Client(sock) as c:
     for req in protocol.requests(kind,2):
      r=c.call(req);protocol.verify(kind,req,r);events.append({'kind':kind,'request':req,'response':r})
     r=c.call(protocol.invalid_request(kind));protocol.verify_error(r);events.append({'kind':kind,'error':r})
     req=protocol.requests(kind,1)[0];req['id']='post-error';r=c.call(req);protocol.verify(kind,req,r);events.append({'kind':kind,'post_error':r})
     for op in ('reset','stats','ping','shutdown'):
      r=c.call({'id':op,'op':op});assert r['status']=='ok';events.append({'kind':kind,op:r})
    assert proc.wait(timeout=10)==0
    events.append({'kind':kind,'stdout_remainder':proc.stdout.read(),'socket_removed':not sock.exists()})
    if kind=='clangd':shutil.copy2(d/'clangd.stderr',out/'clangd.application.stderr')
   finally:
    if proc.poll() is None:proc.kill();proc.wait()
    log.close();proc.stdout.close()
 src=P/'fixture';obj=out/'adler32.o'
 cmd=['/usr/bin/gcc','-std=c11','-O0','-c',str(src/'adler32.c'),'-I'+str(src),'-o',str(obj)]
 cc=subprocess.run(cmd,text=True,capture_output=True);assert cc.returncode==0,cc.stderr
 nm=subprocess.check_output(['nm','--defined-only',str(obj)],text=True)
 names=sorted(l.split()[-1] for l in nm.splitlines() if l.split()[1] in ('T','t'))
 assert names==sorted(x['name'] for x in protocol.oracle('clangd',{},src)['functions'])
 (out/'compiler-oracle.json').write_text(json.dumps({'command':cmd,'exit':cc.returncode,'stdout':cc.stdout,'stderr':cc.stderr,'nm':nm,'function_names':names,'object_sha256':hashlib.sha256(obj.read_bytes()).hexdigest()},indent=2)+'\n')
 (out/'events.json').write_text(json.dumps(events,indent=2)+'\n')
 print(json.dumps({'ok':True,'output':str(out),'note':'host-only functionality, not benchmark'}))
if __name__=='__main__':main()
