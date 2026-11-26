#!/usr/bin/env python3
"""One trusted, serial worker; external B-strict owns sandbox/cgroup lifecycle.

JSONL over a filesystem Unix socket. No arbitrary code evaluation, no sessions,
no cross-tenant reuse, no persistent result cache. Fixed input revision only.
"""
import time
ENTRY_WALL_NS=time.monotonic_ns()
ENTRY_CPU_NS=time.process_time_ns()
import argparse,gc,hashlib,json,os,pathlib,resource,socket,subprocess,sys

SCHEMA=1
MAX_LINE=65536
FIXTURE_NAMES=('adler32.c','zutil.h','zlib.h','zconf.h')

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()
def filehash(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def process_metrics(pid):
 result={'pid':pid,'pss_kib':None,'rss_kib':None,'cpu_ticks':None,'start_ticks':None,'threads':None,'fd_count':None}
 try:
  root=pathlib.Path('/proc')/str(pid)
  st=(root/'stat').read_text();v=st[st.rfind(')')+2:].split()
  result.update(cpu_ticks=int(v[11])+int(v[12]),start_ticks=int(v[19]),clock_ticks_per_second=os.sysconf('SC_CLK_TCK'))
  for line in (root/'status').read_text().splitlines():
   if line.startswith('Threads:'):result['threads']=int(line.split()[1])
  for line in (root/'smaps_rollup').read_text().splitlines():
   if line.startswith('Pss:'):result['pss_kib']=int(line.split()[1])
   elif line.startswith('Rss:'):result['rss_kib']=int(line.split()[1])
  result['fd_count']=len(list((root/'fd').iterdir()))
 except (OSError,ValueError,IndexError) as exc:result['observation_error']=type(exc).__name__
 return result

class ProtocolError(ValueError):pass
class InputChanged(RuntimeError):pass
class BackendError(RuntimeError):pass

class NumpyWorker:
 def __init__(self,workspace,clangd):
  t=time.monotonic_ns();c=time.process_time_ns()
  import numpy
  self.np=numpy
  self.dependency_init={'wall_ns':time.monotonic_ns()-t,'process_cpu_ns':time.process_time_ns()-c}
  self.identity={'numpy':numpy.__version__,'python':sys.version,'python_executable':sys.executable,'numpy_file':numpy.__file__,'operation':'integer-grouped-reduction-v1','state_retained':'interpreter and imported numpy; no request arrays/results retained'}
 def run(self,data):
  if not isinstance(data,dict) or set(data)!={'n','buckets','offset'}:raise ProtocolError('input requires exactly n,buckets,offset')
  n,buckets,offset=(data[k] for k in ('n','buckets','offset'))
  if any(type(x) is not int for x in (n,buckets,offset)) or not 1<=n<=262144 or not 1<=buckets<=1024 or not -1000<=offset<=1000:raise ProtocolError('bounded integer input required')
  np=self.np
  # Every request allocates its own arrays; no synthetic repeated imports.
  index=np.arange(n,dtype=np.int64)
  values=((index*17+offset)%1009)-504
  labels=index%buckets
  sums=np.zeros(buckets,dtype=np.int64)
  np.add.at(sums,labels,values)
  return {'count':n,'sum':int(values.sum()),'sum_of_squares':int(np.multiply(values,values).sum()),'group_sums':sums.tolist()}
 def reset(self):return {'request_state_retained':False,'collected':gc.collect()}
 def metrics(self):return {'server':process_metrics(os.getpid()),'worker':process_metrics(os.getpid()),'same_process':True}
 def close(self):return {'worker_shutdown':'normal','child_reaped':True,'child_exit_code':None}

class Lsp:
 def __init__(self,command,workspace,stderr_path):
  self.sock,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
  self.sock.settimeout(15)
  self.err=open(stderr_path,'xb')
  self.process=subprocess.Popen(command,stdin=child,stdout=child,stderr=self.err,cwd=workspace,close_fds=True)
  child.close();self.buffer=b'';self.sequence=0;self.diagnostics={};self.notifications=0;self.last_request=None
 def send(self,message):
  b=canonical(message);self.sock.sendall(b'Content-Length: '+str(len(b)).encode()+b'\r\n\r\n'+b)
 def notify(self,method,params):self.send({'jsonrpc':'2.0','method':method,'params':params})
 def receive(self):
  while b'\r\n\r\n' not in self.buffer:self._read()
  header,body=self.buffer.split(b'\r\n\r\n',1)
  size=int(next(x.split(b':',1)[1] for x in header.split(b'\r\n') if x.lower().startswith(b'content-length:')))
  if not 0<=size<=8*1024*1024:raise BackendError('LSP frame size')
  while len(body)<size:
   self._read();header,body=self.buffer.split(b'\r\n\r\n',1)
  self.buffer=body[size:];return json.loads(body[:size])
 def _read(self):
  b=self.sock.recv(65536)
  if not b:raise EOFError('clangd stdout closed')
  self.buffer+=b
 def dispatch(self,msg):
  self.notifications+=1
  if 'method' in msg and 'id' in msg:
   self.send({'jsonrpc':'2.0','id':msg['id'],'error':{'code':-32601,'message':'client method not supported'}})
  elif msg.get('method')=='textDocument/publishDiagnostics':
   p=msg['params'];self.diagnostics[(p['uri'],p.get('version'))]=p['diagnostics']
 def rpc(self,method,params):
  self.sequence+=1;rid=self.sequence;self.last_request=method
  self.send({'jsonrpc':'2.0','id':rid,'method':method,'params':params})
  while True:
   msg=self.receive()
   if msg.get('id')==rid and 'method' not in msg:
    if 'error' in msg:raise BackendError('clangd error: '+json.dumps(msg['error']))
    return msg['result']
   self.dispatch(msg)
 def close(self):
  outcome={'worker_shutdown':'normal','child_reaped':False,'child_exit_code':None}
  try:
   self.rpc('shutdown',None);self.notify('exit',None)
   outcome['child_exit_code']=self.process.wait(timeout=5)
  except Exception as exc:
   outcome['worker_shutdown']='forced';outcome['shutdown_error']=repr(exc)
   # This child is owned by this wrapper. Domain cleanup remains B-strict's job.
   self.process.kill();outcome['child_exit_code']=self.process.wait(timeout=5)
  finally:
   self.sock.close();self.err.close();outcome['child_reaped']=self.process.poll() is not None
  r=resource.getrusage(resource.RUSAGE_CHILDREN)
  outcome['waited_child_cpu_seconds']=r.ru_utime+r.ru_stime
  return outcome

class ClangdWorker:
 def __init__(self,workspace,clangd,stderr_path):
  self.workspace=pathlib.Path(workspace).resolve();self.source=self.workspace/'adler32.c';self.uri=self.source.as_uri()
  self.hashes={n:filehash(self.workspace/n) for n in FIXTURE_NAMES}
  self.revision=digest(self.hashes)
  command=[clangd,'--background-index=false','--clang-tidy=false','--pch-storage=memory','--enable-config=false','-j=1','--log=error','--compile_args_from=lsp','--resource-dir=/usr/lib/llvm-14/lib/clang/14.0.0']
  t=time.monotonic_ns();c=time.process_time_ns()
  self.lsp=Lsp(command,str(self.workspace),stderr_path)
  self.lsp.rpc('initialize',{'processId':None,'rootUri':self.workspace.as_uri(),'capabilities':{'textDocument':{'documentSymbol':{'hierarchicalDocumentSymbolSupport':True},'publishDiagnostics':{'versionSupport':True}}}})
  self.lsp.notify('initialized',{})
  self.lsp.notify('workspace/didChangeConfiguration',{'settings':{'compilationDatabaseChanges':{str(self.source):{'workingDirectory':str(self.workspace),'compilationCommand':['/usr/bin/gcc','-std=c11','-I'+str(self.workspace),'-c',str(self.source)]}}}})
  self.lsp.notify('textDocument/didOpen',{'textDocument':{'uri':self.uri,'languageId':'c','version':1,'text':self.source.read_text()}})
  self.dependency_init={'wall_ns':time.monotonic_ns()-t,'process_cpu_ns':time.process_time_ns()-c,'includes_child_cpu':False,'ready_boundary':'initialize response plus didOpen sent; first request pays pending parse'}
  self.identity={'operation':'zlib-1.3.1-adler32-document-symbols-v1','source_revision':self.revision,'source_sha256':self.hashes,'clangd_command':command,'clangd_pid':self.lsp.process.pid,'document_version':1,'state_retained':'clangd AST/preamble for immutable translation unit; no claim of index reuse'}
 def run(self,data):
  if data!={'query':'documentSymbols'}:raise ProtocolError('only immutable documentSymbols request admitted')
  t=time.monotonic_ns()
  current={n:filehash(self.workspace/n) for n in FIXTURE_NAMES}
  if current!=self.hashes:raise InputChanged('fixed source revision changed; restart required')
  check_ns=time.monotonic_ns()-t
  symbols=self.lsp.rpc('textDocument/documentSymbol',{'textDocument':{'uri':self.uri}})
  functions=[]
  for s in symbols or []:
   if s.get('kind')==12:
    start=s.get('selectionRange',s.get('location',{}).get('range',{})).get('start',{})
    functions.append({'name':s['name'],'kind':s['kind'],'line':start.get('line'),'character':start.get('character')})
  # Native query replies require a parsed AST; collect same revision diagnostics.
  while (self.uri,1) not in self.lsp.diagnostics:self.lsp.dispatch(self.lsp.receive())
  diagnostics=self.lsp.diagnostics[(self.uri,1)]
  errors=[{'severity':d.get('severity'),'message':d.get('message')} for d in diagnostics if d.get('severity')==1]
  self.last_revision_check_ns=check_ns
  return {'functions':sorted(functions,key=lambda x:x['name']),'error_diagnostics':errors,'source_revision':self.revision,'document_version':1}
 def reset(self):
  # No source edits, no module reload claim. Request data lives only on stack.
  return {'request_state_retained':False,'application_state_retained':'immutable open document AST'}
 def metrics(self):return {'server':process_metrics(os.getpid()),'worker':process_metrics(self.lsp.process.pid),'same_process':False}
 def close(self):return self.lsp.close()

def unique(pairs):
 result={}
 for k,v in pairs:
  if k in result:raise ProtocolError('duplicate JSON key')
  result[k]=v
 return result

def serve(args):
 path=pathlib.Path(args.socket)
 if path.exists():raise RuntimeError('socket path already exists; refuse to replace')
 worker=None;sock=None;seen=set();quarantined=False;shutdown=None
 try:
  if args.kind=='numpy':worker=NumpyWorker(args.workspace,args.clangd)
  else:worker=ClangdWorker(args.workspace,args.clangd,args.stderr or str(path)+'.clangd.stderr')
  sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.bind(str(path));os.chmod(path,0o600);sock.listen(1)
  identity={'schema':SCHEMA,'kind':args.kind,'pid':os.getpid(),'start_ticks':process_metrics(os.getpid())['start_ticks'],'worker':worker.identity}
  ready={'event':'ready','identity':identity,'init_wall_ns':time.monotonic_ns()-ENTRY_WALL_NS,'init_process_cpu_ns':time.process_time_ns()-ENTRY_CPU_NS,'dependency_init':worker.dependency_init,'metrics':worker.metrics(),'boundary':'script entry to worker protocol ready; excludes interpreter before script entry'}
  print(json.dumps(ready,sort_keys=True),flush=True)
  done=False
  while not done:
   conn,_=sock.accept()
   with conn:
    f=conn.makefile('rb')
    while not done:
     line=f.readline(MAX_LINE+1)
     if not line:break
     begin=time.monotonic_ns();cpu=time.process_time_ns();thread=time.thread_time_ns();rid=None
     try:
      if len(line)>MAX_LINE or not line.endswith(b'\n'):raise ProtocolError('framing/size limit')
      req=json.loads(line,object_pairs_hook=unique)
      if not isinstance(req,dict) or not {'id','op'}<=set(req) or set(req)-{'id','op','input'}:raise ProtocolError('fields')
      rid=req['id']
      if not isinstance(rid,str) or not 0<len(rid)<=128 or rid in seen:raise ProtocolError('invalid or duplicate request id')
      seen.add(rid);op=req['op'];data=req.get('input',{})
      if op=='ping':result={'pong':True}
      elif op=='stats':result=worker.metrics()
      elif op=='reset':result=worker.reset()
      elif op=='shutdown':shutdown=worker.close();worker=None;result=shutdown;done=True
      elif op=='run':
       if quarantined:raise InputChanged('worker quarantined after revision change')
       result=worker.run(data)
      else:raise ProtocolError('unknown operation')
      response={'schema':SCHEMA,'id':rid,'status':'ok','result':result,'input_sha256':digest({'op':op,'input':data}),'output_sha256':digest(result)}
     except (ProtocolError,ValueError,TypeError,KeyError) as exc:
      response={'schema':SCHEMA,'id':rid,'status':'error','error':{'type':type(exc).__name__,'message':str(exc)},'state':'ready'}
     except (InputChanged,BackendError,OSError,EOFError) as exc:
      quarantined=True;response={'schema':SCHEMA,'id':rid,'status':'error','error':{'type':type(exc).__name__,'message':str(exc)},'state':'quarantine'}
     response.update(worker_pid=os.getpid(),worker_start_ticks=identity['start_ticks'],server_wall_ns=time.monotonic_ns()-begin,server_process_cpu_ns=time.process_time_ns()-cpu,server_thread_cpu_ns=time.thread_time_ns()-thread)
     conn.sendall(canonical(response)+b'\n')
     # Do not retain the previous response/input merely because the loop is idle.
     response=None;result=None;req=None;data=None;line=None
    f.close()
 finally:
  if worker is not None:
   shutdown=worker.close()
  if sock is not None:sock.close()
  path.unlink(missing_ok=True)
  if shutdown is not None:print(json.dumps({'event':'shutdown','outcome':shutdown,'socket_removed':not path.exists()},sort_keys=True),flush=True)

def main():
 p=argparse.ArgumentParser();p.add_argument('--kind',choices=['numpy','clangd'],required=True);p.add_argument('--socket',required=True);p.add_argument('--workspace',required=True);p.add_argument('--clangd',default='/usr/bin/clangd');p.add_argument('--stderr');args=p.parse_args();serve(args)
if __name__=='__main__':main()
