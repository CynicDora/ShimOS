"""Outer trusted controller API; socket points at the same /work inode."""
import hashlib,json,pathlib,socket,time

def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(canonical(v)).hexdigest()
class Client:
 def __init__(self,path,timeout=30):
  self.socket=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.socket.settimeout(timeout);self.socket.connect(str(path));self.stream=self.socket.makefile('rb');self.seq=0
 def request(self,op,input=None,request_id=None):
  self.seq+=1;request_id=request_id or 'r'+str(self.seq);message={'id':request_id,'op':op,'input':input or {}}
  wire=canonical(message)+b'\n';start=time.monotonic_ns();cpu=time.process_time_ns();self.socket.sendall(wire);first=self.stream.read(1);first_ns=time.monotonic_ns();rest=self.stream.readline(1048576)
  if not first or not rest.endswith(b'\n'):raise RuntimeError('worker response missing')
  response=json.loads(first+rest)
  if response.get('id')!=request_id:raise RuntimeError('response id mismatch')
  if response.get('status')=='ok':
   if response['output_sha256']!=digest(response['result']) or response['input_sha256']!=digest({'op':op,'input':input or {}}):raise RuntimeError('protocol hash mismatch')
  end=time.monotonic_ns();response['client_measurement']={'submit_ns':start,'first_byte_ns':first_ns,'complete_ns':end,'first_byte_latency_ns':first_ns-start,'complete_latency_ns':end-start,'process_cpu_ns':time.process_time_ns()-cpu,'request_bytes':len(wire),'response_bytes':len(first)+len(rest),'first_byte_is_not_first_valid_response':True}
  return response
 def close(self):self.stream.close();self.socket.close()
 def __enter__(self):return self
 def __exit__(self,*a):self.close()

def numpy_oracle(data):
 n,b,o=data['n'],data['buckets'],data['offset'];groups=[0]*b;total=0;squares=0
 for i in range(n):
  v=(i*17+o)%1009-504;groups[i%b]+=v;total+=v;squares+=v*v
 return {'count':n,'sum':total,'sum_of_squares':squares,'group_sums':groups}

def clangd_oracle(workspace):
 root=pathlib.Path(workspace);hashes={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in ('adler32.c','zutil.h','zlib.h','zconf.h')}
 # Explicit frozen real-source definition sites, independently corroborated by gcc/nm.
 sites={'adler32_z':60,'adler32':127,'adler32_combine_':132,'adler32_combine':157,'adler32_combine64':161};lines=(root/'adler32.c').read_text().splitlines()
 functions=[{'name':name,'kind':12,'line':line,'character':lines[line].index(name+'(')} for name,line in sorted(sites.items())]
 return {'functions':functions,'error_diagnostics':[],'source_revision':digest(hashes),'document_version':1}

def oracle(kind,data,workspace):return numpy_oracle(data) if kind=='numpy' else clangd_oracle(workspace)

def workload_inputs(kind,count):
 if kind=='numpy':return [{'n':16384,'buckets':64,'offset':x} for x in [0,37,-19,11,98,-403,3,509,122,-81][:count]] if count<=10 else [dict(n=16384,buckets=64,offset=(i*37)%999-499) for i in range(count)]
 return [{'query':'documentSymbols'} for _ in range(count)]
