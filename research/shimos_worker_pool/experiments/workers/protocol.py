"""Frozen harness-facing interface, schema 1."""
import pathlib,sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from client import Client as _Client,oracle,workload_inputs,digest
SCHEMA=1
FIXTURE=pathlib.Path(__file__).resolve().parent/'fixture'
class Client(_Client):
 def call(self,request):return self.request(request['op'],request.get('input',{}),request_id=request['id'])
def requests(kind,n):
 if kind not in ('numpy','clangd') or not 1<=n<=10000:raise ValueError('workload bounds')
 return [{'id':'r'+str(i+1),'op':'run','input':data} for i,data in enumerate(workload_inputs(kind,n))]
def verify(kind,request,response,workspace=FIXTURE):
 assert response['schema']==SCHEMA and response['id']==request['id']
 assert response['status']=='ok',response
 expected=oracle(kind,request['input'],workspace)
 assert response['result']==expected,{'expected':expected,'observed':response}
 assert response['output_sha256']==digest(expected)
 assert response['input_sha256']==digest({'op':request['op'],'input':request.get('input',{})})
 return {'oracle':'independent integer loop' if kind=='numpy' else 'frozen gcc/nm-corroborated C definitions and no error diagnostics','ok':True}
def invalid_request(kind):return {'id':'invalid','op':'run','input':{'n':16384,'buckets':0,'offset':0} if kind=='numpy' else {'query':'unsupported'}}
def verify_error(response):
 assert response['id']=='invalid' and response['status']=='error' and response['state']=='ready',response
 assert response['error']['type']=='ProtocolError',response
 return True
