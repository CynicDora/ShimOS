"""Protocol/oracle tests; optional real worker integration uses known local tools."""
import importlib.util,json,os,pathlib,shutil,subprocess,sys,tempfile,unittest
P=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(P))
import client,protocol,server
class Oracles(unittest.TestCase):
 def test_numpy_small_manual(self):self.assertEqual(client.numpy_oracle({'n':2,'buckets':2,'offset':0}),{'count':2,'sum':-991,'sum_of_squares':504**2+487**2,'group_sums':[-504,-487]})
 def test_request_bounds(self):
  for n in (0,-1,10001):
   with self.assertRaises(ValueError):protocol.requests('numpy',n)
 def test_natural_count_not_claimed(self):self.assertEqual(len(protocol.requests('clangd',10)),10)
 def test_document_definition_positions(self):
  result=client.clangd_oracle(P/'fixture');self.assertEqual(len(result['functions']),5)
  self.assertEqual(result['functions'][0]['name'],'adler32')
 def test_duplicate_json_key(self):
  with self.assertRaises(server.ProtocolError):json.loads('{"a":1,"a":2}',object_pairs_hook=server.unique)
 def test_identity_required(self):
  req=protocol.requests('numpy',1)[0]
  with self.assertRaises(AssertionError):protocol.verify('numpy',req,{'schema':1,'id':'wrong'})
 def test_error_not_success(self):
  with self.assertRaises(AssertionError):protocol.verify_error({'id':'invalid','status':'ok'})
 def test_result_hash_changes(self):self.assertNotEqual(client.digest({'a':1}),client.digest({'a':2}))

class Integration(unittest.TestCase):
 def execute(self,kind,mutation=False):
  with tempfile.TemporaryDirectory(prefix='worker-protocol-test-') as tmp:
   d=pathlib.Path(tmp);fixture=d/'fixture';shutil.copytree(P/'fixture',fixture);sock=d/'worker.sock'
   env=dict(os.environ,OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1',PYTHONDONTWRITEBYTECODE='1')
   p=subprocess.Popen(['/usr/bin/python3','-B',str(P/'server.py'),'--kind',kind,'--socket',str(sock),'--workspace',str(fixture)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
   try:
    ready=json.loads(p.stdout.readline());self.assertEqual(ready['event'],'ready')
    with protocol.Client(sock) as c:
     req=protocol.requests(kind,1)[0];r=c.call(req);protocol.verify(kind,req,r,fixture)
     if mutation:
      with (fixture/'adler32.c').open('a') as f:f.write('\n/* controlled input mutation */\n')
      req['id']='changed';r=c.call(req);self.assertEqual(r['state'],'quarantine')
      req['id']='after';r=c.call(req);self.assertEqual(r['state'],'quarantine')
     else:
      bad=c.call(protocol.invalid_request(kind));protocol.verify_error(bad)
      req['id']='after-error';r=c.call(req);protocol.verify(kind,req,r,fixture)
      self.assertEqual(r['worker_pid'],ready['identity']['pid'])
      reset=c.call({'id':'reset','op':'reset'});self.assertFalse(reset['result']['request_state_retained'])
     close=c.call({'id':'close','op':'shutdown'});self.assertEqual(close['result']['worker_shutdown'],'normal');self.assertTrue(close['result']['child_reaped'])
    self.assertEqual(p.wait(timeout=10),0);self.assertFalse(sock.exists());self.assertEqual(p.stderr.read(),'')
   finally:
    if p.poll() is None:p.kill();p.wait()
    p.stdout.close();p.stderr.close()
 def test_numpy_business_and_error_reuse(self):self.execute('numpy')
 def test_clangd_business_and_error_reuse(self):self.execute('clangd')
 def test_clangd_input_change_quarantine(self):self.execute('clangd',True)
if __name__=='__main__':unittest.main()
