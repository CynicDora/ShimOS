#!/usr/bin/env python3
"""Bounded read-only public artifact acquisition. Never executes trajectory actions."""
import concurrent.futures,datetime,hashlib,json,urllib.request,xml.etree.ElementTree as ET
from pathlib import Path
P=Path(__file__).resolve().parents[3];ROOT=P/'research/real_agent_workload';OLD=P/'research/shimos_worker_pool/real_agent_workload/01_trajectory_analysis';OUT=ROOT/'trajectories'
def sha(b): return hashlib.sha256(b).hexdigest()
def fetch(url,path,limit=12_000_000):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 if path.exists():return path.read_bytes()
 start=datetime.datetime.now(datetime.timezone.utc).isoformat()
 try:
  with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'ShimOS-public-artifact-read-only'}),timeout=45) as r:
   b=r.read(limit+1)
   if len(b)>limit:raise ValueError('bounded download limit exceeded')
   receipt={'url':url,'final_url':r.url,'status':r.status,'etag':r.headers.get('ETag'),'last_modified':r.headers.get('Last-Modified'),'started_utc':start,'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'bytes':len(b),'sha256':sha(b)}
  path.write_bytes(b);path.with_suffix(path.suffix+'.receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');return b
 except Exception as e:
  path.with_suffix(path.suffix+'.failure.json').write_text(json.dumps({'url':url,'started_utc':start,'error':repr(e)},indent=2)+'\n');raise

def main():
 ns={'s':'http://s3.amazonaws.com/doc/2006-03-01/'};r=ET.fromstring((OLD/'sources/mini-listing.xml').read_bytes())
 listing={Path(x.find('s:Key',ns).text).name.removesuffix('.traj.json'):{'key':x.find('s:Key',ns).text,'size':int(x.find('s:Size',ns).text)} for x in r.findall('s:Contents',ns) if x.find('s:Key',ns).text.endswith('.traj.json')}
 old=json.loads((OLD/'matched-selection.json').read_text())['task_ids']
 # VM candidate additions selected by source package compatibility, NOT observed outcome or command count.
 priority=['psf__requests-5414','psf__requests-6028','sympy__sympy-19954','sympy__sympy-20154','sympy__sympy-20590','sympy__sympy-21379','sympy__sympy-21614','sympy__sympy-21847']
 priority=[x for x in priority if x in listing]
 groups={}
 for t in listing:groups.setdefault(t.rsplit('-',1)[0],[]).append(t)
 chosen=list(dict.fromkeys(old+priority));roundidx=0
 while len(chosen)<70:
  anynew=False
  for repo,ids in sorted(groups.items()):
   ranked=sorted(ids,key=lambda t:sha(('shimos-corpus-20261020:'+t).encode()))
   if roundidx<len(ranked) and ranked[roundidx] not in chosen:chosen.append(ranked[roundidx]);anynew=True
   if len(chosen)>=70:break
  roundidx+=1
  if roundidx>500:raise RuntimeError('selection exhausted')
 plan={'rule':'Retain historical ten mini and thirty SWE-agent runs. Mini total70: predeclared compatible-repository VM candidates then deterministic SHA-ranked round-robin by repo; not outcome/length/timing selected. This oversamples small repos; no population weights. All downloaded failures/long runs retained.','seed':'shimos-corpus-20261020','listing_sha256':sha((OLD/'sources/mini-listing.xml').read_bytes()),'chosen':chosen,'priority':priority,'old':old,'download_before_outcome_inspection':True}
 planpath=OUT/'selection-mini.json'
 if planpath.exists():assert json.loads(planpath.read_text())==plan
 else:planpath.write_text(json.dumps(plan,indent=2)+'\n')
 def one(t):
  if t in old:return {'task_id':t,'status':'HISTORICAL_REUSED','path':str(OLD/'sources/mini'/f'{t}.json')}
  u='https://swe-bench-submissions.s3.amazonaws.com/'+listing[t]['key'];p=OUT/'raw/mini'/f'{t}.json'
  try:
   b=fetch(u,p);assert len(b)==listing[t]['size'];d=json.loads(b);return {'task_id':t,'status':'DOWNLOADED','bytes':len(b),'exit_status':d.get('info',{}).get('exit_status')}
  except Exception as e:return {'task_id':t,'status':'ACQUISITION_FAILED','error':repr(e)}
 with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(one,chosen))
 (OUT/'acquisition-mini-results.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results,indent=2))
if __name__=='__main__':main()
