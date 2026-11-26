#!/usr/bin/env python3
"""Read-only SHA recheck. Run after timing, not concurrently with benchmark VMs."""
import argparse,datetime,hashlib,json
from pathlib import Path

S=Path(__file__).resolve().parents[1]
ROOT=S.parents[2]
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',required=True,type=Path);a=p.parse_args()
 assert not a.out.exists(),'refuse overwrite'
 started=datetime.datetime.now(datetime.timezone.utc).isoformat()
 old=json.loads((S/'input-freeze.json').read_text());bad=[];count=0;size=0
 for n,v in old['files'].items():
  f=ROOT/n
  try:
   stat=f.stat();got=digest(f)
   if stat.st_size!=v['size'] or got!=v['sha256']:bad.append({'path':n,'kind':'old_input_changed','observed_sha256':got,'observed_size':stat.st_size})
   count+=1;size+=stat.st_size
  except OSError as e:bad.append({'path':n,'error':str(e)})
 baseline=json.loads((S/'analysis/baseline-instrumented-freeze.json').read_text())
 for n,h in baseline['files'].items():
  if digest(S/'baseline_instrumented'/n)!=h:bad.append({'path':'baseline_instrumented/'+n,'kind':'baseline_changed'})
 review=json.loads((S/'docs/variant-source-review-v2.json').read_text())
 for variant,entry in review['variants'].items():
  for n,h in entry['source_sha256'].items():
   if digest(S/variant/n)!=h:bad.append({'path':variant+'/'+n,'kind':'variant_changed'})
 report={'started_utc':started,'completed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
  'scope':old['scope'],'historical_files_checked':count,'historical_bytes_checked':size,
  'baseline_files_checked':len(baseline['files']),'variants':list(review['variants']),
  'status':'PASS' if not bad else 'FAIL','mismatches':bad,'checker_sha256':digest(Path(__file__))}
 with a.out.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
 print(json.dumps(report,indent=2));return bool(bad)
if __name__=='__main__':raise SystemExit(main())
