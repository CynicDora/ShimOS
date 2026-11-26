#!/usr/bin/env python3
"""Read-only qualification batch: verify exported runs, no VM/polling/cleanup.

Creates immutable per-run reports under a new directory and one matrix. A
partial driver can be inspected with --partial, never called a final matrix.
"""
import argparse,collections,json
from pathlib import Path
import verify_round1 as v

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--driver',nargs='+',required=True,type=Path)
 p.add_argument('--out',required=True,type=Path);p.add_argument('--partial',action='store_true');a=p.parse_args()
 out=a.out if a.out.is_absolute() else v.S/a.out
 out.resolve().relative_to(v.S.resolve());out.mkdir(parents=True,exist_ok=False)
 entries=[];bindings=[];complete=True
 for file in a.driver:
  file=file if file.is_absolute() else v.S/file
  ledger=json.loads(file.read_text());complete &= ledger.get('complete') is True
  bindings.append({'path':str(file.resolve().relative_to(v.S.resolve())),'sha256':v.sha(file)})
  entries+=ledger.get('runs',[])
 if not a.partial and not complete:raise ValueError('driver not complete; use explicit --partial')
 names=[x.get('name',x.get('run')) for x in entries]
 if len(names)!=len(set(names)):raise ValueError('driver repeats same run')
 reports=[]
 for index,name in enumerate(names):
  try:report=v.analyze(name,'qualification')
  except Exception as error:
   report={'run':name,'status':'BLOCKED','blockers':[{'check':'inspection failed','detail':repr(error)}],
           'verifier_sha256':v.sha(Path(v.__file__))}
  path=out/(str(index).zfill(2)+'-'+name+'.json')
  with path.open('x') as f:json.dump(report,f,ensure_ascii=False,indent=2);f.write('\n')
  reports.append({'run':name,'architecture_group':report.get('architecture_group'),'status':report['status'],
                  'attempts':report.get('attempts',0),'cases':report.get('cases',[]),'numeric_counts':report.get('numeric_counts',{}),
                  'report':str(path.relative_to(v.S)),'sha256':v.sha(path)})
  print(json.dumps(reports[-1],ensure_ascii=False),flush=True)
 sources={json.dumps(json.loads((v.S/'runs'/n/'source-sha.json').read_text()),sort_keys=True) for n in names}
 counts=collections.Counter(x['status'] for x in reports)
 summary={'scope':'FINAL_FIXED_VERSION_MATRIX' if complete and not a.partial else 'PARTIAL_INSPECTION_NOT_FINAL',
          'complete_driver':complete,'same_source_all_runs':len(sources)==1,'drivers':bindings,
          'status':'PASS' if complete and not a.partial and len(sources)==1 and counts=={'PASS':len(reports)} else 'FAIL' if counts['FAIL'] else 'BLOCKED',
          'runs':reports,'run_counts':dict(counts),'sessions':len(reports),'attempts':sum(r['attempts'] for r in reports),
          'verifier_sha256':v.sha(Path(v.__file__)),'matrix_verifier_sha256':v.sha(Path(__file__)),
          'notes':['Fault-contract PASS is not numerical completion.','No historical PASS replaces a new run.',
                   'Performance requires separate scope review and actual timing-session evidence.']}
 with (out/'summary.json').open('x') as f:json.dump(summary,f,ensure_ascii=False,indent=2);f.write('\n')
 return 0 if summary['status']=='PASS' else 2
if __name__=='__main__':raise SystemExit(main())
