#!/usr/bin/env python3
"""Offline secondary tables, natural-output comparison and init raw-line checks."""
import argparse,csv,difflib,hashlib,json,re
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def load(p):return json.loads(p.read_text())
def put(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--analysis',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);arg=ap.parse_args();arg.out.mkdir(parents=True,exist_ok=False)
 summary=load(arg.analysis/'execution-lifecycle-summary.json');details=load(arg.analysis/'docker-init-details.json');rows=[];pairs=[];scores=[];rawchecks=[];errors=[]
 for x in details:
  q=(x['cleanup']or{}).get('synchronous_cli_wait',{});steps=q.get('steps',[])
  rows.append({'session':x['session'],'init':x['docker_init_requested'],'status':x['controller_status'],'cleanup_ms':x['cleanup_ns']/1e6 if x['cleanup_ns']else None,'stop_sequence_ms':(q['end_ns']-q['start_ns'])/1e6 if q else None,'stop_rc':steps[0].get('rc')if steps else None,'observer_assisted':x['observer_assisted'],'late_side_effect':x['late_side_effect']})
  run=x['session'].split('-B0-',1)[0];kind='natural-trace'if '-natural-'in x['session']else'qualification-trace';trace=BASE/'runs'/run/kind/'process.trace';raw=trace.read_text().splitlines()
  for w in x.get('positive_init_waits',[]):
   line=raw[w['exit_line']-1];ok=bool(re.search(r'-'+str(w['caller_tid'])+r'\s',line))and int(re.search(r'sys_wait4 -> (\S+)',line)[1],0)==w['return_value']
   rawchecks.append({'session':x['session'],'line':w['exit_line'],'raw':line,'match':ok,'bound_child':w['bound_child'],'positive_return':w['return_value'],'binding':w['binding'],'trace':str(trace.relative_to(BASE))})
   if not ok:errors.append(x['session']+':'+str(w['exit_line']))
 for r in summary['runs']:
  run=BASE/'runs'/r['run'];natural=[s for s in r['sessions']if s['case']=='natural']
  for task in sorted({s['task_id']for s in natural}):
   ss={s['variant']:s for s in natural if s['task_id']==task};data={v:load(run/'sessions'/s['session']/'session-result.json')for v,s in ss.items()};count={'commands_equal':0,'returncodes_equal':0,'decoded_output_equal':0,'actions':len(data['B0']['actions'])};diffs=[]
   for i,(aa,bb)in enumerate(zip(data['B0']['actions'],data['B1']['actions']),1):
    count['commands_equal']+=aa['command']==bb['command'];count['returncodes_equal']+=aa.get('returncode')==bb.get('returncode');count['decoded_output_equal']+=aa.get('output')==bb.get('output')
    if aa.get('output')!=bb.get('output'):diffs.append({'action':i,'command':aa['command'],'diff':'\n'.join(difflib.unified_diff(aa.get('output','').splitlines(),bb.get('output','').splitlines(),fromfile='B0_INIT',tofile='B1',lineterm=''))})
   pairs.append({'run':r['run'],'task':task,'counts':count,'output_difference_evidence':diffs,'submissions_equal':data['B0'].get('submission')==data['B1'].get('submission'),'scope':'decoded API outputs; B0 original API uses UTF-8 replacement decoding, not arbitrary byte identity'})
   for v,s in ss.items():
    p=run/'sessions'/s['session']/'validation/result.json';x=load(p);scores.append({'run':r['run'],'session':s['session'],'task':task,'variant':v,'outcome':x.get('outcome'),'collected':x.get('collected'),'returncode':x.get('pytest_returncode'),'candidate_unchanged':x.get('candidate_unchanged'),'resource_released':x.get('resource_released'),'path':str(p.relative_to(BASE)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
 with(arg.out/'docker-cleanup-diagnostic.csv').open('w',newline='')as f:w=csv.DictWriter(f,rows[0]);w.writeheader();w.writerows(rows)
 put(arg.out/'natural-output-comparison.json',pairs);put(arg.out/'natural-scores.json',scores);put(arg.out/'init-raw-line-validation.json',{'status':'CONSISTENT'if not errors else'ERROR','errors':errors,'raw_checks':rawchecks,'not_full_lifecycle_qualification':True})
 put(arg.out/'source.json',{'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'analysis_input':str(arg.analysis),'inputs':{str(p):hashlib.sha256(p.read_bytes()).hexdigest()for p in [arg.analysis/'execution-lifecycle-summary.json',arg.analysis/'docker-init-details.json']}})
 print(json.dumps({'pairs':len(pairs),'scores':len(scores),'init_wait_raw_lines':len(rawchecks),'errors':errors}))
if __name__=='__main__':main()
