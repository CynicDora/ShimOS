#!/usr/bin/env python3
"""Independent raw-line/receipt checker; no workload execution or cleanup."""
import argparse,hashlib,json,re
from pathlib import Path
BASE=Path(__file__).resolve().parents[1];PROJECT=BASE.parents[1]
def load(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--analysis',required=True);p.add_argument('--out',required=True);a=p.parse_args();root=Path(a.analysis);out=Path(a.out)
 if out.exists():raise SystemExit('Refusing to replace validation')
 errors=[];count={'natural_sessions':0,'natural_actions':0,'natural_confirmed_processes':0,'natural_confirmed_wait4_processes':0,'natural_python_processes':0,'natural_unknown_kernel_tasks':0,'b1_natural_groups':0,'b1_natural_complete_groups':0,'b1_foreground_pending_groups':0,'source_files_verified':0,'evidence_files_verified':0,'wait4_raw_lines_verified':0};monitor=[];faults=[]
 for path,h in load(root/'input-sha256.json').items():
  if sha(PROJECT/path)!=h:errors.append('input hash changed '+path)
  count['evidence_files_verified']+=1
 for pth in sorted(root.glob('next-qual-*-execution-audit.json')):
  r=load(pth);run=BASE/'runs'/r['run']
  for path,h in load(run/'source-sha.json').items():
   if sha(run/path)!=h:errors.append('frozen source hash mismatch '+str(run/path))
   count['source_files_verified']+=1
  traces={k:(run/k/'process.trace').read_text().splitlines()for k in r['traces']}
  for s in r['sessions']:
   kind='natural-trace'if s['case']=='natural'else'qualification-trace';raw=traces[kind];natural=s['case']=='natural'
   if natural:
    count['natural_sessions']+=1;count['natural_actions']+=s['counts']['actions'];count['natural_confirmed_processes']+=s['counts']['processes'];count['natural_confirmed_wait4_processes']+=s['counts']['process_wait4_observed'];count['natural_python_processes']+=s['counts']['python_processes'];count['natural_unknown_kernel_tasks']+=s['counts']['unknown_kernel_tasks']
    if s['status']!='COMPLETED'or not s['source_session_result_product_released']or s['observer_assistance']:errors.append('natural session completion '+s['session'])
    if s['counts']['entry_roots']!=s['counts']['actions']:errors.append('entry root count '+s['session'])
    if s['counts']['processes']!=s['counts']['process_wait4_observed']:errors.append('confirmed natural process missing wait '+s['session'])
    if not s['domain_init']or not s['domain_init']['wait4_evidence']:errors.append('domain init missing wait '+s['session'])
    if s['variant']=='B0'and(not s['monitor']or not s['monitor']['wait4_evidence']):errors.append('Docker shim missing wait '+s['session'])
   for action in s['actions']:
    for ent in action['processes']:
     for w in ent['wait4_evidence']:
      line=raw[w['exit_line']-1];z=re.search(r'sys_wait4 -> (\S+)',line)
      if not z or int(z[1],0)!=w['return_value']or not re.search(r'-'+str(w['caller_tid'])+r'\s',line):errors.append('wait line mismatch '+s['session']+' '+str(w['exit_line']))
      if not any(t<=w['exit_ns']for t in ent['exit_ns']):errors.append('wait before exit '+ent['key'])
      count['wait4_raw_lines_verified']+=1
   if s['variant']=='B1':
    g=s['protocol']['groups']
    if natural:
     count['b1_natural_groups']+=len(g);count['b1_natural_complete_groups']+=sum(x['pass']for x in g);count['b1_foreground_pending_groups']+=sum(x['foreground_group_pending']for x in g)
     if not all(x['pass']for x in g):errors.append('B1 protocol inconsistency '+s['session'])
    receipt=s['protocol']['cleanup'].get('monitor_wait');calls=load(root/(r['run']+'-'+kind+'-waits.json'))
    sr=load(run/'sessions'/s['session']/'session-result.json')if(run/'sessions'/s['session']/'session-result.json').exists()else{}
    eventfile=run/'sessions'/s['session']/'adapter-events.jsonl';events=[json.loads(l)for l in eventfile.read_text().splitlines()];mr=[x for x in events if x['event']=='monitor_wait']
    if natural:
     eligible=[x for x in calls if x['name']=='waitid'and x['caller_tid']==sr['controller_pid']and x['return_value']==0 and sr['cleanup']['close_started_ns']<=x['exit_ns']<=sr['cleanup']['released_ns']]
     check=bool(receipt and s['monitor']and receipt['pid']==s['monitor']['pid']and receipt['si_code']==1 and receipt['si_status']==0 and mr and eligible)
     if not check:errors.append('B1 monitor receipt/trace mismatch '+s['session'])
     monitor.append({'session':s['session'],'monitor_pid':receipt.get('pid')if receipt else None,'trusted_waitid_receipt':receipt,'receipt_event':mr,'kernel_calls':[{'line':x['exit_line'],'enter_line':x['enter_line'],'caller_tid':x['caller_tid'],'args':x['args'],'return_value':x['return_value']}for x in eligible],'check':check,'limit':'kernel trace records waitid success but not siginfo; exact reaped identity/status supplied by actual trusted waitid return receipt, not inferred from zero'})
   if not natural:faults.append({'session':s['session'],'case':s['case'],'status':s['status'],'product_release':s['source_session_result_product_released'],'observer_assistance':s['observer_assistance']})
 result={'status':'AUDIT_CONSISTENT'if not errors else'AUDIT_ERROR','not_full_product_qualification':True,'errors':errors,'counts':count,'b1_natural_monitor_receipt_crosscheck':monitor,'qualification_and_failure_scope':faults,'analyzer_sha256':sha(BASE/'analysis/audit_init_lifecycle.py'),'validator_sha256':sha(Path(__file__))}
 out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');print(json.dumps({'status':result['status'],'counts':count,'errors':errors}))
if __name__=='__main__':main()
