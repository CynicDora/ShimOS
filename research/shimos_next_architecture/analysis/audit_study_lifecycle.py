#!/usr/bin/env python3
"""Offline study trace coverage. Not a lifecycle qualification or benchmark runner.

Only completed raw run directories are accepted. All task outcomes, missing
receipts, wait gaps, unknown tasks and observer assistance remain in the output.
"""
import argparse,collections,csv,hashlib,importlib.util,json
from pathlib import Path
BASE=Path(__file__).resolve().parents[1];PROJECT=BASE.parents[1]
CORE=PROJECT/'research/shimos_architecture_challenge/pilot_v1_1/analysis/audit_execution_lifecycle.py'
spec=importlib.util.spec_from_file_location('frozen_pure_audit',CORE);a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a);a.BASE=BASE

def main():
    p=argparse.ArgumentParser();p.add_argument('--run',action='append',required=True);p.add_argument('--out',required=True);arg=p.parse_args();out=Path(arg.out);out.mkdir(parents=True,exist_ok=False)
    files={str(x.relative_to(PROJECT)):a.sha(x)for x in [Path(__file__),CORE,a.PARSER]};runs=[];allrows=[];allactions=[];allpython=[];missing=[];coverage=[]
    for name in arg.run:
        run=Path(name).resolve()
        if not(run/'result.json').exists():raise RuntimeError('run has no final VM receipt: '+str(run))
        config=a.load(run/'pilot-config.json',{});ta=a.trace_audit(run,'natural-trace')
        row={'run':run.name,'config':config,'run_receipt':a.load(run/'result.json'),'guest_release':a.load(run/'guest-release.json'),'batch_result':a.load(run/'batch-result.json'),'fixtures_result':a.load(run/'fixtures-result.json'),'scope':'single-backend observation; never strict B0/B1 qualification','sessions':[]}
        for f in run.rglob('*'):
            if f.is_file()and(f.name in {'process.trace','observer.json','process-identities.jsonl','process-samples.jsonl','result.json','study-results.json','guest-release.json','session-result.json','actions.jsonl','container.json','controller-wait.json','config.json','pilot-config.json','cohort.json','observer-assistance.json','batch-result.json','fixtures-result.json'}):files[str(f.relative_to(PROJECT))]=a.sha(f)
        for task in config.get('tasks',[]):
            fixture=(row['fixtures_result']or{}).get('tasks',{}).get(task,{})
            ledger=[x for x in (row['batch_result']or{}).get('sessions',[])if x.get('task_id')==task]
            matching=[s for s in (run/'sessions').glob('*')if a.load(s/'config.json',{}).get('task_id')==task]
            coverage.append({'run':run.name,'task_id':task,'fixture_status':fixture.get('status','UNKNOWN'),'fixture_error':fixture.get('error'),'registered_kind':config.get('kind'),'batch_statuses':[x.get('status')for x in ledger],'session_ids':[s.name for s in matching],'session_count':len(matching),'denominator_included':True,'scope':'registered task retained even if fixture failed, never admitted, or receipt missing'})
        if ta is None:
            row['trace']={'status':'MISSING','business_process_count':None};runs.append(row);a.dump(out/(run.name+'-study-audit.json'),row);continue
        row['trace']={'path':ta['path'],'events':len(ta['events']),'clock':ta['observer']['trace_clock'],'no_reported_loss':ta['trace_no_reported_loss'],'stats':ta['stats'],'unparsed_lines':ta['unparsed'],'dedicated_proc_scans':ta['observer']['samples'],'wait4_positive':sum(w['name']=='wait4'and w['return_value']>0 for w in ta['waits']),'wait4_bound_global':sum(w['reap_observed']for w in ta['waits']),'limit':'global includes runtime/diagnostic processes; task counts use action+cgroup roots only'}
        a.dump(out/(run.name+'-waits.json'),ta['waits'])
        for s in sorted((run/'sessions').glob('*')):
            cfg=a.load(s/'config.json',{})
            if not cfg:continue
            if cfg.get('variant')!='B0' or cfg.get('case')!='natural':
                row['sessions'].append({'session':s.name,'status':'UNSUPPORTED_BY_OBSERVATION_ANALYZER','config':cfg});continue
            sa=a.session_audit(s,ta);sr=a.load(s/'session-result.json',{});score=a.load(s/'validation/result.json',{});co=a.load(s/'container.json',{});cohort=a.load(s/'cohort.json',{})
            processes={p['key']:p for aa in sa['actions']for p in aa['processes']};unknown={p['key']:p for aa in sa['actions']for p in aa['unknown_tasks']};py={p['key']:p for p in processes.values()if any(a.m.category(e['path'])=='python_interpreter'for e in p['execs'])};k=sa['counts'];sessionshape={'run':run.name,'session':s.name,'task_id':cfg.get('task_id'),'cohort':cohort.get('cohort'),'variant':'B0_INIT'if cfg.get('docker_init')else'B0_NOINIT','controller_status':sa['status'],'score':score.get('outcome'),'product_release_receipt':sa['source_session_result_product_released'],'observer_assistance':sa['observer_assistance'],'domain_id':co.get('Id'),'domain_created':bool(co.get('State',{}).get('Pid')),'K_tool_logged':k['actions'],'K_tool_unique_domain':k['actions']if co.get('Id')else None,'K_proc_confirmed':len(processes),'K_proc_wait4_confirmed':sum(bool(x['wait4_evidence'])for x in processes.values()),'K_proc_exit_observed':sum(bool(x['exit_lines'])for x in processes.values()),'unknown_kernel_tasks':len(unknown),'python_processes_exec_observed':len(py),'python_processes_wait4_bound':sum(bool(x['wait4_evidence'])for x in py.values()),'actions_without_unique_entry_root':sum(x['root_count']!=1 for x in sa['actions']),'K_heap':None,'K_template':None,'heap_template_reason':'fresh shell/exec traces do not establish reusable heap or template admission','resource_and_result_scope':'owned normal receipts only; missing receipt or observer assistance stays non-product recovery'}
            sa['observation_row']=sessionshape;row['sessions'].append(sa);allrows.append(sessionshape)
            for aa in sa['actions']:
                allactions.append({'run':run.name,'task_id':cfg.get('task_id'),'cohort':cohort.get('cohort'),**{k:v for k,v in aa.items()if k not in {'entry_roots','guardian','processes','unknown_tasks'}}})
                for ent in aa['processes']:
                    if not ent['wait4_evidence']:missing.append({'run':run.name,'session':s.name,'task_id':cfg.get('task_id'),'action_id':aa['action_id'],'command':aa['command'],'entity':ent,'scope':'no independently bound user wait; not inferred absent or successful from disappearance'})
                    if ent['key']in py:allpython.append({'run':run.name,'session':s.name,'task_id':cfg.get('task_id'),'cohort':cohort.get('cohort'),'action_id':aa['action_id'],'pid_key':ent['key'],'pid':ent['pid'],'execs':ent['execs'],'wait4_evidence':ent['wait4_evidence'],'inference':'observed exec replaces prior image; no persistent Python heap claim'})
        a.dump(out/(run.name+'-study-audit.json'),row);runs.append(row)
    a.dump(out/'study-process-summary.json',{'schema':'shimos.next.study-process-audit.v1','status':'OBSERVATION_NOT_QUALIFICATION','runs':[{'run':r['run'],'config':r['config'],'trace':r['trace'],'run_receipt':r['run_receipt'],'guest_release':r['guest_release'],'batch_result':r['batch_result'],'fixtures_result':r['fixtures_result']}for r in runs],'sessions':allrows,'limits':['Process count lower bound when entry/TGID/cgroup evidence is missing; no imputed process counts.','Natural workload exec/receipt association only; whole guest/runtime/holdout processes not attributed as business.','Session completion and task score independent; all failure rows retained.','Global waitid success without siginfo is not a particular child wait.','K_heap and K_template unknown; no dependency admission or throughput claim.']})
    a.csvout(out/'session-process-counts.csv',allrows);a.csvout(out/'action-process-coverage.csv',allactions);a.csvout(out/'registered-task-coverage.csv',coverage);a.dump(out/'python-exec-processes.json',allpython);a.dump(out/'missing-business-wait.json',missing);a.dump(out/'input-sha256.json',files)
    print(json.dumps({'runs':len(runs),'sessions':len(allrows),'actions':len(allactions),'python_process_rows':len(allpython),'unbound_wait_process_rows':len(missing),'out':str(out)},indent=2))
if __name__=='__main__':main()
