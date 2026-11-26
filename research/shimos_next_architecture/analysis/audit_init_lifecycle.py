#!/usr/bin/env python3
"""Read-only actual wait/EOF audit for the next-architecture tiny-init pilot.

Reuse the already independently validated pure parser, retaining every source
hash. Does not import a VM/Agent driver, launch workloads or mutate old evidence.
"""
import argparse,hashlib,importlib.util,json,collections
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
PROJECT=BASE.parents[1]
CORE=PROJECT/'research/shimos_architecture_challenge/pilot_v1_1/analysis/audit_execution_lifecycle.py'
spec=importlib.util.spec_from_file_location('frozen_readonly_audit',CORE)
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
a.BASE=BASE

def metadata(e):
    b=a.brief(e)
    if b is not None:
        b['namespace_samples']=[{'identity_line':x.get('identity_line'),'t_ns':x.get('t_ns',x.get('sample_start_ns')),'nspid':x.get('nspid'),'namespaces':x.get('namespaces'),'comm':x.get('comm'),'start_ticks':x.get('start_ticks')} for x in e['samples']]
        b['task_type']=e.get('task_type')
    return b

def init_details(s,sa,ta):
    cfg=a.load(s/'config.json',{});sr=a.load(s/'session-result.json',{})
    co=a.load(s/'container.json',{});result={'session':s.name,'docker_init_requested':cfg.get('docker_init'),'inspect_init':co.get('HostConfig',{}).get('Init'),'inspect_stop_timeout':co.get('Config',{}).get('StopTimeout'),'base_process_receipt':sr.get('domain_base_processes'),'pre_export_receipt':sr.get('pre_export_processes'),'quiescent_receipt':sr.get('quiescent_before_export'),'controller_status':sr.get('status','MISSING_RECEIPT'),'controller_dead_observation':a.load(s/'death-observation.json'),'term_observation':a.load(s/'term-observation.json'),'late_side_effect':sr.get('late_side_effect_after_cancel_or_timeout'),'cleanup':sr.get('cleanup'),'cleanup_ns':sr.get('cleanup_ns'),'observer_assisted':sa['observer_assistance'],'init':sa.get('domain_init'),'runtime':sa.get('monitor'),'actions':[]}
    E=ta['E'];ii=sa.get('domain_init');init=next((e for e in E.all if ii and e['key']==ii['key']),None)
    if init is None:
        # A killed Controller has no final Session receipt. Use the separately
        # written ready identity, not admission+an invented creation delay.
        ready=a.load(s/'ready.json',{})
        if ready.get('domain_ready_ns') and co.get('State',{}).get('Pid'):
            init=E.at(co['State']['Pid'],ready['domain_ready_ns'])
            result['init_binding_source']='container State.Pid + separately persisted DOMAIN_READY'
    if init:
        result['init']=metadata(init)
        init_exec=[x['t_ns']for x in init['execs'] if x['filename']=='/sbin/docker-init']
        result['init_direct_children']=[{'birth_after_docker_init_exec':bool(init_exec and e['birth_ns']>=min(init_exec)),**metadata(e)}for e in E.all if e['parent'] is init]
        result['positive_init_waits']=[w for w in ta['waits']if w['caller_tid']==init['pid'] and w['name']=='wait4' and w['return_value']>0]
        result['all_init_waits']=[w for w in ta['waits']if w['caller_tid']==init['pid']]
        if cfg['case']=='controller_death':
            roots=[e for e in E.all if any(Path(x['filename']).name=='bash' and E.cg(e,x['t_ns'])[0]==sa['business_cgroup']for x in e['execs'])]
            keys={e['key']for e in roots}; roots=[e for e in roots if not(e['parent']and e['parent']['key']in keys)]
            result['fault_business_entries_without_final_action_receipt']=[metadata(e)for e in roots]
            result['fault_result_knowledge']='UNKNOWN; no completed action receipt; do not interpret zero logged actions as zero executed processes'
    for row in sa['actions']:
        result['actions'].append({'action_id':row['action_id'],'command':row['command'],'returncode':row['returncode'],'error':row['error'],'business_processes':row['business_processes'],'wait4_observed':row['business_wait4_observed'],'missing_wait':[p for p in row['processes']if not p['wait4_evidence']],'waited_by_init':[p for p in row['processes']if init and any(w['caller_tid']==init['pid']for w in p['wait4_evidence'])],'unknown_kernel_tasks':row['unknown_kernel_tasks']})
    # Cross-check quiescence from saved process samples with actual lifetime.
    # Namespace trace absence is never inferred from a cardinality assertion.
    if init and cfg['case']=='natural':
        t=sr.get('business_end_ns')
        bg=[];maybe=[]
        for e in E.all:
            if t is None or e['birth_ns']>t or any(x['t_ns']<=t for x in e['exits']):continue
            cg,how=E.cg(e,t)
            if cg==sa['business_cgroup']:
                (bg if E.task_type(e).startswith('process') else maybe).append(metadata(e))
        result['trace_lifetime_at_business_end']={'t_ns':t,'known_live_processes':bg,'other_kernel_tasks':maybe,'limit':'trace lifetime + observed cgroup association; not independent full kernel object inventory; business_end follows evidence export'}
    return result

def main():
    p=argparse.ArgumentParser();p.add_argument('--run',action='append',required=True);p.add_argument('--out',required=True);args=p.parse_args();out=Path(args.out);out.mkdir(parents=True,exist_ok=False)
    summaries=[];inits=[];actions=[];protocol=[]
    inputs={str(x.relative_to(PROJECT)):a.sha(x)for x in [Path(__file__),CORE,a.PARSER]}
    for name in args.run:
        run=Path(name).resolve()
        if not (run/'result.json').exists():raise RuntimeError('run not complete: '+str(run))
        r={'run':run.name,'result':a.load(run/'result.json'),'guest_release':a.load(run/'guest-release.json'),'traces':{},'sessions':[]}
        for kind in ['qualification-trace','natural-trace']:
            ta=a.trace_audit(run,kind)
            if ta is None:r['traces'][kind]={'status':'MISSING'};continue
            r['traces'][kind]={'status':'COMPLETE_EVENT_BUFFER'if ta['trace_no_reported_loss']and not ta['unparsed']else'PARTIAL','trace_path':ta['path'],'clock':ta['observer']['trace_clock'],'stats':ta['stats'],'unparsed':ta['unparsed'],'events':len(ta['events']),'wait4_positive':sum(w['name']=='wait4'and w['return_value']>0 for w in ta['waits']),'wait4_bound':sum(w['reap_observed']for w in ta['waits']),'waitid_unbound':sum(w['name']=='waitid'for w in ta['waits']),'dedicated_proc_samples':ta['observer']['samples']}
            a.dump(out/(run.name+'-'+kind+'-waits.json'),ta['waits'])
            for s in sorted((run/'sessions').iterdir()):
                cfg=a.load(s/'config.json',{})
                if not cfg or(cfg['case']=='natural')!=(kind=='natural-trace'):continue
                sa=a.session_audit(s,ta);r['sessions'].append(sa)
                actions.extend({k:v for k,v in x.items()if k not in {'entry_roots','guardian','processes','unknown_tasks'}}for x in sa['actions'])
                if 'protocol' in sa:protocol.extend(sa['protocol']['groups'])
                if cfg['variant']=='B0':inits.append(init_details(s,sa,ta))
        for x in run.rglob('*'):
            if x.is_file()and(x.name in {'process.trace','observer.json','process-identities.jsonl','process-samples.jsonl','result.json','pilot-results.json','guest-release.json','session-result.json','actions.jsonl','adapter-events.jsonl','adapter-cleanup.json','container.json','controller-wait.json','config.json','death-observation.json','term-observation.json','observer-assistance.json'}or x.name.startswith('action-')and x.suffix=='.bin'):
                inputs[str(x.relative_to(PROJECT))]=a.sha(x)
        a.dump(out/(run.name+'-execution-audit.json'),r);summaries.append(r)
    compact={'schema':'shimos.next-architecture.init-lifecycle-audit.v1','scope':'offline actual trace/receipt audit; no VM launch, no full fault equivalence presumed','runs':[{'run':r['run'],'result':r['result'],'traces':r['traces'],'sessions':[{'session':s['session'],'variant':s['variant'],'case':s['case'],'task_id':s['task_id'],'status':s['status'],'observer_assistance':s['observer_assistance'],'counts':s['counts'],'product_released_receipt':s['source_session_result_product_released']}for s in r['sessions']]}for r in summaries],'known_limits':['Only positive bound wait4 proves a particular observed child reaped; waitid success alone does not.','Wait status pointer is not decoded; exact application status comes from runtime/B1 receipts.','Tini namespace mapping needs creation-return or direct proc snapshot; uncertain short descendants stay UNKNOWN.','EOF is direct B1 read-zero receipt or normal Docker CLI communicate, not generic kernel read trace.','Controller SIGKILL observer cleanup is not product recovery.','No new formal performance claim; diagnostic stop times are nested and not summable.']}
    a.dump(out/'execution-lifecycle-summary.json',compact);a.dump(out/'docker-init-details.json',inits);a.dump(out/'b1-protocol-groups.json',protocol);a.csvout(out/'action-process-coverage.csv',actions);a.dump(out/'input-sha256.json',inputs)
    print(json.dumps({'output':str(out),'runs':len(summaries),'sessions':sum(len(r['sessions'])for r in summaries),'actions':len(actions),'docker_sessions':len(inits)},indent=2))
if __name__=='__main__':main()
