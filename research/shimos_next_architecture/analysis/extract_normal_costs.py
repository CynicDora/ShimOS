#!/usr/bin/env python3
"""Read existing qualification receipts only; no execution/performance rerun."""
import argparse,csv,hashlib,json
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]

def load(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def cpu(cg):return int(dict(l.split() for l in cg['cpu.stat'].splitlines())['usage_usec'])

def main():
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);args=p.parse_args();out=Path(args.out);out.mkdir(parents=True,exist_ok=False)
    data=[];sources={str(Path(__file__)):sha(Path(__file__))}
    for run in ['next-qual-01','next-qual-02']:
        for sd in sorted((BASE/'runs'/run/'sessions').iterdir()):
            cfg=load(sd/'config.json')
            if cfg['case']!='natural':continue
            sr=load(sd/'session-result.json');cw=load(sd/'controller-wait.json');score=load(sd/'validation/result.json')
            for name in ['config.json','session-result.json','controller-wait.json','actions.jsonl','validation/result.json']:
                sources[str(sd/name)]=sha(sd/name)
            assert sr['tool_cumulative_ns']==sum(a['duration_ns']for a in sr['actions'])
            r={'run':run,'session':sd.name,'variant':cfg['variant'],'task_id':cfg['task_id'],
               'executor_status':sr['status'],'score':score.get('outcome'),'product_released':sr['product_released'],
               'observer_assistance':(sd/'observer-assistance.json').exists(),'actions':len(sr['actions']),
               'admit_to_controller_end_s':sr['full_session_ns']/1e9,
               'admit_to_parent_wait_s':(cw['wait_returned_ns']-cfg['admitted_ns'])/1e9,
               'controller_launch_and_import_s':(sr['controller_start_ns']-cfg['admitted_ns'])/1e9,
               'domain_setup_s':sr['domain_setup_ns']/1e9,'tool_cumulative_s':sr['tool_cumulative_ns']/1e9,
               'evidence_copy_s':sr.get('evidence_export_ns',0)/1e9,'cleanup_s':sr['cleanup_ns']/1e9,
               'controller_end_to_parent_wait_s':(cw['wait_returned_ns']-sr['controller_end_ns'])/1e9,
               'workspace_prepare_s_before_admission':cfg['workspace_prepare_ns']/1e9,
               'controller_self_CPU_s':sr['controller_cpu_s'],
               'business_ready_to_before_cleanup_CPU_s':(cpu(sr['business_final_stats'])-cpu(sr['business_cgroup_initial']))/1e6,
               'business_memcg_lifetime_peak_before_cleanup_MiB':int(sr['business_final_stats']['memory.peak'])/1024**2,
               'scope':'qualification trace diagnostic; normal functional subset, not full security/fault equivalence; no LLM or fixture/scoring costs in admission interval'}
            named=['controller_launch_and_import_s','domain_setup_s','tool_cumulative_s','evidence_copy_s','cleanup_s']
            r['other_session_logic_and_evidence_s']=r['admit_to_controller_end_s']-sum(r[k]for k in named)
            data.append(r)
    with (out/'normal-path-costs.csv').open('w',newline='')as f:
        w=csv.DictWriter(f,fieldnames=list(data[0]));w.writeheader();w.writerows(data)
    (out/'normal-path-costs.json').write_text(json.dumps({'scope':'existing raw qualification receipts only; all natural outcomes retained','rows':data,'limitations':['workspace preparation precedes admission and is separately recorded; intermediate pre-admission cgroup setup has no exact full interval','admit-to-parent-wait includes final JSON/exit/wait tail, does not include fixture, scoring or VM launch','business CPU excludes domain construction before ready and domain cleanup after final_stats; controller self CPU is another partial scope, not system total','evidence copying and file hashing are diagnostic costs included in recorded total; no inferred no-diagnostic latency']},ensure_ascii=False,indent=2)+'\n')
    (out/'input-sha256.json').write_text(json.dumps(sources,indent=2)+'\n');print(json.dumps({'rows':len(data),'out':str(out)}))

if __name__=='__main__':main()
