#!/usr/bin/env python3
"""Read-only independent check of a frozen VM run; no workload execution."""
import argparse,json,re,hashlib
from pathlib import Path
def main():
    a=argparse.ArgumentParser();a.add_argument('run');args=a.parse_args()
    study=Path(__file__).resolve().parent.parent;run=study/'runs'/args.run;out=study/'analysis'/args.run;out.mkdir(parents=True,exist_ok=False)
    trace=(run/'process-trace.txt').read_text();edges={};executed={};exited=set()
    for line in trace.splitlines():
        if 'sched_process_fork:' in line:
            m=re.search(r' pid=(\d+) child_comm=.* child_pid=(\d+)',line);assert m,line
            child=int(m[2]);assert child not in edges;edges[child]=int(m[1])
        if 'sched_process_exec:' in line:
            m=re.search(r'filename=(\S+) pid=(\d+)',line);executed.setdefault(int(m[2]),[]).append(m[1])
        if 'sched_process_exit:' in line:
            m=re.search(r' pid=(\d+) ',line);exited.add(int(m[1]))
    loss=json.loads((run/'trace-stats.json').read_text())
    assert all(not re.search(r'(?:^|\n)(?:overrun|commit overrun|dropped events): [1-9]',v) for v in loss.values())
    rows=[];owned=set();zygotes=set()
    for p in sorted(run.glob('[0-9]*.json'),key=lambda p:int(p.name.split('-')[0])):
        r=json.loads(p.read_text());z=r['zygote_host_pid'];s=r.get('transition_host_pid');w=r.get('worker_host_pid');zygotes.add(z)
        assert edges[s]==z
        assert not executed.get(s),('transition exec',s)
        owned.update([z,s,r['init_host_pid'],r['monitor_host_pid']])
        assert r['all_processes_empty'] and r['resources_removed'] and r['output_eof'] and r['transition_reaped']
        if 'qualification' in r:assert r['qualification']=='PASSED'
        assert all('populated 0' in v['cgroup.events'] for v in r['stats'].values())
        if w is not None:
            assert edges[w]==s and not executed.get(w)
            b=r['worker'];assert all(b['checks'].values());assert b['identity']['ns']==r['target_ns']
            assert b['inherited']==r['expected_state']
            assert b['after_cow']['sha256']!=b['inherited']['sha256']
            assert b['identity']['status']['NoNewPrivs']=='1' and b['identity']['status']['Seccomp']=='2'
            owned.add(w)
        else:assert r['mode']=='target_during_entry' and r['task_state']!='SUCCEEDED'
        if r['mode'] in ('normal','nonzero'):
            assert r['transition_status']==0 and r['monitor_status']==0 and r['drained']
            assert r['worker_wait']['exit_code']==(0 if r['mode']=='normal' else 7)
        elif r['mode']=='waiter_failure':
            assert r['worker_wait']['exit_code']==0 and r['task_state']=='TRANSITION_FAILED'
        else:assert r['task_state'] not in ('SUCCEEDED','NONZERO')
        rows.append({'mode':r['mode'],'task_state':r['task_state'],'zygote':z,'transition':s,'worker':w,
            'worker_wait_source':'transition' if r['worker_wait'] else 'controller/adopted' if r.get('controller_worker_wait') is not None else 'no worker created',
            'business_checks':len(r['worker']['checks']) if r['worker'] else 0,
            'task_memory_current_after_exit':int(r['stats']['task']['memory.current']),
            'released':r['resources_removed']})
    # Include all descendants, including unjoined child processes.
    while True:
        added={p for p,parent in edges.items() if parent in owned}-owned
        if not added:break
        owned.update(added)
    assert owned<=exited,('missing exit events',sorted(owned-exited))
    assert len(zygotes)==1
    assert all(executed[z]==['/usr/bin/python3'] for z in zygotes)
    summary=json.loads((run/'summary.json').read_text());assert summary['controller_echild'] and summary['same_template_served_second_domain']
    final=json.loads((run/'external-final-release.json').read_text());assert final['controller_wait_status']==0 and final['delegation_removed'] and not final['observer_killed_processes']
    result={'verified':True,'run':args.run,'cases':rows,'exec_in_transitions_or_workers':0,'zygote_initial_python_exec':1,
      'fork_edges_checked':len(edges),'owned_process_exit_events_checked':len(owned),'trace_loss':False,
      'note':'Controlled mechanism qualification only; no latency/throughput benchmark or untrusted-template claim.',
      'source_hashes':json.loads((run/'source-sha.json').read_text()),
      'evidence_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in run.iterdir() if p.is_file() and p.suffix in ('.json','.txt','.jsonl','.log')}}
    (out/'verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k] for k in ['verified','run','exec_in_transitions_or_workers','owned_process_exit_events_checked']}))
if __name__=='__main__':main()
