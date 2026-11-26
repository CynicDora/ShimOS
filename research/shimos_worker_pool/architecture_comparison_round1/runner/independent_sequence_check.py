#!/usr/bin/env python3
"""Independent direct extraction of only complete endpoints and parent CPU."""
import csv
import hashlib
import json
import statistics
from collections import defaultdict
from pathlib import Path

S=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def table(path,rows):
    with path.open('x',newline='') as stream:
        w=csv.DictWriter(stream,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def main():
    out=S/'analysis/independent-primary-01';out.mkdir(exist_ok=False)
    plan=json.loads((S/'frozen/formal-plan.json').read_text())
    admission=json.loads((S/'analysis/performance-final-01/final-summary.json').read_text())
    assert admission['status']=='PASS' and admission['attempts_observed']==1737
    rows=[];pairs=[];files={}
    for block in plan['blocks']:
        run=S/'runs'/block['name'];config=json.loads((run/'batch-config.json').read_text())
        grouped={}
        for session in config['sessions']:
            path=run/session['relative_dir'];events=defaultdict(list)
            log=path/'guest-output.log'
            for line in log.open():
                try:r=json.loads(line)
                except ValueError:continue
                if isinstance(r,dict) and r.get('event')=='COST' and r.get('role')=='fixture' and r.get('name') in ('fixture_session_start','session_supervisor_waited','fixture_release'):
                    assert r['clock']=='CLOCK_MONOTONIC' and r['session']==session['session'];events[r['name']].append(r['ns'])
            assert len(events)==3 and all(len(x)==1 for x in events.values())
            start,wait,release=[events[k][0] for k in ('fixture_session_start','session_supervisor_waited','fixture_release')]
            assert start<wait<release
            ledger_path=path/'session-resource-ledger.json';parent=json.loads(ledger_path.read_text())['session_parent']
            cpu={k:int(v) for k,v in (x.split() for x in parent['cpu.stat'].splitlines())}
            assert parent['pids.current'].strip()=='0' and 'populated 0' in parent['cgroup.events']
            row=dict(run=block['name'],N=block['N'],block=block['block'],group=session['architecture_group'],
                     sequence_s=(wait-start)/1e9,through_fixture_release_s=(release-start)/1e9,
                     fixture_tail_s=(release-wait)/1e9,parent_cpu_s=cpu['usage_usec']/1e6,
                     parent_peak_mib=int(parent['memory.peak'])/1048576)
            rows.append(row);grouped[row['group']]=row
            files[str(log.relative_to(S))]=sha(log);files[str(ledger_path.relative_to(S))]=sha(ledger_path)
        for base in ('G0','G1'):
            a,b=grouped[base],grouped['G2']
            pairs.append(dict(run=block['name'],N=block['N'],block=block['block'],comparison='G2_vs_'+base,
                              saving_s=a['sequence_s']-b['sequence_s'],saving_ratio=1-b['sequence_s']/a['sequence_s'],
                              cpu_saving_s=a['parent_cpu_s']-b['parent_cpu_s'],cpu_saving_ratio=1-b['parent_cpu_s']/a['parent_cpu_s'],
                              through_fixture_saving_s=a['through_fixture_release_s']-b['through_fixture_release_s']))
    table(out/'sessions.csv',rows);table(out/'paired.csv',pairs)
    stats=[]
    for n in sorted({r['N'] for r in rows}):
        for group in ('G0','G1','G2'):
            selected=[r for r in rows if r['N']==n and r['group']==group];assert len(selected)==3
            row=dict(N=n,group=group,n=3)
            for key in ('sequence_s','through_fixture_release_s','parent_cpu_s','parent_peak_mib'):
                v=[r[key] for r in selected];row.update({key+'_median':statistics.median(v),key+'_min':min(v),key+'_max':max(v)})
            stats.append(row)
    table(out/'summary.csv',stats)
    (out/'evidence.json').write_text(json.dumps({'files':files,'checker_sha256':sha(Path(__file__)),
        'plan_sha256':sha(S/'frozen/formal-plan.json'),'admission_sha256':sha(S/'analysis/performance-final-01/final-summary.json'),
        'scope':'Direct primary endpoint/parent ledger extraction; independent of detailed cost parser; no new VM or experiment'},indent=2)+'\n')
    print(json.dumps({'sessions':len(rows),'pairs':len(pairs),'out':str(out)}))

if __name__=='__main__':main()
