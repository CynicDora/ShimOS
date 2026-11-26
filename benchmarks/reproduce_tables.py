#!/usr/bin/env python3
"""Recompute published tables from sanitized numeric exports; no workload execution."""
import csv,json,statistics
from pathlib import Path
R=Path(__file__).resolve().parents[1]
P=R/'research/shimos_worker_pool'
def load(p):
    with p.open(newline='') as f:return list(csv.DictReader(f))
def results():
    early=load(P/'analysis/final03/sequences.csv')
    worker=[]
    for kind in ('numpy','clangd'):
        row={'workload':kind,'requests':4,'unit':'ms'}
        for mode,key in [('B','fresh'),('C','reused')]:
            selected=[r for r in early if r['cohort']=='cost' and r['kind']==kind and r['n']=='4' and r['mode']==mode]
            assert len(selected)==6 and all(r['passed']=='True' for r in selected)
            row[key]=round(statistics.median(float(r['sequence_total_ms']) for r in selected),3)
        worker.append(row)
    sessions=load(P/'architecture_comparison_round1/analysis/formal-cost-01/sessions.csv')
    z=[]
    for group in ('G0','G1','G2'):
        selected=[r for r in sessions if r['architecture_group']==group and r['declared_N']=='100']
        assert len(selected)==3 and all(r['complete']=='True' for r in selected)
        assert all(r['H_release_state']=='RELEASED' for r in selected)
        z.append({'architecture':group,'requests':100,'blocks':3,'unit':'s',
                  'median':round(statistics.median(float(r['full_sequence_ns'])/1e9 for r in selected),3)})
    assert [(r['fresh'],r['reused']) for r in worker]==[(555.406,163.325),(643.113,177.554)]
    assert [r['median'] for r in z]==[53.793,61.759,22.503]
    return {'kind':'offline numeric reproduction; not a new benchmark or security qualification','worker_sequences':worker,'independent_domains':z}
if __name__=='__main__':print(json.dumps(results(),indent=2))
