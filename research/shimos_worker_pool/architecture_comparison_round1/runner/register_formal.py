#!/usr/bin/env python3
"""Create a once-only preregistration after finite qualification and pilots."""
import datetime, hashlib, json, random
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    out=ROOT/'frozen/formal-plan.json';assert not out.exists(),'never overwrite a registered plan'
    review=ROOT/'docs/performance-source-review.json';r=json.loads(review.read_text())
    assert r.get('performance_admitted') is True,'complete qualification before registration'
    current={p.name:sha(p) for p in sorted((ROOT/'prototype').iterdir()) if p.is_file()}
    assert current==r['variants']['low']['source_sha256']
    for group in ('G0','G1','G2'):assert r['architectures'][group]['admitted'] is True
    required_pilots=['pilot-long-n100-01','sensitivity-timing-01','sensitivity-timing-02','sensitivity-observer-01','sensitivity-observer-02']
    pilots={}
    for name in required_pilots:
        result=ROOT/'runs'/name/'result.json';x=json.loads(result.read_text())
        assert x.get('complete') is True,(name,'incomplete pilot')
        pilots[name]={'result_sha256':sha(result),'path':str(result.relative_to(ROOT))}
    seed=20261020;orders=[['G0','G1','G2'],['G1','G2','G0'],['G2','G0','G1']]
    blocks=[{'N':n,'block':b+1,'order':orders[b],'name':f'round1-n{n}-b{b+1}'} for n in [1,2,5,10,25,50,100] for b in range(3)]
    random.Random(seed).shuffle(blocks)
    for i,row in enumerate(blocks):row['execution_index']=i
    plan={'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'seed':seed,'blocks':blocks,
          'session_deadline_seconds':240,'request_containment_seconds':8,'resource_sample_ms':100,
          'requests_per_group_total':579,'sessions':63,'total_requests':1737,
          'warmup':0,'timing':1,'trace':0,'native_numpy_audit':0,'test_descendant':False,
          'numpy_level':'blas','numpy_case':'normal','vcpus':4,'memory_mib':4096,
          'source_sha256':current,'review_path':str(review.relative_to(ROOT)),'review_sha256':sha(review),
          'runner_sha256':{name:sha(ROOT/'runner'/name) for name in ('register_formal.py','run_formal.py','paired_vm.py','numpy_fixture.py','host_monitor.py')},
          'pilots':pilots,'cache_policy':'natural warm filesystem cache; identical offline oracle before each session; no drop_caches',
          'only_one_vm_at_a_time':True,'physical_hosts':1,
          'primary_time_boundary':'fixture_session_start -> session_supervisor_waited, same-guest CLOCK_MONOTONIC',
          'failure_policy':'retain every failure/UNKNOWN/incomplete; do not extrapolate; no source/deadline change or selective replacement',
          'analysis_unit':'same-VM whole-sequence paired difference, not individual correlated requests'}
    out.write_text(json.dumps(plan,indent=2)+'\n');print(str(out))
if __name__=='__main__':main()
