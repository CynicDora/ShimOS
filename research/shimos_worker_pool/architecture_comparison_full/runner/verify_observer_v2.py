#!/usr/bin/env python3
"""Read-only v2 sampling coverage; supplemental to lifecycle/numerical proof."""
import argparse
import hashlib
import json
from pathlib import Path
S=Path(__file__).resolve().parent.parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def inspect(path):
    checks=[];evidence={}
    def read(p):
        if not p.is_file():return None
        evidence[str(p.relative_to(S))]=sha(p);return json.loads(p.read_text())
    def check(name,value,detail=None):checks.append(dict(name=name,value=value,detail=detail))
    full=read(path/'full-session.json') or {};manifest=read(path/'source-sha.json') or {}
    frozen=read(S/'frozen/sequential-v2.json') or {}
    check('exact v2 observation sources',manifest.get('resource_sampler.py')==frozen.get('source_sha256',{}).get('resource_sampler.py')
          and manifest.get('run.py')==frozen.get('source_sha256',{}).get('run.py'))
    budget=read(path/'root-budget-readback.json') or {}
    check('actual pre-H root/client budget readback',budget.get('changes_limits') is False
          and budget.get('path')=='/sys/fs/cgroup/cdz' and budget.get('clock')=='CLOCK_MONOTONIC'
          and isinstance(budget.get('start_ns'),int) and budget['start_ns']<=budget.get('end_ns',0)
          and set(budget.get('actual_limits',{}))==set(budget.get('client_actual_limits',{}))=={'memory.max','cpu.max','pids.max'})
    wanted=full.get('extra_env',{}).get('FULL_MEMORY_MIB')
    check('root memory limit equals requested finite budget or unchanged max',budget.get('actual_limits',{}).get('memory.max')==str(int(wanted)*1024**2) if wanted else budget.get('actual_limits',{}).get('memory.max')=='max')
    stream=path/'resource-observer.jsonl';records=[]
    if stream.is_file():
        evidence[str(stream.relative_to(S))]=sha(stream)
        for line in stream.read_text().splitlines():records.append(json.loads(line))
    start=[x for x in records if x.get('event')=='RESOURCE_OBSERVER_START']
    stop=[x for x in records if x.get('event')=='RESOURCE_OBSERVER_STOP']
    batches=[x for x in records if x.get('event')=='RESOURCE_BATCH']
    check('observer recorded start/stop and actual samples',len(start)==len(stop)==1 and bool(batches))
    if start:check('read-only sampler actually outside product accounting',start[0].get('observer_in_product_cgroup') is False
                   and start[0].get('cleanup_authority')=='NONE; read-only proc/cgroup, never sends product signals')
    check('every batch includes expanded local-template census contract',bool(batches) and all(
        '{control,template,transition,business}' in x.get('layout_scope','') for x in batches))
    identities=[]
    for p in path.glob('local-domain-*-ready.json'):
        r=read(p);identities.append(dict(domain=r['domain_nonce'],pid=r['runtime_host'],group=r['group']))
    observed=[]
    for item in identities:
        selected=[(b,r) for b in batches for r in b.get('processes',[]) if r.get('pid')==item['pid']
                  and r.get('cgroup_observed')=='/sys/fs/cgroup/cdz/d-'+item['domain']+'/template']
        stable=[(b,r) for b,r in selected if r.get('observed') is True and r.get('identity_stable') is True
                and r.get('membership_stable') is True and r.get('membership_matches_enumeration') is True
                and 'Pss' in r.get('memory_KiB',{})]
        check('actual local template PSS/identity sampled:'+item['domain'],True if stable else None,
              {'pid':item['pid'],'samples':len(selected),'stable_observed_samples':len(stable)})
        observed.append(dict(**item,samples=len(selected),stable_samples=len(stable),
                             observed_pss_KiB=[r['memory_KiB']['Pss'] for _,r in stable],
                             sample_span_ns=[r['end_ns']-r['start_ns'] for _,r in stable]))
    process_status=read(path/'resource-observer-status.json') or {}
    check('sampler stopped without product cleanup',process_status.get('product_cleanup_used') is False
          and process_status.get('returncode')==0)
    summary=stop[0] if stop else {}
    return dict(run=str(path.relative_to(S/'runs')),status='FAIL' if any(x['value'] is False for x in checks) else 'BLOCKED' if any(x['value'] is None for x in checks) else 'PASS',
                checks=checks,observer_summary=summary,batches=len(batches),local_templates=observed,
                stable_census_batches=sum(x.get('membership_census_stable') is True for x in batches),
                root_budget=budget,evidence_sha256=evidence,
                scope='Only sampling coverage/source/actual budget. No independent lifecycle or numeric PASS; PSS batches are not atomic; role Z may be G4 persistent Worker.')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('batch');p.add_argument('--out',required=True);a=p.parse_args()
    batch=(S/'runs'/a.batch).resolve(strict=True);batch.relative_to((S/'runs').resolve())
    rows=[inspect(p) for p in sorted((batch/'sessions').iterdir()) if p.is_dir()]
    value=dict(status='FAIL' if any(x['status']=='FAIL' for x in rows) else 'BLOCKED' if any(x['status']=='BLOCKED' for x in rows) else 'PASS',
               verifier_sha256=sha(Path(__file__)),sessions=rows,counts={k:sum(x['status']==k for x in rows) for k in ['PASS','FAIL','BLOCKED']})
    out=S/a.out;out.resolve().relative_to(S.resolve());out.parent.mkdir(parents=True,exist_ok=True)
    with out.open('x') as f:json.dump(value,f,indent=2,ensure_ascii=False);f.write('\n')
    print(json.dumps(dict(status=value['status'],counts=value['counts'],output=str(out))))
    return 0 if value['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
