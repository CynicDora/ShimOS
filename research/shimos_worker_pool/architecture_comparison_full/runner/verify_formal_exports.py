#!/usr/bin/env python3
"""Independently inspect only driver-exported formal blocks; never starts a VM.

Run after export notifications. Reports are exclusive and immutable. A partial
snapshot lists all preregistered not-yet-exported blocks as PENDING and is never
called a complete qualification matrix. --watch sleeps between notifications;
it does not touch or inspect a still-running VM directory.
"""
import argparse,collections,json,os,time
from pathlib import Path
import verify_round1 as v

S=v.S

def load(p):return json.loads(p.read_text())
def put(p,x):
    with p.open('x') as f:json.dump(x,f,ensure_ascii=False,indent=2);f.write('\n')
def rel(p):return str(p.relative_to(S))
def dependency_hashes():
    return {p.name:v.sha(p) for p in (Path(v.npcheck.__file__),Path(v.perfcheck.__file__),
            Path(v.lifecycle.__file__),Path(v.runtimecheck.__file__))}

def snapshot(args,out):
    plan_path=S/'frozen/formal-plan.json';driver_path=S/'analysis/formal-driver.json'
    plan=load(plan_path);driver=load(driver_path)
    assert driver['plan_sha256']==v.sha(plan_path),'driver differs from preregistration'
    review=S/plan['review_path'];assert v.sha(review)==plan['review_sha256']
    exported={x['name']:x for x in driver['rows']}
    assert len(exported)==len(driver['rows']),'duplicate exported block'
    assert set(exported)<={b['name'] for b in plan['blocks']},'unregistered export'
    rows=[]
    for block in plan['blocks']:
        name=block['name']
        if name not in exported:
            rows.append({'run':name,'N':block['N'],'block':block['block'],'status':'PENDING','sessions':[]});continue
        row=exported[name]
        assert all(row[k]==block[k] for k in ('N','block','order','execution_index'))
        run=S/'runs'/name;config=load(run/'batch-config.json');result=load(run/'result.json')
        assert config.get('pilot') is False,'a pilot cannot join the formal matrix'
        assert config.get('requests')==block['N'] and config.get('warmup')==plan['warmup']
        assert config.get('source_review_path')==plan['review_path'] and config.get('source_review_sha256')==plan['review_sha256']
        assert config.get('session_deadline_seconds')==plan['session_deadline_seconds'] and config.get('test_descendant') is False
        assert str(config.get('timing'))==str(plan['timing']) and str(config.get('trace'))==str(plan['trace'])
        assert config.get('resource_sample_ms')==plan['resource_sample_ms'] and config.get('numpy_level')==plan['numpy_level']
        assert str(config.get('numpy_audit'))==str(plan['native_numpy_audit']) and config.get('numpy_case')==plan['numpy_case']
        command=load(run/'command.json')
        assert command[command.index('-smp')+1]==str(plan['vcpus']) and command[command.index('-m')+1]==str(plan['memory_mib'])
        assert '-enable-kvm' in command and command[command.index('-cpu')+1]=='host'
        assert config.get('order')==block['order'] and len(config['sessions'])==3
        assert [x['architecture_group'] for x in config['sessions']]==block['order']
        evidence=[]
        for session in config['sessions']:
            relative=name+'/'+session['relative_dir'];path=out/(name+'-'+Path(session['relative_dir']).name+'.json')
            if path.exists():
                report=load(path)
                assert report['run']==relative and report['verifier_sha256']==v.sha(Path(v.__file__))
                assert report.get('dependency_verifier_sha256')==dependency_hashes()
                # Prior immutable report already hashes all raw evidence. Do not
                # repeatedly read every runtime byte while another VM executes.
                # Final --rehash-evidence rechecks its complete evidence list.
                if args.rehash_evidence:
                    for p,h in report.get('evidence_sha256_study_relative',{}).items():
                        assert v.sha(v.npcheck.within_run(S,p))==h,(relative,p,'evidence changed')
            else:
                try:report=v.analyze(relative,'performance')
                except Exception as error:
                    report={'run':relative,'status':'BLOCKED','blockers':[{'check':'inspection failed','detail':repr(error)}],
                            'verification_profile':'performance','verifier_sha256':v.sha(Path(v.__file__)),
                            'dependency_verifier_sha256':dependency_hashes()}
                put(path,report)
                print(json.dumps({'session':relative,'status':report['status'],'attempts':report.get('attempts'),
                      'failures':len(report.get('failures',[])),'blockers':len(report.get('blockers',[]))},ensure_ascii=False),flush=True)
            evidence.append({'session':relative,'architecture_group':session['architecture_group'],'status':report['status'],
                             'attempts':report.get('attempts',0),'numeric_counts':report.get('numeric_counts',{}),
                             'report':rel(path),'sha256':v.sha(path)})
        status=('PASS' if result.get('complete') is True and row.get('complete') is True
                and all(x['status']=='PASS' for x in evidence) else 'FAIL' if any(x['status']=='FAIL' for x in evidence) else 'BLOCKED')
        rows.append({'run':name,'N':block['N'],'block':block['block'],'order':block['order'],'status':status,
                     'sessions':evidence,'vm_export_complete':result.get('complete') is True,
                     'result_sha256':v.sha(run/'result.json'),'config_sha256':v.sha(run/'batch-config.json'),
                     'vm_command_sha256':v.sha(run/'command.json'),'lab_manifest_sha256':v.sha(run/'lab-manifest.json')})
    counts=collections.Counter(x['status'] for x in rows)
    sessions=[r for row in rows for r in row['sessions']]
    complete=driver.get('complete') is True and not counts['PENDING']
    status=('PASS' if complete and counts=={'PASS':len(rows)} else 'FAIL' if counts['FAIL'] else 'BLOCKED' if complete else 'IN_PROGRESS')
    answer={'scope':'FINAL_PREREGISTERED_PERFORMANCE_MATRIX' if complete else 'PARTIAL_EXPORTED_BLOCKS_NOT_FINAL',
            'status':status,'complete_driver':driver.get('complete') is True,'blocks':rows,'block_counts':dict(counts),
            'session_counts':dict(collections.Counter(x['status'] for x in sessions)),
            'sessions_observed':len(sessions),'sessions_planned':plan['sessions'],
            'attempts_observed':sum(x['attempts'] for x in sessions),'attempts_planned':plan['total_requests'],
            'numeric_counts':dict(sum((collections.Counter(x['numeric_counts']) for x in sessions),collections.Counter())),
            'verifier_sha256':v.sha(Path(v.__file__)),'dependency_verifier_sha256':dependency_hashes(),
            'matrix_verifier_sha256':v.sha(Path(__file__)),'plan':{'path':rel(plan_path),'sha256':v.sha(plan_path)},
            'driver':{'path':rel(driver_path),'sha256':v.sha(driver_path)},
            'source_review':{'path':rel(review),'sha256':v.sha(review)},
            'cached_evidence_rehashed_this_pass':args.rehash_evidence,
            'limitations':['Same physical host; per-task equal limits, no shared whole-session hard cap.',
                          'No observed request prefix may replace a complete N sequence.',
                          'Pilot diagnostics and intentional qualification faults are outside this matrix.']}
    return answer

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,default=Path('analysis/performance-final-01'))
    p.add_argument('--watch',action='store_true');p.add_argument('--interval',type=float,default=30)
    p.add_argument('--rehash-evidence',action='store_true');a=p.parse_args()
    assert a.interval>=15,'avoid busy polling';os.nice(15)
    out=a.out if a.out.is_absolute() else S/a.out;out.resolve().relative_to(S.resolve());out.mkdir(parents=True,exist_ok=True)
    while True:
        value=snapshot(a,out)
        stamp=time.time_ns();path=out/('matrix-'+str(stamp)+'.json');put(path,value)
        print(json.dumps({'matrix':rel(path),'status':value['status'],'sessions':value['sessions_observed'],
                          'attempts':value['attempts_observed'],'block_counts':value['block_counts']},ensure_ascii=False),flush=True)
        if not a.watch or value['complete_driver']:
            return 0 if value['status'] in ('PASS','IN_PROGRESS') else 2
        time.sleep(a.interval)
if __name__=='__main__':raise SystemExit(main())
