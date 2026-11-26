#!/usr/bin/env python3
"""Read-only traced PID1 lifetime diagnostic; never a performance/namespace-lifetime claim."""
import argparse,collections,hashlib,json,re
from decimal import Decimal
from pathlib import Path
S=Path(__file__).resolve().parent.parent

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def overlap(intervals):
    events=sorted([(a,1) for a,b in intervals]+[(b,-1) for a,b in intervals]);active=maximum=0
    for _,delta in events:active+=delta;maximum=max(active,maximum)
    return maximum

def analyze(record):
    rp=S/record['report'];assert sha(rp)==record['report_sha256'];report=json.loads(rp.read_text())
    run=S/'runs'/report['run'];evidence={str(rp.relative_to(S)):sha(rp)}
    def read(name,optional=False):
        p=run/name
        if optional and not p.exists():return None
        expected=report['evidence_sha256_study_relative'].get(str(p.relative_to(S)))
        actual=sha(p)
        if expected is not None:assert actual==expected,(p,'changed after qualification')
        evidence[str(p.relative_to(S))]=actual
        return p.read_text()
    mode=report['mode'];result=dict(run=report['run'],mode=mode,status='UNKNOWN',qualification_report=record['report'],qualification_report_sha256=record['report_sha256'],domains=[],pid1_lifetime_overlap=None)
    config=json.loads(read('trace-config.json'))
    if str(config.get('tracing_on','')).strip()!='1':
        result['reason']='NO_TRACE_NOT_OBSERVED';return result
    stats=json.loads(read('trace-stats.json'));text=read('process-trace.txt')
    header=re.search(r'entries-in-buffer/entries-written:\s*(\d+)/(\d+)\s+#P:(\d+)',text)
    assert header and header[1]==header[2] and int(header[3])==len(stats)
    assert '[mono]' in config['trace_clock']
    for raw in stats.values():
        loss=dict(re.findall(r'^(overrun|commit overrun|dropped events): (\d+)$',raw,re.M));assert len(loss)==3 and all(int(v)==0 for v in loss.values())
    births=collections.defaultdict(list);exits=collections.defaultdict(list);execs=collections.defaultdict(list);quanta=set();count=0
    for line_no,line in enumerate(text.splitlines(),1):
        m=re.search(r'\s(\d+\.\d+): sched_process_(fork|exit|exec): (.*)$',line)
        if not m:continue
        count+=1;ns=int(Decimal(m[1])*1000000000);quanta.add(10**max(0,9-len(m[1].split('.')[1])));kind,payload=m[2],m[3]
        if kind=='fork':
            x=re.search(r'\bpid=(\d+) child_comm=.* child_pid=(\d+)',payload);assert x
            births[int(x[2])].append(dict(begin_ns=ns,parent_pid=int(x[1]),birth_line=line_no))
        elif kind=='exit':
            x=re.search(r'\bpid=(\d+)',payload);assert x;exits[int(x[1])].append(dict(end_ns=ns,exit_line=line_no))
        else:
            x=re.search(r'filename=(.*?) pid=(\d+)',payload);assert x;execs[int(x[2])].append(dict(ns=ns,image=x[1],line=line_no))
    assert count==int(header[1])
    rows={}
    for p in run.glob('attempt-*.json'):
        x=json.loads(read(p.name));rows[x['nonce']]=x
    for p in sorted(run.glob('[0-9]*-*.json')):
        x=json.loads(read(p.name))
        if x.get('nonce') and 'case' in x:rows[x['nonce']]=x
    logs=[]
    for line in read('events.jsonl').splitlines():
        try:logs.append(json.loads(line))
        except ValueError:raise ValueError('required Controller event stream malformed')
    bindings=[]
    if mode=='G2_CONCURRENT':
        for n,r in rows.items():
            if not r.get('init_pid'):continue
            bindings.append(dict(domain_nonce=n,pid=r['init_pid'],anchor_ns=r['domain_ready_record']['monotonic_ns'],
                                 expected_image='/probe/domain_init',expected_parent=r['monitor_pid'],target_ns=r['target_ns'],binding='R SCM credential-bound init_pid + PID1 DOMAIN_READY'))
    elif mode=='G3_CONCURRENT':
        for p in sorted(run.glob('local-domain-*-ready.json')):
            r=json.loads(read(p.name));n=r['domain_nonce'];runtime=r['runtime_host']
            messages=[x for x in logs if x.get('event')=='LOCAL_CONTROL_RECEIVED' and x.get('message',{}).get('event')=='LOCAL_READY' and x['message'].get('nonce')==n]
            assert len(messages)==1 and messages[0]['credentials'][0]==runtime
            released=json.loads(read(p.name.replace('-ready.json','-released.json')))
            assert released['init_pid']==r['pid1_host'] and released['resources']=='RELEASED'
            bindings.append(dict(domain_nonce=n,pid=r['pid1_host'],anchor_ns=messages[0]['monotonic_ns'],
                                 expected_image='/probe/domain_init_local',expected_parent=None,target_ns=r['target_ns'],
                                 runtime_host=runtime,binding='R validated ready-domain pid1_host + SCM-bound LOCAL_READY runtime + final init_pid'))
    else:return dict(result,reason='UNSUPPORTED_MECHANISM')
    for binding in bindings:
        pid=binding['pid'];anchor=binding['anchor_ns'];candidates=[]
        for birth in births[pid]:
            next_birth=min([b['begin_ns'] for b in births[pid] if b['begin_ns']>birth['begin_ns']],default=2**64)
            ends=[x for x in exits[pid] if birth['begin_ns']<=x['end_ns']<next_birth]
            if len(ends)!=1:continue
            end=ends[0]
            if not birth['begin_ns']<=anchor<=end['end_ns']:continue
            images=[x for x in execs[pid] if birth['begin_ns']<=x['ns']<=end['end_ns']]
            if len(images)!=1 or images[0]['image']!=binding['expected_image']:continue
            if binding['expected_parent'] is not None and birth['parent_pid']!=binding['expected_parent']:continue
            if binding.get('runtime_host'):
                rb=[b for b in births[binding['runtime_host']] if birth['begin_ns']<b['begin_ns']<anchor and b['parent_pid']==pid]
                if len(rb)!=1:continue
            candidates.append(dict(**birth,**end,exec_event=images[0]))
        assert len(candidates)==1,(binding,'missing or ambiguous actual lifetime')
        result['domains'].append(dict(**binding,**candidates[0],status='OBSERVED',pid1_lifetime_ms=(candidates[0]['end_ns']-candidates[0]['begin_ns'])/1e6))
    result.update(status='OBSERVED',pid1_lifetime_overlap=overlap([(d['begin_ns'],d['end_ns']) for d in result['domains']]),
                  domain_count=len(result['domains']),trace_timestamp_resolution_ns=sorted(quanta),evidence_sha256_study_relative=evidence,
                  boundary='Kernel sched_process_fork of the actual target PID1 through its sched_process_exit; identity bound to domain ready evidence and process image. PID reuse is separated by birth/exit windows.',
                  limitation='PID1 process lifetime, not complete namespace object lifetime: retained namespace FDs may outlive PID1. Traced qualification only, never copied into untraced formal samples.')
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('summaries',nargs='+');p.add_argument('--out',required=True);a=p.parse_args();out=S/a.out;out.parent.mkdir(exist_ok=True,parents=True)
    results=[];sources={}
    for name in a.summaries:
        path=S/name;sources[name]=sha(path)
        for record in json.loads(path.read_text())['sessions']:
            report=json.loads((S/record['report']).read_text())
            if report.get('mode') not in ('G2_CONCURRENT','G3_CONCURRENT') or record['status']!='PASS':continue
            if set(report.get('actual_cases',[]))!={'normal'}:continue
            try:r=analyze(record)
            except Exception as exc:r=dict(run=record['run'],status='UNKNOWN',pid1_lifetime_overlap=None,reason=repr(exc))
            results.append(r)
    result=dict(schema=1,scope='READ_ONLY_TRACED_PID1_LIFETIME_DIAGNOSTIC_NOT_NEW_PRODUCT_QUALIFICATION',source_summaries=sources,analyzer_sha256=sha(Path(__file__)),sessions=results)
    with out.open('x') as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps([dict(run=x['run'],status=x['status'],overlap=x.get('pid1_lifetime_overlap'),reason=x.get('reason')) for x in results],indent=2))
if __name__=='__main__':main()
