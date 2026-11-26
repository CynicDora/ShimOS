#!/usr/bin/env python3
"""Read only exported NP_ADMISSION rows; isolated process point observations."""
import argparse,csv,hashlib,json,statistics
from collections import defaultdict
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('initialization',type=Path);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    records=[];excluded=[]
    with args.initialization.open() as source:
        for index,raw in enumerate(csv.DictReader(source)):
            if raw.get('event')!='NP_ADMISSION' or (raw.get('group'),raw.get('location')) not in (('G2','Z'),('G3','Z_domain')):
                excluded.append(dict(row=index,event=raw.get('event'),location=raw.get('location'),reason='not a measured product template admission'))
                continue
            after=json.loads(raw.get('after') or '{}');before=json.loads(raw.get('before') or '{}')
            memory=after.get('memory',{});ki=memory.get('KiB',{});fingerprint=json.loads(raw.get('fingerprint') or '{}')
            security=after.get('security',{})
            row={k:raw.get(k) for k in ('run','session','group','label','D','K','N','profile','level','location','_source')}
            row.update(snapshot='NP_ADMISSION.after initialized',snapshot_monotonic_ns=after.get('monotonic_ns'),
                       smaps_monotonic_ns=memory.get('monotonic_ns'),pid_namespace_local=after.get('pid_namespace_local'),
                       record_identity=[raw.get('run'),raw.get('session'),raw.get('_source'),after.get('pid_namespace_local'),after.get('monotonic_ns')],
                       identity_scope='run/session/source-log/local-PID/time record; local PID is not a globally unique host PID',
                       origin_pid=fingerprint.get('origin_pid'),numpy_version=fingerprint.get('version'),
                       data_bytes=fingerprint.get('data_bytes'),threads=len(after['threads']) if isinstance(after.get('threads'),list) else None,
                       uid=security.get('uid'),nnp=security.get('nnp'),seccomp=security.get('seccomp'),capabilities=security.get('capabilities'),
                       smaps_error=memory.get('error'),observation_scope='single process at initialized point, before later Worker forks; not total PSS or lifetime integral')
            for key in ('Pss','Rss','Private_Dirty','Shared_Dirty','Anonymous','AnonHugePages'):
                row[key+'_KiB']=ki.get(key)
            records.append(row)
    groups=defaultdict(list)
    for row in records:groups[(row['run'],row['session'])].append(row)
    summary=[]
    for _,rows in groups.items():
        entry={key:rows[0].get(key) for key in ('run','session','group','label','D','K','N','profile','level')}
        entry['initialized_template_records']=len(rows)
        for metric in ('Pss_KiB','Rss_KiB','Private_Dirty_KiB'):
            values=[r[metric] for r in rows if isinstance(r[metric],(int,float))]
            entry[metric+'_median']=statistics.median(values) if values else None
            entry[metric+'_min']=min(values) if values else None;entry[metric+'_max']=max(values) if values else None
            entry[metric+'_observed_count']=len(values)
        entry['scope']='within-session median of separate template-initialized point samples; no sum across processes or domains'
        summary.append(entry)
    for name,rows in [('template_initialized_points',records),('template_initialized_sessions',summary),('excluded',excluded)]:
        (args.output/(name+'.json')).write_text(json.dumps(rows,ensure_ascii=False,indent=2)+'\n')
        if rows:
            with (args.output/(name+'.csv')).open('w') as stream:
                writer=csv.DictWriter(stream,sorted(set().union(*(r.keys() for r in rows))));writer.writeheader()
                writer.writerows({k:json.dumps(v,ensure_ascii=False) if isinstance(v,(dict,list)) else v for k,v in r.items()} for r in rows)
    (args.output/'manifest.json').write_text(json.dumps(dict(source=str(args.initialization.resolve()),
        source_sha256=hashlib.sha256(args.initialization.read_bytes()).hexdigest(),
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),point_records=len(records),
        sessions=len(summary),raw_logs_read=False,net_physical_saving='Unknown',runtime_executed=False),indent=2)+'\n')
    print(json.dumps(dict(output=str(args.output),records=len(records),sessions=len(summary))))


if __name__=='__main__':main()
