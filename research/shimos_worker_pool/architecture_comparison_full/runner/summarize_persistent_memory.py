#!/usr/bin/env python3
"""Read exported G4 request smaps points; no raw logs or runtime execution."""
import argparse,csv,hashlib,json,statistics
from collections import defaultdict
from pathlib import Path


def read(path):
    with path.open() as stream:return list(csv.DictReader(stream))


def number(value):
    try:return int(value)
    except (TypeError,ValueError):return None


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--numpy-costs',type=Path,required=True)
    p.add_argument('--ledger',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();sources=[a.numpy_costs/'workers.csv',a.ledger/'requests.csv',a.ledger/'resource_role_growth.csv']
    workers,requests,growth=[read(path) for path in sources]
    reqs=defaultdict(list)
    for row in requests:reqs[(row['run'],row['session'],row['nonce'])].append(row)
    identities=defaultdict(set)
    for row in growth:
        if row['role']=='W_PERSISTENT':identities[(row['run'],row['session'])].add((row['pid'],row['start_ticks']))
    grouped=defaultdict(list)
    for row in workers:
        if row['group']=='G4':grouped[(row['run'],row['session'])].append(row)
    result=[]
    for key,rs in sorted(grouped.items()):
        problems=[];joined=[]
        for row in rs:
            candidates=reqs[(key[0],key[1],row['nonce'])]
            if len(candidates)!=1:problems.append('request nonce missing or ambiguous');continue
            request=candidates[0];idx=number(request['call_index'])
            if idx is None:problems.append('missing call index');continue
            joined.append((idx,row,request))
        joined.sort(key=lambda item:item[0]);sample=rs[0]
        n=number(sample['N']);indices=[x[0] for x in joined]
        if n is None or indices!=list(range(n)):problems.append('request order/count mismatch')
        if len({x['nonce'] for x in rs})!=len(rs):problems.append('duplicate nonce')
        if len({x['pid_namespace_local'] for x in rs})!=1:problems.append('multiple local PID observations')
        domains={x[2]['domain_nonce'] for x in joined}
        if len(domains)!=1:problems.append('multiple/missing target domains')
        if len(identities[key])!=1:problems.append('sampler host PID/starttime identity missing or multiple')
        if not all(x['reuse_model']=='persistent' and x['completed_level']=='blas' and
                   x['initialized_in_this_worker']=='False' for x in rs):problems.append('not all business snapshots already initialized')
        if not all(x['reported_check_status']=='REPORTED_CHECKS_PASS' for x in rs):problems.append('local business checks not all reported pass')
        out={k:sample[k] for k in ['run','session','label','group','profile','N','K']}
        out.update(status='OBSERVED_CONDITIONAL_ON_QUALIFIED_G4_IDENTITY' if not problems else 'UNKNOWN',
                   problems=problems,request_records=len(rs),domain_nonce=next(iter(domains)) if len(domains)==1 else None,
                   local_pid=sample['pid_namespace_local'],sampler_pid_starttime=sorted(identities[key]),
                   scope='first pre-business smaps after NumPy initialization versus last pre-business (after earlier reset) and last post-business (before final reset); not integral or leak verdict')
        if joined:
            first,last=joined[0][1],joined[-1][1]
            out.update(first_nonce=first['nonce'],last_nonce=last['nonce'],first_source_log=first['source_log'],last_source_log=last['source_log'])
            for field in ['Pss','Rss','Private_Dirty','Shared_Dirty','Anonymous']:
                b=number(first[field+'_before_KiB']);pb=number(last[field+'_before_KiB']);pa=number(last[field+'_after_KiB'])
                out.update({field+'_first_before_KiB':b,field+'_last_before_KiB':pb,field+'_last_after_KiB':pa,
                            field+'_prebusiness_delta_KiB':pb-b if pb is not None and b is not None and not problems else None,
                            field+'_first_before_to_last_after_delta_KiB':pa-b if pa is not None and b is not None and not problems else None})
        result.append(out)
    a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'sessions.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    fields=sorted({k for row in result for k in row})
    with (a.output/'sessions.csv').open('w') as f:
        w=csv.DictWriter(f,fields);w.writeheader()
        for row in result:w.writerow({k:json.dumps(v) if isinstance(v,(list,dict)) else v for k,v in row.items()})
    g=defaultdict(list)
    for row in result:g[row['label']].append(row)
    summaries=[]
    for label,rs in sorted(g.items()):
        for metric in ['Pss_prebusiness_delta_KiB','Pss_first_before_to_last_after_delta_KiB','Private_Dirty_prebusiness_delta_KiB','Private_Dirty_first_before_to_last_after_delta_KiB']:
            values=[r[metric]/1024 for r in rs if r.get(metric) is not None]
            summaries.append(dict(label=label,metric=metric.replace('_KiB','_MiB'),VMs=len(rs),observed=len(values),median=statistics.median(values) if values else None,minimum=min(values) if values else None,maximum=max(values) if values else None))
    (a.output/'summary.json').write_text(json.dumps(summaries,indent=2)+'\n')
    manifest=dict(sources={str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),sessions=len(result),statuses={s:sum(r['status']==s for r in result) for s in sorted({r['status'] for r in result})},qualification='Not independently granted by this parser; source/session qualification remains required',post_final_reset_smaps='NOT_OBSERVED_BY_THESE_INPUTS')
    (a.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({k:v for k,v in manifest.items() if k not in ['sources','script_sha256']}))


if __name__=='__main__':main()
