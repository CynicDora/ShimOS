#!/usr/bin/env python3
"""Reacquire preselected public Pro artifacts / frozen metadata and mirror members.
No AWS login, paid API, model call, or recorded command execution occurs.
Requires selection manifests already frozen before transcript inspection.
"""
import argparse, concurrent.futures, json, tarfile
from pathlib import Path
from acquire_corpus import ROOT,fetch,sha

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--download',action='store_true');args=ap.parse_args()
    plan=json.loads((ROOT/'trajectories/selection-pro.json').read_text())
    def one(x):
        p=ROOT/'trajectories/raw/pro'/(x['task_id']+'.traj')
        if args.download:fetch('https://scaleapi-results.s3.amazonaws.com/'+x['key'],p,max(100_000_000,x['size']+1))
        assert p.stat().st_size==x['size']
        receipt=json.loads(p.with_suffix('.traj.receipt.json').read_text());assert sha(p.read_bytes())==receipt['sha256']
        q=ROOT/'trajectories/raw/pro_eval'/(x['task_id']+'.json')
        if args.download:fetch('https://scaleapi-results.s3.amazonaws.com/swe-bench-pro/claude-45sonnet-10132025/eval/'+x['task_id']+'/_output.json',q)
        return {'task_id':x['task_id'],'bytes':p.stat().st_size,'sha256':receipt['sha256'],'status':'VERIFIED'}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:r=list(pool.map(one,plan['chosen']))
    arc=ROOT/'sources/trajectory_corpus/terminal-thirdparty-v0.1.tar.gz'
    if args.download:fetch('https://github.com/Jiacheng-Zhu-AIML/terminal_bench_trajectories/releases/download/v0.1/trajectories.tar.gz',arc,25_000_000)
    tp=json.loads((ROOT/'trajectories/selection-terminal-v2.json').read_text());assert sha(arc.read_bytes())==tp['archive_sha256']
    with tarfile.open(arc) as tf:
        for x in tp['chosen']:
            b=tf.extractfile(x['member']).read();p=ROOT/'trajectories/raw/terminal'/x['group']/(x['task']+'.json')
            if args.download and not p.exists():p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
            assert p.read_bytes()==b
    print(json.dumps({'pro_verified':len(r),'terminal_mirror_members_verified':len(tp['chosen']),'no_recorded_commands_executed':True},indent=2))
if __name__=='__main__':main()
