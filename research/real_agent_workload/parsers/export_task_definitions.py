#!/usr/bin/python3.10
"""Decode fixed public SWE task metadata, not benchmark execution."""
import hashlib,json,sys
from pathlib import Path
P=Path(__file__).resolve().parents[3];R=P/'research/real_agent_workload'
sys.path.insert(0,str(P/'experiments/worker_state_discovery/sources/tooling_py310'))
import fastparquet
f=P/'experiments/worker_reuse_screening/sources/swe-test.parquet'
assert hashlib.sha256(f.read_bytes()).hexdigest()=='db4f70ef735b3162c74801ddcdf8d7bae8d704193788c6d844f898c20b571cbb'
rows={x['instance_id']:x for x in fastparquet.ParquetFile(f).to_pandas().to_dict(orient='records')}
sel=json.loads((R/'trajectories/selection-mini.json').read_text());o=R/'trajectories/task_definitions';o.mkdir(exist_ok=True)
for tid in sel['chosen']:
    p=o/(tid+'.json');b=(json.dumps(rows[tid],indent=2)+'\n').encode()
    if p.exists():assert p.read_bytes()==b
    else:p.write_bytes(b)
print('Verified/exported',len(sel['chosen']),'fixed task definitions; no task command executed')
