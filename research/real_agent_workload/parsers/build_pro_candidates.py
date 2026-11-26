#!/usr/bin/env python3
"""Static future environment candidates; never executes their commands."""
import json,csv,collections
from pathlib import Path
P=Path(__file__).resolve().parents[3];R=P/'research/real_agent_workload'
m={x['run_id']:x for x in json.loads((R/'trajectories/trajectory_manifest.json').read_text())};by=collections.defaultdict(list)
for line in (R/'workload_analysis/actions.jsonl').read_text().splitlines():
    x=json.loads(line)
    if x['benchmark'].startswith('SWE-bench Pro'):by[x['run_id']].append(x)
rows=[]
for rid,aa in by.items():
    target=[x for x in aa if set(x['categories']) & {'javascript_typescript','other_language_build_test','cpp_build_entry','background_service_candidate'}]
    if not target:continue
    mm=m[rid];rows.append({'task_id':mm['task_id'],'run_id':rid,'repo':mm['repo'],'candidate_features':sorted({c for x in target for c in x['categories']} & {'javascript_typescript','other_language_build_test','cpp_build_entry','background_service_candidate'}),'source_url':mm['url'],'source_sha256':mm['sha256'],'source_path':mm['path'],'base_commit':mm['base_commit'],'base_commit_scope':mm.get('base_commit_scope'),'recorded_image':mm['image'],'backend':mm['environment_backend'],'selected_action_indices':[x['action_index'] for x in target[:6]],'real_commands':[x['command'] for x in target[:6]],'command_sha256':[x['command_sha256'] for x in target[:6]],'recorded_tool_wall_s':[x['execution_time_s'] for x in target[:6]],'preparation_gap':'Recorded Modal/ECR image; no pull or environment reconstruction attempted. Need official V1 Docker/setup provenance, dependency versions, image access, repo checkout, fixed evaluator and network/state audit.','status':'STATIC_REAL_TRAJECTORY_CANDIDATE_NOT_REPRODUCED','shell_session_equivalence':'SWE-ReX1.2.2 persistent session behavior must be preserved; cannot silently replace with fresh Bash','heap_qualification':'UNKNOWN; exec Node/Go does not inherit a Python heap'})
with (R/'workload_analysis/pro-execution-candidates.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows({k:json.dumps(v,ensure_ascii=False) if isinstance(v,(dict,list)) else v for k,v in x.items()} for x in rows)
(R/'workload_analysis/pro-execution-candidates.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2)+'\n')
(R/'workload_analysis/pro-candidate-coverage.json').write_text(json.dumps({'candidate_runs':len(rows),'repos':sorted({x['repo'] for x in rows}),'cpp_entries_observed':sum('cpp_build_entry' in x['categories'] for aa in by.values() for x in aa),'background_entries_observed':sum('background_service_candidate' in x['categories'] for aa in by.values() for x in aa),'scope':'Syntactic commands in selected22 trajectories; absence is not absence in full Pro workload.'},indent=2)+'\n')
print(len(rows),'static candidate runs')
