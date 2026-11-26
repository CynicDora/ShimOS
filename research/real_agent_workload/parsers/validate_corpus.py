#!/usr/bin/env python3
"""Independent data integrity checks plus meaningful static-parser counterexamples."""
import collections,hashlib,json
from pathlib import Path
from analyze_corpus import classify_extended
P=Path(__file__).resolve().parents[3];R=P/'research/real_agent_workload'
checks=[]
def check(name,ok,detail=None):checks.append({'check':name,'pass':bool(ok),'detail':detail})
m=json.loads((R/'trajectories/trajectory_manifest.json').read_text());tt=json.loads((R/'workload_analysis/tasks.json').read_text());aa=[json.loads(x) for x in (R/'workload_analysis/actions.jsonl').read_text().splitlines()]
check('Unique run IDs',len({x['run_id'] for x in m})==len(m))
check('All source digests',all(hashlib.sha256((P/x['path']).read_bytes()).hexdigest()==x['sha256'] for x in m))
check('Task/action counts',all(sum(a['run_id']==t['run_id'] for a in aa)==t['tool_records'] for t in tt))
check('No manufactured PID/domain IDs',all(a['process_identity'] is None and a['domain_identity'] is None for a in aa))
check('No manufactured K counts',all(all(t[k] is None for k in ['K_tool','K_proc','K_heap','K_template','domain_count']) for t in tt))
check('Only Pro has action wall samples',all(a['execution_time_s'] is None or a['benchmark'].startswith('SWE-bench Pro V1') for a in aa))
check('Requested terminal wait not execution duration',all(a['execution_time_s'] is None for a in aa if a['benchmark'].startswith('Terminal')))
check('No terminal mirror in primary',all(not t['included_main'] for t in tt if t['benchmark'].startswith('Terminal')))
check('Historical 40 complete retained',sum(x['historical_reused'] and x['included_main'] for x in m)==40)
check('No reused historical run counted new',sum(not x['historical_reused'] and x['included_main'] for x in m)==82)
check('All selected Pro, all selected mini retained',sum(t['benchmark'].startswith('SWE-bench Pro') for t in tt)==22 and sum(t['agent']=='mini-SWE-agent' for t in tt)==70)
check('Command byte hashes',all(hashlib.sha256(a['command'].encode()).hexdigest()==a['command_sha256'] for a in aa))
check('Repeated task identity kept separate',len({t['task_id'] for t in tt if t['included_main']})<sum(t['included_main'] for t in tt))
cases=[('editor code is not Python execution',"str_replace_editor create /app/x.py --file_text 'import numpy\nprint(1)'",'swe_aci',{},lambda c:'python_script_or_entry' not in c['categories'] and 'file_edit_request' in c['categories']),('heredoc write is not Python execution',"cat >x.py <<'PY'\nimport numpy\nPY",'bash',{},lambda c:'python_script_or_entry' not in c['categories']),('compound Python action retained',"cd /app && python -m pytest a.py | tee log",'bash',{},lambda c:'python_test' in c['categories']),('quoted Python filename is not exec',"rg 'python numpy' x.py",'bash',{},lambda c:'python_script_or_entry' not in c['categories']),('JS tool distinct',"npm test",'bash',{},lambda c:'javascript_typescript' in c['categories']),('Go tool distinct',"go test ./...",'bash',{},lambda c:'other_language_build_test' in c['categories']),('Read tool not shell',"/app/x.py",'Read',{'file_path':'/app/x.py'},lambda c:c['categories']==['file_read_search'])]
for name,cmd,tool,args,predicate in cases:check(name,predicate(classify_extended(cmd,tool,args)))
out={'status':'PASS' if all(x['pass'] for x in checks) else 'FAIL','checks':checks,'scope':'Offline data/parser validation only; not workload correctness or execution qualification.'}
(R/'workload_analysis/validation.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2));assert out['status']=='PASS'
