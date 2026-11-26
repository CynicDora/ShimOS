#!/usr/bin/env python3
"""Offline data-only corpus analysis; never runs recorded commands.

Counts tool records, not processes. Nulls remain null when identity/time is absent.
The inherited conservative shell classifier is extended for multilingual tasks.
"""
import argparse, collections, csv, datetime, hashlib, json, re, statistics, shlex
from pathlib import Path
from classify_static import classify, returncode, text

PROJECT=Path(__file__).resolve().parents[3]
ROOT=PROJECT/'research/real_agent_workload'
OLD=PROJECT/'research/shimos_worker_pool/real_agent_workload/01_trajectory_analysis'
OUT=ROOT/'workload_analysis'
MAN=[];TASKS=[];ACTIONS=[];ERRORS=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):return json.loads(Path(p).read_text())
def rel(p):return str(Path(p).relative_to(PROJECT))
def js(p,o):Path(p).write_text(json.dumps(o,ensure_ascii=False,indent=2)+'\n')
def csvwrite(p,items):
    keys=list(dict.fromkeys(k for x in items for k in x))
    with Path(p).open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=keys);w.writeheader();w.writerows({k:json.dumps(v,ensure_ascii=False) if isinstance(v,(list,dict)) else v for k,v in x.items()} for x in items)
def percentile(vals,p):
    if not vals:return None
    a=sorted(vals);i=(len(a)-1)*p;lo=int(i);hi=min(lo+1,len(a)-1);return a[lo]+(a[hi]-a[lo])*(i-lo)
def dist(vals):
    return {'n':len(vals),'min':min(vals) if vals else None,'median':statistics.median(vals) if vals else None,'mean':statistics.mean(vals) if vals else None,'p90_descriptive':percentile(vals,.9),'max':max(vals) if vals else None}

def classify_extended(cmd,tool,args):
    # SWE-agent's executable editor command wraps a tool call, not a Python process.
    editor_args=args
    if re.match(r'^str_replace_editor\s',cmd):
        try:
            tokens=shlex.split(cmd);editor_args={'command':tokens[1]}
            for key in ['--new_str','--file_text']:
                if key in tokens:editor_args[key[2:]]=tokens[tokens.index(key)+1]
            c=classify('', 'str_replace_editor',editor_args)
        except (ValueError,IndexError):c=classify(cmd,tool,args)
    elif tool in {'Read','Glob','Grep','LS'}:
        c={'signals':['inspect'],'entries':[],'python_targets':[],'dependency_candidates':[],'parser_warnings':[]}
    elif tool in {'Write','Edit','MultiEdit','NotebookEdit'}:
        c=classify('', 'str_replace_editor',{'command':'write','file_text':args.get('content',args.get('new_string',''))})
    else:c=classify(cmd,tool,args)
    sig=set(c['signals']);labels=set()
    mapping={'inspect':'file_read_search','edit_request':'file_edit_request','git':'git','python_entry':'python_script_or_entry','ipython_cell':'python_kernel','test_entry':'python_test','dependency_setup':'dependency_install','network_entry':'network','environment_or_cwd':'shell_state'}
    labels.update(mapping[s] for s in sig if s in mapping)
    for e in c['entries']:
        n=e['executable'];a=e['argv'][1:]
        if n in {'node','nodejs','npm','npx','yarn','pnpm','tsc','eslint','jest','vitest'}:labels.add('javascript_typescript')
        if n in {'gcc','g++','clang','clang++','make','ninja','cmake','bazel'}:labels.add('cpp_build_entry')
        if n in {'sphinx-build','cythonize'}:labels.add('documentation_or_extension_build')
        if n in {'go','cargo','rustc','javac','java','mvn','gradle','dotnet','ruby','bundle','rspec','mix','elixir','php','composer'}:labels.add('other_language_build_test')
        if n in {'sleep','wait','watch','tail'}:labels.add('wait_poll_candidate')
        if n in {'echo','printf','true','false','pwd','ls','cd','env','which','type','uname','date','exit','export','source','bash','sh'}:labels.add('shell_basic')
        if n in {'kill','pkill','killall','timeout'}:labels.add('cancel_timeout_command')
        if n in {'nohup','systemctl','service','uvicorn','gunicorn','redis-server','mongod','npm'} and (n!='npm' or 'start' in a):labels.add('background_service_candidate')
    # Outside-payload syntax hints only; not evidence a background child survived.
    if re.search(r'(?<!&)&(?![&>])\s*(?:\n|$)',cmd):labels.add('background_service_candidate')
    if tool in {'str_replace_editor','str_replace_based_edit_tool','edit_file'}:
        labels.add('file_read_search' if args.get('command')=='view' else 'file_edit_request')
    if not labels:labels.add('unclassified')
    c['categories']=sorted(labels)
    c['cpu_intensive_actual']='UNKNOWN'
    return c

def add_run(meta,steps,terminal,complete,evaluation=None):
    p=Path(meta['path']);raw=p.read_bytes();rid=meta['run_id']
    receipt_path=p.with_suffix(p.suffix+'.receipt.json')
    receipt=read(receipt_path) if receipt_path.exists() else {}
    # Acquisition clocks are provenance only. Never attach to execution events.
    manifest={**meta,'path':rel(p),'sha256':sha(raw),'bytes':len(raw),'acquired_utc':receipt.get('finished_utc',meta.get('acquired_utc','HISTORICAL_ACQUISITION')),'terminal_status':terminal,'complete_terminal_transcript':complete,'included_main':complete and meta['source_tier']=='PRIMARY','exclusion_reason':'' if complete and meta['source_tier']=='PRIMARY' else meta.get('exclusion_reason','No reliable terminal record or incomplete source export'),'artifact_license':meta.get('artifact_license','UNKNOWN transcript redistribution grant; private local research copy only, do not republish'),'selection_reason':meta.get('selection_reason','Inherited fixed historical selection'),'duration_coverage':sum(s.get('execution_time_s') is not None for s in steps),'pid_identity_coverage':0,'namespace_identity_coverage':0,'cpu_memory_coverage':0,'official_evaluation':evaluation}
    MAN.append(manifest)
    task={k:manifest[k] for k in ['run_id','task_id','agent','model','benchmark','repo','base_commit','terminal_status','complete_terminal_transcript','included_main','source_tier','official_evaluation']}
    task.update({'tool_records':len(steps),'business_tool_actions':0,'duration_s':None,'total_task_wall_s':None,'llm_wall_s':None,'K_tool':None,'K_proc':None,'K_heap':None,'K_template':None,'domain_count':None,'unit_warning':'Tool records from transcript; domain/process/heap/template identities absent. Do not substitute tool_records for any K.'})
    TASKS.append(task)
    for i,s in enumerate(steps,1):
        cmd=s['command'];tool=s.get('tool','bash');args=s.get('args',{})
        c=classify_extended(cmd,tool,args)
        control=cmd.strip() in {'','exit_cost','exit_error','exit_format','exit_context','skip'}
        obs=s.get('observation','');dur=s.get('execution_time_s')
        reported_dur=dur
        # Pro contains one terminal-only empty-action record per run, with default 0.
        # Preserve its numeric field but never call it a measured zero-latency tool.
        if control:dur=None
        if dur is not None and (not isinstance(dur,(int,float)) or dur<0):
            ERRORS.append({'run_id':rid,'index':i,'error':'invalid recorded execution time'});dur=None
        row={'run_id':rid,'task_id':meta['task_id'],'agent':meta['agent'],'benchmark':meta['benchmark'],'included_main':manifest['included_main'],'action_index':i,'source_pointer':s['pointer'],'tool':tool,'command':cmd,'action_raw':s.get('raw',cmd),'command_sha256':sha(cmd.encode()),'action_sha256':sha((tool+'\0'+s.get('raw',cmd)).encode()),'observation':obs,'response_pair_observed':s.get('paired',True),'boundary_kind':'terminal_control_record' if control else 'recorded_tool_action','returncode':s.get('returncode',returncode(obs)),'returncode_scope':'recorded tool envelope only; not child process exit accounting','execution_time_s':dur,'reported_execution_time_s':reported_dur,'execution_time_scope':s.get('execution_time_scope') if dur is not None else None,'step_timestamp':s.get('timestamp'),'timestamp_scope':s.get('timestamp_scope'),'requested_wait_s':s.get('requested_wait_s'),'working_dir_recorded':s.get('cwd'),'actual_file_change':None,'process_identity':None,'domain_identity':None,'runtime_identity':None,'heap_reuse':'UNKNOWN','template_admission':'UNKNOWN','retry_evidence':'UNKNOWN',**c}
        if control:row['categories']=['terminal_control']
        ACTIONS.append(row)
        if not control:task['business_tool_actions']+=1
    manifest['duration_coverage']=sum(a['run_id']==rid and a['execution_time_s'] is not None for a in ACTIONS)

def parse_all():
    oldsources=read(OLD/'analysis-03/source-manifest.json')
    oldtasks={x['run_id']:x for x in read(OLD/'analysis-03/tasks.json')}
    oldactions=collections.defaultdict(list)
    for line in (OLD/'analysis-03/actions.jsonl').read_text().splitlines():
        x=json.loads(line);oldactions[x['run_id']].append(x)
    for s in oldsources:
        rid=s['run_id']
        if rid.startswith('local-tools:'):continue
        t=oldtasks[rid];agent='SWE-agent' if rid.startswith('swe-agent') else 'mini-SWE-agent' if rid.startswith('mini') else 'OpenHands'
        model={'SWE-agent':'claude-3-5-sonnet-20240620','mini-SWE-agent':'claude-sonnet-4-20250514','OpenHands':'claude-3-5-sonnet-20241022'}[agent]
        meta={**s,'path':PROJECT/s['path'],'agent':agent,'model':model,'task_id':t['task_id'],'benchmark':'SWE-bench test' if agent=='SWE-agent' else 'SWE-bench Verified','source_tier':'PRIMARY','historical_reused':True,'framework_version':{'SWE-agent':'20240620 submission; exact commit UNKNOWN','mini-SWE-agent':'1.0.0','OpenHands':'CodeAct2.1'}[agent]}
        steps=[]
        for x in oldactions[rid]:
            steps.append({'command':x['command'],'raw':x['action_raw'],'observation':x['observation'],'pointer':x['source_pointer'],'tool':x['tool'],'args':json.loads(x['action_raw']) if agent=='OpenHands' else {},'cwd':x.get('working_dir_recorded'),'paired':x['response_pair_observed']})
        add_run(meta,steps,t['terminal_status'],t['terminal_recorded'],evaluation=evaluation_status(agent,t['task_id']))
    sel=read(ROOT/'trajectories/selection-mini.json')
    for tid in sel['chosen']:
        if tid in sel['old']:continue
        p=ROOT/'trajectories/raw/mini'/f'{tid}.json'
        if not p.exists():ERRORS.append({'task_id':tid,'error':'download missing'});continue
        d=read(p);td=read(ROOT/'trajectories/task_definitions'/f'{tid}.json');r=read(p.with_suffix('.json.receipt.json'));steps=[]
        for i,m in enumerate(d['messages']):
            if m.get('role')!='assistant':continue
            blocks=re.findall(r'```bash\n(.*?)\n```',text(m['content']),re.S)
            paired=i+1<len(d['messages']) and d['messages'][i+1]['role']=='user'
            if len(blocks)!=1:
                ERRORS.append({'task_id':tid,'pointer':f'/messages/{i}','type':'OBSERVED_AGENT_FORMAT_REJECTION_NOT_TOOL_ACTION','error':'expected one bash block','count':len(blocks),'assistant_response':text(m['content']),'executor_feedback':text(d['messages'][i+1]['content']) if paired else ''});continue
            steps.append({'command':blocks[0].strip(),'observation':text(d['messages'][i+1]['content']) if paired else '', 'pointer':f'/messages/{i}','paired':paired})
        meta={'run_id':'mini-v1.0.0:'+tid,'path':p,'url':r['url'],'agent':'mini-SWE-agent','framework_version':'1.0.0','framework_commit':'a2b0efee5fd9c1d3bc9fdfc6fe88036a2235d74d','task_id':tid,'repo':td['repo'],'base_commit':td['base_commit'],'model':'claude-sonnet-4-20250514','benchmark':'SWE-bench Verified','source_tier':'PRIMARY','historical_reused':False,'selection_reason':'predeclared compatible-repo candidates + SHA-ranked round-robin repo sample; no outcome/length filter'}
        add_run(meta,steps,d['info'].get('exit_status'),bool(d['info'].get('exit_status')),evaluation_status('mini-SWE-agent',tid))
    for x in read(ROOT/'trajectories/selection-pro.json')['chosen']:
        tid=x['task_id'];p=ROOT/'trajectories/raw/pro'/(tid+'.traj')
        if not p.exists():ERRORS.append({'task_id':tid,'error':'download missing'});continue
        d=read(p);r=read(p.with_suffix('.traj.receipt.json'));cfg=json.loads(d['replay_config']);steps=[]
        for i,s in enumerate(d['trajectory']):
            state=s.get('state',{});state=json.loads(state) if isinstance(state,str) else state
            steps.append({'command':s['action'],'observation':s.get('observation',''),'pointer':f'/trajectory/{i}','tool':'swe_aci','cwd':state.get('working_dir'),'execution_time_s':s.get('execution_time'),'execution_time_scope':'SWE-agent recorded StepOutput execution_time; tool/action wrapper wall, not CPU or per-process initialization; exact build unavailable'})
        match=re.match(r'instance_(.+?)-[0-9a-f]{40}(?:-|$)',tid)
        repo=match.group(1).replace('__','/') if match else 'UNKNOWN'
        meta={'run_id':'swepro-v1-claude45:'+tid,'path':p,'url':r['url'],'agent':'SWE-agent','framework_version':d['info'].get('swe_agent_version'),'framework_commit':None,'swe_rex_version':d['info'].get('swe_rex_version'),'swe_rex_commit':d['info'].get('swe_rex_hash'),'model':cfg['agent']['model']['name'],'task_id':tid,'repo':repo,'base_commit':cfg['env']['repo'].get('base_commit'),'base_commit_scope':'preexisting image reset commit recorded by actual run; not inferred from task ID','environment_backend':cfg['env']['deployment']['type'],'image':cfg['env']['deployment'].get('image'),'benchmark':'SWE-bench Pro V1 public (2025-10-13 run)','source_tier':'PRIMARY','historical_reused':False,'selection_reason':'two SHA-ranked runs per repository, selected before transcript/outcome download; long, failed and budget exits retained','source_index_commit':'66f92766bba642462d4bbe5479e83f91f9211862'}
        add_run(meta,steps,d['info'].get('exit_status'),bool(d['info'].get('exit_status')),evaluation_status('Pro',tid))
    for x in read(ROOT/'trajectories/selection-terminal-v2.json')['chosen']:
        p=ROOT/'trajectories/raw/terminal'/x['group']/(x['task']+'.json');d=read(p);t=d['trajectory'];steps=[];refs=[]
        def unresolved(v,ptr):
            if isinstance(v,str) and re.fullmatch(r'\$[0-9a-fA-F]+',v):refs.append(ptr)
            elif isinstance(v,dict):
                for k,vv in v.items():unresolved(vv,ptr+'/'+str(k))
            elif isinstance(v,list):
                for k,vv in enumerate(v):unresolved(vv,ptr+'/'+str(k))
        unresolved(t,'/trajectory')
        for i,s in enumerate(t.get('steps',[])):
            obs=s.get('observation',{});ostr=json.dumps(obs,ensure_ascii=False)
            for j,c in enumerate(s.get('tool_calls',[])):
                args=c.get('arguments',{});args=json.loads(args) if isinstance(args,str) else args
                cmd=args.get('command',args.get('keystrokes',args.get('code',json.dumps(args,ensure_ascii=False))))
                steps.append({'command':cmd,'raw':json.dumps(args,ensure_ascii=False),'args':args,'tool':c.get('function_name','UNKNOWN'),'observation':ostr,'pointer':f'/trajectory/steps/{i}/tool_calls/{j}','paired':bool(obs),'timestamp':s.get('timestamp'),'timestamp_scope':'ATIF step timestamp; may be shared by multiple calls, not start/end pair','requested_wait_s':args.get('duration')})
        meta={'run_id':'terminal-mirror:'+d['trial_id'],'path':p,'url':'https://github.com/Jiacheng-Zhu-AIML/terminal_bench_trajectories/releases/tag/v0.1','archive_member':x['member'],'task_id':d['task_name'],'task_checksum':d['task_checksum'],'repo':'N/A task fixture','base_commit':None,'agent':d['agent_name'],'framework_version':d['agent_version'],'framework_commit':None,'model':d['model'],'benchmark':'Terminal-Bench 2.0 mirror','source_tier':'THIRD_PARTY_MIRROR','historical_reused':False,'selection_reason':'20 SHA-ranked tasks each of two groups; one SHA-ranked trial; no reward/length filter','unresolved_RSC_references':len(refs),'exclusion_reason':'Third-party mirror; official original now redirects; unresolved Next.js RSC refs='+str(len(refs))+'; not a complete authenticated primary transcript'}
        add_run(meta,steps,'reward='+str(d.get('reward')),not refs,evaluation={'source':'third-party copied leaderboard reward','reward':d.get('reward'),'independently_verified':False})

def evaluation_status(agent,tid):
    f={'SWE-agent':'swe-eval.json','mini-SWE-agent':'mini-eval.json','OpenHands':'openhands-eval.json'}.get(agent)
    if f:
        p=ROOT/'sources/trajectory_corpus'/f
        if not p.exists():return None
        d=read(p)
        if agent=='mini-SWE-agent':
            if isinstance(d,dict) and tid in d:return {'source':rel(p),'record':d[tid]}
            return None
        if isinstance(d,dict):
            for key in ['resolved','resolved_ids']:
                if key in d and isinstance(d[key],list):return {'source':rel(p),'resolved':tid in d[key]}
        return None
    if agent=='Pro':
        p=ROOT/'trajectories/raw/pro_eval'/(tid+'.json')
        if p.exists():
            d=read(p);return {'source':rel(p),'record':d}
    return None

def analyze():
    OUT.mkdir(parents=True,exist_ok=True);parse_all();byrun=collections.defaultdict(list)
    for a in ACTIONS:byrun[a['run_id']].append(a)
    repeats=[];cycles=[];deps=[];runs=[];timing=[]
    for t in TASKS:
        aa=byrun[t['run_id']];seen={};lastprobe=None;edits=[];previouscats=None;length=0;longest=0
        for a in aa:
            prev=seen.get(a['action_sha256']);a['previous_identical_action']=prev;seen[a['action_sha256']]=a['action_index']
            if prev is not None:
                changed=[x['action_index'] for x in aa[prev:a['action_index']-1] if 'file_edit_request' in x['categories']]
                repeats.append({'run_id':t['run_id'],'action_index':a['action_index'],'previous':prev,'categories':a['categories'],'intervening_edit_requests':changed,'safe_same_state':'UNKNOWN'})
            if 'file_edit_request' in a['categories']:edits.append(a['action_index'])
            probe=bool(set(a['signals'])&{'test_entry','test_or_reproducer_candidate'})
            if probe:
                if lastprobe and edits:cycles.append({'run_id':t['run_id'],'before':lastprobe,'edits':edits,'after':a['action_index'],'same_command':aa[lastprobe-1]['command_sha256']==a['command_sha256'],'actual_file_change':'UNKNOWN','after_rc':a['returncode']})
                lastprobe=a['action_index'];edits=[]
            for d in a['dependency_candidates']:deps.append({'run_id':t['run_id'],'action_index':a['action_index'],**d,'actual_import':'UNKNOWN','version':'UNKNOWN','init_time_s':None,'fork_admission':'UNKNOWN'})
            cats=tuple(a['categories']);length=length+1 if cats==previouscats else 1;longest=max(longest,length);previouscats=cats
            if a['execution_time_s'] is not None:timing.append({k:a[k] for k in ['run_id','action_index','execution_time_s','execution_time_scope','categories','returncode']})
        t.update({'category_counts':dict(collections.Counter(c for a in aa for c in a['categories'])),'exact_repeat_extra_actions':sum(a['previous_identical_action'] is not None for a in aa),'python_repeat_extra_actions':sum(a['previous_identical_action'] is not None and 'python_entry' in a['signals'] for a in aa),'edit_probe_cycles':sum(x['run_id']==t['run_id'] for x in cycles),'same_category_longest_run':longest,'tool_duration_recorded_actions':sum(a['execution_time_s'] is not None for a in aa),'recorded_tool_wall_sum_s':sum(a['execution_time_s'] or 0 for a in aa) if any(a['execution_time_s'] is not None for a in aa) else None,'recorded_rc_actions':sum(a['returncode'] is not None for a in aa),'nonzero_recorded_rc_actions':sum(a['returncode'] is not None and a['returncode']!=0 for a in aa),'timed_tool_fraction':sum(a['execution_time_s'] is not None for a in aa)/len(aa) if aa else 0})
    main=[t for t in TASKS if t['included_main']];maina=[a for a in ACTIONS if a['included_main']]
    summary={'schema':1,'meaning':'Descriptive convenience/stratified corpus; no population estimator; no measured ShimOS acceleration.','main_runs':len(main),'main_unique_task_ids':len(set(t['task_id'] for t in main)),'main_business_tool_actions':sum(t['business_tool_actions'] for t in main),'main_raw_tool_records':len(maina),'historical_complete_reused':sum(m['historical_reused'] and m['included_main'] for m in MAN),'new_primary_complete':sum(not m['historical_reused'] and m['included_main'] for m in MAN),'supplemental_runs':len(TASKS)-len(main),'all_manifest_rows':len(MAN),'main_action_count_distribution':dist([t['business_tool_actions'] for t in main]),'main_categories':dict(collections.Counter(c for a in maina for c in a['categories'])),'main_repositories':dict(collections.Counter(t['repo'] for t in main)),'missing_process_identity_fraction':1.0,'missing_namespace_identity_fraction':1.0,'K_heap_and_K_template':'UNKNOWN, not zero; no package admission inferred from text','main_timed_action_count':sum(a['execution_time_s'] is not None for a in maina),'main_timing_coverage':sum(a['execution_time_s'] is not None for a in maina)/len(maina),'main_task_wall_coverage':0,'main_repeat_extra_actions':sum(t['exact_repeat_extra_actions'] for t in main),'main_python_repeat_extra_actions':sum(t['python_repeat_extra_actions'] for t in main),'main_edit_probe_cycles':sum(t['edit_probe_cycles'] for t in main),'main_dependency_mentions':dict(collections.Counter(x['module'] for x in deps if next(t for t in TASKS if t['run_id']==x['run_id'])['included_main'])),'groups':{}}
    for group in sorted(set(t['benchmark']+' | '+t['agent'] for t in TASKS)):
        tt=[t for t in TASKS if t['benchmark']+' | '+t['agent']==group];ids={t['run_id'] for t in tt};aa=[a for a in ACTIONS if a['run_id'] in ids]
        summary['groups'][group]={'runs':len(tt),'included_main':sum(t['included_main'] for t in tt),'raw_tool_records':len(aa),'business_tool_actions':sum(t['business_tool_actions'] for t in tt),'unique_task_ids':len({t['task_id'] for t in tt}),'action_distribution':dist([t['business_tool_actions'] for t in tt]),'categories':dict(collections.Counter(c for a in aa for c in a['categories'])),'terminal_statuses':dict(collections.Counter(str(t['terminal_status']) for t in tt)),'repeated_actions':sum(t['exact_repeat_extra_actions'] for t in tt),'python_repeated_actions':sum(t['python_repeat_extra_actions'] for t in tt),'edit_probe_cycles':sum(t['edit_probe_cycles'] for t in tt),'recorded_tool_duration_distribution_s':dist([a['execution_time_s'] for a in aa if a['execution_time_s'] is not None]),'total_recorded_tool_wall_s':sum(a['execution_time_s'] or 0 for a in aa) if any(a['execution_time_s'] is not None for a in aa) else None,'paired_actions':sum(a['response_pair_observed'] for a in aa),'known_returncode_actions':sum(a['returncode'] is not None for a in aa),'nonzero_returncode_actions':sum(a['returncode'] is not None and a['returncode']!=0 for a in aa)}
    csvwrite(ROOT/'trajectory_manifest.csv',MAN);js(ROOT/'trajectories/trajectory_manifest.json',MAN)
    js(OUT/'summary.json',summary);js(OUT/'tasks.json',TASKS);csvwrite(OUT/'tasks.csv',TASKS)
    (OUT/'actions.jsonl').write_text(''.join(json.dumps(x,ensure_ascii=False)+'\n' for x in ACTIONS))
    csvwrite(OUT/'actions.csv',[{k:v for k,v in a.items() if k not in {'observation','entries'}} for a in ACTIONS]);csvwrite(OUT/'exact_repeats.csv',repeats);csvwrite(OUT/'edit_probe_cycles.csv',cycles);csvwrite(OUT/'dependency_candidates.csv',deps);csvwrite(OUT/'recorded_action_timing.csv',timing);js(OUT/'parser_failures.json',ERRORS)
    js(OUT/'analysis_manifest.json',{'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'script':rel(Path(__file__)),'script_sha256':sha(Path(__file__).read_bytes()),'classifier_sha256':sha((Path(__file__).parent/'classify_static.py').read_bytes()),'input_sha256':{m['path']:m['sha256'] for m in MAN},'trajectory_commands_executed':False,'known_action_time_is_not_cpu_or_init':True,'missing_PID_is_not_zero_processes':True})
    print(json.dumps({k:v for k,v in summary.items() if k not in {'groups','main_dependency_mentions','main_categories','main_repositories'}},indent=2))

if __name__=='__main__':analyze()
