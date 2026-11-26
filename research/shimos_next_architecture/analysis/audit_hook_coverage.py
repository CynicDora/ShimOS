#!/usr/bin/env python3
"""Trace/hook coverage crosscheck from completed artifacts; no Python task run."""
import argparse,hashlib,json,tarfile
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]

def load(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);args=p.parse_args();out=Path(args.out);out.mkdir(parents=True,exist_ok=False)
    rows=[];details=[];sources={str(Path(__file__)):sha(Path(__file__))}
    audit=BASE/'analysis/study-process-dependency-01'
    # The two concrete, manually localized exec identities; not a classifier
    # that assumes every missing hook must be a version invocation.
    cases={'next-dependency-01r1':3846,'next-dependency-02':2671}
    for run,probe_pid in cases.items():
        src=audit/(run+'-study-audit.json');sources[str(src)]=sha(src)
        for s in load(src)['sessions']:
            if s['observation_row']['cohort']!='identity-on':continue
            root=BASE/'runs'/run;sd=root/'sessions'/s['session'];records=root/'dependency-identity'/s['task_id']/'records'
            starts=sorted(records.glob('*-start.json'));ends=sorted(records.glob('*-end.json'))
            for f in starts+ends:sources[str(f)]=sha(f)
            rows.append({'run':run,'session':s['session'],'task_id':s['task_id'],
                         'trace_Python_exec_processes':s['observation_row']['python_processes_exec_observed'],
                         'hook_start_files':len(starts),'hook_end_files':len(ends),
                         'limit':'hook file pairing is not coverage of every Python exec; raw argv pointers were not dereferenced'})
            for action in s['actions']:
                for entity in action['processes']:
                    if entity['pid']!=probe_pid:continue
                    source=sd/'final-workspace/sympy/testing/runtests.py'
                    if source.exists():
                        data=source.read_bytes();sources[str(source)]=sha(source);ref=str(source)
                    else:
                        archive=sd/'final-workspace.tar.gz';sources[str(archive)]=sha(archive)
                        with tarfile.open(archive,'r:gz')as tf:
                            member=tf.getmember('./sympy/testing/runtests.py');assert member.isfile()
                            data=tf.extractfile(member).read()
                        ref=str(archive)+'::./sympy/testing/runtests.py'
                    code=data.decode().splitlines();assert 'subprocess.Popen([command, "-RV"]'in code[251]
                    assert 'subprocess.Popen([command, "-R", "-c", commandstring]'in code[272]
                    trace=root/'natural-trace/process.trace';sources[str(trace)]=sha(trace)
                    raw=trace.read_text().splitlines();evlines=[entity['birth_line']]+[x['line']for x in entity['execs']]+entity['exit_lines']+[x['exit_line']for x in entity['wait4_evidence']]
                    details.append({'run':run,'session':s['session'],'action_id':action['action_id'],'action_command':action['command'],
                                    'unhooked_exec':entity,'raw_trace_lines':{str(n):raw[n-1]for n in evlines},
                                    'source_file':ref,'source_file_sha256':hashlib.sha256(data).hexdigest(),'source_function':'run_in_subprocess_with_hash_randomization',
                                    'source_lines':{'probe':252,'wait_probe':254,'real_test_child':273},
                                    'source_reconstructed_argv':['/usr/bin/python','-RV'],
                                    'argument_evidence':'source reconstruction plus actual process order, not captured argv bytes',
                                    'observed_exec_to_exit_ms':(entity['exit_ns'][0]-entity['execs'][0]['t_ns'])/1e6,
                                    'interpretation':'short version/hash-support check accounts for one extra Python exec; no dependency/heap reuse qualification follows'})
    result={'hook_start_files':sum(r['hook_start_files']for r in rows),'hook_end_files':sum(r['hook_end_files']for r in rows),
            'trace_python_exec_processes':sum(r['trace_Python_exec_processes']for r in rows),'rows':rows,'localized_missing_hook':details,
            'conclusion':'36 start/end records cover 36 hooked executions, whereas trace observes 38 Python exec processes in these identity-on sessions; two source-localized version probes are separate.',
            'limits':['No direct runtime argv string capture for the short probes; exact argument interpretation remains source+event-order evidence.','Missing hook is not generalized to absent site initialization for arbitrary future processes.','All Python exec counts are image/process facts, never a reusable heap count.']}
    (out/'hook-coverage.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    (out/'input-sha256.json').write_text(json.dumps(sources,indent=2)+'\n')
    print(json.dumps({k:result[k]for k in ['hook_start_files','hook_end_files','trace_python_exec_processes']}))

if __name__=='__main__':main()
