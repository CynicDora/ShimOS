"""Bounded evidence handling. No contents from tools become control messages."""
import os,stat,time,json
from pathlib import Path

OUTPUT_LIMIT=1024*1024

def workspace_snapshot(work):
    result={};budget=1024*1024
    for index,entry in enumerate(os.scandir(work)):
        p=Path(entry.path)
        if index>=128:
            result['_truncated_entries']=True;break
        s=p.lstat();row={'mode':s.st_mode,'size':s.st_size}
        if stat.S_ISLNK(s.st_mode):row['symlink']=os.readlink(p)
        elif stat.S_ISREG(s.st_mode) and budget>0:
            try:
                fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
                try:
                    current=os.fstat(fd)
                    if stat.S_ISREG(current.st_mode):
                        data=os.read(fd,min(65536,budget));budget-=len(data)
                        row.update(text=data.decode(errors='replace'),truncated=current.st_size>len(data))
                finally:os.close(fd)
            except OSError as e:row['error']=repr(e)
        result[p.name]=row
    return result

def process_memory(pid):
    result={'monotonic_ns':time.monotonic_ns(),'pid':pid}
    try:
        for line in Path(f'/proc/{pid}/smaps_rollup').read_text().splitlines():
            if line.startswith(('Rss:','Pss:','Private_Clean:','Private_Dirty:')):
                k,v=line.split(':',1);result[k+'_kib']=int(v.split()[0])
        result['exe']=os.readlink(f'/proc/{pid}/exe')
    except OSError as e:result['unavailable']=repr(e)
    return result

def validate_tool(row,case,streams):
    """Fixture expectations, separate from product results and raw wait status."""
    checks={
      'resources_removed':row['resources_removed'],
      'all_streams_eof':all(row['stream_eof'].values()),
      'domain_empty':row['domain_empty'],
      'sealed':row['admission'].startswith('SEALED'),
      'fd_inventory':row['controller_fd_before']==row['controller_fd_after'],
    }
    action=case.get('action')
    if action=='cancel_before_business':
        checks['not_executed']=not row['business_permit'] and row['business']=='NOT_EXECUTED'
        checks['no_tool_output']=not any(streams.values())
    else:
        checks['gate_security']=bool(row.get('tool_security')) and all(row['tool_security']['checks'].values())
        checks['business_permit']=row['business_permit']
    if case.get('action')=='result_loss_side_effect':
        checks['unknown_result']=row['business']=='UNKNOWN' and row['result'] is None and row['outcome']!='SUCCEEDED'
        checks['effect_before_lost_receipt']=row.get('workspace_snapshot',{}).get('tool-side-effect',{}).get('text')=='FIXED_TOOL_SIDE_EFFECT\n'
    elif action!='cancel_before_business':
        if case['expected_exit'] is not None:checks['exit_code']=(row.get('result') or {}).get('exit_code')==case['expected_exit']
        if case.get('expected_signal') is not None:
            # S can be killed concurrently during cancellation; a missing exact
            # W wait remains UNKNOWN and must not be fabricated as SIGKILL.
            checks['signal_or_unknown_cleanup']=(row.get('result') or {}).get('exit_code')==-case['expected_signal'] or (row['business']=='UNKNOWN' and row['failure'] in ('CANCELLED','TIMED_OUT'))
        if case.get('expect_timeout'):checks['timeout']=row['outcome']=='TIMED_OUT'
        if action=='cancel':checks['cancel']=row['outcome']=='CANCELLED'
        if case.get('expected_outcome'):checks['expected_outcome']=row['outcome']==case['expected_outcome']
        if case.get('expect_descendants_after_main'):
            checks['post_main_tree_deadline']=row['outcome']=='DESCENDANT_DEADLINE' and (row.get('result') or {}).get('exit_code')==0
        elif not case.get('expect_timeout') and not case.get('expected_outcome') and action not in ('cancel','controller_death'):
            checks['no_infrastructure_failure']=row['failure'] is None
        for stream in ('stdout','stderr'):
            text=streams[stream].decode(errors='replace')
            for i,expected in enumerate(case.get('expected_'+stream,[])):
                checks[f'{stream}_fixture_{i}']=expected in text
        if case['name']=='tool_output_limit':
            checks['bounded_output']=row['stream_truncated']['stdout'] and len(streams['stdout'])==OUTPUT_LIMIT
        if case['name']=='tool_unsafe_result':
            snap=row['workspace_snapshot'];checks['fifo_not_read']=stat.S_ISFIFO(snap['result']['mode']) and 'text' not in snap['result']
            checks['symlink_not_followed']=snap['link'].get('symlink')=='/state' and 'text' not in snap['link']
    row['fixture_checks']=checks
    if not all(checks.values()):raise AssertionError({'tool_fixture_failure':checks,'case':case['name'],'outcome':row['outcome'],'result':row['result']})
