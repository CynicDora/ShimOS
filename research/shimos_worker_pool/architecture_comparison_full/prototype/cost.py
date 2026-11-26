"""Optional, bounded same-guest timing. No additional control messages or FDs.

Records are diagnostics, never permissions, status or cleanup evidence.
Parent/child fork intervals overlap. CPU and wall time are different quantities.
"""
import os,time,json,ctypes,resource

ENABLED=os.environ.get('COST_ENABLED','1')=='1'
SESSION=os.environ.get('COST_SESSION','unset')
VARIANT=os.environ.get('COST_VARIANT','baseline_instrumented')
DIAGNOSTICS=os.environ.get('ARCH_DIAGNOSTICS','full')
if DIAGNOSTICS not in ('full','low'):raise ValueError('ARCH_DIAGNOSTICS must be full or low')
ROLE='fixture';NONCE=None;PID=os.getpid();SEQ=0;ROWS=[];WAIT_AGGREGATES={}
REPEAT=None;WARMUP=False
# Bound the number of retained Python records/aggregate keys in each process.
# stdout is already owned by the execution protocol; no extra descriptor is
# opened or inherited. Writes are synchronous and remain charged to the caller.
BUFFER_LIMIT_ROWS=128
FLUSHING=False
STREAM_FLUSHES=0
STREAM_UNCONFIRMED_RECORDS=0
STREAM_MAX_BUFFERED_ROWS=0

def context(role=None,nonce=None,repeat=None,warmup=None):
    global ROLE,NONCE,PID,SEQ,ROWS,REPEAT,WARMUP,WAIT_AGGREGATES
    global FLUSHING,STREAM_FLUSHES,STREAM_UNCONFIRMED_RECORDS,STREAM_MAX_BUFFERED_ROWS
    p=os.getpid()
    if p!=PID:
        # Neither unflushed parent observations nor parent sequence numbers
        # belong to the child's log. The real fork wrapper is unchanged.
        PID=p;SEQ=0;ROWS=[];WAIT_AGGREGATES={};FLUSHING=False
        STREAM_FLUSHES=0;STREAM_UNCONFIRMED_RECORDS=0;STREAM_MAX_BUFFERED_ROWS=0
    if role is not None:ROLE=role
    NONCE=nonce
    if repeat is not None:REPEAT=repeat
    if warmup is not None:WARMUP=warmup

def now():return time.monotonic_ns() if ENABLED else 0

def record(name,kind='phase',force=False,**fields):
    global SEQ,STREAM_MAX_BUFFERED_ROWS
    if not ENABLED and not force:return
    if os.environ.get('FULL_COST_MODE')=='stages' and not force:
        if kind=='span' and name not in {'native_launcher_spawn','wait_worker','cgroup_delete','workspace_delete','rpc_register','rpc_forget','rpc_ping','rpc_retire','enter_target','fork_entry_to_parent_return','fork_entry_to_child_return'}:return
        if name in {'controller_journal_buffered'}:return
    if os.getpid()!=PID:context('descendant',NONCE)
    row={'event':'COST','clock':'CLOCK_MONOTONIC','ns':time.monotonic_ns(),
         'session':SESSION,'variant':VARIANT,'diagnostics':DIAGNOSTICS,'role':ROLE,'pid':PID,'seq':SEQ,
         'nonce':NONCE,'repeat':REPEAT,'warmup':WARMUP,'kind':kind,'name':name,**fields}
    SEQ+=1;ROWS.append(row)
    STREAM_MAX_BUFFERED_ROWS=max(STREAM_MAX_BUFFERED_ROWS,len(ROWS)+len(WAIT_AGGREGATES))
    if not FLUSHING and len(ROWS)+len(WAIT_AGGREGATES)>=BUFFER_LIMIT_ROWS:
        flush(reason='buffer_limit')

def span(name,start,**fields):
    if ENABLED:record(name,'span',start_ns=start,end_ns=time.monotonic_ns(),**fields)

def mark():
    """Same-thread CPU excludes blocking time; wall spans include scheduling."""
    return (time.monotonic_ns(),time.thread_time_ns()) if ENABLED else (0,0)

def finish(name,started,**fields):
    if ENABLED:
        wall=time.monotonic_ns();cpu=time.thread_time_ns()
        # Preserve every actual wait result. Empty/non-child polls still run,
        # but their diagnostic records are bounded by role/attempt/result.
        # Totals are NOT a single wall span and must not enter interval unions.
        if name=='waitpid_poll' and (fields.get('waited_pid')==0 or fields.get('result')=='ECHILD'):
            result='ECHILD' if fields.get('result')=='ECHILD' else 'NO_READY_CHILD'
            key=(ROLE,NONCE,result);duration=wall-started[0];busy=cpu-started[1]
            value=WAIT_AGGREGATES.get(key)
            if value is None:
                value={'role':ROLE,'nonce':NONCE,'result':result,'count':0,
                       'total_wall_ns':0,'total_thread_cpu_ns':0,
                       'min_wall_ns':duration,'max_wall_ns':duration,
                       'first_observed_ns':started[0],'last_observed_ns':wall}
                WAIT_AGGREGATES[key]=value
            value['count']+=1;value['total_wall_ns']+=duration;value['total_thread_cpu_ns']+=busy
            value['min_wall_ns']=min(value['min_wall_ns'],duration);value['max_wall_ns']=max(value['max_wall_ns'],duration)
            value['last_observed_ns']=wall
            if not FLUSHING and len(ROWS)+len(WAIT_AGGREGATES)>=BUFFER_LIMIT_ROWS:
                flush(reason='aggregate_limit')
            return
        record(name,'span',start_ns=started[0],end_ns=wall,
               thread_cpu_ns=cpu-started[1],cpu_clock='CLOCK_THREAD_CPUTIME_ID',**fields)

def ipc(direction,obj,start,fd):
    if ENABLED:record(obj.get('op',obj.get('event','unknown')),direction,
                      nonce=obj.get('nonce',NONCE),message=obj.get('op',obj.get('event')),
                      start_ns=start,end_ns=time.monotonic_ns(),fd=fd)

def configure_bridge(lib):
    if hasattr(lib,'timing_enable'):
        lib.timing_enable.argtypes=[ctypes.c_int];lib.timing_enable(int(ENABLED))
        lib.timing_drain.argtypes=[ctypes.c_void_p,ctypes.c_size_t]

def drain_bridge(lib,prefix='timing',source='bridge'):
    symbol=prefix+'_drain'
    if not ENABLED or not hasattr(lib,symbol):return
    saved=ctypes.get_errno();started=mark()
    b=ctypes.create_string_buffer(65536)
    try:n=getattr(lib,symbol)(b,len(b))
    finally:ctypes.set_errno(saved)
    if n<0:raise RuntimeError('timing buffer export failed',n)
    if n:
        data=json.loads(b.raw[:n])
        if isinstance(data,dict):
            record('timing_export_header','measurement_metadata',source=source,
                   metadata={k:v for k,v in data.items() if k!='records'})
        for entry in data.get('records',[]) if isinstance(data,dict) else data:
            record(entry.pop('stage'),'c_span',source=source,**entry)
        if isinstance(data,dict) and (data.get('overflow') or data.get('dropped') or data.get('clock_errors')):
            raise RuntimeError('C timing export incomplete: '+repr({k:v for k,v in data.items() if k!='records'}))
    finish('timing_drain_overhead',started,source=source)

def usage(name):
    if not ENABLED:return
    a=resource.getrusage(resource.RUSAGE_SELF);b=resource.getrusage(resource.RUSAGE_CHILDREN)
    record(name,'resource',cpu_user_ns=round(a.ru_utime*1e9),cpu_system_ns=round(a.ru_stime*1e9),
           waited_children_user_ns=round(b.ru_utime*1e9),waited_children_system_ns=round(b.ru_stime*1e9),
           maxrss_kib=a.ru_maxrss,nvcsw=a.ru_nvcsw,nivcsw=a.ru_nivcsw)

def flush(reason='explicit'):
    global ROWS,WAIT_AGGREGATES,SEQ,FLUSHING,STREAM_FLUSHES,STREAM_UNCONFIRMED_RECORDS,STREAM_MAX_BUFFERED_ROWS
    if os.getpid()!=PID:context('descendant',NONCE)
    if FLUSHING:return
    if not ROWS and not WAIT_AGGREGATES:return
    FLUSHING=True
    started=(time.monotonic_ns(),time.thread_time_ns()) if ENABLED else None
    rows=ROWS;ROWS=[]
    values=list(WAIT_AGGREGATES.values());WAIT_AGGREGATES={}
    for value in values:
        # Do not call record() from flush(): that would recurse or re-buffer
        # measurements. Aggregate count/total is not one wall-clock interval.
        rows.append({'event':'COST','clock':'CLOCK_MONOTONIC','ns':time.monotonic_ns(),
            'session':SESSION,'variant':VARIANT,'diagnostics':DIAGNOSTICS,'role':ROLE,'pid':PID,'seq':SEQ,
            'nonce':NONCE,'repeat':REPEAT,'warmup':WARMUP,'kind':'aggregate','name':'waitpid_poll',
            'aggregation':'sum of disjoint individual calls; not a wall interval',
            'cpu_clock':'CLOCK_THREAD_CPUTIME_ID',**value})
        SEQ+=1
    STREAM_MAX_BUFFERED_ROWS=max(STREAM_MAX_BUFFERED_ROWS,len(rows))
    batch=b'';written=0;max_record_bytes=0
    def write(raw):
        nonlocal written
        while raw:
            n=os.write(1,raw)
            if n<=0:raise OSError('zero-progress diagnostic stdout write')
            written+=n;raw=raw[n:]
    try:
        for r in rows:
            raw=(json.dumps(r,separators=(',',':'))+'\n').encode()
            max_record_bytes=max(max_record_bytes,len(raw))
            if len(batch)+len(raw)>4096:write(batch);batch=b''
            batch+=raw
        if batch:write(batch)
        STREAM_FLUSHES+=1
        if ENABLED:
            # The metadata is written directly, never retained across requests.
            # Its own formatting/write is excluded from this local span but is
            # included in the measured full request/session latency.
            end=time.monotonic_ns();busy=time.thread_time_ns()-started[1]
            detail={'event':'COST','clock':'CLOCK_MONOTONIC','ns':end,
                'session':SESSION,'variant':VARIANT,'diagnostics':DIAGNOSTICS,'role':ROLE,'pid':PID,'seq':SEQ,
                'nonce':NONCE,'repeat':REPEAT,'warmup':WARMUP,'kind':'span','name':'diagnostic_stream_flush',
                'start_ns':started[0],'end_ns':end,'thread_cpu_ns':busy,'cpu_clock':'CLOCK_THREAD_CPUTIME_ID',
                'stream_mode':'bounded_stdout','reason':reason,'buffer_limit_rows':BUFFER_LIMIT_ROWS,
                'rows':len(rows),'aggregate_keys':len(values),'bytes':written,'max_record_bytes':max_record_bytes,
                'flush_count':STREAM_FLUSHES,'max_buffered_rows':STREAM_MAX_BUFFERED_ROWS,
                'unconfirmed_records':STREAM_UNCONFIRMED_RECORDS,
                'scope':'serialize/write buffered records; excludes this summary write; stdout backpressure stays charged'}
            SEQ+=1;write((json.dumps(detail,separators=(',',':'))+'\n').encode())
    except BaseException:
        # A partial write cannot safely be retried without duplicating records.
        # Invalidate observation instead of changing business/control semantics.
        STREAM_UNCONFIRMED_RECORDS+=len(rows)
        raise
    finally:
        FLUSHING=False

def exit(code):
    try:
        record('process_exit',exit_code=code);usage('process_exit_usage');flush()
    finally:os._exit(code)

def calibration():
    if not ENABLED:return
    values=[]
    for _ in range(1000):
        a=time.monotonic_ns();b=time.monotonic_ns();values.append(b-a)
    record('clock_pair_calibration','calibration',sample_count=len(values),min_ns=min(values),median_ns=sorted(values)[500],max_ns=max(values))

def memory(name,pid=None):
    if not ENABLED:return
    from pathlib import Path
    p=pid or os.getpid()
    try:
        data=Path('/proc/'+str(p)+'/smaps_rollup').read_text()
        fields={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in data.splitlines() if ':' in line}
        record(name,'memory',sampled_pid=p,values={k:fields.get(k) for k in ['Rss','Pss','Private_Clean','Private_Dirty','Shared_Clean','Shared_Dirty']})
    except OSError as e:record(name,'memory',sampled_pid=p,error=str(e))

# A failed diagnostic must never turn successful process creation into rejection,
# prevent the original exit, or change cleanup responsibility. Missing/error
# records invalidate timing admission; they do not grant business permission.
DIAGNOSTIC_ERRORS=0
def _best_effort(fn):
    def wrapped(*args,**kwargs):
        global DIAGNOSTIC_ERRORS
        try:return fn(*args,**kwargs)
        except Exception as e:
            DIAGNOSTIC_ERRORS+=1
            try:
                ROWS.append({'event':'COST','clock':'CLOCK_MONOTONIC','ns':time.monotonic_ns(),
                    'session':SESSION,'variant':VARIANT,'diagnostics':DIAGNOSTICS,'role':ROLE,'pid':os.getpid(),
                    'nonce':NONCE,'seq':-DIAGNOSTIC_ERRORS,'kind':'measurement_error',
                    'name':fn.__name__,'error':repr(e),'unconfirmed_records':STREAM_UNCONFIRMED_RECORDS})
                # Broken stdout may prevent export, but it must not grow a
                # permanent error buffer or change a lifecycle decision.
                if len(ROWS)+len(WAIT_AGGREGATES)>=BUFFER_LIMIT_ROWS and not FLUSHING:
                    try:_raw_flush(reason='measurement_error_limit')
                    except Exception:ROWS.clear();WAIT_AGGREGATES.clear()
            except Exception:pass
            return (0,0) if fn.__name__=='mark' else (0 if fn.__name__=='now' else None)
    return wrapped
_raw_flush=flush
for _n in ('context','now','record','span','mark','finish','ipc','configure_bridge','drain_bridge','usage','flush','memory','calibration'):
    globals()[_n]=_best_effort(globals()[_n])
