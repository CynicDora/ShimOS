#!/usr/bin/env python3
"""Offline analysis of explicitly enabled, mono-clock clone3 diagnostics.

Does not run a workload, change tracefs, or modify an input run. Syscall entry
to exit is an elapsed wall interval (including scheduling), not kernel CPU.
Only --out writes new analysis files. --self-test uses in-memory fixtures.
"""
import argparse
import collections
import csv
import errno
import hashlib
import io
import json
from pathlib import Path
import re
import statistics


EVENTS = ('sched/sched_process_fork', 'sched/sched_process_exec',
          'sched/sched_process_exit', 'syscalls/sys_enter_clone3',
          'syscalls/sys_exit_clone3')
LINE = re.compile(r'^\s*(.*?)\s+\[(\d+)\]\s+(?:\S+\s+)?(\d+\.\d+):\s+(.*)$')
TID = re.compile(r'-(\d+)(?:\s+\(\s*\d+\s*\))?\s*$')


def stamp_ns(value):
    whole, fraction = value.split('.')
    if len(fraction) > 9:
        raise ValueError('timestamp precision exceeds nanoseconds')
    return int(whole) * 10**9 + int(fraction.ljust(9, '0'))


def signed_ret(raw):
    raw = raw.strip()
    base = 16 if 'x' in raw.lower() or re.search('[a-f]', raw, re.I) else 10
    value = int(raw, base)
    if value >= 1 << 63:
        value -= 1 << 64
    return value


def parse_trace(text):
    events, unparsed, losses = [], [], []
    for number, line in enumerate(text.splitlines(), 1):
        if re.search(r'(?:LOST\s+\d+\s+EVENTS|\d+\s+EVENTS\s+LOST)', line, re.I):
            losses.append({'line': number, 'text': line})
        if line.startswith('#') or not line.strip():
            continue
        match = LINE.match(line)
        if not match:
            if 'clone3' in line or 'sched_process_' in line:
                unparsed.append({'line': number, 'text': line})
            continue
        task, cpu, stamp, tail = match.groups()
        tid = TID.search(task)
        if not tid:
            unparsed.append({'line': number, 'text': line})
            continue
        event = {'line': number, 'tid': int(tid[1]), 'cpu': int(cpu),
                 'ns': stamp_ns(stamp), 'resolution_ns': 10**(9-len(stamp.split('.')[1])),
                 'raw': tail}
        if 'sched_process_fork:' in tail:
            fields = re.search(r'\bpid=(\d+)\s+child_comm=.*?\s+child_pid=(\d+)', tail)
            if fields:
                event.update(kind='fork', parent=int(fields[1]), child=int(fields[2]))
        elif 'sched_process_exec:' in tail:
            fields = re.search(r'filename=(.*?)\s+pid=(\d+)\s+old_pid=(\d+)', tail)
            if fields:
                event.update(kind='exec', pid=int(fields[2]), old_pid=int(fields[3]), filename=fields[1])
        elif 'sched_process_exit:' in tail:
            fields = re.search(r'\bpid=(\d+)\b', tail)
            if fields:
                event.update(kind='exit', pid=int(fields[1]))
        elif 'sys_enter_clone3:' in tail or re.match(r'(?:syscalls:)?sys_clone3\(', tail):
            event.update(kind='clone_enter')
        elif 'sys_exit_clone3:' in tail or re.match(r'(?:syscalls:)?sys_clone3\s+->', tail):
            fields = re.search(r'(?:ret\s*[:=]|->)\s*(-?(?:0x)?[0-9a-fA-F]+)', tail)
            if fields:
                event.update(kind='clone_exit', ret=signed_ret(fields[1]), ret_raw=fields[1])
        if 'kind' in event:
            events.append(event)
        elif 'clone3' in tail or 'sched_process_' in tail:
            unparsed.append({'line': number, 'text': line})
    # Timestamp sorting handles cross-CPU interleaving; source line is a stable
    # tie-break at ftrace's display resolution, not a stronger causal claim.
    events.sort(key=lambda row: (row['ns'], row['line']))
    return events, unparsed, losses


def pair_calls(events):
    pending, calls, unmatched, child_returns = {}, [], [], []
    births = [row for row in events if row['kind'] == 'fork']
    for event in events:
        pid = event['tid']
        if event['kind'] == 'clone_enter':
            if pid in pending:
                unmatched.append({'kind': 'second_enter_before_exit', 'event': pending[pid]})
            pending[pid] = event
        elif event['kind'] == 'clone_exit':
            enter = pending.pop(pid, None)
            if enter:
                calls.append({'caller_host_tid': pid, 'enter': enter, 'exit': event,
                              'syscall_wall_ns': event['ns'] - enter['ns'], 'ret': event['ret'],
                              'errno': -event['ret'] if -4095 <= event['ret'] < 0 else None,
                              'errno_name': errno.errorcode.get(-event['ret']) if event['ret'] < 0 else None})
            elif event['ret'] == 0:
                # ret_from_fork may emit a child-side exit with no child-side
                # entry. It is NOT paired with the parent's entry for a cost.
                parents = [row for row in births if row['child'] == pid and row['ns'] <= event['ns']]
                child_returns.append({'event': event, 'birth': parents[-1] if parents else None})
            else:
                unmatched.append({'kind': 'exit_without_enter', 'event': event})
        elif event['kind'] == 'exit' and event['pid'] in pending:
            unmatched.append({'kind': 'caller_exited_inside_syscall', 'event': pending.pop(event['pid']),
                              'process_exit': event})
        elif event['kind'] == 'fork' and event['child'] in pending:
            unmatched.append({'kind': 'pid_reused_with_pending_enter', 'event': pending.pop(event['child']),
                              'new_birth': event})
    unmatched += [{'kind': 'enter_without_exit_at_trace_end', 'event': value} for value in pending.values()]
    return calls, unmatched, child_returns


def metadata(run, sources):
    def read(name):
        path = run / name
        if not path.exists():
            return None
        raw = path.read_bytes()
        sources[name] = hashlib.sha256(raw).hexdigest()
        return json.loads(raw)
    config = read('trace-config.json')
    stats = read('trace-stats.json')
    requested = bool(config and config.get('syscall_requested') is True)
    checks = []
    def check(name, passed, detail=None):
        checks.append({'name': name, 'passed': bool(passed), 'detail': detail})
    check('explicit COST_SYSCALL_TRACE=1 runtime record', requested)
    clock = config.get('trace_clock', '') if config else ''
    selected = re.search(r'\[([^]]+)\]', clock)
    selected = selected[1] if selected else clock.strip()
    check('trace clock readback is mono', selected == 'mono', clock)
    check('tracing enabled at runtime configuration snapshot',
          config and str(config.get('tracing_on', '')).strip() == '1')
    enabled = config.get('events', {}) if config else {}
    for event in EVENTS:
        value = enabled.get('events/' + event + '/enable')
        check(event + ' enabled readback', str(value).strip() == '1', value)
    check('per-CPU loss statistics present', isinstance(stats, dict) and bool(stats))
    for cpu, raw in (stats or {}).items():
        values = dict(re.findall(r'^(overrun|commit overrun|dropped events):\s*(\d+)\s*$', raw, re.M))
        check(cpu + ' loss counters complete and zero', len(values) == 3
              and all(int(value) == 0 for value in values.values()), values)
    return config, stats, checks, requested


def load_logs(run, sources):
    records, malformed, seen = [], [], set()
    for path in sorted(set(run.glob('*.log')) | set(run.glob('*.jsonl'))):
        raw = path.read_bytes()
        sources[path.name] = hashlib.sha256(raw).hexdigest()
        for line_no, line in enumerate(raw.decode(errors='replace').splitlines(), 1):
            pos = line.find('{')
            if pos < 0:
                continue
            try:
                data = json.loads(line[pos:])
            except ValueError:
                if '"ACTUAL_' in line or ('"COST"' in line and 'fork_' in line):
                    malformed.append({'file': path.name, 'line': line_no, 'text': line})
                continue
            if not isinstance(data, dict):
                continue
            if not (str(data.get('event', '')).startswith('ACTUAL_') or
                    data.get('event') in ('COST', 'ZYGOTE_READY', 'AB_RUNTIME_SNAPSHOT')):
                continue
            key = json.dumps(data, sort_keys=True, separators=(',', ':'))
            if key in seen:
                continue
            seen.add(key)
            data['_origin'] = {'file': path.name, 'line': line_no}
            records.append(data)
    return records, malformed


def describe(values):
    values = list(values)
    return {'n': len(values), 'median_ns': statistics.median(values) if values else None,
            'min_ns': min(values) if values else None, 'max_ns': max(values) if values else None}


def analyze(run):
    sources = {}
    config, stats, checks, requested = metadata(run, sources)
    result = {'run': str(run.resolve()), 'analysis_status': 'NOT_DIAGNOSTIC',
              'diagnostic_only': True, 'safety_qualification': 'NOT_EVALUATED',
              'metric': 'clone3 sys_enter to same-TID sys_exit elapsed wall time',
              'not_kernel_cpu': True, 'checks': checks, 'source_sha256': sources,
              'limitations': [
                  'Tracing perturbs execution; never pool with untraced response-ready samples.',
                  'clone3 wall time includes scheduling and is not CPU charged solely to the kernel.',
                  'Native callbacks/glibc work outside the syscall is outside this interval.',
                  'Wrapper-minus-syscall is an elapsed residual, not pure libc CPU.',
                  'Child-side return timestamps are separate observations, not another syscall duration.',
                  'Displayed ftrace timestamp precision limits boundary matching.',
                  'Process exit is not wait/reap or external side-effect completion.',
                  'A missing receipt remains missing; kernel events do not reconstruct business success.']}
    if not requested:
        result['reason'] = 'No explicit runtime syscall-trace opt-in; ordinary runs are excluded.'
        return result
    path = run / 'process-trace.txt'
    if not path.exists():
        checks.append({'name': 'process-trace present', 'passed': False})
        result['analysis_status'] = 'INCOMPLETE'
        return result
    raw = path.read_bytes(); sources[path.name] = hashlib.sha256(raw).hexdigest()
    text = raw.decode(errors='replace')
    events, unparsed, losses = parse_trace(text)
    calls, unmatched, child_returns = pair_calls(events)
    logs, malformed = load_logs(run, sources)
    checks += [{'name': 'recognized trace contains clone3 entry and exit',
                'passed': any(e['kind'] == 'clone_enter' for e in events)
                          and any(e['kind'] == 'clone_exit' for e in events)},
               {'name': 'no explicit LOST EVENTS markers', 'passed': not losses, 'detail': losses},
               {'name': 'all relevant trace lines parsed', 'passed': not unparsed, 'detail': unparsed},
               {'name': 'all relevant log records parsed', 'passed': not malformed, 'detail': malformed}]
    header = re.search(r'entries-in-buffer/entries-written:\s*(\d+)/(\d+)\s+#P:(\d+)', text)
    checks.append({'name': 'trace header complete and buffer equals written',
                   'passed': bool(header and header[1] == header[2]),
                   'detail': header.group(0) if header else None})
    checks.append({'name': 'statistics cover all header CPUs',
                   'passed': bool(header and isinstance(stats, dict) and len(stats) == int(header[3]))})
    births = [e for e in events if e['kind'] == 'fork']
    execs = [e for e in events if e['kind'] == 'exec']
    exits = [e for e in events if e['kind'] == 'exit']
    spans = [e for e in logs if e.get('event') == 'COST' and e.get('kind') == 'c_span'
             and e.get('name') == 'fork_vendor_call_parent' and e.get('clock') == 'CLOCK_MONOTONIC']
    z_pids = {e.get('identity', {}).get('pid') for e in logs if e.get('event') == 'ZYGOTE_READY'}
    z_pids |= {e.get('native', {}).get('pid') for e in logs
               if e.get('event') == 'AB_RUNTIME_SNAPSHOT' and e.get('stage') == 'Z_ready'}
    z_pids.discard(None)
    actual = [e for e in logs if e.get('event', '').startswith('ACTUAL_')]
    transitions = [e for e in actual if e['event'] == 'ACTUAL_TRANSITION_FORK']
    workers = [e for e in actual if e['event'] == 'ACTUAL_WORKER_FORK']
    role_births = []
    for receipt, field, role in [(e, 'pid', 'S') for e in transitions] + [(e, 'worker_host_pid', 'W') for e in workers]:
        options = [b for b in births if b['child'] == receipt.get(field)
                   and b['ns'] <= receipt.get('monotonic_ns', -1) + b['resolution_ns']]
        if role == 'S':
            options = [b for b in options if b['parent'] in z_pids]
        else:
            options = [b for b in options if b['parent'] == receipt.get('waiter_host_pid')]
        chosen = options[-1] if options else None
        check = {'name': f'{receipt.get("nonce")}:{receipt["event"]}:kernel fork corroboration',
                 'passed': chosen is not None, 'detail': {'receipt': receipt, 'birth': chosen}}
        checks.append(check)
        if chosen:
            role_births.append({'role': role, 'nonce': receipt.get('nonce'), 'birth': chosen,
                                'receipt': receipt})

    for call in calls:
        start, end, pid = call['enter']['ns'], call['exit']['ns'], call['caller_host_tid']
        tolerance = max(call['enter']['resolution_ns'], call['exit']['resolution_ns'])
        compatible = [s for s in spans if s.get('pid') == pid and s.get('clock_valid') is True
                      and s.get('start_ns', end+1) <= start+tolerance
                      and s.get('end_ns', start-1) >= end-tolerance
                      and ((s.get('ret') == call['ret']) or
                           (s.get('ret') == -1 and s.get('error') == call['errno']))]
        call.update(role='OTHER_OR_UNKNOWN', nonce=None, issues=[], wrapper=None)
        if len(compatible) == 1:
            span = compatible[0]
            call.update(role=span.get('role'), nonce=span.get('nonce'), wrapper=span,
                        wrapper_wall_ns=span['end_ns'] - span['start_ns'])
            call['wrapper_elapsed_residual_ns'] = call['wrapper_wall_ns'] - call['syscall_wall_ns']
        elif len(compatible) > 1:
            call['issues'].append('ambiguous wrapper interval match')
        else:
            # Fallback identity uses actual creation receipts plus kernel birth
            # epochs. Local W PID 2 is never promoted to a host PID.
            if pid in z_pids:
                call['role'] = 'Z'
            s_births = [b for b in role_births if b['role'] == 'S' and b['birth']['child'] == pid
                        and b['birth']['ns'] <= start]
            if s_births:
                owner = s_births[-1]
                later_birth = any(b['child'] == pid and owner['birth']['ns'] < b['ns'] <= start for b in births)
                dead = any(e['pid'] == pid and owner['birth']['ns'] <= e['ns'] < start for e in exits)
                if not later_birth and not dead:
                    call.update(role='S', nonce=owner['nonce'])
        fork_edges = [b for b in births if b['parent'] == pid and b['child'] == call['ret']
                      and start-tolerance <= b['ns'] <= end+tolerance] if call['ret'] > 0 else []
        call['fork_edges'] = fork_edges
        if call['ret'] > 0 and len(fork_edges) != 1:
            call['issues'].append('successful return lacks one same-interval kernel fork edge')
        created = fork_edges[0] if len(fork_edges) == 1 else None
        role_record = next((b for b in role_births if created and b['birth']['line'] == created['line']), None)
        if role_record:
            if call['nonce'] is not None and call['nonce'] != role_record['nonce']:
                call['issues'].append('nonce conflict between wrapper and ACTUAL creation')
            call['nonce'] = role_record['nonce']
            call['actual_creation'] = role_record['receipt']
            expected_role = 'Z' if role_record['role'] == 'S' else 'S'
            if call['role'] not in ('OTHER_OR_UNKNOWN', expected_role):
                call['issues'].append('role conflict between wrapper and process tree')
            call['role'] = expected_role
        if call['role'] in ('Z', 'S'):
            if call['nonce'] is None:
                call['issues'].append('no unambiguous attempt identity')
            if not compatible:
                call['issues'].append('no buffered wrapper boundary; syscall-only observation retained')
            if call['ret'] > 0 and not role_record:
                call['issues'].append('ACTUAL creation receipt missing; execution result remains unknown')
        if created:
            subsequent = [b['ns'] for b in births if b['child'] == created['child'] and b['ns'] > created['ns']]
            epoch_end = min(subsequent) if subsequent else 2**63
            dead = [e for e in exits if e['pid'] == created['child'] and created['ns'] <= e['ns'] < epoch_end]
            exec_end = dead[0]['ns'] if dead else epoch_end
            call['child_lifecycle'] = {'birth': created, 'exit': dead[0] if dead else None,
                'exec_events': [e for e in execs if e['pid'] == created['child']
                                and created['ns'] <= e['ns'] <= exec_end]}
            wait_event = 'ACTUAL_TRANSITION_WAIT' if call['role'] == 'Z' else 'ACTUAL_WORKER_WAIT'
            wait_field = 'pid' if call['role'] == 'Z' else 'worker_host_pid'
            waits = [e for e in actual if e['event'] == wait_event and e.get('nonce') == call['nonce']
                     and e.get(wait_field) == created['child']]
            call['actual_wait'] = waits
            if call['role'] in ('Z', 'S') and call['child_lifecycle']['exec_events']:
                call['issues'].append('exec observed on derived S/W process')
            if waits and dead and any(e.get('monotonic_ns', -1)+tolerance < dead[0]['ns'] for e in waits):
                call['issues'].append('ACTUAL wait precedes kernel exit beyond trace precision')
        if call['errno'] is not None and call['role'] in ('Z', 'S'):
            expected = 'ACTUAL_TRANSITION_CLONE_REJECTED' if call['role'] == 'Z' else 'ACTUAL_WORKER_CLONE_REJECTED'
            call['actual_rejection'] = [e for e in actual if e['event'] == expected
                                       and e.get('nonce') == call['nonce'] and e.get('errno') == call['errno']]
            if not call['actual_rejection']:
                call['issues'].append('kernel errno has no matching ACTUAL rejection receipt')

    relevant = [c for c in calls if c['role'] in ('Z', 'S')]
    checks.append({'name': 'at least one Z/S syscall attributed', 'passed': bool(relevant)})
    checks.append({'name': 'Z/S intervals have complete unambiguous evidence',
                   'passed': bool(relevant) and not any(c['issues'] for c in relevant)})
    checks.append({'name': 'no unpaired non-child syscall records', 'passed': not unmatched, 'detail': unmatched})
    checks.append({'name': 'child-only return records corroborated by fork',
                   'passed': all(c['birth'] is not None for c in child_returns)})
    result.update(analysis_status='COMPLETE' if all(c['passed'] for c in checks) else 'INCOMPLETE',
                  trace_config=config, event_counts=dict(collections.Counter(e['kind'] for e in events)),
                  process_events=[e for e in events if e['kind'] in ('fork', 'exec', 'exit')],
                  calls=calls, child_return_observations=child_returns, unmatched=unmatched,
                  known_zygote_host_pids=sorted(z_pids),
                  summaries={role: {'syscall_wall': describe(c['syscall_wall_ns'] for c in relevant if c['role'] == role),
                                    'errors': dict(collections.Counter(c['errno_name'] or 'success' for c in relevant if c['role'] == role))}
                             for role in ('Z', 'S')})
    # Incomplete traces retain raw numbers for diagnosis but are not admissible
    # evidence for a timing comparison; no failed/excluded row is discarded.
    result['timing_comparison_admitted'] = result['analysis_status'] == 'COMPLETE'
    return result


def self_test():
    text = '''# entries-in-buffer/entries-written: 9/9   #P:1
 python3-10 [000] ..... 1.000000: sys_clone3(uargs: 1234, size: 58)
 python3-10 [000] ..... 1.000100: sched_process_fork: comm=python3 pid=10 child_comm=python3 child_pid=11
 python3-11 [000] ..... 1.000110: sys_clone3 -> 0x0
 python3-10 [000] ..... 1.000200: sys_clone3 -> 0xb
 python3-11 [000] ..... 1.001000: sys_enter_clone3: uargs: 1234, size: 88
 python3-11 [000] ..... 1.001050: sys_exit_clone3: ret: 0xfffffffffffffff5
 python3-11 [000] ..... 1.002000: sched_process_exit: comm=python3 pid=11 prio=120
 python3-10 [000] ..... 1.003000: sched_process_exec: filename=/bin/python3 pid=10 old_pid=10
 python3-10 [000] ..... 1.004000: sched_process_exit: comm=python3 pid=10 prio=120
'''
    events, unknown, losses = parse_trace(text)
    calls, unmatched, children = pair_calls(events)
    assert not unknown and not losses and not unmatched
    assert len(calls) == 2 and calls[0]['syscall_wall_ns'] == 200000
    assert calls[1]['errno'] == errno.EAGAIN and calls[1]['syscall_wall_ns'] == 50000
    assert len(children) == 1 and children[0]['birth']['child'] == 11
    assert signed_ret('-11') == -11 and stamp_ns('12.000000001') == 12000000001
    broken = parse_trace(text.replace('sys_clone3 -> 0xb', 'unrelated_event: x'))[0]
    assert pair_calls(broken)[1]
    return {'self_test': 'PASS', 'fixture': 'synthetic parser tests, not VM/clone qualification'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs', nargs='*', type=Path)
    parser.add_argument('--out', type=Path, help='new analysis directory; never overwrite')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps(self_test(), ensure_ascii=False))
        return 0
    if not args.runs:
        parser.error('provide one or more independent syscall-diagnostic run directories')
    results = [analyze(run) for run in args.runs]
    report = {'diagnostic_only': True, 'runs': results}
    if args.out:
        args.out.mkdir(parents=True, exist_ok=False)
        (args.out / 'clone-trace-analysis.json').write_text(json.dumps(report, indent=2, ensure_ascii=False)+'\n')
        buf = io.StringIO()
        fields = ['run', 'analysis_status', 'nonce', 'role', 'caller_host_tid', 'enter_ns', 'exit_ns',
                  'syscall_wall_ns', 'ret', 'errno', 'errno_name', 'wrapper_wall_ns',
                  'wrapper_elapsed_residual_ns', 'issues']
        writer = csv.DictWriter(buf, fieldnames=fields); writer.writeheader()
        for result in results:
            for call in result.get('calls', []):
                row = {key: call.get(key) for key in fields}
                row.update(run=result['run'], analysis_status=result['analysis_status'],
                           enter_ns=call['enter']['ns'], exit_ns=call['exit']['ns'],
                           issues=json.dumps(call['issues'], ensure_ascii=False))
                writer.writerow(row)
        (args.out / 'clone-syscall-intervals.csv').write_text(buf.getvalue())
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if all(r['analysis_status'] == 'COMPLETE' for r in results) else 2


if __name__ == '__main__':
    raise SystemExit(main())
