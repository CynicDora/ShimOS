#!/usr/bin/env python3
"""Read-only same-guest diagnostic attribution; never runs an execution path.

Combines original bwrap's trace events, PID1 fields, and buffered C boundaries.
Trace elapsed time includes scheduling. Nothing here is pure kernel CPU.
Output directories are exclusive: a failed/incomplete result is not overwritten.
"""
import argparse
import collections
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import statistics

import analyze_clone_trace as clone

CALLS = ('clone3', 'clone', 'unshare', 'setns', 'mount', 'mount_setattr', 'execve', 'chroot')
CALL = '|'.join(sorted(CALLS, key=len, reverse=True))
ENTER = re.compile(r'^(?:syscalls:)?(?:sys_enter_(' + CALL + r'):\s*|sys_(' + CALL + r')\()')
EXIT = re.compile(r'^(?:syscalls:)?(?:sys_exit_(' + CALL + r'):\s*|sys_(' + CALL + r')\s*->)')


def parse_syscalls(text):
    events, malformed = [], []
    for line_no, line in enumerate(text.splitlines(), 1):
        match = clone.LINE.match(line)
        if not match:
            if any('sys_' + name in line or 'sys_enter_' + name in line or
                   'sys_exit_' + name in line for name in CALLS):
                malformed.append({'line': line_no, 'raw': line})
            continue
        task, cpu, stamp, tail = match.groups()
        entry, exit_ = ENTER.match(tail), EXIT.match(tail)
        if not entry and not exit_:
            continue
        tid = clone.TID.search(task)
        if not tid:
            malformed.append({'line': line_no, 'raw': line}); continue
        selected = entry or exit_
        row = dict(line=line_no, tid=int(tid[1]), cpu=int(cpu), ns=clone.stamp_ns(stamp),
                   resolution_ns=10 ** (9 - len(stamp.split('.')[1])),
                   name=selected[1] or selected[2], kind='enter' if entry else 'exit', raw=tail)
        if exit_:
            ret = re.search(r'(?:ret\s*[:=]|->)\s*(-?(?:0x)?[0-9a-fA-F]+)', tail)
            if not ret:
                malformed.append({'line': line_no, 'raw': line}); continue
            row['ret'] = clone.signed_ret(ret[1])
        events.append(row)
    return sorted(events, key=lambda r: (r['ns'], r['line'])), malformed


def pair_syscalls(events, processes):
    pending, calls, unmatched, special = {}, [], [], []
    births = [p for p in processes if p['kind'] == 'fork']
    execs = [p for p in processes if p['kind'] == 'exec']
    for row in events:
        key = (row['tid'], row['name'])
        if row['kind'] == 'enter':
            if key in pending:
                unmatched.append({'reason': 'enter_before_previous_exit', 'event': pending[key]})
            pending[key] = row
            continue
        first = pending.pop(key, None)
        if first:
            calls.append(dict(caller_host_tid=row['tid'], name=row['name'], enter=first, exit=row,
                              wall_ns=row['ns'] - first['ns'], ret=row['ret']))
        elif row['name'] in ('clone', 'clone3') and row['ret'] == 0:
            parents = [b for b in births if b['child'] == row['tid'] and b['ns'] <= row['ns']]
            special.append(dict(reason='child_return_without_child_enter', event=row,
                                corroborating_birth=parents[-1] if parents else None))
        else:
            unmatched.append({'reason': 'exit_without_enter', 'event': row})
    for first in pending.values():
        replacements = [e for e in execs if e['pid'] == first['tid'] and e['ns'] >= first['ns']]
        if first['name'] == 'execve' and replacements:
            # Successful exec may have no syscall-return event. Do not invent
            # a sys_exit timestamp: retain the distinct sched-exec boundary.
            special.append(dict(reason='exec_replacement_without_syscall_exit', event=first,
                                exec_event=replacements[0]))
        else:
            unmatched.append({'reason': 'enter_without_exit', 'event': first})
    return calls, unmatched, special


def union_length(intervals):
    total, end = 0, None
    for start, stop in sorted(intervals):
        if stop < start:
            raise ValueError('negative interval')
        if end is None or start > end:
            total += stop - start; end = stop
        elif stop > end:
            total += stop - end; end = stop
    return total


def stats(values):
    values = sorted(values)
    return dict(n=len(values), median_ns=statistics.median(values) if values else None,
                min_ns=min(values) if values else None, max_ns=max(values) if values else None)


def analyze(run):
    sources = {}
    config, trace_stats, checks, requested = clone.metadata(run, sources)
    result = dict(run=str(run.resolve()), diagnostic_only=True, safety_qualification='NOT_EVALUATED',
                  analysis_status='NOT_DIAGNOSTIC', source_sha256=sources, checks=checks,
                  limitations=[
                      'Traced samples are never pooled with ordinary latency samples.',
                      'All wall intervals include scheduling; syscall wall is not kernel CPU.',
                      'Explicit bwrap loader exec is not a second bwrap program exec event.',
                      'PID1 C main is later than the domain_init exec tracepoint.',
                      'Native callback groups contain only our registered probe callbacks.',
                      'Wrapper residual includes uninstrumented libc, clock reads and scheduling.',
                      'PID1 DRAINED lacks a timestamp after its own final send; that duration is N/A.',
                      'No record here substitutes for real wait or successful business result.'])
    if not requested:
        return result

    def check(name, value, detail=None):
        checks.append(dict(name=name, passed=bool(value), detail=detail))

    trace_file = run / 'process-trace.txt'
    if not trace_file.exists():
        check('trace file present', False); result['analysis_status'] = 'INCOMPLETE'; return result
    raw = trace_file.read_bytes(); sources[trace_file.name] = hashlib.sha256(raw).hexdigest()
    text = raw.decode(errors='replace')
    processes, _, lost = clone.parse_trace(text)
    processes = [e for e in processes if e['kind'] in ('fork', 'exec', 'exit')]
    events, malformed = parse_syscalls(text)
    calls, unmatched, special = pair_syscalls(events, processes)
    logs, malformed_logs = clone.load_logs(run, sources)
    check('generic syscall lines parsed', not malformed, malformed)
    check('relevant userspace logs parsed', not malformed_logs, malformed_logs)
    check('no LOST EVENTS marker', not lost, lost)
    header = re.search(r'entries-in-buffer/entries-written:\s*(\d+)/(\d+)\s+#P:(\d+)', text)
    check('trace header buffer equals written', header and header[1] == header[2], header.group(0) if header else None)
    check('loss statistics cover all CPUs', header and len(trace_stats or {}) == int(header[3]))
    enabled = config.get('events', {})
    for name in CALLS:
        for edge in ('enter', 'exit'):
            key = 'events/syscalls/sys_' + edge + '_' + name + '/enable'
            check(key + ' readback', str(enabled.get(key, '')).strip() == '1', enabled.get(key))
    check('child-only returns have birth evidence', all(s.get('corroborating_birth')
          for s in special if s['reason'] == 'child_return_without_child_enter'))

    attempts = []
    for path in sorted(run.glob('*.json')):
        if not re.match(r'^\d+-[^/]+\.json$', path.name):
            continue
        data = json.loads(path.read_text())
        if isinstance(data, dict) and data.get('nonce') and data.get('monitor_pid'):
            sources[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
            attempts.append(data)
    supervisor = json.loads((run / 'supervisor.json').read_text()) if (run / 'supervisor.json').exists() else {}
    if supervisor:
        sources['supervisor.json'] = hashlib.sha256((run / 'supervisor.json').read_bytes()).hexdigest()
    controller = supervisor.get('controller_pid')
    births = [e for e in processes if e['kind'] == 'fork']
    execs = [e for e in processes if e['kind'] == 'exec']
    cost = [r for r in logs if r.get('event') == 'COST']
    denied_observations, unexplained = [], []
    for item in unmatched:
        event = item['event']
        required = {'setns': 'setns_denied', 'unshare': 'unshare_denied', 'execve': 'exec_denied'}
        matches = []
        if item['reason'] == 'exit_without_enter' and event['name'] in required and event.get('ret') == -1:
            for attempt in attempts:
                worker = attempt.get('worker') or {}
                begin = [r['ns'] for r in cost if r.get('nonce') == attempt['nonce']
                         and r.get('role') == 'W' and r.get('name') == 'business_enter']
                end = [r['ns'] for r in cost if r.get('nonce') == attempt['nonce']
                       and r.get('role') == 'W' and r.get('name') == 'business_end']
                permissions = worker.get('identity', {}).get('status', {})
                if (event['tid'] == attempt.get('w_pid') and len(begin) == len(end) == 1
                    and begin[0] <= event['ns'] + event['resolution_ns'] <= end[0] + event['resolution_ns']
                    and worker.get('checks', {}).get(required[event['name']]) is True
                    and permissions.get('NoNewPrivs') == '1' and permissions.get('Seccomp') == '2'
                    and int(permissions.get('CapEff', '-1'), 16) == 0):
                    matches.append(attempt['nonce'])
        if len(matches) == 1:
            denied_observations.append(dict(item, nonce=matches[0], classification='corroborated denied business probe; exit only',
                elapsed_ns=None, syscall_entry_observed=False,
                evidence='same host W PID, business interval, EPERM return, corresponding denial assertion, NNP/seccomp/cap snapshot',
                inference='Consistent with the fixed seccomp deny rule preceding syscall-entry tracing; no entry timestamp is reconstructed.'))
        else:
            unexplained.append(item)
    check('unpaired exits either explicitly corroborated denied probes or absent', not unexplained, unexplained)
    domains = []
    for attempt in attempts:
        nonce, monitor, pid1 = attempt['nonce'], attempt['monitor_pid'], attempt['init_pid']
        timeline = {'nonce': nonce, 'controller_host_pid': controller, 'monitor_host_pid': monitor,
                    'pid1_host_pid': pid1, 'case': attempt['case'], 'points': {}, 'intervals': {}, 'issues': []}
        points = timeline['points']
        for name in ('request_begin', 'domain_build_begin', 'bwrap_spawn_begin',
                     'bwrap_spawn_return', 'domain_fd_received', 'domain_ready', 'domain_quiescent'):
            matches = [e for e in cost if e.get('nonce') == nonce and e.get('role') == 'R' and e.get('name') == name]
            if len(matches) == 1:
                points['R_' + name] = matches[0]['ns']
            else:
                timeline['issues'].append(name + ': missing or duplicate R point')
        for name, matches in (
                ('monitor_birth', [e for e in births if e['child'] == monitor and e['parent'] == controller]),
                ('bwrap_loader_exec', [e for e in execs if e['pid'] == monitor and e['filename'].startswith('/assets/bwrap/')]),
                ('pid1_birth', [e for e in births if e['child'] == pid1 and e['parent'] == monitor]),
                ('domain_init_exec', [e for e in execs if e['pid'] == pid1 and e['filename'] == '/probe/domain_init'])):
            if len(matches) == 1:
                points[name] = matches[0]['ns']
                timeline[name + '_record'] = matches[0]
            else:
                timeline['issues'].append(name + ': not unique')
        pid1_record = attempt.get('domain_ready_record', {}).get('timing', {})
        drained = attempt.get('drained', {}).get('timing', {})
        timeline['pid1_setup_observation'] = pid1_record
        timeline['pid1_drain_observation'] = drained
        for name, value in pid1_record.items():
            if name.endswith('_ns'):
                points['PID1_' + name] = value
        for name in ('ready_send_begin_ns', 'ready_send_end_ns', 'exports_closed_ns', 'stop_received_ns', 'drained_record_ns'):
            if name in drained:
                points['PID1_' + name] = drained[name]
        check(nonce + ': PID1 clock metadata valid', pid1_record.get('clock') == 'CLOCK_MONOTONIC'
              and attempt.get('domain_ready_record', {}).get('timing_error') == 0
              and drained.get('clock_errors') == 0)
        boundaries = [
            ('domain_build_to_received', 'R_domain_build_begin', 'R_domain_fd_received'),
            ('spawn_call', 'R_bwrap_spawn_begin', 'R_bwrap_spawn_return'),
            ('monitor_birth_to_loader_exec', 'monitor_birth', 'bwrap_loader_exec'),
            ('loader_exec_to_pid1_birth', 'bwrap_loader_exec', 'pid1_birth'),
            ('pid1_birth_to_domain_init_exec', 'pid1_birth', 'domain_init_exec'),
            ('domain_init_exec_to_C_main', 'domain_init_exec', 'PID1_entry_ns'),
            ('pid1_policy', 'PID1_policy_begin_ns', 'PID1_policy_end_ns'),
            ('pid1_export_objects', 'PID1_export_begin_ns', 'PID1_export_end_ns'),
            ('pid1_marker', 'PID1_marker_begin_ns', 'PID1_marker_end_ns'),
            ('pid1_local_setup', 'PID1_entry_ns', 'PID1_ready_ns'),
            ('pid1_ready_sendmsg', 'PID1_ready_send_begin_ns', 'PID1_ready_send_end_ns'),
            ('pid1_ready_send_begin_to_R_receive', 'PID1_ready_send_begin_ns', 'R_domain_fd_received'),
            ('R_reference_validation', 'R_domain_fd_received', 'R_domain_ready'),
            ('pid1_stop_to_drained_record', 'PID1_stop_received_ns', 'PID1_drained_record_ns')]
        for name, first, last in boundaries:
            if first in points and last in points and points[first] > 0 and points[last] >= points[first]:
                timeline['intervals'][name] = dict(start_ns=points[first], end_ns=points[last],
                                                  wall_ns=points[last] - points[first])
            else:
                timeline['issues'].append(name + ': missing/negative boundary')
        timeline['setup_syscalls'] = []
        for call in calls:
            start, end, tid = call['enter']['ns'], call['exit']['ns'], call['caller_host_tid']
            if tid in (monitor, pid1) and points.get('monitor_birth', 2**63) <= start <= points.get('PID1_entry_ns', -1):
                item = dict(call, role='BWRAP_MONITOR' if tid == monitor else 'BWRAP_PID1_SETUP', nonce=nonce)
                timeline['setup_syscalls'].append(item)
        timeline['syscall_summaries'] = []
        grouped = collections.defaultdict(list)
        for call in timeline['setup_syscalls']:
            grouped[(call['role'], call['name'])].append(call)
        for (role, name), group in sorted(grouped.items()):
            timeline['syscall_summaries'].append(dict(role=role, name=name, calls=len(group),
                wall=stats(c['wall_ns'] for c in group),
                elapsed_union_ns=union_length((c['enter']['ns'], c['exit']['ns']) for c in group),
                returns=dict(collections.Counter(str(c['ret']) for c in group))))
        check(nonce + ': domain timeline complete', not timeline['issues'], timeline['issues'])
        domains.append(timeline)

    clone_result = clone.analyze(run)
    check('independent clone3 diagnostic admission', clone_result.get('analysis_status') == 'COMPLETE',
          clone_result.get('analysis_status'))
    transition_details = []
    namespace_masks = {'enter_base_userns': 0x10000000, 'enter_inner_userns': 0x10000000,
                       'enter_mountns': 0x20000, 'enter_networkns': 0x40000000,
                       'enter_ipcns': 0x08000000, 'enter_utsns': 0x04000000,
                       'enter_pidns_for_children': 0x20000000}
    for attempt in attempts:
        nonce, host_tid = attempt['nonce'], attempt.get('s_pid')
        spans = [r for r in cost if r.get('kind') == 'c_span' and r.get('role') == 'S'
                 and r.get('nonce') == nonce and r.get('pid') == host_tid
                 and str(r.get('name', '')).startswith('enter_')]
        for span in spans:
            name = span['name']
            syscall = 'chroot' if name == 'enter_root_chroot' else ('setns' if 'userns' in name
                or name in ('enter_mountns', 'enter_networkns', 'enter_ipcns', 'enter_utsns', 'enter_pidns_for_children') else None)
            row = dict(nonce=nonce, caller_host_tid=host_tid, stage=name,
                       c_wall_ns=span['end_ns'] - span['start_ns'], c_span=span,
                       syscall_name=syscall, syscall_observation='N/A: syscall not selected in diagnostic trace')
            if syscall:
                matches = [c for c in calls if c['caller_host_tid'] == host_tid and c['name'] == syscall
                    and span['start_ns'] <= c['enter']['ns'] + c['enter']['resolution_ns']
                    and span['end_ns'] >= c['exit']['ns'] - c['exit']['resolution_ns']]
                if syscall == 'setns':
                    matches = [c for c in matches if (m := re.search(r'flags:\s*(0x[0-9a-fA-F]+|[0-9]+)', c['enter']['raw']))
                               and int(m[1], 0) == namespace_masks[name]]
                check(nonce + ':' + name + ': exact syscall match', len(matches) == 1)
                if len(matches) == 1:
                    row.update(syscall_observation='one same-TID interval', syscall=matches[0],
                               syscall_wall_ns=matches[0]['wall_ns'],
                               elapsed_residual_ns=row['c_wall_ns'] - matches[0]['wall_ns'],
                               ftrace_resolution_ns=max(matches[0]['enter']['resolution_ns'], matches[0]['exit']['resolution_ns']),
                               below_trace_resolution=matches[0]['wall_ns'] < max(matches[0]['enter']['resolution_ns'], matches[0]['exit']['resolution_ns']))
            transition_details.append(row)
    fork_details = []
    for call in clone_result.get('calls', []):
        if call.get('role') not in ('Z', 'S'):
            continue
        wrapper = call.get('wrapper')
        detail = {k: call.get(k) for k in ('role', 'nonce', 'caller_host_tid', 'ret', 'errno', 'syscall_wall_ns', 'issues')}
        detail['native_parent_groups'] = []
        if wrapper:
            begin, end = wrapper['start_ns'], wrapper['end_ns']
            detail.update(wrapper_wall_ns=end - begin,
                          wrapper_start_ns=begin, wrapper_end_ns=end,
                          syscall_start_ns=call['enter']['ns'], syscall_end_ns=call['exit']['ns'])
            pieces = [(call['enter']['ns'], call['exit']['ns'])]
            for name in ('native_prepare_group', 'native_parent_group'):
                choices = [r for r in cost if r.get('kind') == 'c_span' and r.get('name') == name
                           and r.get('nonce') == call['nonce'] and r.get('role') == call['role']
                           and r.get('pid') == call['caller_host_tid'] and r.get('clock_valid') is True
                           and begin <= r.get('start_ns', -1) <= r.get('end_ns', 2**63) <= end]
                check(str(call['nonce']) + ':' + str(call['role']) + ':' + name + ' one matching group', len(choices) == 1)
                if len(choices) == 1:
                    selected = choices[0]; detail['native_parent_groups'].append(selected)
                    pieces.append((selected['start_ns'], selected['end_ns']))
            detail['observed_union_in_wrapper_ns'] = union_length(pieces)
            detail['unattributed_wrapper_elapsed_residual_ns'] = end - begin - union_length(pieces)
            check(str(call['nonce']) + ':' + str(call['role']) + ': wrapper residual nonnegative',
                  detail['unattributed_wrapper_elapsed_residual_ns'] >= 0)
        child_role = 'S' if call['role'] == 'Z' else 'W'
        first = [r for r in cost if r.get('kind') == 'c_span' and r.get('name') == 'native_child_first_callback'
                 and r.get('nonce') == call['nonce'] and r.get('role') == child_role]
        birth = (call.get('child_lifecycle') or {}).get('birth')
        if len(first) == 1 and birth:
            detail['child_first_callback'] = first[0]
            detail['kernel_birth_to_first_callback_ns'] = first[0]['start_ns'] - birth['ns']
        else:
            detail['child_first_callback'] = None
        detail['child_native_groups'] = [r for r in cost if r.get('kind') == 'c_span'
            and r.get('name') == 'native_child_group' and r.get('nonce') == call['nonce']
            and r.get('role') == child_role]
        fork_details.append(detail)
    check('at least one domain and two relevant fork calls', bool(domains) and len(fork_details) >= 2)
    result.update(analysis_status='COMPLETE' if all(c['passed'] for c in checks) else 'INCOMPLETE',
                  domains=domains, fork_details=fork_details, transition_details=transition_details, syscall_calls=calls,
                  syscall_unmatched_raw=unmatched, syscall_unmatched_unexplained=unexplained,
                  syscall_denied_exit_only=denied_observations, syscall_nonreturn_observations=special,
                  event_counts=dict(collections.Counter(r['name'] + ':' + r['kind'] for r in events)))
    result['timing_attribution_admitted'] = result['analysis_status'] == 'COMPLETE'
    return result


def self_test():
    text = '''# entries-in-buffer/entries-written: 8/8 #P:1
 p-10 [000] ..... 1.000000: sys_mount(dev_name: 1, dir_name: 2)
 p-10 [000] ..... 1.000300: sys_mount -> 0x0
 p-10 [000] ..... 1.001000: sys_enter_clone3: uargs: 1, size: 58
 p-10 [000] ..... 1.001010: sched_process_fork: comm=p pid=10 child_comm=p child_pid=11
 p-11 [000] ..... 1.001020: sys_exit_clone3: ret: 0x0
 p-10 [000] ..... 1.001100: sys_exit_clone3: ret: 0xb
 p-11 [000] ..... 1.002000: sys_execve(filename: 2, argv: 3)
 p-11 [000] ..... 1.003000: sched_process_exec: filename=/probe/domain_init pid=11 old_pid=11
'''
    events, malformed = parse_syscalls(text)
    processes, _, _ = clone.parse_trace(text)
    calls, unmatched, special = pair_syscalls(events, processes)
    assert not malformed and not unmatched and len(calls) == 2
    assert calls[0]['wall_ns'] == 300000 and calls[1]['ret'] == 11
    assert {s['reason'] for s in special} == {'child_return_without_child_enter', 'exec_replacement_without_syscall_exit'}
    assert union_length([(1, 4), (2, 7), (9, 10)]) == 7
    return {'self_test': 'PASS', 'scope': 'synthetic parser fixtures; not VM qualification'}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('runs', nargs='*', type=Path)
    ap.add_argument('--out', type=Path)
    ap.add_argument('--self-test', action='store_true')
    args = ap.parse_args()
    if args.self_test:
        print(json.dumps(self_test())); return 0
    if not args.runs or not args.out:
        ap.error('provide diagnostic run(s) and a new --out directory')
    results = [analyze(run) for run in args.runs]
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / 'namespace-trace-analysis.json').write_text(json.dumps({'runs': results}, ensure_ascii=False, indent=2) + '\n')
    flat = []
    for result in results:
        for domain in result.get('domains', []):
            for name, interval in domain['intervals'].items():
                flat.append(dict(run=result['run'], status=result['analysis_status'], nonce=domain['nonce'],
                                 group='domain', name=name, wall_ns=interval['wall_ns']))
        for fork in result.get('fork_details', []):
            for key in ('syscall_wall_ns', 'wrapper_wall_ns', 'unattributed_wrapper_elapsed_residual_ns',
                        'kernel_birth_to_first_callback_ns'):
                flat.append(dict(run=result['run'], status=result['analysis_status'], nonce=fork['nonce'],
                                 group='fork-' + fork['role'], name=key, wall_ns=fork.get(key)))
        for transition in result.get('transition_details', []):
            for key in ('c_wall_ns', 'syscall_wall_ns', 'elapsed_residual_ns'):
                flat.append(dict(run=result['run'], status=result['analysis_status'], nonce=transition['nonce'],
                    group='transition-' + transition['stage'], name=key, wall_ns=transition.get(key)))
    with (args.out / 'mechanism-intervals.csv').open('w') as stream:
        writer = csv.DictWriter(stream, fieldnames=['run', 'status', 'nonce', 'group', 'name', 'wall_ns'])
        writer.writeheader(); writer.writerows(flat)
    print(json.dumps([dict(run=r['run'], status=r['analysis_status'], checks=len(r['checks']),
                           failed=[c['name'] for c in r['checks'] if not c['passed']]) for r in results], ensure_ascii=False))
    return 0 if all(r['analysis_status'] == 'COMPLETE' for r in results) else 2


if __name__ == '__main__':
    raise SystemExit(main())
