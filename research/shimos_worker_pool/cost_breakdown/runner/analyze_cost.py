#!/usr/bin/env python3
"""Offline COST event analysis. Never launches a process or changes a run.

JSONL may be interleaved with ordinary logs. Logs can be flushed after a role
exits: timestamps, not file order, define the measured intervals. Raw input and
all excluded/incomplete attempts remain in the report.
"""
import argparse
import collections
import csv
import hashlib
import io
import json
import math
from pathlib import Path
import statistics


CLOCK = 'CLOCK_MONOTONIC'
# Adjacent boundaries partition one request. Missing boundaries create unknown
# cost, never an invented interval attributed to the next available stage.
STAGES = [
    ('setup_to_domain_ready', 'request_begin', 'domain_ready'),
    ('cleanup_owner_registration', 'domain_ready', 'registered'),
    ('zygote_preparation', 'registered', 'prepared'),
    ('first_fork_and_namespace_entry', 'prepared', 'entered'),
    ('second_fork_and_worker_gate', 'entered', 'worker_gated'),
    ('business_authorization_delivery', 'worker_gated', 'business_enter'),
    ('business_parent_execution', 'business_enter', 'business_end'),
    ('descendants_output_domain_quiescence', 'business_end', 'domain_quiescent'),
    ('forget_wait', 'domain_quiescent', 'forget_done'),
    ('fd_directory_cgroup_release', 'forget_done', 'resources_deleted'),
    ('validation_and_template_check', 'resources_deleted', 'validation_done'),
    ('retirement_and_response', 'validation_done', 'response_ready'),
]
BOUNDARIES = tuple(dict.fromkeys(k for _, a, b in STAGES for k in (a, b)))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def percentile(values, fraction):
    """Linear interpolation, Hyndman/Fan type 7; not a production tail claim."""
    data = sorted(values)
    if not data:
        return None
    index = (len(data) - 1) * fraction
    lo = math.floor(index)
    hi = math.ceil(index)
    return data[lo] + (data[hi] - data[lo]) * (index - lo)


def describe(values):
    data = list(values)
    return dict(n=len(data), median=statistics.median(data) if data else None,
                p90=percentile(data, .9), minimum=min(data) if data else None,
                maximum=max(data) if data else None)


def union_ns(intervals):
    end = None
    total = 0
    for left, right in sorted(intervals):
        if end is None or left >= end:
            total += right - left
            end = right
        elif right > end:
            total += right - end
            end = right
    return total


def payload(event):
    return event.get('payload') if isinstance(event.get('payload'), dict) else {}


def value(event, key, default=None):
    return event.get(key, payload(event).get(key, default))


def collect(run):
    events, duplicates, malformed, sources = [], [], [], []
    seen = {}
    paths = sorted(set(list(run.glob('*.jsonl')) + list(run.glob('*.log'))
                       + list((run / 'logs').glob('*.jsonl'))
                       + list((run / 'logs').glob('*.log'))))
    for file in paths:
        raw = file.read_bytes()
        sources.append(dict(path=str(file.relative_to(run)), bytes=len(raw),
                            sha256=hashlib.sha256(raw).hexdigest()))
        for number, line in enumerate(raw.decode('utf-8', errors='replace').splitlines(), 1):
            # VM console may prefix a JSON record; do not parse arbitrary code.
            pos = line.find('{')
            if pos < 0:
                continue
            try:
                record = json.loads(line[pos:])
            except ValueError:
                if '"COST"' in line:
                    malformed.append(dict(file=str(file.relative_to(run)), line=number,
                                          reason='COST-like line is not complete JSON'))
                continue
            if not isinstance(record, dict) or record.get('event') != 'COST':
                continue
            origin = dict(file=str(file.relative_to(run)), line=number)
            digest = hashlib.sha256(canonical(record).encode()).hexdigest()
            if digest in seen:
                duplicates.append(dict(origin=origin, original=seen[digest],
                                       identity='identical serialized event', digest=digest))
                continue
            seen[digest] = origin
            record['_origin'] = origin
            events.append(record)
    return events, duplicates, malformed, sources


def records(run):
    """Read Controller receipts and H fallback separately from timing logs."""
    attempts = {}
    # Completed receipts override in-flight journals for the same nonce.
    for pattern in ('attempt-*.json', '[0-9]*-*.json'):
        for file in sorted(run.glob(pattern)):
            try:
                record = json.loads(file.read_text())
            except (ValueError, OSError):
                continue
            if isinstance(record, dict) and record.get('nonce'):
                attempts[record['nonce']] = dict(record, _receipt=file.name)
    supervisor = run / 'supervisor.json'
    if supervisor.exists():
        data = json.loads(supervisor.read_text())
        for record in data.get('attempts', []):
            nonce = record.get('nonce')
            if not nonce:
                continue
            current = attempts.setdefault(nonce, {'nonce': nonce})
            current['_supervisor'] = record
            current['_supervisor_release'] = data.get('release_state')
    return attempts


def read_metadata(run):
    result = {}
    for name in ('cost-config.json', 'review-config.json', 'environment.json'):
        file = run / name
        if file.exists():
            try:
                result[name] = json.loads(file.read_text())
            except ValueError:
                result[name] = {'parse_error': True}
    return result


def metric_summary(rows, key):
    return describe(r[key] for r in rows if isinstance(r.get(key), (int, float)))


def duration_between(events, left, right, role=None):
    def matches(name):
        return [e for e in events if e.get('kind') == 'phase' and e.get('name') == name
                and (role is None or e.get('role') == role)]
    a, b = matches(left), matches(right)
    if len(a) == len(b) == 1 and b[0]['ns'] >= a[0]['ns']:
        return (b[0]['ns'] - a[0]['ns']) / 1e6
    return None


def resource_delta(events, start_name, finish_name, role):
    a = [e for e in events if e.get('kind') == 'resource' and e.get('name') == start_name and e.get('role') == role]
    b = [e for e in events if e.get('kind') == 'resource' and e.get('name') == finish_name and e.get('role') == role]
    if len(a) != 1 or len(b) != 1 or b[0]['ns'] < a[0]['ns']:
        return None
    fields = ('cpu_user_ns', 'cpu_system_ns', 'waited_children_user_ns',
              'waited_children_system_ns', 'nvcsw', 'nivcsw')
    delta = {k: b[0][k] - a[0][k] for k in fields
             if isinstance(a[0].get(k), int) and isinstance(b[0].get(k), int)}
    return dict(start_ns=a[0]['ns'], end_ns=b[0]['ns'], counters=delta,
                nonnegative=all(v >= 0 for v in delta.values()),
                note='self and waited-child CPU are separate; maxrss is a lifetime peak, not a delta')


def request_metric(row, metric):
    if metric == 'controller_self_cpu_ms':
        counters = (row.get('controller_cpu_delta') or {}).get('counters', {})
        if 'cpu_user_ns' in counters and 'cpu_system_ns' in counters:
            return (counters['cpu_user_ns'] + counters['cpu_system_ns']) / 1e6
        return None
    if metric == 'task_cgroup_cpu_ms':
        raw = (row.get('cgroup_receipt_stats') or {}).get('task', {}).get('cpu.stat', '')
        for line in raw.splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[0] == 'usage_usec':
                try:
                    return int(fields[1]) / 1000
                except ValueError:
                    return None
        return None
    if metric in ('controller_non_query_messages', 'query_snapshot_messages'):
        if row.get('controller_boundary_message_count') is None:
            return None
        counts = row.get('controller_boundary_messages', {})
        queries = counts.get('send:QUERY', 0) + counts.get('recv:SNAPSHOT', 0)
        return queries if metric == 'query_snapshot_messages' else row.get('controller_boundary_message_count', 0) - queries
    return row.get(metric)


def compare_pairs(rows, mapping):
    """Explicit same-VM session pairs; never infer hardware identity from names.

    A matched repeat is diagnostic, not simultaneous execution. Confidence
    intervals that treat serial requests as independent VMs are not computed.
    """
    pairs = mapping.get('pairs', []) if isinstance(mapping, dict) else mapping
    if not isinstance(pairs, list):
        raise ValueError('pair map must be a list or contain a pairs list')
    by_session = collections.defaultdict(list)
    for row in rows:
        by_session[row['session']].append(row)
    metrics = ('response_ready_ms', 'controller_self_cpu_ms', 'task_cgroup_cpu_ms',
               'controller_boundary_message_count', 'controller_non_query_messages', 'query_snapshot_messages')
    result = []
    used = set()
    for pair in pairs:
        names = [pair.get('baseline_session'), pair.get('candidate_session')]
        problems = []
        if any(not name or name not in by_session for name in names):
            problems.append('pair names missing or absent from input sessions')
        if names[0] == names[1]:
            problems.append('baseline and candidate refer to the same session')
        if any(name in used for name in names):
            problems.append('a session is assigned to more than one VM pair')
        used.update(name for name in names if name)
        selected = []
        details = []
        for name in names:
            all_measured = [r for r in by_session.get(name, []) if r['sample_class'] == 'measured']
            good = [r for r in all_measured if r['timing_eligible']]
            if len(good) != len(all_measured) or not good:
                problems.append('session has missing or excluded measured requests: ' + str(name))
            if any(r.get('measurement_mode') != 'untraced' for r in good):
                problems.append('pair contains traced or unknown-trace measurements')
            selected.append(good)
            details.append(dict(session=name, measured=len(all_measured), eligible=len(good),
                                excluded=[dict(nonce=r['nonce'], problems=r['problems']) for r in all_measured if not r['timing_eligible']],
                                metrics={k: describe(request_metric(r,k) for r in good if request_metric(r,k) is not None) for k in metrics}))
        baseline, candidate = selected
        declared_vm_ids = {r.get('same_vm_pair') for group in selected for r in group if r.get('same_vm_pair') is not None}
        if len(declared_vm_ids) > 1:
            problems.append('input run metadata assigns the sessions to different VMs')
        if declared_vm_ids and pair.get('pair_id') not in declared_vm_ids:
            problems.append('pair_id differs from recorded same_vm_pair metadata')
        if {r['case'] for r in baseline} != {r['case'] for r in candidate}:
            problems.append('paired sessions contain different workload cases')
        for side, group in zip(('baseline', 'candidate'), selected):
            expected_variant = pair.get(side + '_variant')
            if expected_variant is not None and any(r['variant'] != expected_variant for r in group):
                problems.append('session variant differs from explicit pair map: ' + side)
        repeats = []
        for group in selected:
            table = collections.defaultdict(list)
            for row in group:
                table[row.get('repeat')].append(row)
            if None in table or any(len(v) != 1 for v in table.values()):
                problems.append('missing or nonunique measured repeat ID')
            repeats.append(table)
        matched = sorted(set(repeats[0]) & set(repeats[1]), key=str)
        matched_rows = []
        for repeat in matched:
            a, b = repeats[0][repeat], repeats[1][repeat]
            if repeat is None or len(a) != 1 or len(b) != 1:
                continue
            differences = {}
            for metric in metrics:
                av, bv = request_metric(a[0], metric), request_metric(b[0], metric)
                if av is not None and bv is not None:
                    differences[metric] = av - bv
            matched_rows.append(dict(repeat=repeat, baseline_nonce=a[0]['nonce'], candidate_nonce=b[0]['nonce'], baseline_minus_candidate=differences))
        if set(repeats[0]) != set(repeats[1]):
            problems.append('measured repeat IDs differ between paired sessions')
        differences = {}
        for metric in metrics:
            a, b = [side['metrics'][metric] for side in details]
            vals = [r['baseline_minus_candidate'][metric] for r in matched_rows if metric in r['baseline_minus_candidate']]
            differences[metric] = dict(
                difference_of_session_medians=a['median']-b['median'] if a['median'] is not None and b['median'] is not None else None,
                difference_of_session_p90s=a['p90']-b['p90'] if a['p90'] is not None and b['p90'] is not None else None,
                matched_repeat_diagnostic=describe(vals),
                matched_repeat_positive=sum(v > 0 for v in vals), matched_repeat_negative=sum(v < 0 for v in vals))
        result.append(dict(pair_id=pair.get('pair_id'), declared_pair=pair, sessions=details,
                           recorded_same_vm_pair=sorted(declared_vm_ids, key=str),
                           recorded_session_orders={name:sorted({r.get('session_order') for r in by_session.get(name,[]) if r.get('session_order') is not None}) for name in names},
                           differences=differences, matched_repeats=matched_rows, problems=problems,
                           comparable=not problems))
    across = {}
    for metric in metrics:
        values = [r['differences'][metric]['difference_of_session_medians'] for r in result
                  if r['comparable'] and r['differences'][metric]['difference_of_session_medians'] is not None]
        across[metric] = dict(distribution_of_vm_pair_median_differences=describe(values),
                             positive_vm_pairs=sum(v > 0 for v in values), negative_vm_pairs=sum(v < 0 for v in values))
    return dict(vm_pairs=result, across_vm_pairs=across,
                sign='baseline minus candidate; positive means candidate lower cost',
                pairing_evidence='explicit operator-supplied map; filenames do not establish same-VM identity',
                uncertainty='VM is the cluster. Few same-host VM pairs cannot establish independent-hardware confidence; serial matched repeats are diagnostic and receive no iid confidence interval.',
                limitations=['Order and cache state may differ between sessions.', 'P90 differences are exploratory at this sample size.', 'No failed or incomplete request is silently discarded.'])


def summarize_requests(rows):
    eligible = [r for r in rows if r['timing_eligible'] and r['sample_class'] == 'measured']
    grouped = collections.defaultdict(list)
    for row in eligible:
        grouped[(row['session'], row['variant'], row['case'], row['measurement_mode'])].append(row)
    sessions = []
    for (session, variant, case, mode), selected in sorted(grouped.items()):
        stages = {}
        for name, _, _ in STAGES:
            stages[name] = describe(r['stage_ms'][name] for r in selected
                                    if name in r['stage_ms'])
        sessions.append(dict(session=session, variant=variant, case=case, measurement_mode=mode,
                             response_ready_ms=metric_summary(selected, 'response_ready_ms'),
                             business_ms=metric_summary(selected, 'business_ms'),
                             unattributed_ms=metric_summary(selected, 'unattributed_ms'),
                             controller_self_cpu_ms=describe(request_metric(r,'controller_self_cpu_ms') for r in selected if request_metric(r,'controller_self_cpu_ms') is not None),
                             task_cgroup_cpu_ms=describe(request_metric(r,'task_cgroup_cpu_ms') for r in selected if request_metric(r,'task_cgroup_cpu_ms') is not None),
                             controller_message_count=describe(request_metric(r,'controller_boundary_message_count') for r in selected if request_metric(r,'controller_boundary_message_count') is not None),
                             query_snapshot_message_count=describe(request_metric(r,'query_snapshot_messages') for r in selected if request_metric(r,'query_snapshot_messages') is not None),
                             stages_ms=stages))
    # Aggregating session medians preserves session as the sampling unit. It
    # does not turn VM sessions on one host into independent hardware samples.
    variant_sessions = collections.defaultdict(list)
    for session in sessions:
        variant_sessions[(session['variant'], session['case'], session['measurement_mode'])].append(session)
    across_sessions = []
    for (variant, case, mode), group in sorted(variant_sessions.items()):
        across_sessions.append(dict(variant=variant, case=case, measurement_mode=mode, vm_sessions=len(group),
            distribution_of_session_medians_ms=describe(x['response_ready_ms']['median'] for x in group),
            session_medians_ms={x['session']: x['response_ready_ms']['median'] for x in group}))
    return dict(session_summaries=sessions, across_sessions=across_sessions,
                request_counts=dict(collections.Counter((r['sample_class'] + ':' + r['timing_status']) for r in rows)),
                percentile_method='type 7 linear interpolation; p90 is exploratory, not production tail latency',
                pooled_independent_hardware_claim=False)


def analyze_run(run, warmup, expected_measured, variant_override=None):
    events, duplicates, malformed, sources = collect(run)
    metadata = read_metadata(run)
    receipts = records(run)
    errors = list(malformed)
    config = metadata.get('cost-config.json', {})
    review = metadata.get('review-config.json', {})
    default_variant = variant_override or config.get('variant') or review.get('cost_variant') or review.get('variant') or 'UNKNOWN'
    tracing_enabled = str(review.get('trace', config.get('trace','unknown'))).lower() in ('1','true','yes')
    detail_timing_disabled = str(review.get('timing', config.get('timing','unknown'))).lower() in ('0','false','no')
    mode = 'traced_diagnostic' if tracing_enabled else ('untraced' if str(review.get('trace', config.get('trace','unknown'))).lower() in ('0','false','no') else 'trace_status_unknown')
    groups = collections.defaultdict(list)
    session_events = collections.defaultdict(list)
    all_session_events = collections.defaultdict(list)
    sequence_ids = {}
    for event in events:
        if event.get('clock') != CLOCK:
            errors.append(dict(origin=event['_origin'], reason='unsupported or missing clock', event=event))
            continue
        if not isinstance(event.get('ns'), int) or isinstance(event.get('ns'), bool):
            errors.append(dict(origin=event['_origin'], reason='non-integer CLOCK_MONOTONIC timestamp'))
            continue
        session = str(event.get('session', run.name))
        all_session_events[session].append(event)
        if event.get('seq') is not None:
            # PID 2 and its per-process sequence restart in every private PID
            # namespace. Attempt identity is indispensable for W/descendants.
            key = (session, event.get('role'), event.get('nonce'), event.get('pid'), event['seq'])
            if key in sequence_ids:
                errors.append(dict(origin=event['_origin'], reason='same per-process sequence ID has nonidentical events', key=key))
            sequence_ids[key] = event
        if event.get('kind') == 'measurement_error':
            errors.append(dict(origin=event['_origin'], reason='instrumentation reported measurement_error', event=event))
        if event.get('nonce') and event.get('nonce') != 'session':
            groups[(session, str(event['nonce']))].append(event)
        else:
            session_events[session].append(event)
    # A receipt without COST lines is not silently lost.
    seen_nonces = {n for _, n in groups}
    for nonce in receipts:
        if nonce not in seen_nonces:
            groups[(run.name, nonce)] = []
    rows = []
    for (session, nonce), own in groups.items():
        own.sort(key=lambda x: (x['ns'], str(x.get('role')), x.get('seq', 0)))
        receipt = receipts.get(nonce, {})
        phases = collections.defaultdict(list)
        for event in own:
            if event.get('kind') == 'phase':
                phases[event.get('name')].append(event)
        boundaries, problems = {}, []
        for name in BOUNDARIES:
            entries = phases.get(name, [])
            if len(entries) == 1:
                boundaries[name] = entries[0]['ns']
            elif len(entries) > 1:
                problems.append('ambiguous repeated boundary: ' + name)
        begin, end = boundaries.get('request_begin'), boundaries.get('response_ready')
        duration = (end - begin) if begin is not None and end is not None and end >= begin else None
        if duration is None:
            problems.append('missing or reversed complete request boundary')
        stage_ms, stage_intervals = {}, []
        for name, start, finish in STAGES:
            if start not in boundaries or finish not in boundaries:
                continue
            left, right = boundaries[start], boundaries[finish]
            if right < left or (begin is not None and left < begin) or (end is not None and right > end):
                problems.append('invalid boundary order: ' + name)
                continue
            stage_ms[name] = (right - left) / 1e6
            stage_intervals.append((left, right))
        spans = collections.defaultdict(list)
        resources, memories, messages, outside_messages, raw_spans = [], [], [], [], []
        for event in own:
            kind = event.get('kind')
            if kind in ('span', 'c_span', 'send', 'recv'):
                start, finish = value(event, 'start_ns'), value(event, 'end_ns')
                if not isinstance(start, int) or not isinstance(finish, int) or start <= 0 or finish < start or value(event, 'clock_valid') is False:
                    problems.append('invalid span: ' + str(event.get('name')))
                    continue
                # send/recv wall spans include encoding, decoding or waiting;
                # they are not inferred network/IPC delivery times or RTTs.
                name = ('ipc_' + kind + ':' if kind in ('send', 'recv') else '') + str(event.get('name'))
                spans[(str(event.get('role')), name)].append((start, finish))
                raw_spans.append({k:v for k,v in event.items() if k!='_origin'})
            elif kind == 'resource':
                resources.append({k:v for k,v in event.items() if k != '_origin'})
            elif kind == 'memory':
                memories.append({k:v for k,v in event.items() if k != '_origin'})
            if kind in ('send', 'recv'):
                # R may retain the last request nonce during final STOP/DONE.
                # Report actual request-boundary traffic, not session teardown.
                if begin is not None and end is not None and begin <= event['ns'] <= end:
                    messages.append(event)
                else:
                    outside_messages.append(event)
        span_summary = []
        for (role, name), intervals in sorted(spans.items()):
            overlap = [(max(a,begin), min(b,end)) for a,b in intervals
                       if begin is not None and end is not None and a < end and b > begin]
            span_summary.append(dict(role=role, name=name, count=len(intervals),
                sum_ms=sum(b-a for a,b in intervals)/1e6, union_ms=union_ns(intervals)/1e6,
                within_request_sum_ms=sum(b-a for a,b in overlap)/1e6,
                within_request_union_ms=union_ns(overlap)/1e6))
        sends, recvs = collections.defaultdict(list), collections.defaultdict(list)
        for event in messages:
            message_id = value(event, 'message_id')
            if message_id is None:
                continue
            key = (value(event, 'channel'), str(message_id))
            (sends if event['kind']=='send' else recvs)[key].append(event)
        ipc = []
        for key in sorted(set(sends) | set(recvs), key=str):
            a, b = sends[key], recvs[key]
            item = dict(channel=key[0], message_id=key[1], send_count=len(a), recv_count=len(b))
            if len(a)==1 and len(b)==1 and b[0]['ns'] >= a[0]['ns']:
                item.update(delivery_ms=(b[0]['ns']-a[0]['ns'])/1e6,
                            message=value(a[0], 'message', a[0].get('name')))
            else:
                item['delivery_ms'] = None
            ipc.append(item)
        begin_event = phases.get('request_begin', [{}])[0]
        # R owns request iteration. Z/S/W inherit their own process defaults,
        # not the Controller's repeat/warmup metadata, so do not vote over roles.
        warm_flag = value(begin_event, 'warmup')
        variant = str(value(begin_event, 'variant', default_variant))
        outcome = receipt.get('outcome')
        qualified = receipt.get('qualification') == 'PASS' and receipt.get('resources') == 'RELEASED'
        if not qualified:
            problems.append('no completed qualified Controller receipt')
        row = dict(run=str(run), session=session, nonce=nonce, variant=variant,
                   measurement_mode=mode,
                   detail_timing_disabled=detail_timing_disabled,
                   same_vm_pair=review.get('same_vm_pair'), session_order=review.get('session_order'),
                   case=receipt.get('case', value(begin_event,'case','UNKNOWN')),
                   repeat=value(begin_event,'repeat'), start_ns=begin, end_ns=end,
                   response_ready_ms=duration/1e6 if duration is not None else None,
                   business_ms=stage_ms.get('business_parent_execution'),
                   stage_ms=stage_ms, missing_stage_boundaries=[k for k in BOUNDARIES if k not in boundaries],
                   unattributed_ms=(duration-union_ns(stage_intervals))/1e6 if duration is not None else None,
                   spans=span_summary, raw_spans=raw_spans,
                   controller_cpu_delta=resource_delta(own,'request_cpu_begin','request_cpu_end','R'),
                   cgroup_receipt_stats=receipt.get('stats'),
                   resource_snapshots=resources, memory_snapshots=memories, ipc_deliveries=ipc,
                   messages_outside_request_window=[{k:v for k,v in e.items() if k!='_origin'} for e in outside_messages],
                   message_counts=dict(collections.Counter(
                       str(e.get('role'))+':'+str(e.get('kind'))+':'+str(value(e,'message',e.get('name')))
                       for e in messages)),
                   controller_boundary_message_count=None if detail_timing_disabled else sum(e.get('role')=='R' for e in messages),
                   controller_boundary_messages=dict(collections.Counter(
                       str(e.get('kind'))+':'+str(value(e,'message',e.get('name')))
                       for e in messages if e.get('role')=='R')),
                   outcome=outcome, business=receipt.get('business'), resources=receipt.get('resources'),
                   supervisor_release=receipt.get('_supervisor_release'), receipt=receipt.get('_receipt'),
                   problems=problems, timing_eligible=not problems,
                   timing_status='ADMITTED' if not problems else 'NOT_ADMITTED',
                   sample_class='warmup' if warm_flag is True else ('measured' if warm_flag is False else 'UNCLASSIFIED'))
        rows.append(row)
    rows.sort(key=lambda r:(r['session'], r['start_ns'] if r['start_ns'] is not None else 2**63, r['nonce']))
    by_session = collections.defaultdict(list)
    for row in rows:
        by_session[row['session']].append(row)
    for session, selected in by_session.items():
        for index, row in enumerate(selected):
            if row['sample_class']=='UNCLASSIFIED' and warmup is not None:
                row['sample_class']='warmup' if index<warmup else 'measured'
                row['sample_class_source']='explicit CLI ordered request count'
            elif row['sample_class']!='UNCLASSIFIED':
                row['sample_class_source']='Controller request_begin metadata'
        measured=sum(r['sample_class']=='measured' for r in selected)
        if expected_measured is not None and measured!=expected_measured:
            errors.append(dict(session=session, reason='measured count differs from declared design',
                               expected=expected_measured, observed=measured))
    sessions=[]
    for session, own in sorted(all_session_events.items()):
        # Session markers may carry the last nonce in early instrumentation.
        # Locate them by their explicit phase and role, never by PID/nonce.
        sessions.append(dict(session=session,
            controller_session_ms=duration_between(own,'session_begin','session_end','R'),
            product_session_through_supervisor_wait_ms=duration_between(own,'fixture_session_start','session_supervisor_waited','fixture'),
            fixture_through_observer_release_ms=duration_between(own,'fixture_session_start','fixture_release','fixture'),
            controller_cpu_delta=resource_delta(own,'controller_initial_usage','controller_final_usage','R'),
            supervisor_cpu_delta=resource_delta(own,'supervisor_initial_usage','supervisor_final_usage','H'),
            resource_snapshots=[{k:v for k,v in e.items() if k!='_origin'} for e in own if e.get('kind')=='resource'],
            memory_snapshots=[{k:v for k,v in e.items() if k!='_origin'} for e in own if e.get('kind')=='memory'],
            calibration_records=[{k:v for k,v in e.items() if k!='_origin'} for e in own if e.get('kind')=='calibration'],
            events=[{k:v for k,v in e.items() if k!='_origin'} for e in session_events[session]]))
    if errors:
        # Descriptive raw durations remain available, but a clock/schema/count
        # inconsistency cannot silently enter the qualified summary.
        for row in rows:
            row['problems'].append('run-level measurement integrity errors; inspect input run errors')
            row['timing_eligible']=False
            row['timing_status']='NOT_ADMITTED'
    return dict(run=str(run), metadata=metadata, raw_event_count=len(events),
                tracing_enabled=tracing_enabled,
                result_scope='traced diagnostic only; not untraced performance' if tracing_enabled else 'measurement summary; independent qualification evidence must also be checked',
                identical_duplicate_count=len(duplicates), duplicate_records=duplicates,
                input_sources=sources, errors=errors, requests=rows, sessions=sessions)


def save_new(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as output:
        output.write(data)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs', nargs='+', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--csv', type=Path)
    parser.add_argument('--warmup', type=int, help='Explicit fallback: first N attempts in each session are warmup')
    parser.add_argument('--expected-measured', type=int)
    parser.add_argument('--variant', help='Explicit label only if events/config do not label the variant')
    parser.add_argument('--pair-map', type=Path, help='Explicit list of pair_id/baseline_session/candidate_session objects; same-VM evidence remains the caller\'s responsibility')
    args=parser.parse_args()
    if args.output.exists() or (args.csv and args.csv.exists()):
        parser.error('refusing to overwrite existing analysis outputs')
    if args.warmup is not None and args.warmup<0:
        parser.error('--warmup must be nonnegative')
    results=[analyze_run(p.resolve(),args.warmup,args.expected_measured,args.variant) for p in args.runs]
    rows=[row for result in results for row in result['requests']]
    measured=[row for row in rows if row['sample_class']=='measured']
    complete=bool(measured) and all(row['timing_eligible'] for row in measured) and not any(r['errors'] for r in results)
    report=dict(schema='shimos-cost-analysis-v2', performance_scope='controlled mechanism diagnosis, not online Agent E2E',
                clock=CLOCK, analyzer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                qualification_scope='ADMITTED means parseable timing plus Controller PASS/RELEASED receipt; not an independent security or formal qualification verdict',
                analysis_status='COMPLETE' if complete else 'INCOMPLETE',
                input_runs=results, summary=summarize_requests(rows),
                limitations=[
                    'Role-local spans overlap and must not be added to request latency.',
                    'recv spans can include pre-request idle time; request-clipped overlap is separately reported, not causal IPC cost.',
                    'syscall wall spans are not kernel CPU time.',
                    'waited-child CPU and cgroup CPU overlap; no automatic total is computed.',
                    'Shared-host VM sessions are not independent physical machines.',
                    'Normal inherited workload includes a deliberate 40 ms descendant wait.',
                    'Trusted runtime probes may scan 4096 FDs; 9p journals are experiment costs.',
                    'No completed receipt means timing not admitted; UNKNOWN/failures remain listed.',
                    'Missing phase boundaries remain unattributed; no duration is invented.',
                    'p90 at this sample size is exploratory, not a stable service tail estimate.'])
    if args.pair_map:
        raw = args.pair_map.read_bytes()
        report['paired_comparison'] = compare_pairs(rows, json.loads(raw))
        report['pair_map_source'] = dict(path=str(args.pair_map), sha256=hashlib.sha256(raw).hexdigest())
        if any(not p['comparable'] for p in report['paired_comparison']['vm_pairs']):
            report['analysis_status'] = 'INCOMPLETE'
            complete = False
    save_new(args.output,json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    if args.csv:
        fields=['run','session','nonce','variant','case','measurement_mode','sample_class','timing_status','outcome','business','resources',
                'response_ready_ms','business_ms','unattributed_ms']+[n for n,_,_ in STAGES]
        out=io.StringIO();writer=csv.DictWriter(out,fieldnames=fields);writer.writeheader()
        for row in rows:
            writer.writerow({**{k:row.get(k) for k in fields if k not in row['stage_ms']},**row['stage_ms']})
        save_new(args.csv,out.getvalue())
    print(json.dumps(dict(output=str(args.output),requests=len(rows),
                          analysis_status=report['analysis_status'],
                          errors=sum(len(r['errors']) for r in results),
                          timing_counts=report['summary']['request_counts']),ensure_ascii=False))
    return 0 if complete else 1


if __name__=='__main__':
    raise SystemExit(main())
