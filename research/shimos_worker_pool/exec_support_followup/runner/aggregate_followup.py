#!/usr/bin/env python3
"""Aggregate existing independent audits and raw artifacts; never runs a VM.

Every historical audit remains listed. For each run, select the highest explicit
vN audit revision (ties require identical contents, otherwise abort). PASS is an
experiment assertion verdict, not business success or complete resource release.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re

STUDY = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path, default=None):
    return json.loads(path.read_text()) if path.is_file() else default


def write_tables(out, name, rows):
    (out / (name + '.json')).write_text(json.dumps(rows, ensure_ascii=False, indent=2) + '\n')
    keys = list(dict.fromkeys(key for row in rows for key in row))
    with (out / (name + '.csv')).open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=keys)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: json.dumps(value, ensure_ascii=False, separators=(',', ':'))
                             if isinstance(value, (dict, list)) else value for key, value in row.items()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--outdir', type=Path, required=True)
    parser.add_argument('--report', type=Path, action='append', help='repeat for an explicit subset; otherwise discover analysis/verify-*.json')
    args = parser.parse_args()
    out = args.outdir.resolve()
    if not out.is_relative_to(STUDY.resolve()) or out.is_relative_to((STUDY / 'runs').resolve()):
        parser.error('write only inside this study, outside raw runs')
    if out.exists():
        parser.error('output directory must be new; never replace a prior aggregate')
    reports = args.report or sorted((STUDY / 'analysis').glob('verify-*.json'))
    history, candidates, inputs = [], {}, {}
    for path in reports:
        data = read(path, {})
        if not {'run', 'status', 'counts', 'verifier_sha256'} <= set(data):
            continue
        run = Path(data['run']).resolve()
        if not run.is_relative_to((STUDY / 'runs').resolve()) or not run.is_dir():
            raise ValueError('audit references a non-followup or missing run: ' + str(run))
        match = re.search(r'-v(\d+)\.json$', path.name)
        revision = int(match[1]) if match else 0
        record = {'run': run.name, 'audit_path': str(path.resolve().relative_to(STUDY)),
                  'audit_sha256': digest(path), 'revision': revision, 'status': data['status'],
                  'checks': data['counts']['checks'], 'failed': data['counts']['failed'],
                  'blocked': data['counts']['blocked'], 'verifier_sha256': data['verifier_sha256'],
                  'failure_names': [x['check'] for x in data.get('failures', [])]}
        history.append(record)
        candidates.setdefault(run.name, []).append((revision, record, data))
        inputs[str(path.resolve().relative_to(STUDY))] = record['audit_sha256']
    matrix, requests, streams, selections = [], [], [], []
    for name, versions in sorted(candidates.items()):
        greatest = max(item[0] for item in versions)
        selected = [item for item in versions if item[0] == greatest]
        if len(selected) != 1:
            raise ValueError('ambiguous latest audit revision for ' + name)
        _, audit, report = selected[0]
        selections.append(audit)
        run = STUDY / 'runs' / name
        expected = read(run / 'followup-expectations.json', {})
        result = read(run / 'result.json', {})
        supervisor = read(run / 'supervisor.json', {})
        source = read(run / 'source-sha.json', {})
        source_hash = digest(run / 'source-sha.json') if (run / 'source-sha.json').is_file() else None
        for file in ('followup-expectations.json', 'result.json', 'supervisor.json', 'source-sha.json',
                     'process-trace.txt', 'supervisor-events.jsonl', 'protocol-fixture-controller-events.jsonl',
                     'fault-injection-events.jsonl'):
            path = run / file
            if path.is_file(): inputs[str(path.relative_to(STUDY))] = digest(path)
        category = ('baseline' if expected.get('supervisor_baseline') else 'pilot' if 'pilot' in name
                    else 'regression' if expected.get('profile') == 'regression' else 'qualification')
        matrix.append({
            'run': name, 'category': category, 'profile': report.get('profile'),
            'configured_profile': expected.get('profile'), 'tool_suite': expected.get('tool_suite'),
            'protocol_case': expected.get('protocol_case'),
            'audit_status': report['status'], 'audit_checks': report['counts']['checks'],
            'audit_failed': report['counts']['failed'], 'audit_blocked': report['counts']['blocked'],
            'audit_path': audit['audit_path'], 'source_manifest_sha256': source_hash,
            'unsupported_dimensions': report.get('unsupported_dimensions', []),
            'H_source_sha256': source.get('supervisor.py'), 'R_source_sha256': source.get('run.py'),
            'launcher_source_sha256': source.get('tool_launcher.c'),
            'VM_export_complete': result.get('experiment_export_complete'),
            'VM_legacy_complete': result.get('complete'), 'VM_timeout': result.get('timeout'),
            'H_release_state': supervisor.get('release_state'),
            'physical_resources_released': supervisor.get('physical_resources_released'),
            'legacy_resources_removed': supervisor.get('resources_removed'),
            'recovery_evidence_complete': supervisor.get('recovery_evidence_complete'),
            'output_eof_confirmed': supervisor.get('output_eof_confirmed'),
            'H_business_result': supervisor.get('business_result'),
            'actual_Controller_wait_status': supervisor.get('controller_wait_status'),
            'actual_ECHILD': supervisor.get('echild'),
            'H_FDs_restored': supervisor.get('fd_before') == supervisor.get('fd_after') if supervisor else None,
            'remaining_cgroups': supervisor.get('remaining_cgroups'),
            'remaining_workspaces': supervisor.get('remaining_workspaces'),
            'H_errors': supervisor.get('errors'), 'H_protocol_errors': supervisor.get('protocol_errors'),
            'private_disk_retained': (run / 'disk.raw').is_file(),
            'observer_cleanup_used': supervisor.get('observer_cleanup_used'),
        })
        finals = [(path, read(path)) for path in run.glob('[0-9]*-*.json')
                  if re.fullmatch(r'\d+-.*\.json', path.name)]
        nonces = {row.get('nonce') for _, row in finals}
        rows = [row for _, row in sorted(finals, key=lambda pair: int(pair[0].name.split('-', 1)[0]))]
        rows += [row for row in (read(path) for path in sorted(run.glob('attempt-*.json')))
                 if row.get('nonce') not in nonces]
        facts = {item.get('nonce'): item for item in report.get('request_facts', [])}
        for row in rows:
            receipt = row.get('exec_receipt') or {}
            nonce = row.get('nonce'); fact = facts.get(nonce, {})
            requests.append({'run': name, 'category': category, 'source_manifest_sha256': source_hash,
                'case': row.get('case'), 'nonce': nonce, 'execution_mode': row.get('execution_mode'),
                'business_permit': row.get('business_permit'), 'business_result_state': row.get('business'),
                'outcome': row.get('outcome'), 'process_state': row.get('process_state'),
                'actual_exit_code': (row.get('result') or {}).get('exit_code'),
                'wait_receipt_event': (row.get('w_wait') or {}).get('event'),
                'private_exec_status': receipt.get('status'), 'private_exec_errno': receipt.get('errno'),
                'private_exec_stages': receipt.get('stages'), 'private_exec_eof': receipt.get('eof'),
                'private_exec_raw_available': 'raw_hex' in receipt,
                'kernel_exec_paths': fact.get('kernel_exec_paths'),
                'kernel_target_exec_observed': fact.get('kernel_target_exec_observed'),
                'response_committed': row.get('response_committed'),
                'output_eof': row.get('output_eof'), 'row_resources_removed': row.get('resources_removed')})
        for attempt in supervisor.get('attempts', []):
            nonce = attempt.get('nonce')
            for stream, data in attempt.get('output_streams', {}).items():
                suffix = '' if stream == 'combined' else '-' + stream
                path = run / ('supervisor-output-' + str(nonce) + suffix + '.log')
                streams.append({'run': name, 'category': category, 'nonce': nonce, 'stream': stream,
                    'output_eof': data.get('output_eof'), 'eof_source': data.get('eof_source'),
                    'content_complete': data.get('complete'), 'drained_bytes': data.get('drained_bytes'),
                    'logical_stored_bytes': data.get('stored_bytes'),
                    'logical_unconfirmed_or_discarded_bytes': data.get('discarded_bytes'),
                    'stored_bytes_exact': data.get('stored_bytes_exact'),
                    'actual_recovered_file_bytes': path.stat().st_size if path.is_file() else 0,
                    'actual_recovered_file_sha256': digest(path) if path.is_file() else None,
                    'truncated': data.get('truncated'), 'storage_error': data.get('storage_error'),
                    'read_error': data.get('read_error'), 'storage_limit_bytes': data.get('storage_limit_bytes'),
                    'attempt_business_result': attempt.get('business_result'),
                    'attempt_resources_removed': attempt.get('resources_removed')})
    out.mkdir(parents=True)
    write_tables(out, 'qualification-matrix', matrix)
    write_tables(out, 'requests', requests)
    write_tables(out, 'H-streams', streams)
    write_tables(out, 'audit-history', history)
    (out / 'audit-selection.json').write_text(json.dumps(selections, ensure_ascii=False, indent=2) + '\n')
    (out / 'input-sha256.json').write_text(json.dumps(inputs, ensure_ascii=False, indent=2) + '\n')
    summary = {
        'run_count': len(matrix), 'request_rows': len(requests), 'H_stream_rows': len(streams),
        'selected_audit_assertions': sum(row['audit_checks'] for row in matrix),
        'unsupported_dimensions': sorted({item['dimension'] for row in matrix for item in row['unsupported_dimensions']}),
        'counts_by_category': {category: {
            'runs': sum(row['category'] == category for row in matrix),
            'audit_PASS': sum(row['category'] == category and row['audit_status'] == 'PASS' for row in matrix),
            'audit_FAIL': sum(row['category'] == category and row['audit_status'] == 'FAIL' for row in matrix),
            'audit_BLOCKED': sum(row['category'] == category and row['audit_status'] == 'BLOCKED' for row in matrix),
            'product_RELEASED': sum(row['category'] == category and row['H_release_state'] == 'RELEASED' for row in matrix),
            'product_INCOMPLETE': sum(row['category'] == category and row['H_release_state'] == 'INCOMPLETE' for row in matrix),
        } for category in sorted({row['category'] for row in matrix})},
        'selection_rule': 'highest explicit -vN audit revision per run; every prior audit is retained in audit-history; no results are inferred from product fixture verdicts',
        'boundaries': [
            'Audit PASS means the specified fault experiment matches evidence. It does not turn INCOMPLETE into successful recovery.',
            'Selected audit assertions include repeated source/runtime SHA checks. They are not independent workload tests or a measure of production safety.',
            'Request rows and H-only protocol fixture cases are distinct; do not count them as the same kind of task.',
            'Logical discarded bytes include bytes not confirmed as stored after a partial-write exception; inspect actual file size and stored_bytes_exact.',
            'Runtime source hashes remain per-run; multiple candidate versions must not be silently combined into one implementation claim.',
        ], 'aggregator_sha256': digest(Path(__file__)),
    }
    (out / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
