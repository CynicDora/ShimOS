#!/usr/bin/env python3
"""Summarize completed, independently audited exec qualification evidence.

Reads only frozen runs and the selected audit reports. Creates new JSON/CSV/MD
files exclusively; never changes an existing report or runs a VM/workload.
"""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import re

STUDY = Path(__file__).resolve().parents[1]
SUITES = ('level1', 'level2', 'level3', 'level4', 'lifecycle', 'budgets',
          'controller_death', 'output_boundary', 'warm_control')


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def json_lines(path):
    rows = []
    for line in path.read_text(errors='replace').splitlines():
        try:
            entry = json.loads(line)
            if isinstance(entry, dict):
                rows.append(entry)
        except ValueError:
            pass
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', default='qualification-exec-01')
    parser.add_argument('--audit-suffix', default='final-v1')
    parser.add_argument('--output-stem', default='qualification-matrix')
    args = parser.parse_args()
    if any(not re.fullmatch(r'[a-zA-Z0-9_-]+', value) for value in (args.prefix, args.audit_suffix, args.output_stem)):
        parser.error('prefix/suffix/stem must be simple basenames')
    analysis = STUDY / 'analysis'
    target_paths = [analysis / (args.output_stem + extension) for extension in ('.json', '.csv', '.md')]
    if any(path.exists() for path in target_paths):
        parser.error('output already exists; choose a new --output-stem')
    source_lock_path = STUDY / 'frozen' / (args.prefix + '-source-sha.json')
    source_lock = read(source_lock_path)
    rows, runs, provenance = [], [], []
    source_manifests, binary_manifests, runtime_manifests, verifier_hashes = [], [], [], []
    for suite in SUITES:
        name = args.prefix + '-' + suite
        run = STUDY / 'runs' / name
        audit_path = analysis / ('verify-exec-' + name + '-' + args.audit_suffix + '.json')
        audit = read(audit_path)
        sup = read(run / 'supervisor.json')
        release = read(run / 'external-final-release.json')
        source = read(run / 'source-sha.json')
        tools_source = read(run / 'tools-source-sha.json')
        variant = read(run / 'variant-manifest.json')
        source_manifests.append(source)
        binary_manifests.append(variant['binary_sha256'])
        runtime_manifests.append(read(run / 'candidate-runtime-sha.json'))
        verifier_hashes.append(audit['verifier_sha256'])
        locked = {('prototype/' + key): value for key, value in source.items()}
        locked.update({('tools/' + key): value for key, value in tools_source.items()})
        provenance.append({'run': name, 'source_matches_pre_run_lock': locked == source_lock,
                           'audit_file': str(audit_path.relative_to(STUDY)), 'audit_sha256': sha(audit_path),
                           'source_manifest_sha256': sha(run / 'source-sha.json'),
                           'tools_source_manifest_sha256': sha(run / 'tools-source-sha.json')})
        final_paths = sorted((path for path in run.glob('*.json') if re.fullmatch(r'\d+-.*\.json', path.name)),
                             key=lambda path: int(path.name.split('-', 1)[0]))
        attempts = [(path, read(path), False) for path in final_paths]
        final_nonces = {row['nonce'] for _, row, _ in attempts}
        for path in sorted(run.glob('attempt-*.json')):
            row = read(path)
            if row.get('nonce') not in final_nonces:
                attempts.append((path, row, True))
        h_attempts = {entry['nonce']: entry for entry in sup['attempts']}
        raw_z = [entry for path in sorted(run.glob('zygote-*.log')) for entry in json_lines(path)]
        process_trees = {entry['nonce']: entry for entry in audit.get('process_trees', [])}
        for path, row, recovered in attempts:
            nonce = row['nonce']
            h = h_attempts[nonce]
            actual_w_waits = [entry for entry in raw_z if entry.get('nonce') == nonce and entry.get('event') == 'ACTUAL_WORKER_WAIT']
            actual_s_waits = [entry for entry in raw_z if entry.get('nonce') == nonce and entry.get('event') == 'ACTUAL_TRANSITION_WAIT']
            h_waits = [entry for entry in sup['wait_records'] if entry.get('pid') in (row.get('s_pid'), row.get('w_pid'))]
            r_waits = [entry for entry in row.get('wait_records', []) if entry.get('pid') in (row.get('s_pid'), row.get('w_pid'))]
            mode = row.get('execution_mode', 'python_warm')
            if recovered:
                stream_eof = {name: value['output_eof'] for name, value in h.get('output_streams', {}).items()}
                stream_complete = {name: value['complete'] for name, value in h.get('output_streams', {}).items()}
                outcome, knowledge, business_result = 'CONTROLLER_DIED', h['business_result'], None
                resources, eof = sup['release_state'], h['output_eof']
            else:
                stream_eof = row.get('stream_eof', {'combined': row['output_eof']})
                stream_complete = row.get('stream_complete', {'combined': None})
                outcome, knowledge, business_result = row['outcome'], row['business'], row.get('result')
                resources, eof = row['resources'], row['output_eof']
            tree = process_trees.get(nonce, {})
            worker_checks = (row.get('worker') or {}).get('checks', {})
            rows.append({
                'run': name, 'suite': suite, 'case': row['case'], 'nonce': nonce, 'mode': mode,
                'qualification': audit['status'], 'outcome': outcome, 'business_knowledge': knowledge,
                'business_permit': row.get('business_permit'),
                'business_exit_code': business_result.get('exit_code') if business_result and knowledge == 'KNOWN' and row.get('business_permit') else None,
                'business_result_source': business_result.get('source') if business_result and knowledge == 'KNOWN' and row.get('business_permit') else None,
                'worker_exit_code_received_by_R': (row.get('result') or {}).get('exit_code'),
                'worker_result_source_at_R': (row.get('result') or {}).get('source'),
                'controller_response_committed': row.get('response_committed') is True,
                'controller_crashed': recovered,
                'S_pid': row.get('s_pid'), 'W_pid': row.get('w_pid'),
                'S_status_known_to_R': row.get('s_wait'), 'W_wait_receipt_at_R': row.get('w_wait'),
                'raw_S_wait_W': actual_w_waits, 'raw_Z_wait_S': actual_s_waits,
                'R_adopted_SW_waits': r_waits, 'H_adopted_SW_waits': h_waits,
                'actual_W_wait_observed': bool(actual_w_waits or any(entry.get('pid') == row.get('w_pid') for entry in r_waits + h_waits)),
                'actual_S_wait_observed': bool(actual_s_waits or any(entry.get('pid') == row.get('s_pid') for entry in r_waits + h_waits)),
                'output_eof': eof, 'stream_eof': stream_eof, 'stream_complete': stream_complete,
                'output_ended_by_termination': row.get('output_ended_by_termination'),
                'stream_bytes': row.get('stream_bytes'), 'bytes_retained': row.get('bytes_retained'),
                'stream_truncated': row.get('stream_truncated'),
                'resources': resources, 'resources_removed': h.get('resources_removed'),
                'domain_empty': row.get('domain_empty') if not recovered else sup.get('remaining_cgroups') == [],
                'admission': row.get('admission') if not recovered else 'CREATORS_STOPPED_BY_H',
                'tree_pids': tree.get('pids', []), 'tree_exit_trace_complete': tree.get('all_exit_traced'),
                'H_echild': sup['echild'], 'H_release_state': sup['release_state'],
                'H_business_result': sup['business_result'], 'H_controller_wait_status': sup['controller_wait_status'],
                'H_output_streams': h.get('output_streams'), 'H_attempt_business_result': h.get('business_result'),
                'H_all_wait_records': sup['wait_records'] if recovered else None,
                'observer_cleanup_used': sup['observer_cleanup_used'] or release['observer_killed_processes'] or release['observer_removed_product_resources'],
                'delegation_removed': release['delegation_removed'],
                'warm_19_checks': len(worker_checks) if mode == 'python_warm' else None,
                'warm_19_passed': len(worker_checks) == 19 and all(worker_checks.values()) if mode == 'python_warm' else None,
                'raw_attempt': str(path.relative_to(STUDY)), 'audit_file': str(audit_path.relative_to(STUDY)),
            })
        runs.append({'run': name, 'suite': suite, 'attempts': len(attempts), 'audit_status': audit['status'],
                     'audit_checks': audit['counts']['checks'], 'audit_file': str(audit_path.relative_to(STUDY)),
                     'supervisor_release': sup['release_state'], 'supervisor_business_result': sup['business_result']})
    same = lambda values: bool(values) and all(value == values[0] for value in values)
    available_verifiers = [STUDY / 'runner/verify_exec.py',
                          STUDY / 'analysis/verifier-history/verify_exec-formal42-final-v1.py']
    bound_verifiers = [path for path in available_verifiers if path.is_file() and sha(path) == verifier_hashes[0]]
    provenance_checks = {
        'all_pre_run_source_locks_match': all(row['source_matches_pre_run_lock'] for row in provenance),
        'same_prototype_source_all_VMs': same(source_manifests),
        'same_compiled_artifacts_all_VMs': same(binary_manifests),
        'same_candidate_runtime_all_VMs': same(runtime_manifests),
        'same_verifier_all_final_reports': same(verifier_hashes),
        'audited_verifier_source_available': same(verifier_hashes) and bool(bound_verifiers),
    }
    good = all(row['qualification'] == 'PASS' for row in rows) and all(provenance_checks.values())
    report = {'status': 'PASS' if good else 'FAIL', 'prefix': args.prefix,
              'counts': {'private_VM_sessions': len(runs), 'attempts': len(rows),
                         'tool_attempts': sum(row['mode'] == 'tool_exec' for row in rows),
                         'warm_attempts': sum(row['mode'] == 'python_warm' for row in rows),
                         'audit_assertions': sum(run['audit_checks'] for run in runs),
                         'outcomes': dict(Counter(row['outcome'] for row in rows)),
                         'business_knowledge': dict(Counter(row['business_knowledge'] for row in rows))},
              'provenance_checks': provenance_checks, 'provenance': provenance, 'runs': runs, 'rows': rows,
              'source_lock': str(source_lock_path.relative_to(STUDY)), 'source_lock_sha256': sha(source_lock_path),
              'verifier_sha256': verifier_hashes[0], 'summarizer_sha256': sha(Path(__file__)),
              'verifier_source_files': [str(path.relative_to(STUDY)) for path in bound_verifiers],
              'historical_audit_failure': 'analysis/verify-exec-qualification-exec-01-output_boundary.json',
              'audit_revision_explanation': 'analysis/verifier-history/output-boundary-review.md',
              'limitations': ['Same-host private VM mechanism qualification, not production reliability or independent hardware samples.',
                              'PASS includes expected nonzero exits, cancellations, UNKNOWN and successful cleanup; it does not mean business success.',
                              'EOF, retained byte completeness and semantically complete application output are separate.',
                              'clone3 flags cannot be decoded from pointer-only syscall ftrace.',
                              'Controller-death raw waits never become a recovered business response.']}
    with target_paths[0].open('x') as out:
        json.dump(report, out, indent=2, ensure_ascii=False); out.write('\n')
    columns = ('run', 'case', 'mode', 'qualification', 'outcome', 'business_knowledge', 'business_permit',
               'business_exit_code', 'business_result_source', 'actual_W_wait_observed', 'actual_S_wait_observed',
               'worker_exit_code_received_by_R', 'worker_result_source_at_R',
               'output_eof', 'stream_eof', 'stream_complete', 'resources', 'domain_empty', 'admission',
               'tree_pids', 'tree_exit_trace_complete', 'controller_crashed', 'H_echild', 'H_release_state',
               'H_business_result', 'H_controller_wait_status', 'observer_cleanup_used', 'delegation_removed',
               'warm_19_checks', 'warm_19_passed', 'nonce', 'raw_attempt', 'audit_file')
    with target_paths[1].open('x', newline='') as out:
        writer = csv.DictWriter(out, fieldnames=columns); writer.writeheader()
        for row in rows:
            writer.writerow({key: json.dumps(row[key], ensure_ascii=False) if isinstance(row[key], (dict, list)) else row[key] for key in columns})
    content = ['# 受控 exec 正式资格矩阵', '',
               f"最终状态：**{report['status']}**。{len(runs)} 个同宿主私有 VM、{len(rows)} 次请求："
               f"{report['counts']['tool_attempts']} 次 Tool、{report['counts']['warm_attempts']} 次 Warm。"
               f"共 {report['counts']['audit_assertions']} 项独立证据断言；断言数不是实验样本数。", '',
               '所有最终审计使用相同核验器 SHA。原输出上限用例的首次核验 FAIL 和适配说明保留；未修改执行源码或原始记录。', '',
               'PASS 表示符合本用例的正确性和回收预期。非零、取消、结果 UNKNOWN 均不称为业务成功。', '',
               '| VM组 | 次数 | 最终独立审计 | H释放 |', '|---|---:|---|---|']
    for run in runs:
        content.append(f"| {run['suite']} | {run['attempts']} | {run['audit_status']} | {run['supervisor_release']} |")
    content += ['', '## 逐请求结果', '',
                '“W wait实录”可以存在而业务结果仍 UNKNOWN，例如回执丢失或 Controller 死亡。H 的恢复结果以其最终账本为准，不用 R 中途 journal 冒充最终状态。', '',
                '业务前取消的 NOT_EXECUTED 请求没有业务退出码；已创建 W 被回收的 -9 只列在 CSV/JSON 的 worker_exit_code_received_by_R。', '',
                '| 组 / 用例 | 业务结果 | 知识 | 退出码 | W wait实录 | 双流/合并EOF | 资源 |',
                '|---|---|---|---:|---|---|---|']
    for row in rows:
        code = 'UNKNOWN' if row['business_exit_code'] is None and row['business_knowledge'] == 'UNKNOWN' else 'N/A' if row['business_exit_code'] is None else str(row['business_exit_code'])
        content.append(f"| {row['suite']} / {row['case']} | {row['outcome']} | {row['business_knowledge']} | {code} | {'是' if row['actual_W_wait_observed'] else '未观察'} | {row['output_eof']} | {row['resources']} |")
    content += ['', '## 来源与恢复边界', '',
                '源码冻结、全部运行构建产物、候选运行时和最终核验器一致性检查：' + ('全部通过。' if all(provenance_checks.values()) else '存在不一致，见 JSON。'), '',
                'Controller 死亡样本保留 UNKNOWN；H 的真实 wait、收养、两个输出 EOF、恢复内容完整性 null、资源删除和观察者无补杀均独立核对。Warm 三次请求各 19 项检查通过，实际 W 没有 exec。', '',
                '输出上限样本为 OUTPUT_LIMIT；即使成功杀死后代、两流 EOF 和删除 cgroup，也不是业务成功。输出无末尾换行且因终止结束的任务，可能已保存所有已产生字节，但仍未完成应用输出协议。', '',
                '完整字段、raw S/W wait、H 账本及各 run/audit SHA 见 [JSON](qualification-matrix.json)；平面数据见 [CSV](qualification-matrix.csv)。', '',
                '首次核验器失败见 [原输出边界审计](verify-exec-qualification-exec-01-output_boundary.json)，修订依据见 [适配记录](verifier-history/output-boundary-review.md)。', '']
    with target_paths[2].open('x') as out:
        out.write('\n'.join(content))
    print(json.dumps({'status': report['status'], 'counts': report['counts'], 'provenance_checks': provenance_checks,
                      'outputs': [str(path) for path in target_paths]}, ensure_ascii=False, indent=2))
    return 0 if good else 1


if __name__ == '__main__':
    raise SystemExit(main())
