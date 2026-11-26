#!/usr/bin/env python3
"""Read-only audit of this study's frozen VM evidence; never runs workload code.

PASS means these explicit evidence assertions pass, not a general sandbox claim.
Missing required raw evidence is BLOCKED; contradictory evidence is FAIL.
--check-only writes nothing. Other output is exclusively created outside runs/.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat

STUDY = Path(__file__).resolve().parents[1]
STREAMS = {'stdout', 'stderr'}
CAPS = ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')
TOOL_CHECKS = {'namespaces', 'root_identity', 'cgroup', 'caps_zero',
               'nnp_seccomp', 'fd_allowlist', 'cwd', 'environment', 'no_management_paths'}
WARM_CHECKS = {'marker', 'inherited', 'not_recreated', 'no_host_path',
               'no_other_workspace', 'readonly', 'writable', 'setns_denied',
               'unshare_denied', 'chroot_denied', 'exec_denied', 'caps_zero',
               'nnp_seccomp', 'fd_allowlist', 'namespaces', 'cgroup',
               'environment', 'cwd', 'root_identity'}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def counts(value):
    if not isinstance(value, str):
        return {}
    result = {}
    for line in value.splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                result[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return result


def analyze(run, allow_no_trace=False):
    checks = []
    observations = []
    process_trees = []

    def check(name, value, evidence=None, required=True):
        checks.append({'check': name, 'value': None if value is None else bool(value),
                       'required': required, 'evidence': evidence})

    def read(name, required=True):
        path = run / name
        if not path.is_file():
            if required:
                check('present:' + name, None, 'required raw file missing')
            return {}
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            check('parse:' + name, False, repr(exc))
            return {}

    def lines(path, required=True, strict=False):
        if not path.is_file():
            if required:
                check('present:' + path.name, None)
            return []
        rows = []
        for number, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    rows.append(obj)
                elif strict:
                    check(f'jsonl-object:{path.name}:{number}', False)
            except ValueError:
                if strict:
                    check(f'jsonl-parse:{path.name}:{number}', False)
        return rows

    config = read('review-config.json')
    result = read('result.json')
    source = read('source-sha.json')
    build = read('build.json')
    variant = read('variant-manifest.json')
    environment = read('environment.json')
    command = read('command.json')
    lab = read('lab-manifest.json')
    sup = read('supervisor.json')
    release = read('external-final-release.json')
    events = lines(run / 'events.jsonl', strict=True)
    se = lines(run / 'supervisor-events.jsonl', strict=True)
    zpaths = sorted(run.glob('zygote-*.log'))
    check('raw_zygote_log_present', bool(zpaths))
    zl = [entry for path in zpaths for entry in lines(path)]
    check('vm_completed_without_harness_timeout', result.get('complete') is True and result.get('timeout') is False)
    check('private_qemu_no_network', isinstance(command, list) and '-net' in command and
          command[command.index('-net') + 1] == 'none')
    check('guest_environment_recorded', bool(environment.get('kernel')) and bool(environment.get('python')) and bool(environment.get('glibc')))
    check('kernel_initramfs_hashes_recorded', bool(lab.get('kernel_sha256')) and bool(lab.get('initramfs_sha256')))
    check('source_manifest_not_empty', isinstance(source, dict) and len(source) >= 10)
    if isinstance(source, dict):
        for name, digest in source.items():
            path = run / 'prototype' / name
            safe = Path(name).name == name
            check('source_sha:' + name, safe and path.is_file() and sha(path) == digest)
            check('guest_build_source_sha:' + name, build.get(name) == digest)
        check('variant_source_manifest_matches', variant.get('source_sha256') == source)
    binary_manifest = variant.get('binary_sha256', {})
    for name in ('bridge.so', 'native.so', 'domain_init', 'bridge_d.so', 'libab_probe.so', 'tool_guard.so', 'tool_launcher'):
        path = run / name
        check('binary_sha:' + name, path.is_file() and sha(path) == build.get(name) == binary_manifest.get(name))
    tool_source = read('tools-source-sha.json')
    tool_build = read('tool-build-sha256.json')
    read('tool-rootfs.json')
    for name, digest in tool_source.items():
        path = run / 'tools' / name
        safe = not Path(name).is_absolute() and '..' not in Path(name).parts
        check('tool_source_sha:' + name, safe and path.is_file() and sha(path) == digest == tool_build.get(name))
    for name, digest in tool_build.items():
        if name.startswith('bin/'):
            path = run / 'tool-binaries' / name[4:]
            check('tool_binary_sha:' + name, path.is_file() and sha(path) == digest)
    candidate = read('candidate-runtime-sha.json')
    check('candidate_manifest_nonempty', bool(candidate))
    for name, digest in candidate.items():
        path = run / 'candidate-runtime' / name
        safe = not Path(name).is_absolute() and '..' not in Path(name).parts
        check('candidate_sha:' + name, safe and path.is_file() and sha(path) == digest)
    # This audit inspects the exact frozen source, rather than importing it.
    controller_path = run / 'prototype/run.py'
    if controller_path.is_file():
        text = controller_path.read_text()
        try:
            tree = ast.parse(text)
            branches = [node for node in ast.walk(tree) if isinstance(node, ast.If)
                        and ast.unparse(node.test) == 'tool and item in output_fds']
            check('tool_output_branch_unique', len(branches) == 1)
            if len(branches) == 1:
                branch = branches[0]
                forbidden = {'loads', 'eval', 'exec', 'recv', 'ss', 'zs'}
                calls = [node.func for node in ast.walk(branch) if isinstance(node, ast.Call)]
                names = [node.attr if isinstance(node, ast.Attribute) else node.id
                         for node in calls if isinstance(node, (ast.Attribute, ast.Name))]
                check('tool_output_is_opaque_in_frozen_source', not forbidden.intersection(names)
                      and isinstance(branch.body[-1], ast.Continue))
        except (SyntaxError, ValueError) as exc:
            check('frozen_controller_source_parse', False, repr(exc))

    check('H_real_echild', sup.get('echild') is True)
    check('H_release_state', sup.get('release_state') == 'RELEASED' and sup.get('resources_removed') is True)
    check('H_no_reported_errors', sup.get('errors') == [] and sup.get('protocol_errors') == [])
    check('H_no_leftovers', sup.get('remaining_cgroups') == [] and sup.get('remaining_workspaces') == [])
    check('H_fd_inventory_restored', bool(sup.get('fd_before')) and sup.get('fd_before') == sup.get('fd_after'))
    check('H_no_observer_cleanup', sup.get('observer_cleanup_used') is False)
    check('fixture_only_removed_empty_delegation', release.get('delegation_removed') is True and
          release.get('supervisor_wait_status') == 0 and release.get('observer_killed_processes') is False and
          release.get('observer_removed_product_resources') is False)
    for filename in ('observer-after.json', 'observer-later.json'):
        observed = read(filename)
        check(filename + ':no_uid65534_processes', observed.get('uid65534_processes') == {})
        check(filename + ':no_workspaces', observed.get('workspaces') == {})
        for path, group in observed.get('cgroups', {}).items():
            check(filename + ':empty:' + path, counts(group.get('cgroup.events')).get('populated') == 0
                  and str(group.get('pids.current', '')).strip() == '0')

    trace_path = run / 'process-trace.txt'
    trace_config = read('trace-config.json')
    tracing = str(config.get('trace', '1')) == '1'
    check('qualification_has_process_trace', tracing, required=not allow_no_trace)
    check('process_trace_file_present', trace_path.is_file())
    trace = trace_path.read_text(errors='replace') if trace_path.is_file() else ''
    if tracing:
        trace_stats = read('trace-stats.json')
        check('trace_stats_present', bool(trace_stats))
        for cpu, value in trace_stats.items():
            for field in ('overrun', 'commit overrun', 'dropped events'):
                match = re.search(r'^' + re.escape(field) + r':\s*(\d+)', value, re.M)
                check('trace_loss:' + cpu + ':' + field, match is not None and int(match.group(1)) == 0)
        check('trace_clock_mono', '[mono]' in trace_config.get('trace_clock', ''))
    else:
        observations.append('No process trace: actual fork/exec/exit assertions are not observed. This is an evidence-only cost audit, not execution qualification.')
    forks = set()
    exits = set()
    execs = []
    clone3_returns = set()
    for line in trace.splitlines():
        match = re.search(r'sched_process_fork: .*\bpid=(\d+) .*\bchild_pid=(\d+)', line)
        if match:
            forks.add(tuple(map(int, match.groups())))
        match = re.search(r'sched_process_exit: .*\bpid=(\d+)', line)
        if match:
            exits.add(int(match.group(1)))
        match = re.search(r'sched_process_exec: filename=(.*?) pid=(\d+) old_pid=(\d+)', line)
        if match:
            execs.append((int(match.group(2)), match.group(1)))
        match = re.search(r'-(\d+)\s+\[\d+\].*sys_clone3 -> (0x[0-9a-fA-F]+|-?\d+)', line)
        if match:
            parent_pid = int(match.group(1)); returned_pid = int(match.group(2), 0)
            if 0 < returned_pid < 2**31:
                clone3_returns.add((parent_pid, returned_pid))
    if trace_config.get('syscall_requested'):
        observations.append('sys_clone3 ftrace exposes only the userspace clone_args pointer and size, not flags or cgroup FD contents. Successful parent returns are correlated with fork edges; CLONE_INTO_CGROUP flags remain frozen-runtime/source evidence plus early cgroup observations, not decoded syscall arguments.')

    def check_identity(label, identity, target, expected_cgroup, root=None, gated=False):
        check(label + ':namespace_set', set(identity.get('ns', {})) == {'user', 'mnt', 'pid', 'net', 'ipc', 'uts'})
        check(label + ':target_namespaces', identity.get('ns') == target)
        status = identity.get('status', {})
        try:
            zero = all(int(status.get(name, '-1'), 16) == 0 for name in CAPS)
        except (ValueError, TypeError):
            zero = False
        check(label + ':caps_zero', zero)
        check(label + ':nnp_seccomp', status.get('NoNewPrivs') == '1' and status.get('Seccomp') == '2')
        check(label + ':business_cgroup', expected_cgroup in identity.get('cgroup', ''))
        fds = identity.get('fds', {})
        check(label + ':fd_inventory', set(fds) >= {'0', '1', '2'} and (len(fds) == 5 if gated else set(fds) == {'0', '1', '2'}))
        check(label + ':distinct_output_pipes', str(fds.get('1', '')).startswith('pipe:[')
              and str(fds.get('2', '')).startswith('pipe:[') and fds.get('1') != fds.get('2'))
        if not gated:
            check(label + ':cwd', identity.get('cwd') == '/work')
            if root is not None:
                check(label + ':root', identity.get('root_identity') == root)

    final_paths = sorted((p for p in run.glob('*.json') if re.fullmatch(r'\d+-.*\.json', p.name)),
                         key=lambda path: int(path.name.split('-', 1)[0]))
    rows = [read(path.name) for path in final_paths]
    journals = [read(path.name) for path in sorted(run.glob('attempt-*.json'))]
    suite = config.get('tool_suite')
    if suite:
        catalog_path = run / 'prototype/tool_cases.py'
        catalog_suites = {}
        if catalog_path.is_file():
            # Decode only literal suite declarations. Never execute the frozen
            # Python file or its imports while auditing untrusted artifacts.
            for node in ast.parse(catalog_path.read_text()).body:
                if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                    continue
                target = node.targets[0]
                if isinstance(target, ast.Name) and target.id == 'SUITES':
                    catalog_suites.update(ast.literal_eval(node.value))
                elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id == 'SUITES':
                    try:
                        catalog_suites[ast.literal_eval(target.slice)] = ast.literal_eval(node.value)
                    except (ValueError, TypeError):
                        pass
            if suite == 'all' and 'all' not in catalog_suites:
                catalog_suites['all'] = [case for name in ('level1', 'level2', 'level3', 'level4', 'lifecycle', 'budgets') for case in catalog_suites.get(name, [])]
        expected = catalog_suites.get(suite, [suite]) * int(config.get('tool_repeats', 1))
        actual = [row.get('case') for row in rows]
        actual += [row.get('case') for row in journals if row.get('nonce') not in {entry.get('nonce') for entry in rows}]
        check('configured_suite_executed_in_full', actual == expected, {'actual': actual, 'expected': expected})
    elif config.get('case') in ('control', 'runtime'):
        check('warm_three_request_matrix', [row.get('case') for row in rows] == ['normal', 'normal', 'nonzero'])
    check('attempt_evidence_present', bool(rows or journals))
    nonces = [row.get('nonce') for row in rows]
    check('unique_completed_attempts', len(set(nonces)) == len(nonces))
    h_attempts = {item.get('nonce'): item for item in sup.get('attempts', [])}
    wait_records = sup.get('wait_records', [])
    controllers = [entry for entry in wait_records if entry.get('pid') == sup.get('controller_pid')]
    check('H_actual_controller_wait', len(controllers) == 1 and controllers[0].get('wait_status') == sup.get('controller_wait_status'))
    summary_rows = read('summary.json', required=False).get('rows', [])
    if sup.get('failure_reason') is None:
        check('summary_covers_every_completed_row', {entry.get('nonce') for entry in summary_rows} == set(nonces))
        check('all_journals_finished', {entry.get('nonce') for entry in journals} == set(nonces))

    for path, row in zip(final_paths, rows):
        nonce = row.get('nonce')
        label = str(row.get('case')) + ':' + str(nonce)
        h = h_attempts.get(nonce, {})
        ev = [entry for entry in events if entry.get('nonce') == nonce]
        z = [entry for entry in zl if entry.get('nonce') == nonce]
        check(label + ':resources', row.get('resources') == 'RELEASED' and row.get('resources_removed') is True and row.get('domain_empty') is True)
        check(label + ':EOF', row.get('output_eof') is True)
        check(label + ':sealed', str(row.get('admission')).startswith('SEALED'))
        check(label + ':seal_evidence', any(entry.get('event') == 'CANCEL_ACK' and entry.get('sealed') is True for entry in ev)
              or (row.get('admission') == 'SEALED_CREATOR_WAITED' and any(entry.get('pid') == row.get('zygote_pid') for entry in row.get('wait_records', []))))
        check(label + ':controller_fds_restored', row.get('controller_fd_before') == row.get('controller_fd_after'))
        check(label + ':response_after_retire', row.get('response_committed') is True and h.get('retired') is True)
        check(label + ':monitor_real_wait', any(entry.get('pid') == row.get('monitor_pid') and entry.get('wait_status') == row.get('monitor_wait') for entry in row.get('wait_records', [])))
        for name, stats in row.get('stats', {}).items():
            check(label + ':empty_stats:' + name, counts(stats.get('cgroup.events')).get('populated') == 0
                  and str(stats.get('pids.current', '')).strip() == '0')
        check(label + ':all_cgroup_stats', set(row.get('stats', {})) == {'task', 'control', 'transition', 'business'})
        s, w = row.get('s_pid'), row.get('w_pid')
        if s is not None and tracing:
            check(label + ':Z_fork_S', (row.get('zygote_pid'), s) in forks)
            if trace_config.get('syscall_requested'):
                check(label + ':Z_clone3_return_S', (row.get('zygote_pid'), s) in clone3_returns)
            check(label + ':S_exited', s in exits)
            check(label + ':S_no_exec', not any(pid == s for pid, _ in execs))
        if w is not None and tracing:
            check(label + ':S_fork_W', (s, w) in forks)
            if trace_config.get('syscall_requested'):
                check(label + ':S_clone3_return_W', (s, w) in clone3_returns)
            check(label + ':W_exited', w in exits)
            descendants = {w}
            while True:
                expanded = descendants | {child for parent, child in forks if parent in descendants}
                if expanded == descendants:
                    break
                descendants = expanded
            check(label + ':all_tool_descendants_exit_traced', descendants <= exits)
            process_trees.append({'nonce': nonce, 'root_pid': w, 'pids': sorted(descendants),
                                  'all_exit_traced': descendants <= exits,
                                  'execs': [{'pid': pid, 'filename': filename} for pid, filename in execs if pid in descendants]})
        if row.get('s_wait') is not None:
            check(label + ':S_real_wait', any(entry.get('event') == 'ACTUAL_TRANSITION_WAIT' and entry.get('pid') == s and entry.get('wait_status') == row['s_wait'] for entry in z)
                  or any(entry.get('pid') == s and entry.get('wait_status') == row['s_wait'] for entry in row.get('wait_records', [])))
        worker_wait = row.get('w_wait')
        if worker_wait is not None:
            wait_status = worker_wait.get('wait_status')
            check(label + ':W_real_wait', any(entry.get('event') == 'ACTUAL_WORKER_WAIT' and entry.get('worker_host_pid') == w and entry.get('wait_status') == wait_status for entry in z)
                  or any(entry.get('pid') == w and entry.get('wait_status') == wait_status for entry in row.get('wait_records', [])))
            check(label + ':result_from_real_wait', isinstance(wait_status, int) and row.get('result', {}).get('exit_code') == os.waitstatus_to_exitcode(wait_status))
        elif row.get('business_permit'):
            check(label + ':missing_wait_stays_unknown', row.get('business') == 'UNKNOWN' and row.get('result') is None and row.get('outcome') != 'SUCCEEDED')
        if row.get('failure') is None:
            check(label + ':normal_completion_waits', row.get('s_wait') == 0 and worker_wait is not None and row.get('drained', {}).get('echild') is True and row.get('monitor_wait') == 0)
        if row.get('execution_mode') != 'tool_exec':
            worker = row.get('worker') or {}
            if worker:
                check(label + ':warm_all_19_checks', set(worker.get('checks', {})) == WARM_CHECKS
                      and all(value is True for value in worker.get('checks', {}).values()))
                check(label + ':warm_heap_matches_Z', worker.get('inherited') == row.get('expected_state'))
                identity = worker.get('identity', {})
                check(label + ':warm_actual_namespaces', identity.get('ns') == row.get('target_ns'))
                check(label + ':warm_actual_fd_allowlist', set(identity.get('fds', {})) == {'0', '1', '2'})
                check(label + ':warm_actual_cgroup', '/d-' + nonce + '/business' in identity.get('cgroup', ''))
                status = identity.get('status', {})
                check(label + ':warm_actual_caps_nnp_seccomp', all(int(status.get(name, '-1'), 16) == 0 for name in CAPS)
                      and status.get('NoNewPrivs') == '1' and status.get('Seccomp') == '2')
            else:
                check(label + ':warm_business_boundary_observed', not row.get('business_permit'))
            if tracing:
                check(label + ':warm_W_no_exec', not any(pid == w for pid, _ in execs))
            continue
        check(label + ':two_stream_EOF', row.get('stream_eof') == {'stdout': True, 'stderr': True})
        check(label + ':H_two_stream_retire', h.get('streams') == ['stdout', 'stderr'] and
              set(h.get('output_streams', {})) == STREAMS and all(stream.get('output_eof') is True for stream in h.get('output_streams', {}).values()))
        check(label + ':no_stdout_control_record', row.get('worker') is None and not any(entry.get('event') in ('WORKER_READY', 'WORKER_EXIT') for entry in ev))
        security = row.get('tool_security') or {}
        if security:
            check(label + ':required_gate_checks', set(security.get('checks', {})) == TOOL_CHECKS and all(value is True for value in security.get('checks', {}).values()))
            check(label + ':trusted_gate_receipt', any(entry.get('event') == 'WORKER_GATED' and entry.get('tool_security') == security for entry in ev))
            check_identity(label + ':gate_identity', security.get('identity', {}), row.get('target_ns'), '/d-' + nonce + '/business', gated=True)
        else:
            check(label + ':gate_security_required', not row.get('business_permit'))
        case = row.get('tool_case') or {}
        data_by_stream = {}
        for stream in ('stdout', 'stderr'):
            file = path.with_name(path.stem + '-' + stream + '.log')
            check(label + ':raw_' + stream + '_file', file.is_file())
            data = file.read_bytes() if file.is_file() else b''
            data_by_stream[stream] = data
            retained = row.get('bytes_retained', {}).get(stream)
            check(label + ':' + stream + '_retained_count', retained == len(data) and len(data) <= 1024 * 1024)
            check(label + ':' + stream + '_count_monotonic', row.get('stream_bytes', {}).get(stream, -1) >= len(data))
            check(label + ':' + stream + '_EOF_event', any(entry.get('event') == 'TOOL_STREAM_EOF' and entry.get('stream') == stream for entry in ev))
            check(label + ':' + stream + '_complete_matches_retention', row.get('stream_complete', {}).get(stream) is (row.get('stream_truncated', {}).get(stream) is False))
            for index, expected in enumerate(case.get('expected_' + stream, [])):
                check(label + ':' + stream + '_fixture:' + str(index), expected.encode() in data)
        # Fixed fixture JSON is an offline observation only, never authority.
        identities = []
        for line in data_by_stream.get('stdout', b'').splitlines():
            try:
                entry = json.loads(line)
                if isinstance(entry, dict) and entry.get('event') == 'TOOL_IDENTITY':
                    identities.append(entry)
            except ValueError:
                pass
        for index, identity in enumerate(identities):
            check_identity(label + ':fixed_fixture_identity:' + str(index), identity, row.get('target_ns'),
                           '/d-' + nonce + '/business', row.get('root_identity'))
        action = case.get('action')
        if action == 'cancel_before_business':
            check(label + ':no_permission_no_business', row.get('business_permit') is False and row.get('business') == 'NOT_EXECUTED')
            check(label + ':no_tool_bytes_before_gate', not any(data_by_stream.values()))
            if tracing:
                check(label + ':no_exec_before_gate', not any(pid == w for pid, _ in execs))
        else:
            check(label + ':business_permission_recorded', row.get('business_permit') is True)
            if tracing:
                check(label + ':actual_launcher_exec', any(pid == w and filename == '/probe/tool_launcher' for pid, filename in execs))
                argv = case.get('argv', [])
                check(label + ':actual_target_exec', bool(argv) and any(pid == w and filename == argv[0] for pid, filename in execs))
        if action == 'result_loss_side_effect':
            check(label + ':lost_receipt_unknown', row.get('business') == 'UNKNOWN' and row.get('result') is None and row.get('outcome') == 'RESULT_UNKNOWN')
            check(label + ':lost_receipt_raw_wait_and_drop', any(entry.get('event') == 'ACTUAL_WORKER_WAIT' for entry in z)
                  and any(entry.get('event') == 'FAULT_WORKER_WAIT_RECEIPT_DROPPED' for entry in z)
                  and not any(entry.get('event') == 'WORKER_WAITED' for entry in ev))
            check(label + ':side_effect_not_success', 'FIXED_TOOL_SIDE_EFFECT' in row.get('workspace_snapshot', {}).get('tool-side-effect', {}).get('text', ''))
        elif action != 'cancel_before_business' and case.get('expected_exit') is not None:
            check(label + ':expected_exit', (row.get('result') or {}).get('exit_code') == case['expected_exit'])
        if case.get('expected_signal') is not None:
            actual = (row.get('result') or {}).get('exit_code')
            check(label + ':expected_signal_or_honest_unknown', actual == -case['expected_signal'] or
                  (row.get('business') == 'UNKNOWN' and row.get('outcome') in ('CANCELLED', 'TIMED_OUT')))
        if case.get('expected_outcome') is not None:
            check(label + ':explicit_expected_outcome', row.get('outcome') == case['expected_outcome'])
        if action not in ('cancel', 'controller_death', 'result_loss_side_effect', 'cancel_before_business') and not case.get('expect_timeout') and not case.get('expect_descendants_after_main') and case.get('expected_outcome') is None:
            check(label + ':no_unexpected_infrastructure_failure', row.get('failure') is None)
        if action == 'cancel':
            check(label + ':cancel_outcome', row.get('outcome') == 'CANCELLED')
        if case.get('expect_timeout'):
            check(label + ':timeout_outcome', row.get('outcome') == 'TIMED_OUT')
        if case.get('expect_descendants_after_main'):
            check(label + ':post_main_descendant_deadline', row.get('outcome') == 'DESCENDANT_DEADLINE' and (row.get('result') or {}).get('exit_code') == 0)
        if row.get('case') == 'tool_pids_budget':
            check(label + ':pids_kernel_rejection', counts(row.get('stats', {}).get('business', {}).get('pids.events')).get('max', 0) > 0)
        if row.get('case') == 'tool_cpu_budget':
            check(label + ':cpu_throttled', counts(row.get('stats', {}).get('business', {}).get('cpu.stat')).get('nr_throttled', 0) > 0)
        if row.get('case') == 'tool_memory_budget':
            check(label + ':actual_oom_kill', counts(row.get('stats', {}).get('business', {}).get('memory.events')).get('oom_kill', 0) > 0)
        if row.get('case') == 'tool_output_limit':
            check(label + ':actual_output_limit_cancellation', row.get('failure') == 'OUTPUT_LIMIT' and
                  any(entry.get('event') == 'CANCEL_REQUEST' and entry.get('reason') == 'OUTPUT_LIMIT' for entry in ev))
            check(label + ':stdout_bounded_and_truncation_explicit', row.get('stream_bytes', {}).get('stdout', 0) > 1024 * 1024
                  and row.get('bytes_retained', {}).get('stdout') == 1024 * 1024
                  and row.get('stream_truncated', {}).get('stdout') is True and row.get('stream_complete', {}).get('stdout') is False)
        if row.get('case') == 'tool_unsafe_result':
            workspace = row.get('workspace_snapshot', {})
            fifo = workspace.get('result', {})
            link = workspace.get('link', {})
            check(label + ':FIFO_not_read', stat.S_ISFIFO(fifo.get('mode', 0)) and 'text' not in fifo)
            check(label + ':symlink_not_followed', stat.S_ISLNK(link.get('mode', 0)) and link.get('symlink') == '/state' and 'text' not in link)
        if row.get('case') == 'tool_output_spoof':
            stdout = data_by_stream.get('stdout', b'')
            check(label + ':real_nonce_spoof_remained_data', nonce.encode() in stdout
                  and b'real-nonce-output-spoof' in stdout and row.get('worker') is None)

    crashed = [row for row in journals if (row.get('tool_case') or {}).get('action') == 'controller_death'
               or (row.get('execution_mode') != 'tool_exec' and row.get('case') == 'controller_death')]
    if crashed:
        check('controller_death_no_success_summary', not summary_rows)
        check('controller_death_H_unknown', sup.get('business_result') == 'UNKNOWN' and sup.get('controller_wait_status') == 9)
        check('controller_death_real_adopted_wait', any(entry.get('role') == 'adopted-child' for entry in wait_records))
        for row in crashed:
            nonce = row.get('nonce'); h = h_attempts.get(nonce, {})
            label = 'controller_death:' + str(nonce)
            tool_mode = row.get('execution_mode') == 'tool_exec'
            expected_streams = ['stdout', 'stderr'] if tool_mode else ['combined']
            check(label + ':no_response_commit', row.get('response_committed') is not True and nonce not in nonces)
            check(label + ':H_unknown_resources_released', h.get('business_result') == 'UNKNOWN' and h.get('resources_removed') is True)
            check(label + ':registered_outputs_match_mode', h.get('streams') == expected_streams and set(h.get('output_streams', {})) == set(expected_streams))
            check(label + ':H_all_EOF_and_unknown_content', h.get('output_eof') is True and h.get('output_complete') is None
                  and all(value.get('output_eof') is True and value.get('complete') is None for value in h.get('output_streams', {}).values()))
            for stream, value in h.get('output_streams', {}).items():
                check(label + ':bounded_recovery:' + stream, value.get('stored_bytes', -1) >= 0 and value.get('stored_bytes', 2**32) <= 1024 * 1024
                      and value.get('drained_bytes') == value.get('stored_bytes', 0) + value.get('discarded_bytes', 0))
                check(label + ':raw_H_EOF:' + stream, any(entry.get('event') == 'SUPERVISOR_OUTPUT_EOF' and entry.get('nonce') == nonce and entry.get('stream') == stream for entry in se))
            if tool_mode:
                security = row.get('tool_security') or {}
                check(label + ':trusted_gate_was_reached', bool(security) and row.get('business_permit') is True)
                if security:
                    check_identity(label + ':gate_identity', security.get('identity', {}), row.get('target_ns'), '/d-' + nonce + '/business', gated=True)
            else:
                worker = row.get('worker') or {}
                check(label + ':warm_19_business_checks_before_crash', set(worker.get('checks', {})) == WARM_CHECKS
                      and all(value is True for value in worker.get('checks', {}).values()))
                check(label + ':warm_heap_matches_Z', worker.get('inherited') == row.get('expected_state'))
                identity = worker.get('identity', {})
                check(label + ':warm_namespaces_and_fd_boundary', identity.get('ns') == row.get('target_ns')
                      and set(identity.get('fds', {})) == {'0', '1', '2'}
                      and '/d-' + nonce + '/business' in identity.get('cgroup', ''))
            if tracing:
                w = row.get('w_pid'); s = row.get('s_pid')
                check(label + ':actual_Z_S_W', (row.get('zygote_pid'), s) in forks and (s, w) in forks)
                if tool_mode:
                    check(label + ':actual_tool_exec_and_exit', any(pid == w and filename == '/probe/tool_launcher' for pid, filename in execs) and w in exits)
                else:
                    check(label + ':warm_no_exec_and_exit', not any(pid == w for pid, _ in execs) and w in exits)
                descendants = {w}
                while True:
                    expanded = descendants | {child for parent, child in forks if parent in descendants}
                    if expanded == descendants:
                        break
                    descendants = expanded
                check(label + ':all_tool_descendants_exit_traced', descendants <= exits)
                process_trees.append({'nonce': nonce, 'root_pid': w, 'pids': sorted(descendants),
                                      'all_exit_traced': descendants <= exits,
                                      'execs': [{'pid': pid, 'filename': filename} for pid, filename in execs if pid in descendants]})
    if sup.get('failure_reason') is not None and not crashed:
        check('unexpected_supervisor_recovery', False, sup.get('failure_reason'))
    failed = [item for item in checks if item['required'] and item['value'] is False]
    blocked = [item for item in checks if item['required'] and item['value'] is None]
    status = 'FAIL' if failed else 'BLOCKED' if blocked else 'PASS'
    return {'run': str(run), 'status': status, 'audit_scope': 'execution_qualification' if tracing else 'evidence_only_no_trace',
            'counts': {'checks': len(checks), 'failed': len(failed), 'blocked': len(blocked),
                       'completed_rows': len(rows), 'controller_death_attempts': len(crashed)},
            'failures': failed, 'blocked': blocked, 'observations': observations, 'checks': checks,
            'process_trees': process_trees,
            'input_source_sha256': source, 'verifier_sha256': sha(Path(__file__)),
            'clone3_evidence': {'successful_parent_return_edges': sorted(clone3_returns),
                                'flags_decoded_from_trace': False,
                                'argument_pointer_only': bool(trace_config.get('syscall_requested'))},
            'limitations': ['No workload is run by this verifier.', 'Fixed fixture stdout is only offline test evidence, never a control message.',
                            'Trace exit corroborates process termination; real wait evidence remains separately required.',
                            'H survival and the declared private VM/filesystem contract remain assumptions.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', help='new exec_support run basename or path')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--allow-no-trace', action='store_true', help='explicit evidence-only cost audit; no fork/exec qualification')
    args = parser.parse_args()
    run = Path(args.run)
    if run.name == args.run:
        run = STUDY / 'runs' / args.run
    run = run.resolve()
    if not run.is_dir() or not run.is_relative_to((STUDY / 'runs').resolve()):
        parser.error('only an existing exec_support/runs directory may be audited')
    report = analyze(run, args.allow_no_trace)
    if not args.check_only:
        out = args.out or STUDY / 'analysis' / ('verify-exec-' + run.name + '.json')
        if out.resolve().is_relative_to((STUDY / 'runs').resolve()):
            parser.error('audit must not modify raw runs')
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open('x') as stream:
            json.dump(report, stream, indent=2, ensure_ascii=False)
            stream.write('\n')
    print(json.dumps({key: report[key] for key in ('run', 'status', 'audit_scope', 'counts', 'failures', 'blocked')}, ensure_ascii=False, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
