#!/usr/bin/env python3
"""Read-only, independent audit of followup VM artifacts.

This script never imports the frozen product or any workload. Its private-pipe
decoder is independent of exec_receipt.py. Expected fault outcomes come from an
explicit experiment manifest, never from product verdicts. FAIL means evidence
contradicts a required assertion; BLOCKED means necessary evidence is absent.
An experiment PASS is not a claim that an INCOMPLETE recovery was successful.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

STUDY = Path(__file__).resolve().parents[1]
LIMIT = 1 << 20
STAGES = {1: 'LAUNCHER_EXEC_ATTEMPT', 2: 'LAUNCHER_EXEC_FAILED',
          3: 'LAUNCHER_READY', 4: 'TARGET_EXEC_ATTEMPT',
          5: 'EXEC_FAILED', 6: 'LAUNCHER_SETUP_FAILED'}
TRANSITIONS = {0: {1}, 1: {2, 3, 6}, 2: set(), 3: {4, 6},
               4: {5}, 5: set(), 6: set()}
FRAME = struct.Struct('<4sBBHiIQ')
CAPS = ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')
TOOL_CHECKS = {'namespaces', 'root_identity', 'cgroup', 'caps_zero', 'nnp_seccomp',
               'fd_allowlist', 'cwd', 'environment', 'no_management_paths'}
PROTOCOL_REJECT = {
    'register_missing_fds', 'register_extra_fd', 'register_duplicate_pipe',
    'register_nonpipe', 'register_write_end', 'register_bad_order',
    'register_bad_names', 'register_path_identity', 'register_same_nonce_new_pipe',
    'register_same_nonce_swapped_pipe', 'register_named_fifo',
    'retire_missing_stream', 'retire_false_stream', 'retire_fake_eof_buffered',
    'retire_fake_eof_open_writer', 'done_unretired', 'unknown_op_with_fd',
    'malformed_json_with_fd',
}
PROTOCOL_REASON = {
    'register_missing_fds': 'one read FD per named output stream',
    'register_extra_fd': 'one read FD per named output stream',
    'register_duplicate_pipe': 'distinct pipe objects',
    'register_nonpipe': 'output must be a pipe',
    'register_write_end': 'output must be read-only',
    'register_bad_order': 'streams must be stdout,stderr in that order',
    'register_bad_names': 'streams must be stdout,stderr in that order',
    'register_path_identity': 'paths do not match nonce and owned roots',
    'register_same_nonce_new_pipe': 'changes output object',
    'register_same_nonce_swapped_pipe': 'changes output object',
    'register_named_fifo': 'output must be an anonymous pipe',
    'retire_missing_stream': 'requires EOF for both stdout and stderr',
    'retire_false_stream': 'requires EOF for both stdout and stderr',
    'retire_fake_eof_buffered': 'pipe EOF is not independently confirmed',
    'retire_fake_eof_open_writer': 'pipe EOF is not independently confirmed',
    'done_unretired': 'DONE with unretired attempts',
    'unknown_op_with_fd': 'unknown supervisor operation',
    'malformed_json_with_fd': 'JSONDecodeError',
}
R = '/workloads/bin/receipt-probe'
L = '/probe/tool_launcher'
A_EXPECTED = {
    'receipt_static': {'receipt_stages': [1, 3, 4], 'exec_paths': [L, R], 'exit_code': 0, 'target_fd_check': True},
    'receipt_launcher_missing': {'receipt_stages': [1, 2], 'exec_paths': [], 'exit_code': 125, 'receipt_errno': 2, 'receipt_status': 'LAUNCHER_FAILED'},
    'receipt_target_missing': {'receipt_stages': [1, 3, 4, 5], 'exec_paths': [L], 'exit_code': 127, 'receipt_errno': 2, 'receipt_status': 'TARGET_EXEC_FAILED'},
    'receipt_target_noexec': {'receipt_stages': [1, 3, 4, 5], 'exec_paths': [L], 'exit_code': 127, 'receipt_errno': 13, 'receipt_status': 'TARGET_EXEC_FAILED'},
    'receipt_target_format': {'receipt_stages': [1, 3, 4, 5], 'exec_paths': [L], 'exit_code': 127, 'receipt_errno': 8, 'receipt_status': 'TARGET_EXEC_FAILED'},
    'receipt_loader_missing': {'receipt_stages': [1, 3, 4], 'exec_paths': [L, '/workloads/bin/linked-missing'], 'exit_code': 127},
    'receipt_exit127': {'receipt_stages': [1, 3, 4], 'exec_paths': [L, R], 'exit_code': 127, 'target_fd_check': True},
    'receipt_launcher_sigkill': {'receipt_stages': [1, 3, 4], 'exec_paths': [L], 'exit_code': -9},
    'receipt_drop_error': {'receipt_stages': [1, 3, 4], 'exec_paths': [L], 'exit_code': 127},
    'receipt_early_death': {'receipt_stages': [1], 'exec_paths': [L], 'exit_code': 124},
    'receipt_timeout': {'exec_paths': [L], 'receipt_missing_allowed': True, 'expected_outcome': 'TIMED_OUT'},
    'receipt_controller_death': {'exec_paths': [L], 'receipt_missing_allowed': True, 'controller_death': True},
    'receipt_spoof': {'receipt_stages': [1, 3, 4], 'exec_paths': [L, R], 'exit_code': 0, 'target_fd_check': True},
    'elf_static': {'receipt_stages': [1, 3, 4], 'exec_paths': [L, '/workloads/bin/probe-static'], 'exit_code': 0},
    'tool_before_gate_cancel': {'exec_paths': [], 'receipt_missing_allowed': True, 'not_executed': True},
    'tool_output_spoof': {'receipt_stages': [1, 3, 4], 'exec_paths': [L, '/workloads/bin/probe-dynamic'], 'exit_code': 0},
    'shell_cancel': {'exec_paths': [L, '/bin/sh'], 'receipt_missing_allowed': True, 'expected_outcome': 'CANCELLED'},
}


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(4 << 20), b''):
            digest.update(data)
    return digest.hexdigest()


def parse_receipt(data, eof):
    """Return independent protocol facts. In particular, never infer success."""
    rows = []
    error = None
    previous = 0
    last_ns = 0
    if len(data) > 192:
        error = 'receipt_limit'
    elif eof and len(data) % 24:
        error = 'truncated_frame_at_eof'
    else:
        for offset in range(0, len(data) - len(data) % 24, 24):
            magic, version, stage, reserved, eno, detail, ns = FRAME.unpack_from(data, offset)
            if magic != b'SXRC' or version != 1 or reserved != 0:
                error = 'frame_header'; break
            if stage not in STAGES:
                error = 'unknown_stage'; break
            if (stage in {2, 5, 6} and not 1 <= eno <= 4095) or (stage not in {2, 5, 6} and eno != 0):
                error = 'invalid_errno'; break
            if (stage == 6 and detail not in range(1, 13)) or (stage != 6 and detail != 0):
                error = 'invalid_detail'; break
            if stage not in TRANSITIONS[previous]:
                error = 'stage_order'; break
            if ns and last_ns and ns < last_ns:
                error = 'timestamp_order'; break
            rows.append({'event': STAGES[stage], 'errno': eno, 'detail': detail,
                         'monotonic_ns': ns})
            previous = stage
            if ns:
                last_ns = ns
    status = 'EXEC_STATUS_UNKNOWN'
    failure_stage = None
    error_number = None
    if error is None and rows:
        last = rows[-1]
        if last['event'] in ('LAUNCHER_EXEC_FAILED', 'LAUNCHER_SETUP_FAILED', 'EXEC_FAILED'):
            failure_stage = {'LAUNCHER_EXEC_FAILED': 'launcher_exec',
                             'LAUNCHER_SETUP_FAILED': 'launcher_setup',
                             'EXEC_FAILED': 'target_exec'}[last['event']]
            status = 'TARGET_EXEC_FAILED' if failure_stage == 'target_exec' else 'LAUNCHER_FAILED'
            error_number = last['errno']
    return {'valid': error is None, 'error': error, 'status': status,
            'stages': [row['event'] for row in rows], 'records': rows,
            'failure_stage': failure_stage, 'errno': error_number,
            'bytes': len(data), 'pending_bytes': len(data) % 24,
            'eof': eof, 'success_observed': False}


class Audit:
    def __init__(self, run, profile, expected):
        self.run, self.profile, self.expected = run, profile, expected
        self.checks, self.observations, self.request_facts = [], [], []
        self.unsupported_dimensions = []

    def check(self, name, value, evidence=None):
        self.checks.append({'check': name, 'value': value if value is None else bool(value),
                            'evidence': evidence})

    def read(self, name, required=True):
        path = self.run / name
        if not path.is_file():
            if required:
                self.check('present:' + name, None)
            return {}
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            self.check('parse:' + name, False, repr(exc))
            return {}

    def lines(self, name, required=True):
        path = self.run / name
        if not path.is_file():
            if required:
                self.check('present:' + name, None)
            return []
        rows = []
        for number, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
            try:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError('not a JSON object')
                rows.append(value)
            except ValueError as exc:
                self.check(f'jsonl:{name}:{number}', False, repr(exc))
        return rows

    def manifest(self, name, directory, build=None):
        manifest = self.read(name)
        self.check(name + ':nonempty', bool(manifest))
        for rel, digest in manifest.items():
            path = Path(rel)
            safe = not path.is_absolute() and '..' not in path.parts
            local = self.run / directory / path
            self.check(name + ':' + rel, safe and local.is_file() and not local.is_symlink()
                       and sha(local) == digest)
            if build is not None:
                self.check(name + ':guest-build:' + rel, build.get(rel) == digest)
        return manifest

    def common(self):
        self.config = self.read('review-config.json')
        result = self.read('result.json')
        self.check('private_VM_did_not_timeout', result.get('timeout') is False)
        self.check('QEMU_exit_recorded', result.get('qemu_rc') == 0)
        serial = self.run / 'serial.log'
        self.check('guest_completion_marker', serial.is_file() and
                   re.search(r'BENCHMARK_LAB_COMPLETE rc=-?\d+', serial.read_text(errors='replace')) is not None)
        command = self.read('command.json')
        self.check('QEMU_no_network', isinstance(command, list) and '-net' in command
                   and command[command.index('-net') + 1] == 'none')
        self.check('QEMU_private_evidence_and_state', isinstance(command, list)
                   and any('file=' + str(self.run / 'disk.raw') in str(x) for x in command)
                   and any('id=evidence,path=' + str(self.run) in str(x) for x in command))
        environment = self.read('environment.json')
        self.check('guest_runtime_versions_recorded', all(environment.get(k) for k in ('kernel', 'python', 'glibc')))
        lab = self.read('lab-manifest.json')
        self.check('guest_kernel_initramfs_frozen', bool(lab.get('kernel_sha256')) and bool(lab.get('initramfs_sha256')))
        build = self.read('build.json')
        self.source = self.manifest('source-sha.json', 'prototype', build)
        self.tool_source = self.manifest('tools-source-sha.json', 'tools')
        tool_build = self.read('tool-build-sha256.json', required=False)
        for name, value in tool_build.items():
            if name.startswith('bin/'):
                path = self.run / 'tool-binaries' / name[4:]
                self.check('tool_binary_sha:' + name, path.is_file() and sha(path) == value)
            else:
                self.check('tool_build_source:' + name, self.tool_source.get(name) == value)
        candidate = self.manifest('candidate-runtime-sha.json', 'candidate-runtime')
        baseline = STUDY.with_name('exec_support') / 'runs/qualification-exec-01-level1/candidate-runtime-sha.json'
        self.check('candidate_D_unchanged', baseline.is_file()
                   and candidate == json.loads(baseline.read_text()))
        variant = self.read('variant-manifest.json')
        self.check('variant_source_matches', variant.get('source_sha256') == self.source)
        for name, digest in variant.get('binary_sha256', {}).items():
            path = self.run / name
            self.check('binary_sha:' + name, Path(name).name == name and path.is_file()
                       and sha(path) == digest == build.get(name))
        self.se = self.lines('supervisor-events.jsonl')
        self.events = self.lines('events.jsonl', required=False)
        self.sup = self.read('supervisor.json')
        self.release = self.read('external-final-release.json', required=False)
        if not self.sup:
            exception_rows = self.lines('protocol-fixture-h-events.jsonl', required=False)
            exceptions = [row for row in exception_rows if row.get('event') == 'PRODUCT_H_EXCEPTION']
            self.check('H_has_no_unhandled_product_exception', not exceptions if exception_rows else None, exceptions)
            self.observations.append('H final report is absent. Its missing wait, FD, and release assertions are unverified; they are not fabricated as observed leaks or successful cleanup.')
            self.trace()
            self.finals, self.rows = [], []
            return
        self.check('observer_never_cleanup', self.sup.get('observer_cleanup_used') is False)
        self.check('real_wait_ECHILD', self.sup.get('echild') is True)
        self.check('H_FD_inventory_restored', bool(self.sup.get('fd_before'))
                   and self.sup.get('fd_before') == self.sup.get('fd_after'))
        controller_pid = self.sup.get('controller_pid')
        waits = [row for row in self.sup.get('wait_records', []) if row.get('pid') == controller_pid]
        self.check('real_controller_wait', len(waits) == 1 and isinstance(waits[0].get('wait_status'), int)
                   and waits[0]['wait_status'] == self.sup.get('controller_wait_status'))
        self.check('no_live_task_cgroups', self.sup.get('remaining_cgroups') == [])
        physical = self.expected.get('physical_resources_released', True)
        expected_release = self.expected.get('h_release_state', 'RELEASED')
        self.check('expected_H_release_state', self.sup.get('release_state') == expected_release,
                   {'expected': expected_release, 'actual': self.sup.get('release_state')})
        self.check('legacy_release_flag_matches_total_state', self.sup.get('resources_removed') is (expected_release == 'RELEASED'))
        if self.profile in ('a', 'b1', 'b2', 'b4'):
            self.check('no_unexpected_protocol_errors', self.sup.get('protocol_errors') == [])
        allowed_errors = self.expected.get('allowed_error_messages', [])
        actual_errors = self.sup.get('errors', [])
        self.check('no_unexpected_recovery_errors', all(error.get('message') in allowed_errors for error in actual_errors), actual_errors)
        if 'physical_resources_released' in self.sup:
            self.check('physical_release_separate', self.sup['physical_resources_released'] is physical)
            observed_physical = (self.sup.get('remaining_cgroups') == [] and self.sup.get('remaining_workspaces') == []
                                 and self.sup.get('echild') is True and self.sup.get('fd_before') == self.sup.get('fd_after'))
            self.check('physical_release_matches_raw_dimensions', self.sup['physical_resources_released'] is observed_physical)
        else:
            self.check('physical_release_observation', (self.sup.get('remaining_workspaces') == []) is physical)
        for name in ('observer-after.json', 'observer-later.json'):
            observation = self.read(name)
            self.check(name + ':no_processes', observation.get('uid65534_processes') == {})
            if physical:
                self.check(name + ':no_workspaces', observation.get('workspaces') == {})
            else:
                self.check(name + ':workspace_failure_remains_visible', bool(observation.get('workspaces')))
            for cg, values in observation.get('cgroups', {}).items():
                self.check(name + ':empty:' + cg, str(values.get('pids.current', '')).strip() == '0'
                           and re.search(r'^populated 0$', values.get('cgroup.events', ''), re.M) is not None)
        if self.release:
            self.check('external_observer_no_kills', self.release.get('observer_killed_processes') is False)
            self.check('external_observer_no_product_removal', self.release.get('observer_removed_product_resources') is False)
        self.trace()
        final_paths = sorted((path for path in self.run.glob('[0-9]*-*.json')
                              if re.fullmatch(r'\d+-.*\.json', path.name)),
                             key=lambda path: int(path.name.split('-', 1)[0]))
        self.finals = [(path, self.read(path.name)) for path in final_paths
                       if re.fullmatch(r'\d+-.*\.json', path.name)]
        journal_rows = [self.read(path.name) for path in sorted(self.run.glob('attempt-*.json'))]
        final_nonces = {row.get('nonce') for _, row in self.finals}
        self.rows = [row for _, row in self.finals] + [row for row in journal_rows if row.get('nonce') not in final_nonces]
        if any(row.get('execution_mode') == 'tool_exec' for row in self.rows):
            self.unsupported_dimensions.extend([
                {'dimension': 'online_target_exec_success', 'status': 'NOT_IMPLEMENTED',
                 'reason': 'Private stage receipts and EOF do not prove target exec success. Only separately collected kernel exec trace provides offline image-transition evidence.'},
                {'dimension': 'generic_loader_failure_vs_program_exit127', 'status': 'BLOCKED_UNOBSERVABLE',
                 'reason': 'An executed dynamic loader failure and a program returning 127 can share receipt/EOF/wait observations. Fixed fixture stderr is not a generic trusted discriminator.'},
            ])
        self.zygote_records = []
        for path in self.run.glob('zygote-*.log'):
            for line in path.read_text(errors='replace').splitlines():
                try:
                    entry = json.loads(line)
                    if isinstance(entry, dict): self.zygote_records.append(entry)
                except ValueError:
                    pass  # Logs can also contain human traceback diagnostics.
        if self.rows:
            self.configured_cases()
        if self.rows:
            self.boundaries()
        if 'attempt_count' in self.expected:
            self.check('expected_attempt_count', len(self.rows) == self.expected['attempt_count'])

    def trace(self):
        self.execs, self.forks, self.exits = [], set(), set()
        path = self.run / 'process-trace.txt'
        self.check('process_trace_present', path.is_file())
        if not path.is_file():
            return
        stats = self.read('trace-stats.json')
        self.check('trace_stats_nonempty', bool(stats))
        for cpu, fields in stats.items():
            for field in ('overrun', 'commit overrun', 'dropped events'):
                found = re.search(r'^' + re.escape(field) + r':\s*(\d+)', fields, re.M)
                self.check('trace_loss:' + cpu + ':' + field, found is not None and int(found[1]) == 0)
        for line in path.read_text(errors='replace').splitlines():
            match = re.search(r'sched_process_exec: filename=(.*?) pid=(\d+) old_pid=(\d+)', line)
            if match:
                self.execs.append({'pid': int(match[2]), 'path': match[1]})
            match = re.search(r'sched_process_fork: .*\bpid=(\d+) .*\bchild_pid=(\d+)', line)
            if match:
                self.forks.add((int(match[1]), int(match[2])))
            match = re.search(r'sched_process_exit: .*\bpid=(\d+)', line)
            if match:
                self.exits.add(int(match[1]))

    def raw_receipt(self, row):
        receipt = row.get('exec_receipt')
        if not isinstance(receipt, dict):
            receipt = (row.get('w_wait') or {}).get('exec_receipt')
        receipt = receipt if isinstance(receipt, dict) else {}
        raw_hex = receipt.get('raw_hex', row.get('exec_receipt_raw_hex'))
        raw_file = receipt.get('raw_file', row.get('exec_receipt_raw_file'))
        if raw_hex is not None:
            try:
                return receipt, bytes.fromhex(raw_hex)
            except (TypeError, ValueError):
                self.check(str(row.get('nonce')) + ':valid_receipt_raw_hex', False)
        if raw_file:
            rel = Path(raw_file)
            if not rel.is_absolute() and '..' not in rel.parts and (self.run / rel).is_file():
                return receipt, (self.run / rel).read_bytes()
            self.check(str(row.get('nonce')) + ':safe_receipt_raw_file', False)
        return receipt, None

    def configured_cases(self):
        suite = self.config.get('tool_suite')
        if suite:
            source = self.run / 'prototype/tool_cases.py'
            suites = {}
            for node in ast.parse(source.read_text()).body:
                if not isinstance(node, ast.Assign) or len(node.targets) != 1: continue
                target = node.targets[0]
                try:
                    if isinstance(target, ast.Name) and target.id == 'SUITES':
                        suites.update(ast.literal_eval(node.value))
                    elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name) and target.value.id == 'SUITES':
                        suites[ast.literal_eval(target.slice)] = ast.literal_eval(node.value)
                except (ValueError, TypeError):
                    pass  # Never execute comprehensions or fixture imports.
            expected = suites.get(suite, [suite]) * int(self.config.get('tool_repeats', 1))
            actual = [row.get('case') for row in self.rows]
            self.check('configured_case_matrix_complete', actual == expected, {'actual': actual, 'expected': expected})
        elif self.config.get('case') in ('control', 'runtime'):
            self.check('warm_configured_case_matrix_complete', [row.get('case') for row in self.rows] == ['normal', 'normal', 'nonzero'])

    def boundaries(self):
        """The exec receipt is additional evidence, never a substitute for isolation."""
        source = self.run / 'prototype/run.py'
        try:
            tree = ast.parse(source.read_text())
            branches = [node for node in ast.walk(tree) if isinstance(node, ast.If)
                        and ast.unparse(node.test) == 'tool and item in output_fds']
            self.check('opaque_stdout_branch_unique', len(branches) == 1)
            if len(branches) == 1:
                names = []
                for node in ast.walk(branches[0]):
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name): names.append(node.func.id)
                        elif isinstance(node.func, ast.Attribute): names.append(node.func.attr)
                self.check('tool_output_not_protocol_parser', not {'loads', 'decode_receipts', 'eval', 'exec', 'recv', 'ss', 'zs'}.intersection(names)
                           and isinstance(branches[0].body[-1], ast.Continue))
        except (OSError, SyntaxError) as exc:
            self.check('frozen_output_branch_inspection', None, repr(exc))
        for row in self.rows:
            nonce = row.get('nonce'); key = str(row.get('case')) + ':' + str(nonce)
            if row.get('execution_mode') != 'tool_exec':
                continue
            security = row.get('tool_security') or {}
            self.check(key + ':trusted_gate_check_set', set(security.get('checks', {})) == TOOL_CHECKS
                       and all(value is True for value in security.get('checks', {}).values()))
            ident = security.get('identity', {})
            self.check(key + ':actual_six_namespaces', set(ident.get('ns', {})) == {'user', 'mnt', 'pid', 'net', 'ipc', 'uts'}
                       and ident.get('ns') == row.get('target_ns'))
            status = ident.get('status', {})
            try:
                caps_zero = all(int(status.get(name, '-1'), 16) == 0 for name in CAPS)
            except (ValueError, TypeError):
                caps_zero = False
            self.check(key + ':actual_capabilities_zero', caps_zero)
            self.check(key + ':actual_NNP_seccomp', status.get('NoNewPrivs') == '1' and status.get('Seccomp') == '2')
            fds = ident.get('fds', {})
            self.check(key + ':gate_stdio_plus_three_private_FDs', set(fds) >= {'0', '1', '2'} and len(fds) == 6)
            self.check(key + ':distinct_stdout_stderr_pipes', str(fds.get('1', '')).startswith('pipe:[')
                       and str(fds.get('2', '')).startswith('pipe:[') and fds.get('1') != fds.get('2'))
            self.check(key + ':business_cgroup_at_gate', '/d-' + str(nonce) + '/business' in ident.get('cgroup', ''))
            self.check(key + ':tool_stdout_not_worker_control', row.get('worker') is None
                       and not any(event.get('nonce') == nonce and event.get('event') in ('WORKER_READY', 'WORKER_EXIT') for event in self.events))
            s, w = row.get('s_pid'), row.get('w_pid')
            if s is not None:
                self.check(key + ':S_never_exec', not any(event['pid'] == s for event in self.execs))
            if w is not None:
                descendants = {w}
                while True:
                    expanded = descendants | {child for parent, child in self.forks if parent in descendants}
                    if expanded == descendants: break
                    descendants = expanded
                self.check(key + ':all_observed_descendants_exited', descendants <= self.exits)
        for _, row in self.finals:
            key = str(row.get('case')) + ':' + str(row.get('nonce'))
            self.check(key + ':final_domain_empty_removed', row.get('domain_empty') is True and row.get('resources_removed') is True)
            self.check(key + ':final_Controller_FDs_restored', row.get('controller_fd_before') == row.get('controller_fd_after'))
            self.check(key + ':final_output_EOF', row.get('output_eof') is True)
            self.check(key + ':final_admission_sealed', str(row.get('admission', '')).startswith('SEALED'))
            attempt = next((item for item in self.sup.get('attempts', []) if item.get('nonce') == row.get('nonce')), {})
            self.check(key + ':H_retired_before_response', attempt.get('retired') is True and row.get('response_committed') is True)
            if not self.expected.get('supervisor_baseline'):
                observed = attempt.get('retire_eof_observation', {})
                self.check(key + ':H_independent_RETIRE_EOF', set(observed) == set(attempt.get('streams', []))
                           and bool(observed) and all(value.get('output_eof') is True and value.get('writer_hangup') is True
                           and value.get('unread_bytes') == 0 for value in observed.values()))

    def audit_a(self):
        self.check('A_attempts_present', bool(self.rows))
        expected_cases = {**A_EXPECTED, **self.expected.get('cases', {})}
        for row in self.rows:
            name, nonce = row.get('case'), row.get('nonce')
            label = str(name) + ':' + str(nonce)
            if row.get('execution_mode') != 'tool_exec':
                worker = row.get('worker') or {}
                checks = worker.get('checks', {})
                self.check(label + ':warm_19_checks', len(checks) == 19 and all(value is True for value in checks.values()))
                self.check(label + ':warm_heap_inherited', worker.get('inherited') == row.get('expected_state') and bool(row.get('expected_state')))
                self.check(label + ':warm_target_stdio_only', set(worker.get('identity', {}).get('fds', {})) == {'0', '1', '2'})
                self.check(label + ':warm_W_no_exec', not any(event['pid'] == row.get('w_pid') for event in self.execs))
                if name == 'controller_death':
                    self.check(label + ':warm_death_business_UNKNOWN', self.sup.get('business_result') == 'UNKNOWN'
                               and self.sup.get('controller_wait_status') == 9 and row.get('response_committed') is not True)
                    attempts = [item for item in self.sup.get('attempts', []) if item.get('nonce') == nonce]
                    self.check(label + ':warm_combined_EOF_preserved', len(attempts) == 1 and attempts[0].get('streams') == ['combined']
                               and attempts[0].get('output_eof') is True and attempts[0].get('output_complete') is None)
                continue
            exp = dict(expected_cases.get(name, {}))
            exp.setdefault('receipt_status', 'EXEC_STATUS_UNKNOWN')
            if 'receipt_stages' in exp:
                exp['receipt_stages'] = [STAGES.get(stage, stage) for stage in exp['receipt_stages']]
            self.check(label + ':explicit_case_expectations', bool(exp) if expected_cases else None)
            receipt, raw = self.raw_receipt(row)
            if raw is None:
                self.check(label + ':private_raw_receipt', True if exp.get('receipt_missing_allowed') else None)
                self.check(label + ':missing_receipt_never_success', receipt.get('success_observed') is not True
                           and receipt.get('status') not in ('EXEC_SUCCEEDED', 'SUCCESS', 'EXEC_OBSERVED'))
                decoded = None
            else:
                decoded = parse_receipt(raw, bool(receipt.get('eof')))
                self.check(label + ':independent_receipt_valid', decoded['valid'])
                for field in ('status', 'stages', 'failure_stage', 'errno'):
                    self.check(label + ':receipt_' + field, receipt.get(field) == decoded[field],
                               {'decoded': decoded[field], 'recorded': receipt.get(field)})
                self.check(label + ':receipt_never_promotes_success', receipt.get('success_observed') is False)
                files = [path.with_name(path.stem + '-exec-receipt.bin') for path, final in self.finals if final.get('nonce') == nonce]
                self.check(label + ':receipt_binary_copy_matches', len(files) == 1 and files[0].is_file() and files[0].read_bytes() == raw)
                self.check(label + ':receipt_source_real_S_wait', receipt.get('source') == 'S_private_pipe_after_real_W_wait'
                           and isinstance((row.get('w_wait') or {}).get('wait_status'), int))
                logged = [entry for entry in self.zygote_records if entry.get('event') == 'PRIVATE_EXEC_RECEIPT'
                          and entry.get('nonce') == nonce and entry.get('worker_host_pid') == row.get('w_pid')]
                self.check(label + ':S_raw_receipt_log_matches_R', len(logged) == 1 and logged[0].get('receipt') == receipt)
                if 'receipt_stages' in exp:
                    self.check(label + ':expected_stages', decoded['stages'] == exp['receipt_stages'])
                for key in ('status', 'errno', 'failure_stage'):
                    if 'receipt_' + key in exp:
                        self.check(label + ':expected_' + key, decoded[key] == exp['receipt_' + key])
            pid = row.get('w_pid')
            actual_execs = [event['path'] for event in self.execs if event['pid'] == pid]
            if 'exec_paths' in exp:
                self.check(label + ':actual_exec_sequence', actual_execs == exp['exec_paths'], actual_execs)
            elif 'exec_count' in exp:
                self.check(label + ':actual_exec_count', len(actual_execs) == exp['exec_count'], actual_execs)
            if pid is not None:
                self.check(label + ':W_exit_trace', pid in self.exits)
                self.check(label + ':two_D_fork_edges', (row.get('zygote_pid'), row.get('s_pid')) in self.forks
                           and (row.get('s_pid'), pid) in self.forks)
            if 'exit_code' in exp:
                self.check(label + ':business_exit_code', (row.get('result') or {}).get('exit_code') == exp['exit_code'])
            if 'expected_outcome' in exp:
                self.check(label + ':expected_outcome', row.get('outcome') == exp['expected_outcome'])
            if exp.get('controller_death'):
                self.check(label + ':controller_death_UNKNOWN', self.sup.get('business_result') == 'UNKNOWN'
                           and self.sup.get('controller_wait_status') == 9 and row.get('response_committed') is not True)
            if exp.get('not_executed'):
                self.check(label + ':no_business_permit', row.get('business_permit') is False and row.get('business') == 'NOT_EXECUTED')
            wait = row.get('w_wait') or {}
            if isinstance(wait.get('wait_status'), int) and row.get('result') is not None:
                self.check(label + ':business_status_from_real_wait', row['result'].get('exit_code') == os.waitstatus_to_exitcode(wait['wait_status']))
                self.check(label + ':PROCESS_EXITED_is_wait_state', row.get('process_state') == 'PROCESS_EXITED')
                self.check(label + ':actual_S_or_adoptive_R_wait_log', any(entry.get('event') == 'ACTUAL_WORKER_WAIT'
                           and entry.get('nonce') == nonce and entry.get('worker_host_pid') == row.get('w_pid')
                           and entry.get('wait_status') == wait['wait_status'] for entry in self.zygote_records)
                           or (wait.get('event') == 'ADOPTED_WORKER_WAIT' and any(entry.get('event') == 'CONTROLLER_WAIT'
                               and entry.get('pid') == row.get('w_pid') and entry.get('wait_status') == wait['wait_status']
                               for entry in row.get('wait_records', []))))
            if exp.get('target_fd_check'):
                paths = [path.with_name(path.stem + '-stdout.log') for path, final in self.finals if final.get('nonce') == nonce]
                data = b''.join(path.read_bytes() for path in paths if path.is_file())
                fds = [int(value) for value in re.findall(rb'^RECEIPT_TARGET_FD=(\d+)$', data, re.M)]
                self.check(label + ':target_only_stdio', sorted(fds) == [0, 1, 2]
                           and b'RECEIPT_TARGET_FD_CHECK extras=0 scan_errno=0' in data)
                self.check(label + ':target_NNP_seccomp', b'RECEIPT_TARGET_SECURITY nnp=1 seccomp=2' in data)
            self.request_facts.append({'case': name, 'nonce': nonce, 'independent_receipt': decoded,
                                       'kernel_exec_paths': actual_execs,
                                       'kernel_target_exec_observed': bool(actual_execs and actual_execs[-1] == (row.get('tool_case') or {}).get('argv', [None])[0]),
                                       'business': row.get('business'), 'outcome': row.get('outcome')})

    def recoveries(self):
        attempts = self.sup.get('attempts', [])
        self.check('recovered_attempts_present', bool(attempts))
        self.check('recovery_business_UNKNOWN', self.sup.get('business_result') == 'UNKNOWN')
        self.check('real_Controller_SIGKILL', self.sup.get('controller_wait_status') == 9)
        self.check('actual_adopted_wait', any(row.get('role') == 'adopted-child' for row in self.sup.get('wait_records', [])))
        for attempt in attempts:
            nonce = attempt.get('nonce'); label = str(nonce)
            row = next((item for item in self.rows if item.get('nonce') == nonce), {})
            observation = row.get('recovery_fault_observation', {})
            consumed = observation.get('volatile_prefix_consumed', {})
            self.check(label + ':attempt_UNKNOWN', attempt.get('business_result') == 'UNKNOWN')
            self.check(label + ':two_streams', set(attempt.get('output_streams', {})) == {'stdout', 'stderr'})
            for stream, detail in attempt.get('output_streams', {}).items():
                key = label + ':' + stream
                self.check(key + ':real_EOF', detail.get('output_eof') is True and detail.get('eof_source') == 'supervisor_read')
                self.check(key + ':EOF_event', any(event.get('event') == 'SUPERVISOR_OUTPUT_EOF'
                           and event.get('nonce') == nonce and event.get('stream') == stream for event in self.se))
                self.check(key + ':content_not_complete', detail.get('complete') is not True)
                stored, drained, discarded = [detail.get(k, -1) for k in ('stored_bytes', 'drained_bytes', 'discarded_bytes')]
                self.check(key + ':bounded_storage', 0 <= stored <= LIMIT)
                self.check(key + ':byte_accounting', min(drained, discarded) >= 0 and drained == stored + discarded)
                raw_path = self.run / ('supervisor-output-' + str(nonce) + '-' + stream + '.log')
                actual_size = raw_path.stat().st_size if raw_path.is_file() else 0
                if detail.get('stored_bytes_exact') is True:
                    self.check(key + ':raw_stored_size_exact', actual_size == stored)
                else:
                    self.check(key + ':raw_size_with_partial_failure', stored <= actual_size <= LIMIT)
                if self.profile == 'b1':
                    self.check(key + ':H_drained_over_1MiB', drained > LIMIT)
                    self.check(key + ':stored_exact_1MiB', stored == LIMIT and actual_size == LIMIT
                               and detail.get('stored_bytes_exact') is True)
                    self.check(key + ':truncation_explicit', discarded > 0 and detail.get('truncated') is True)
                    self.check(key + ':known_discard_content_incomplete', detail.get('complete') is False)
                    if consumed:
                        prefix = consumed.get(stream, {})
                        self.check(key + ':volatile_prefix_was_consumed', prefix.get('bytes') == 4096 and prefix.get('persisted') is False
                                   and re.fullmatch(r'[0-9a-f]{64}', prefix.get('sha256', '')) is not None)
                        self.check(key + ':H_only_drained_post_consumption_suffix', observation.get('buffered', {}).get(stream) == drained)
                        if stream == 'stderr':
                            self.check(key + ':fixture_stderr_byte_conservation', drained + prefix.get('bytes', 0) == 1536 * 1024)
                        self.check(key + ':R_did_not_persist_prefix_stream_log', not any(self.run.glob('[0-9]*-' + row.get('case', '') + '-' + stream + '.log')))
                if self.profile == 'b2':
                    self.check(key + ':storage_error_recorded', bool(detail.get('storage_error')))
                    self.check(key + ':content_failure_explicit', detail.get('complete') is False)
            if self.profile == 'b4':
                self.snapshot(attempt)
            if self.profile in ('b1', 'b2'):
                self.check(label + ':fixture_completed_both_full_writes',
                           'phase=both-stream-writes-completed' in attempt.get('side_effects', {}).get('fixture-ready', {}).get('text_prefix', ''))
                self.check(label + ':large_pipe_fixture_explicit', self.expected.get('big_pipes') is True
                           and len(row.get('fixture_prepared_pipe_capacities', [])) == 2
                           and all(size >= 2 * LIMIT for size in row.get('fixture_prepared_pipe_capacities', [])))
            if consumed:
                self.observations.append('R consumed a 4096-byte prefix from each stream and recorded only counts/hash before SIGKILL. H drained the measured remaining pipe suffix; it did not restore the volatile prefix and content is not complete.')

    def audit_b2(self):
        self.recoveries()
        injections = self.lines('fault-injection-events.jsonl')
        faults = [event for event in injections if event.get('event') == 'H_RECOVERY_WRITE_FAULT']
        self.check('actual_H_write_faults', {event.get('stream') for event in faults} == {'stdout', 'stderr'})
        for event in faults:
            self.check('fault_only_in_H:' + str(event.get('stream')), event.get('pid') == event.get('target_h_pid') == self.sup.get('pid'))
            self.check('controlled_errno:' + str(event.get('stream')), event.get('errno_name') == self.expected.get('storage_errno'))
            path = self.run / Path(event.get('path', '')).name
            actual_bytes = path.stat().st_size if path.is_file() else 0
            self.check('fault_file_length_matches_actual_partial_write:' + str(event.get('stream')),
                       actual_bytes == event.get('successful_bytes_before_fault'))
            if self.expected.get('h_after_bytes', 0):
                self.check('fault_partial_write_reproduced:' + str(event.get('stream')),
                           event.get('partial_bytes', 0) > 0 and actual_bytes == self.expected['h_after_bytes'])
        self.check('storage_fault_errors_visible', bool(self.sup.get('errors')))
        self.check('storage_fault_evidence_incomplete', self.sup.get('recovery_evidence_complete') is False)
        self.observations.append('ENOSPC/EIO is explicitly injected into H recovered-output .write, not a claim of physical disk exhaustion or a kernel device fault. Partial writes are audited separately from logical counters.')

    def snapshot(self, attempt):
        label = str(attempt.get('nonce'))
        limits = attempt.get('side_effect_snapshot_limits', {})
        self.check(label + ':snapshot_limits', limits == {'max_entries': 128, 'max_total_content_bytes': LIMIT, 'max_file_content_bytes': 65536})
        effects = attempt.get('side_effects', {})
        self.check(label + ':bounded_entries', len(effects) <= 128)
        self.check(label + ':bounded_total_content', sum(value.get('content_bytes', 0) for value in effects.values()) <= LIMIT)
        for name, value in effects.items():
            self.check(label + ':bounded_file:' + name, value.get('content_bytes', 0) <= 65536)
            if value.get('type') == 'symlink':
                self.check(label + ':symlink_not_followed:' + name, 'text_prefix' not in value and value.get('content_read') is not True)
            elif value.get('type') == 'other':
                self.check(label + ':nonregular_not_read:' + name, value.get('content_read') is False and 'text_prefix' not in value)
        if self.expected.get('snapshot_truncated'):
            self.check(label + ':snapshot_truncation_visible', attempt.get('side_effect_snapshot_truncated') is True)
        for name, typ in self.expected.get('snapshot_types', {}).items():
            self.check(label + ':snapshot_type:' + name, effects.get(name, {}).get('type') == typ)

    def audit_b3(self):
        events = self.lines('protocol-fixture-controller-events.jsonl')
        starts = [event for event in events if event.get('event') == 'FIXTURE_STARTED']
        self.check('one_protocol_fixture_case', len(starts) == 1)
        name = starts[0].get('case') if starts else self.expected.get('case')
        if 'case' in self.expected:
            self.check('configured_protocol_case', name == self.expected['case'])
        reject = name in PROTOCOL_REJECT
        actual_rejection = bool(self.sup.get('protocol_errors'))
        if name == 'retire_late_queued':
            errors = self.sup.get('protocol_errors', [])
            only_peer_reset = bool(errors) and all(error.get('detail') == "ConnectionResetError(104, 'Connection reset by peer')" for error in errors)
            confirmed = [event for event in self.se if event.get('event') == 'SUPERVISOR_RETIRE_EOF_CONFIRMED']
            retired = [event for event in self.se if event.get('event') == 'ATTEMPT_RETIRED']
            resets = [event for event in self.se if event.get('event') == 'SUPERVISOR_PROTOCOL_ERROR'
                      and event.get('detail') == "ConnectionResetError(104, 'Connection reset by peer')"]
            self.check('queued_RETIRE_was_actually_validated', len(confirmed) == len(retired) == 1
                       and confirmed[0]['monotonic_ns'] <= retired[0]['monotonic_ns'])
            self.check('queued_RETIRE_then_real_Controller_death', self.sup.get('controller_wait_status') == 9
                       and self.sup.get('business_result') == 'UNKNOWN' and self.sup.get('done_received') is False)
            if errors:
                self.check('late_RETIRE_only_expected_transport_reset', only_peer_reset and bool(resets)
                           and len(retired) == 1 and all(event['monotonic_ns'] > retired[0]['monotonic_ns'] for event in resets))
            if only_peer_reset:
                actual_rejection = False
                self.observations.append('Queued RETIRE passed the independent EOF check before R SIGKILL caused recvmsg ECONNRESET. The original fixture classified every protocol_errors entry as a rejected RETIRE and reported false; its raw verdict is preserved. This audit recognizes only the exact ordered transport-reset case, not arbitrary protocol exceptions.')
        self.check('protocol_rejection_matches_case', actual_rejection is reject,
                   {'case': name, 'expected_rejection': reject, 'actual': self.sup.get('protocol_errors')})
        self.check('false_EOF_never_acknowledged', not any(event.get('event') == 'FALSE_EOF_WAS_ACKNOWLEDGED' for event in events))
        self.check('named_FIFO_never_registered', not any(event.get('event') == 'NAMED_FIFO_WAS_REGISTERED' for event in events))
        if reject:
            self.check('protocol_error_does_not_promote_business', self.sup.get('business_result') == 'UNKNOWN')
            self.check('rejection_has_expected_cause', any(PROTOCOL_REASON[name] in error.get('detail', '')
                       for error in self.sup.get('protocol_errors', [])))
            self.check('rejection_does_not_retire_responsibility', not any(attempt.get('retired') is True for attempt in self.sup.get('attempts', [])))
        if name in ('register_identical_duplicate', 'register_first_swapped_pipe', 'retire_duplicate'):
            self.check('valid_protocol_completes_Controller', self.sup.get('controller_wait_status') == 0
                       and self.sup.get('done_received') is True)
            self.check('valid_protocol_retires_attempt', bool(self.sup.get('attempts'))
                       and all(attempt.get('retired') is True for attempt in self.sup.get('attempts', [])))
        if name == 'retire_dropped':
            self.check('lost_RETIRE_does_not_drop_responsibility', self.sup.get('done_received') is False
                       and self.sup.get('business_result') == 'UNKNOWN'
                       and all(attempt.get('retired') is False for attempt in self.sup.get('attempts', [])))
        for attempt in self.sup.get('attempts', []):
            if attempt.get('registered') and not self.expected.get('supervisor_baseline'):
                self.check('registered_streams_reach_actual_EOF:' + str(attempt.get('nonce')),
                           bool(attempt.get('output_streams')) and all(value.get('output_eof') is True
                           and value.get('eof_source') in ('supervisor_read', 'supervisor_retire_poll')
                           for value in attempt.get('output_streams', {}).values()))
            if attempt.get('retired') and not self.expected.get('supervisor_baseline'):
                observed = attempt.get('retire_eof_observation', {})
                self.check('RETIRE_has_independent_pipe_state:' + str(attempt.get('nonce')),
                           bool(observed) and all(value.get('output_eof') is True and value.get('unread_bytes') == 0
                           and value.get('writer_hangup') is True for value in observed.values()))
        if name == 'register_first_swapped_pipe':
            self.observations.append('First registration can bind two anonymous pipe objects to supplied names but cannot independently infer stdout/stderr semantics. This case is an explicitly retained trust-boundary limitation, not rejected-by-H evidence.')
            self.unsupported_dimensions.append({'dimension': 'first_registration_semantic_stream_identity',
                'status': 'BLOCKED_UNOBSERVABLE',
                'reason': 'H has no independent provenance for whether two fresh anonymous pipes originally carried stdout or stderr. Its acceptance/recovery experiment can pass while this semantic identity guarantee remains unsupported.'})
        if name and name.startswith('workspace_'):
            for attempt in self.sup.get('attempts', []):
                self.snapshot(attempt)
        self.request_facts.append({'case': name, 'protocol_rejected': actual_rejection,
                                   'raw_protocol_errors_present': bool(self.sup.get('protocol_errors')),
                                   'H_release_state': self.sup.get('release_state')})

    def finish(self):
        self.common()
        if not self.sup:
            self.check('profile_final_H_audit_possible', None, 'missing supervisor.json')
        elif self.profile == 'a':
            self.audit_a()
        elif self.profile in ('b1', 'b4'):
            self.recoveries()
        elif self.profile == 'b2':
            self.audit_b2()
        elif self.profile == 'b3':
            self.audit_b3()
        else:
            self.check('explicit_followup_profile', None, 'Use a, b1, b2, b3 or b4; baseline source runs retain their intended profile and actual failures.')
        failed = [item for item in self.checks if item['value'] is False]
        blocked = [item for item in self.checks if item['value'] is None]
        return {'schema': 1, 'run': str(self.run), 'profile': self.profile,
                'status': 'FAIL' if failed else 'BLOCKED' if blocked else 'PASS',
                'meaning': 'PASS means this explicit experiment expectation is evidenced, not general correctness or successful recovery when release_state is INCOMPLETE.',
                'counts': {'checks': len(self.checks), 'failed': len(failed), 'blocked': len(blocked)},
                'failures': failed, 'blocked': blocked, 'checks': self.checks,
                'request_facts': self.request_facts, 'observations': self.observations,
                'unsupported_dimensions': self.unsupported_dimensions,
                'source_sha256': getattr(self, 'source', {}), 'verifier_sha256': sha(Path(__file__)),
                'limitations': ['No guest process or workload is executed by this verifier.',
                    'Output from fixed workload fixtures is offline evidence only, never protocol authority.',
                    'Private exec failure receipts are checked independently; EOF and successful wait never become exec success.',
                    'sched_process_exec proves an image transition, not arrival at main or business success.',
                    'H survival and healthy final diagnostic persistence remain explicit assumptions.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run')
    parser.add_argument('--profile', choices=['a', 'b1', 'b2', 'b3', 'b4', 'baseline', 'regression'])
    parser.add_argument('--expectations', type=Path)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    run = Path(args.run)
    if run.name == args.run:
        run = STUDY / 'runs' / args.run
    run = run.resolve()
    if not run.is_dir() or not run.is_relative_to((STUDY / 'runs').resolve()):
        parser.error('audit only an existing exec_support_followup/runs directory')
    expected_path = args.expectations or run / 'followup-expectations.json'
    expected = json.loads(expected_path.read_text()) if expected_path.is_file() else {}
    profile = args.profile or expected.get('profile')
    if expected.get('protocol_case'):
        expected.setdefault('case', expected['protocol_case'])
        if profile in ('baseline', 'b4'):
            profile = 'b3'
    if profile == 'regression':
        profile = 'a'
    case = expected.get('case') or expected.get('tool_suite')
    if profile == 'b2':
        expected.setdefault('storage_errno', expected.get('h_write_fault'))
        expected.setdefault('h_release_state', 'INCOMPLETE')
        expected.setdefault('allowed_error_messages', ['cannot save recovered output'])
    if case in ('workspace_read_denied', 'recovery_unreadable_file'):
        expected.setdefault('h_release_state', 'INCOMPLETE')
        expected.setdefault('allowed_error_messages', ['side effect observation failed'])
    if case in ('workspace_scan_denied', 'recovery_unreadable_dir'):
        expected.setdefault('h_release_state', 'INCOMPLETE')
        expected.setdefault('physical_resources_released', False)
        expected.setdefault('allowed_error_messages', ['side effect directory enumeration failed', 'workspace removal failed'])
    if case in ('workspace_delete_denied', 'recovery_undeletable'):
        expected.setdefault('h_release_state', 'INCOMPLETE')
        expected.setdefault('physical_resources_released', False)
        expected.setdefault('allowed_error_messages', ['workspace removal failed'])
    if case in ('workspace_many_entries', 'workspace_total_bytes', 'workspace_fifo_symlink_sparse', 'recovery_hostile'):
        expected.setdefault('snapshot_truncated', True)
    if case == 'recovery_hostile':
        expected.setdefault('snapshot_types', {'fifo': 'other', 'host-link': 'symlink', 'sparse': 'file'})
    if case == 'workspace_fifo_symlink_sparse':
        expected.setdefault('snapshot_types', {'fifo': 'other', 'symlink': 'symlink', 'sparse': 'file'})
    audit = Audit(run, profile, expected)
    audit.check('explicit_experiment_expectations', bool(expected) if expected_path.is_file() else None)
    report = audit.finish()
    if expected_path.is_file():
        report['expectations_path'] = str(expected_path)
        report['expectations_sha256'] = sha(expected_path)
    if not args.check_only:
        out = args.out or STUDY / 'analysis' / ('verify-followup-' + run.name + '.json')
        if out.resolve().is_relative_to((STUDY / 'runs').resolve()) or not out.resolve().is_relative_to(STUDY):
            parser.error('audit writes only inside new study and outside raw runs')
        out.parent.mkdir(parents=True, exist_ok=True)
        frozen_verifier = STUDY / 'analysis/verifier-sources' / (report['verifier_sha256'] + '.py')
        frozen_verifier.parent.mkdir(parents=True, exist_ok=True)
        if not frozen_verifier.exists():
            with frozen_verifier.open('xb') as stream:
                stream.write(Path(__file__).read_bytes())
        report['verifier_source_copy'] = str(frozen_verifier.relative_to(STUDY))
        with out.open('x') as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
    print(json.dumps({key: report[key] for key in ('run', 'profile', 'status', 'counts', 'failures', 'blocked')}, ensure_ascii=False, indent=2))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
