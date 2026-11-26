#!/usr/bin/env python3
"""Independent, read-only architecture_cost lifecycle qualification verifier.

Never executes a workload, sends a signal, or modifies a run. Default writes one
new analysis/<run>.json with exclusive creation. --check-only writes nothing.
Trace exit is corroboration, not a substitute for a real wait record. All times
compared below are the guest's monotonic_ns, never ftrace vs userspace clocks.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path


STUDY = Path(__file__).resolve().parent.parent
INTEGRATION = STUDY.parent / 'integration_ab'
CG = '/sys/fs/cgroup/cdz'
SECURITY = ('bridge.c', 'native.c', 'domain_init.c', 'policy.h', 'common.py')
UNCHANGED_SECURITY = ('bridge.c', 'native.c', 'policy.h')
VARIANTS = {'full', 'low'}
COUNTEREXAMPLES = {
    'counter_state_corruption', 'counter_fd_leak', 'counter_forgotten_drop',
    'counter_late_ack', 'counter_post_ack_controller_death', 'counter_post_forget_zygote_death',
}
AUDIT_ITEMS = {
    'common_ipc_fd_semantics', 'domain_pid1_exit_and_export',
    'bridge_d_fork_and_namespace_security', 'supervisor_failure_and_reaping',
    'controller_gate_and_release', 'zygote_gate_revoke_and_forget',
    'timing_errno_signal_and_fd_preservation',
}
CHECK_NAMES = {'marker', 'inherited', 'not_recreated', 'no_host_path',
               'no_other_workspace', 'readonly', 'writable', 'setns_denied',
               'unshare_denied', 'chroot_denied', 'exec_denied', 'caps_zero',
               'nnp_seccomp', 'fd_allowlist', 'namespaces', 'cgroup',
               'environment', 'cwd', 'root_identity'}
GROUP_CASES = {
    'control': ['normal', 'normal', 'nonzero'],
    'runtime': ['normal', 'normal', 'nonzero'],
    'budgets': ['pid_budget', 'normal', 'second_budget', 'normal'],
    'receipts': ['created_drop', 'reaped_drop', 'result_loss_side_effect', 'normal'],
    'cancels': ['cancel_queued', 'cancel_before_business', 'cancel_during_entry',
                'double_cancel', 'timeout', 'revoke_ack_loss', 'normal'],
    'failures': ['fork_ack_loss', 'reap_ack_loss', 'zygote_death', 'pid1_death',
                 'control_eof', 'normal'],
    'controller_death': ['controller_death'],
    'controller_during_entry': ['controller_during_entry'],
}
EXPECTED_OUTCOME = {
    'normal': ('SUCCEEDED', 'KNOWN'), 'nonzero': ('NONZERO', 'KNOWN'),
    'pid_budget': ('RESOURCE_REJECTED', 'NOT_EXECUTED'),
    'second_budget': ('RESOURCE_REJECTED', 'NOT_EXECUTED'),
    'created_drop': ('SUCCEEDED', 'KNOWN'), 'reaped_drop': ('SUCCEEDED', 'KNOWN'),
    'result_loss_side_effect': ('RESULT_UNKNOWN', 'UNKNOWN'),
    'cancel_queued': ('CANCELLED', 'NOT_EXECUTED'),
    'cancel_before_business': ('CANCELLED', 'NOT_EXECUTED'),
    'cancel_during_entry': ('CANCELLED', 'NOT_EXECUTED'),
    'double_cancel': ('CANCELLED', 'KNOWN'), 'timeout': ('TIMED_OUT', 'KNOWN'),
    'revoke_ack_loss': ('CANCELLED', 'NOT_EXECUTED'),
    'fork_ack_loss': ('TEMPLATE_CHANNEL_LOST', 'NOT_EXECUTED'),
    'reap_ack_loss': ('TEMPLATE_LOST', 'KNOWN'),
    'zygote_death': ('TEMPLATE_CHANNEL_LOST', 'KNOWN'),
    'pid1_death': ('DOMAIN_CHANNEL_LOST', 'KNOWN'),
    'control_eof': ('STATUS_CHANNEL_LOST', 'NOT_EXECUTED'),
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def analyze(name, *, counterexample=False):
    run = STUDY / 'runs' / name
    if Path(name).name != name or not run.is_dir():
        raise ValueError('expected an existing run basename')
    checks, blockers = [], []

    def check(label, value, evidence=None, required=True):
        checks.append({'check': label, 'value': value if value is None else bool(value),
                       'required': required, 'evidence': evidence})
        if required and value is None and not any(b['check'] == label for b in blockers):
            blockers.append({'check': label, 'evidence': evidence or 'required observation missing'})

    def block(label, evidence):
        blockers.append({'check': label, 'evidence': evidence})
        check(label, None, evidence)

    def read(filename, required=True):
        path = run / filename
        if not path.exists():
            if required:
                check('present:' + filename, None, 'missing raw evidence')
            return {}
        try:
            return json.loads(path.read_text())
        except (ValueError, OSError) as exc:
            check('parse:' + filename, False, repr(exc))
            return {}

    def lines(path, strict=False):
        values = []
        if not path.exists():
            check('present:' + path.name, None)
            return values
        for number, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
            try:
                value = json.loads(line)
                if isinstance(value, dict):
                    values.append(value)
            except ValueError:
                if strict:
                    check(f'jsonl:{path.name}:{number}', False, line)
        return values

    events = lines(run / 'events.jsonl', True)
    se = lines(run / 'supervisor-events.jsonl', True)
    zl = [r for path in sorted(run.glob('zygote-*.log')) for r in lines(path)]
    summary = read('summary.json', False)
    sup = read('supervisor.json')
    ext = read('external-final-release.json')
    result = read('result.json')
    config = read('review-config.json')
    manifest = read('source-sha.json')
    build = read('build.json')
    frozen = json.loads((INTEGRATION / 'historical-source-freeze.json').read_text())
    vm_manifest = read('variant-manifest.json', False)
    review_name = vm_manifest.get('source_review_path', 'docs/variant-source-review.json')
    review_path_valid = isinstance(review_name, str) and re.fullmatch(r'docs/variant-source-review(?:-v[0-9]+)?\.json', review_name) is not None
    check('source review uses a restricted versioned local path', review_path_valid, review_name)
    review_path = STUDY / review_name if review_path_valid else STUDY / 'docs/__invalid_source_review__'
    review = {}
    if not vm_manifest:
        block('variant manifest present', 'missing variant-manifest.json; never infer a variant from its run name')
    if not review_path.is_file():
        block('source changes independently admitted', str(review_path) + ' is not yet present')
    else:
        try:
            review = json.loads(review_path.read_text())
        except (OSError, ValueError) as exc:
            check('source review valid JSON', False, repr(exc))
    variant = vm_manifest.get('variant')
    admitted = review.get('variants', {}).get(variant, {})
    check('explicit supported variant', variant in VARIANTS, variant)
    if variant in VARIANTS and not admitted:
        block('variant has a completed source review', variant)
    elif admitted:
        check('variant explicitly admitted', admitted.get('admitted') is True, admitted.get('scope'))
    check('review is pinned by each run', bool(review) and vm_manifest.get('source_review_sha256') == sha(review_path),
          'variant-manifest.json / ' + str(review_name))
    check('variant metadata agrees with configuration', config.get('variant') == variant, config.get('variant'))
    check('diagnostics mode explicitly matches source-reviewed variant',
          config.get('diagnostics') == vm_manifest.get('diagnostics') == variant,
          {'config': config.get('diagnostics'), 'manifest': vm_manifest.get('diagnostics')})
    # Explicit old cases may also run alone as supplementary qualification.
    # The fixed eight-session/29-attempt aggregate is checked separately; a
    # single-case PASS never pretends to be that entire matrix.
    allowed_groups = COUNTEREXAMPLES if counterexample else set(GROUP_CASES) | set(EXPECTED_OUTCOME)
    check('qualification uses the declared non-performance suite', config.get('case') in allowed_groups,
          {'case': config.get('case'), 'allowed_groups': sorted(allowed_groups),
           'counterexample': counterexample})

    check('private VM completed without emergency timeout',
          result.get('complete') is True and result.get('timeout') is False
          and result.get('qemu_rc') == 0, 'result.json')
    check('not a benchmark or observer cleanup', config.get('performance_benchmark') is False
          and config.get('observer_cleanup_performed') is False, 'review-config.json')
    check('required frozen sources present', set(SECURITY) | {
          'run.py', 'zygote.py', 'supervisor.py', 'bridge_d.c', 'runtime_support.py',
          'runtime_probe.c', 'runtime_probe.py'} <= set(manifest),
          'source-sha.json')
    for name_, expected in manifest.items():
        p = run / 'prototype' / name_
        check('frozen source:' + name_, p.exists() and sha(p) == expected,
              ['source-sha.json', 'prototype/' + name_])
    check('all run sources equal separately audited variant', bool(manifest)
          and manifest == vm_manifest.get('source_sha256') == admitted.get('source_sha256'),
          'source-sha.json / variant-manifest.json / independent source review')
    audit_items = admitted.get('checks', {})
    for item in sorted(AUDIT_ITEMS):
        record = audit_items.get(item, {})
        check('independent source review:' + item,
              record.get('passed') is True and bool(record.get('evidence')),
              record)
    review_note = admitted.get('review_notes') or {}
    note_name = review_note.get('path', '')
    note_path = STUDY / note_name
    note_ok = (bool(note_name) and not Path(note_name).is_absolute()
               and '..' not in Path(note_name).parts and note_path.is_file())
    check('source-review rationale frozen', note_ok
          and review_note.get('sha256') == sha(note_path), review_note)
    security_hashes = {}
    for name_ in UNCHANGED_SECURITY:
        expected = frozen.get('cross_domain_zygote/prototype/' + name_)
        current = run / 'prototype' / name_
        security_hashes[name_] = {'original': expected,
                                 'run': sha(current) if current.exists() else None}
        check('security implementation unchanged:' + name_,
              expected is not None and security_hashes[name_]['run'] == expected,
              security_hashes[name_])
    old = STUDY.parent / 'cross_domain_zygote/runs/qualification-02'
    binary_hashes = {}
    for name_ in ('bridge.so', 'native.so', 'domain_init', 'bridge_d.so', 'libab_probe.so'):
        p, original = run / name_, old / name_
        binary_hashes[name_] = {'run': sha(p) if p.exists() else None,
                               'original': sha(original) if original.exists() else None,
                               'build_manifest': build.get(name_)}
        v = binary_hashes[name_]
        check('actual binary equals audited variant:' + name_,
              v['run'] is not None and v['run'] == v['build_manifest']
              == vm_manifest.get('binary_sha256', {}).get(name_)
              == admitted.get('binary_sha256', {}).get(name_), v)
        if name_ in ('bridge.so', 'native.so'):
            check('unchanged security binary matches qualification:' + name_,
                  v['run'] is not None and v['run'] == v['original'], v)

    # D is a separate runtime path: keep A's stock H/R helper guarantees and
    # independently establish that Z/S/W really use the frozen candidate.
    bstudy = STUDY.parent / 'fork_runtime_compat'
    bfinal = bstudy / 'runs/candidate-04'
    dsource = run / 'prototype/bridge_d.c'
    doriginal = bstudy / 'prototype/cross_domain/bridge_d.c'
    # Provenance fields existed in the prior admission frozen before this study.
    # The new source-review schema omitted them, but did not change either
    # source or candidate runtime. Validate that frozen historical source rather
    # than modifying old run manifests or treating missing metadata as permission.
    original_source_sha = admitted.get('bridge_d_original_sha256')
    original_binary_sha = admitted.get('bridge_d_original_binary_sha256')
    provenance_supplement = None
    if original_source_sha is None or original_binary_sha is None:
        freeze_path = STUDY / 'frozen/source-inputs.json'
        historical_rel = 'research/shimos_worker_pool/cost_breakdown/docs/variant-source-review-v2.json'
        historical_path = STUDY.parent / 'cost_breakdown/docs/variant-source-review-v2.json'
        try:
            historical_freeze = json.loads(freeze_path.read_text())
            pinned = historical_freeze.get('files', {}).get(historical_rel, {}).get('sha256')
            actual = sha(historical_path)
            pin_valid = isinstance(pinned, str) and pinned == actual
            check('historical provenance was pinned in pre-run input freeze', pin_valid,
                  {'freeze': str(freeze_path), 'freeze_sha256': sha(freeze_path),
                   'historical_path': historical_rel, 'expected': pinned, 'actual': actual})
            if pin_valid:
                historical = json.loads(historical_path.read_text()).get('variants', {}).get('baseline_instrumented', {})
                source_value = historical.get('bridge_d_original_sha256')
                binary_value = historical.get('bridge_d_original_binary_sha256')
                check('historical candidate-D provenance fields present',
                      isinstance(source_value, str) and re.fullmatch(r'[0-9a-f]{64}', source_value) is not None
                      and isinstance(binary_value, str) and re.fullmatch(r'[0-9a-f]{64}', binary_value) is not None)
                if original_source_sha is None:original_source_sha = source_value
                if original_binary_sha is None:original_binary_sha = binary_value
                provenance_supplement = {'reason': 'two original provenance fields omitted from new source-review schema',
                    'historical_review_sha256': actual, 'freeze_sha256': sha(freeze_path),
                    'source_sha256': source_value, 'binary_sha256': binary_value,
                    'new_source_and_binary_checks_unchanged': True}
        except (OSError, ValueError) as exc:
            block('pre-run historical provenance readable', repr(exc))
    check('D bridge instrumentation derives from frozen B implementation', dsource.exists()
          and doriginal.exists() and original_source_sha == sha(doriginal)
          and build.get('bridge_d.c') == sha(dsource),
          'instrumented bridge source requires the separately pinned security review')
    dbinary = run / 'bridge_d.so'
    dbaseline = bfinal / 'cross-domain-glibc-d/bridge_d.so'
    check('D bridge original binary provenance retained', dbaseline.exists()
          and original_binary_sha == sha(dbaseline),
          'candidate-04 provenance; instrumented binary is separately admitted above')
    runtime = read('candidate-runtime.json')
    rsha = read('candidate-runtime-sha.json')
    baseline_rsha = json.loads((bfinal / 'candidate-runtime-sha.json').read_text())
    check('candidate package is exactly candidate-04', rsha == baseline_rsha
          and bool(rsha), 'candidate-runtime-sha.json')
    bundle_bad = [name_ for name_, expected in rsha.items()
                  if not (run / 'candidate-runtime' / name_).is_file()
                  or sha(run / 'candidate-runtime' / name_) != expected]
    check('all frozen candidate package members match hashes', not bundle_bad
          and bool(rsha), {'members': len(rsha), 'mismatches': bundle_bad})
    installed = read('candidate-runtime-install.json')
    check('guest installed exactly the recorded candidate package',
          installed.get('verified_sha256') == rsha
          and installed.get('location') == runtime.get('bundle')
          and bool(rsha), 'candidate-runtime-install.json')
    check('candidate public API and bounded support explicit',
          runtime.get('public_api') == 'shimos_fork_into_cgroup(int,int*)'
          and runtime.get('full_compatibility_claim') is False
          and runtime.get('controller_libc') == 'stock guest', 'candidate-runtime.json')
    check('candidate excluded incompatible legacy libcrypt',
          'lib/libcrypt.so' not in rsha and 'lib/libcrypt.so.1' not in rsha,
          'candidate-04 retains stock guest libxcrypt; no crypt qualification inferred')
    expected_loader = str(runtime.get('bundle', '')) + '/lib/ld-linux-x86-64.so.2'
    check('candidate bundle has an absolute dedicated prefix',
          isinstance(runtime.get('bundle'), str) and runtime['bundle'].startswith('/opt/'),
          'candidate-runtime.json')
    dso_info = runtime.get('dso_sha256', {})
    for path, info in dso_info.items():
        try:
            relative = str(Path(path).relative_to(runtime['bundle']))
        except (KeyError, ValueError):
            relative = None
        check('candidate runtime object:' + path, relative in rsha
              and info.get('sha256') == rsha.get(relative)
              and info.get('realpath', '').startswith(runtime.get('bundle', '') + '/'), info)
    check('candidate runtime core DSOs recorded', all(
          runtime.get('bundle', '') + '/lib/' + name_ in dso_info
          for name_ in ('libc.so.6', 'libm.so.6', 'ld-linux-x86-64.so.2')))
    missing = read('candidate-missing-api.json')
    check('missing candidate API fails closed without a fallback',
          missing.get('passed') is True and missing.get('symbol_present') is False
          and missing.get('fallback_allowed') is False and missing.get('return_value') == -1
          and missing.get('errno') == missing.get('expected_errno') == 38
          and missing.get('pidfd') == -1, 'candidate-missing-api.json')
    runtime_records = sorted(run.glob('zygote-*-runtime.json'))
    check('actual Z runtime mappings recorded', bool(runtime_records))
    for path in runtime_records:
        zr = read(path.name)
        maps_path = path.with_name(path.name.replace('-runtime.json', '-maps.txt'))
        check('actual runtime maps present:' + maps_path.name, maps_path.is_file())
        maps = maps_path.read_text() if maps_path.is_file() else ''
        zargv = zr.get('argv', [])
        check('explicit candidate loader:' + path.name, bool(zargv)
              and zargv[0] == expected_loader and '/usr/bin/python3' in zargv
              and zargv[-1].endswith('/bridge_d.so') and zr.get('runtime') == runtime, zargv)
        recorded = zr.get('mapping_checks', {})
        check('mapped runtime identity check:' + path.name,
              recorded.get('same_name_stock_glibc_rejected') is True
              and recorded.get('all_mapped_glibc_inode_devices_match_manifest') is True)
        by_path = {v.get('realpath'): v for v in dso_info.values()}
        glibc_names = {Path(p).name for p in [*dso_info, *by_path] if p}
        observed = {}
        for line in maps.splitlines():
            fields = line.split(maxsplit=5)
            if len(fields) < 6 or Path(fields[5]).name not in glibc_names:
                continue
            actual_path = fields[5]
            expected = by_path.get(actual_path, {})
            device = [int(value, 16) for value in fields[3].split(':')]
            check('actual DSO mapping:' + path.name + ':' + actual_path,
                  bool(expected) and int(fields[4]) == expected.get('inode')
                  and device == expected.get('device'), line)
            observed[actual_path] = {'device': device, 'inode': int(fields[4]),
                                     'sha256': expected.get('sha256')}
        check('all required candidate DSOs actually mapped:' + path.name, all(
              dso_info.get(runtime.get('bundle', '') + '/lib/' + name_, {}).get('realpath') in observed
              for name_ in ('libc.so.6', 'libm.so.6', 'ld-linux-x86-64.so.2')))
        check('actual maps agree with controller identity evidence:' + path.name,
              observed == recorded.get('mapped_glibc'))

    edges, execs, exits = {}, {}, set()
    trace = run / 'process-trace.txt'
    if not trace.exists():
        check('kernel process trace present', None)
    else:
        for line in trace.read_text().splitlines():
            if 'sched_process_fork:' in line:
                m = re.search(r' pid=(\d+) child_comm=.* child_pid=(\d+)', line)
                if not m:
                    check('fork trace parse', False, line)
                    continue
                parent, child = map(int, m.groups())
                if child in edges:
                    check('no PID reuse ambiguity in trace', False, child)
                edges[child] = parent
            elif 'sched_process_exec:' in line:
                m = re.search(r'filename=(\S+) pid=(\d+)', line)
                if m:
                    execs.setdefault(int(m[2]), []).append(m[1])
                else:
                    check('exec trace parse', False, line)
            elif 'sched_process_exit:' in line:
                m = re.search(r' pid=(\d+) ', line)
                if m:
                    exits.add(int(m[1]))
                else:
                    check('exit trace parse', False, line)
    losses = read('trace-stats.json')
    for cpu, stat in losses.items():
        values = dict(re.findall(r'^(overrun|commit overrun|dropped events): (\d+)$', stat, re.M))
        check('trace loss:' + cpu, len(values) == 3 and all(int(x) == 0 for x in values.values()), values)
    check('trace covers CPUs', bool(losses), 'trace-stats.json')

    check('supervisor actual child of traced fixture', sup.get('pid') in edges, 'process-trace.txt')
    check('cleanup supervisor runs as delegated UID, not root observer', any(
          e.get('event') == 'SUPERVISOR_STARTED' and e.get('uid') == 65534
          and e.get('pid') == sup.get('pid') for e in se))
    check('Controller actual child of surviving supervisor',
          sup.get('controller_pid') is not None and edges.get(sup['controller_pid']) == sup.get('pid'))
    swaits = [e for e in se if e.get('event') == 'SUPERVISOR_REAL_WAIT']
    check('supervisor Controller status comes from real wait log', any(
          e.get('pid') == sup.get('controller_pid') and e.get('wait_status') == sup.get('controller_wait_status')
          for e in swaits), 'supervisor-events.jsonl')
    for w in sup.get('wait_records', []):
        check('supervisor wait corroborated:' + str(w.get('pid')), any(
              e.get('pid') == w.get('pid') and e.get('wait_status') == w.get('wait_status')
              for e in swaits), w)
    check('supervisor real wait reached ECHILD', sup.get('echild') is True, 'supervisor.json')
    check('supervisor final FD inventory restored',
          sup.get('fd_before') is not None and sup.get('fd_before') == sup.get('fd_after'))
    check('supervisor product release complete', sup.get('release_state') == 'RELEASED'
          and sup.get('resources_removed') is True and sup.get('remaining_cgroups') == []
          and sup.get('remaining_workspaces') == [] and sup.get('errors') == [])
    check('root observer did not perform product cleanup',
          sup.get('observer_cleanup_used') is False and ext.get('observer_killed_processes') is False
          and ext.get('observer_removed_product_resources') is False)
    check('fixture removed only empty outer delegation', ext.get('delegation_removed') is True
          and ext.get('remaining_before_fixture_release') == [CG + '/client']
          and ext.get('supervisor_wait_status') == 0)
    for name_ in ('observer-after.json', 'observer-later.json'):
        obs = read(name_)
        groups = obs.get('cgroups', {})
        check(name_ + ': no unprivileged process or workspace',
              obs.get('uid65534_processes') == {} and obs.get('workspaces') == {})
        check(name_ + ': only empty delegation/client remains',
              set(groups) == {CG, CG + '/client'} and all(
                  'populated 0' in g.get('cgroup.events', '') and g.get('cgroup.procs') == ''
                  and g.get('cgroup.threads') == '' and int(g.get('pids.current', '-1')) == 0
                  for g in groups.values()), 'sampling is not atomic; corroborated by real wait and removal')

    complete_rows = [read(p.name) for p in sorted(run.glob('[0-9]*-*.json'),
                       key=lambda p: int(p.name.split('-')[0]))]
    journals = [read(p.name) for p in sorted(run.glob('attempt-*.json'))]
    rows = complete_rows if summary else journals
    expected_cases = GROUP_CASES.get(config.get('case'), [config.get('case')])
    check('complete intended case sequence, no omitted attempts',
          [r.get('case') for r in rows] == expected_cases,
          {'expected': expected_cases, 'observed': [r.get('case') for r in rows]})
    nonces = [r.get('nonce') for r in rows]
    check('unique attempt identities', bool(rows) and len(nonces) == len(set(nonces))
          and all(isinstance(x, str) and re.fullmatch(r'[0-9a-f]{32}', x) for x in nonces))
    if summary:
        check('summary matches independent attempt records',
              summary.get('all_passed') is True and summary.get('controller_echild') is True
              and len(summary.get('rows', [])) == len(rows)
              and all(all(r.get(k) == s.get(k) for k in s)
                      for r, s in zip(rows, summary.get('rows', []))))
        check('normal Controller shutdown', sup.get('controller_wait_status') == 0
              and sup.get('done_received') is True and sup.get('failure_reason') is None)
    else:
        intentional_counter = counterexample and config.get('case') in COUNTEREXAMPLES
        check('no summary belongs to an intended failure test', intentional_counter
              or config.get('case') in ('controller_death', 'controller_during_entry'))
        expected_status = (9 if config.get('case') == 'counter_post_ack_controller_death' else 256)
        forgotten_timeout_stopped_by_h = False
        if intentional_counter and config.get('case') == 'counter_forgotten_drop' and sup.get('controller_wait_status') == 9:
            # This one observed race is admitted only with the complete causal
            # chain, never by accepting a generic {SIGKILL, exit(1)} set.
            # R closes H's channel in its error handler before diagnostic flush
            # and _exit(1); H may then conservatively SIGKILL the still-live R.
            failure_trace = read('controller-failure.json').get('traceback', '')
            dropped = [e for e in zl if e.get('event') == 'COUNTEREXAMPLE_INJECTED'
                       and e.get('kind') == 'forgotten_drop' and e.get('nonce') in nonces
                       and e.get('response_event') == 'FORGOTTEN' and e.get('sent') is False]
            eofs = [e for e in se if e.get('event') == 'CONTROLLER_CHANNEL_EOF']
            recovers = [e for e in se if e.get('event') == 'SUPERVISOR_RECOVERY_START'
                        and e.get('reason') == 'CONTROL_CHANNEL_CLOSED_WITHOUT_DONE']
            stops = [e for e in se if e.get('event') == 'SUPERVISOR_STOP_CONTROLLER'
                     and e.get('pid') == sup.get('controller_pid')]
            waited = [e for e in swaits if e.get('pid') == sup.get('controller_pid')
                      and e.get('wait_status') == 9]
            ordered = len(eofs) == len(recovers) == len(stops) == len(waited) == 1 and (
                eofs[0].get('monotonic_ns', float('inf')) <= recovers[0].get('monotonic_ns', -1)
                <= stops[0].get('monotonic_ns', -1) <= waited[0].get('monotonic_ns', -1))
            forgotten_timeout_stopped_by_h = (
                len(rows) == len(dropped) == 1 and 'TimeoutError: timed out' in failure_trace
                and "m,fs,_=recv(self.z['sock'])" in failure_trace
                and 'self.domain(c)' in failure_trace and ordered
                and sup.get('failure_reason') == 'CONTROL_CHANNEL_CLOSED_WITHOUT_DONE'
                and sup.get('done_received') is False and not complete_rows
                and all(r.get('response_committed') is not True for r in rows)
                and not any(e.get('event') == 'ATTEMPT_RETIRED' for e in se)
                and sup.get('business_result') == 'UNKNOWN' and sup.get('release_state') == 'RELEASED'
                and sup.get('echild') is True and sup.get('errors') == [])
            check('lost FORGOTTEN timeout was overtaken by evidenced H conservative stop',
                  forgotten_timeout_stopped_by_h,
                  {'injection': dropped, 'eof': eofs, 'recovery': recovers, 'stop': stops,
                   'actual_wait': waited, 'traceback': failure_trace})
        check('Controller failure not converted to business success',
              (sup.get('controller_wait_status') == (expected_status if intentional_counter else 9)
               or forgotten_timeout_stopped_by_h)
              and sup.get('done_received') is False
              and sup.get('business_result') == 'UNKNOWN' and sup.get('recovery_started_ns') is not None)
        check('surviving supervisor sealed creators before domain kills',
              any(e.get('event') == 'SUPERVISOR_CREATORS_STOPPED' for e in se)
              and any(e.get('event') == 'SUPERVISOR_QUIESCENCE' and e.get('echild') is True for e in se))

    attempt_results = []
    cwaits = [e for e in events if e.get('event') == 'CONTROLLER_WAIT']
    for index, r in enumerate(rows):
        nonce, case = r.get('nonce'), r.get('case')
        pre = f'{case}:{nonce}:'
        ev = [e for e in events if e.get('nonce') == nonce]
        z = [e for e in zl if e.get('nonce') == nonce]
        etypes = {e.get('event') for e in ev}
        ztypes = {e.get('event') for e in z}
        regs = [e for e in se if e.get('event') == 'ATTEMPT_REGISTERED' and e.get('nonce') == nonce]
        forks = [e for e in z if e.get('event') == 'ACTUAL_TRANSITION_FORK']
        check(pre + 'registered before any S fork', len(regs) == 1 and all(
              e['monotonic_ns'] >= regs[0]['monotonic_ns'] for e in forks))
        check(pre + 'all control responses identity-bound',
              all(e.get('nonce') == nonce for e in r.get('events', [])))
        for f in forks:
            check(pre + 'kernel Z-to-S edge', edges.get(f['pid']) == r.get('zygote_pid'), f)
            check(pre + 'S did not exec and exited', not execs.get(f['pid']) and f['pid'] in exits, f)
            for child, parent in edges.items():
                if parent == f['pid']:
                    check(pre + f'S child {child} inherited without exec and exited',
                          not execs.get(child) and child in exits)
        for f in (e for e in z if e.get('event') == 'ACTUAL_WORKER_FORK'):
            check(pre + 'kernel S-to-W edge', edges.get(f['worker_host_pid']) == f['waiter_host_pid'], f)
        cancel_acks = [e for e in ev if e.get('event') == 'CANCEL_ACK']
        if cancel_acks:
            first = min(e['monotonic_ns'] for e in cancel_acks)
            check(pre + 'no actual S fork after revoke ACK',
                  all(e['monotonic_ns'] <= first for e in forks),
                  {'ack_guest_monotonic_ns': first, 'fork_guest_monotonic_ns': [e['monotonic_ns'] for e in forks]})
        else:
            check(pre + 'revoke ACK not applicable or creator died', None,
                  'no revoke ACK; creator wait and recovery checked instead', required=False)
        worker = r.get('worker')
        if worker:
            check(pre + '19 business/security checks present and pass',
                  set(worker.get('checks', {})) == CHECK_NAMES and all(worker['checks'].values()))
            check(pre + 'actual memory inheritance and child COW',
                  worker.get('inherited') == r.get('expected_state')
                  and worker.get('after_cow', {}).get('sha256') != worker.get('inherited', {}).get('sha256')
                  and worker.get('after_cow', {}).get('object_id') == worker.get('inherited', {}).get('object_id'))
            ident = worker.get('identity', {})
            status = ident.get('status', {})
            check(pre + 'namespace identity and final security', ident.get('ns') == r.get('target_ns')
                  and status.get('NoNewPrivs') == '1' and status.get('Seccomp') == '2'
                  and all(int(status.get(k, '1'), 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'))
                  and set(ident.get('fds', {})) <= {'0', '1', '2'})
            check(pre + 'raw business cgroup matches this attempt',
                  ident.get('cgroup', '').strip() == '0::' + CG.removeprefix('/sys/fs/cgroup') + '/d-' + nonce + '/business',
                  ident.get('cgroup'))
            check(pre + 'business raw output corroborates oracle', any(
                  e.get('event') == 'WORKER_READY' and all(e.get(k) == worker.get(k) for k in worker)
                  for e in ev), 'events.jsonl actual stdout observation')
            check(pre + 'post-drop gate preceded business authorization',
                  r.get('business_permit') is True and 'WORKER_GATED' in etypes)
        limits = r.get('limits', {})
        expected_limits = {'task': ('400000 100000', str(512*1024**2), '256'),
                           'transition': ('200000 100000', str(256*1024**2), '0' if case == 'pid_budget' else '128'),
                           'business': ('200000 100000', str(256*1024**2), '0' if case == 'second_budget' else '128')}
        check(pre + 'same cgroup safety limits', all(tuple(limits.get(k, {}).get(n, '').strip()
              for n in ('cpu.max', 'memory.max', 'pids.max')) == want for k, want in expected_limits.items()))
        argv = r.get('argv', [])
        check(pre + 'namespace and capability setup retained', all(x in argv for x in (
              '--unshare-user', '--disable-userns', '--unshare-pid', '--unshare-net',
              '--unshare-ipc', '--unshare-uts', '--cap-drop', 'ALL', '--as-pid-1', '--die-with-parent')))
        ro_binds = [argv[i+1:i+3] for i, arg in enumerate(argv) if arg == '--ro-bind']
        check(pre + 'candidate runtime is read-only in target rootfs',
              [runtime.get('bundle'), runtime.get('bundle')] in ro_binds
              and all(pair in ro_binds for pair in runtime.get('readonly_domain_overlays', []))
              and bool(runtime.get('readonly_domain_overlays')), 'actual bwrap argv')
        if summary:
            zpid = r.get('zygote_pid')
            # This request's quiescence snapshot excludes later normal STOP.
            # Session-wide waits would falsely suppress all live-template
            # post-forget checks because STOP eventually waits every Z.
            z_wait_records = [e for e in r.get('wait_records', []) if e.get('pid') == zpid]
            z_waited = bool(z_wait_records)
            check(pre + 'request-local Z wait evidence excludes later session STOP',
                  all(any(all(e.get(k) == global_e.get(k) for k in ('pid', 'wait_status', 'seq', 'time_ns'))
                              for global_e in cwaits) for e in z_wait_records), z_wait_records)
            post = r.get('zygote_post')
            if not z_waited:
                ready_records = [e for e in events if e.get('event') == 'ZYGOTE_READY'
                                 and e.get('identity', {}).get('pid') == zpid]
                ready_fds = (ready_records[0].get('identity', {}).get('fds', {})
                             if len(ready_records) == 1 else {})
                expected_post_event = 'PONG'  # both full/low retain the complete A+B protocol
                check(pre + 'fresh post-forget template evidence present', isinstance(post, dict)
                      and post.get('event') == expected_post_event
                      and post.get('nonce') == nonce,
                      {'expected_event': expected_post_event, 'observed': post})
                post = post or {}
                check(pre + 'template session identity matches actual READY', len(ready_records) == 1
                      and ready_records[0].get('session') not in (None, '', 'unset')
                      and post.get('session') == ready_records[0].get('session'))
                check(pre + 'template state and serial active-attempt count restored',
                      post.get('state_unchanged') is True and post.get('active_attempts') == 0,
                      'same assertion for both variants; fingerprint covers the explicit test STATE only')
                check(pre + 'template FD-number inventory and process identity restored',
                      len(ready_records) == 1 and bool(ready_fds)
                      and set(post.get('identity', {}).get('fds', {})) == set(ready_fds)
                      and post.get('identity', {}).get('pid') == zpid,
                      'FD-number equality is the existing contract, not full FD object identity')
                if False:  # no PING merge in the architecture_cost full/low baseline
                    check(pre + 'late template exit check retained without a new RPC',
                          r.get('zygote_pidfd_alive_at_validation') is True,
                          'nonblocking existing pidfd check at the original final validation point; not a wait result')
            expected_outcome = EXPECTED_OUTCOME.get(case)
            if case == 'reap_ack_loss':
                # A's unchanged event loop preserves the first failure reason:
                # wait(Z) first => TEMPLATE_LOST; socket EOF first =>
                # TEMPLATE_CHANNEL_LOST. Only admit this two-label equivalence
                # when the precise historical lost-S-wait scenario and ALL
                # recovery facts below are present. Never accept arbitrary errors.
                sw = [e for e in z if e.get('event') == 'ACTUAL_TRANSITION_WAIT'
                      and e.get('pid') == r.get('s_pid') and e.get('wait_status') == 0]
                fault = [e for e in z if e.get('event') == 'FAULT_Z_DIES_BEFORE_REAPED'
                         and e.get('pid') == r.get('s_pid') and e.get('wait_status') == 0]
                ww = r.get('w_wait') or {}
                same_semantics = (
                    r.get('outcome') in {'TEMPLATE_LOST', 'TEMPLATE_CHANNEL_LOST'}
                    and r.get('failure') == r.get('outcome') and r.get('business') == 'KNOWN'
                    and len(sw) == len(fault) == 1
                    and sw[0]['monotonic_ns'] <= fault[0]['monotonic_ns']
                    and 'TRANSITION_REAPED' not in etypes
                    and r.get('s_state') == 'RECLAIMED_STATUS_UNKNOWN' and r.get('s_wait') is None
                    and ww.get('event') == 'WORKER_WAITED' and ww.get('wait_status') == 0
                    and ww.get('exit_code') == 0 and r.get('w_state') == 'REAPED'
                    and r.get('result') == {'exit_code': 0, 'source': 'WORKER_WAITED'}
                    and any(e.get('pid') == r.get('zygote_pid') and e.get('wait_status') == 9 for e in cwaits)
                    and r.get('admission') == 'SEALED_CREATOR_WAITED'
                    and r.get('adopted_echild') is True and r.get('children_at_release') == []
                    and r.get('resources') == 'RELEASED' and r.get('domain_empty') is True
                    and r.get('output_eof') is True and r.get('resources_removed') is True)
                check(pre + 'lost REAPED two detection orders retain identical recovery guarantees',
                      same_semantics, {'allowed_failure_labels': ['TEMPLATE_LOST', 'TEMPLATE_CHANNEL_LOST'],
                      'actual': [r.get('outcome'), r.get('business')],
                      'rationale': 'qualification-ab-01-failures-classification-audit.md'})
            else:
                check(pre + 'same fault outcome and result knowledge as A',
                      expected_outcome is not None
                      and (r.get('outcome'), r.get('business')) == expected_outcome,
                      {'expected': expected_outcome, 'actual': [r.get('outcome'), r.get('business')]})
            check(pre + 'complete release and output EOF', r.get('qualification') == 'PASS'
                  and r.get('resources_removed') is True and r.get('resources') == 'RELEASED'
                  and r.get('domain_empty') is True and r.get('output_eof') is True
                  and str(r.get('admission', '')).startswith('SEALED'))
            check(pre + 'cgroups really empty', bool(r.get('stats')) and all(
                  'populated 0' in v.get('cgroup.events', '') and int(v.get('pids.current', '-1')) == 0
                  for v in r.get('stats', {}).values()))
            check(pre + 'Controller FD inventory restored', r.get('controller_fd_before') == r.get('controller_fd_after'))
            check(pre + 'monitor exit from actual Controller wait', any(
                  e.get('pid') == r.get('monitor_pid') and e.get('wait_status') == r.get('monitor_wait') for e in cwaits))
            if r.get('s_state') == 'REAPED':
                check(pre + 'S result backed by true waiter', any(
                      e.get('event') == 'ACTUAL_TRANSITION_WAIT' and e.get('pid') == r.get('s_pid')
                      and e.get('wait_status') == r.get('s_wait') for e in z) or any(
                      e.get('pid') == r.get('s_pid') and e.get('wait_status') == r.get('s_wait') for e in cwaits))
            if r.get('w_wait') is not None:
                wait = r['w_wait']
                check(pre + 'W result backed by true waiter', any(
                      e.get('event') == 'ACTUAL_WORKER_WAIT' and e.get('worker_host_pid') == r.get('w_pid')
                      and e.get('wait_status') == wait.get('wait_status') for e in z) or any(
                      e.get('pid') == r.get('w_pid') and e.get('wait_status') == wait.get('wait_status') for e in cwaits))
            if r.get('s_state') == 'RECLAIMED_STATUS_UNKNOWN':
                check(pre + 'unknown S exit not invented', r.get('s_wait') is None
                      and r.get('adopted_echild') is True and r.get('failure') is not None)
            if r.get('business') == 'UNKNOWN':
                check(pre + 'unknown result not turned into success', r.get('result') is None
                      and r.get('outcome') not in ('SUCCEEDED', 'NONZERO'))
            if case in ('normal', 'nonzero', 'created_drop', 'reaped_drop'):
                expected_exit = 7 if case == 'nonzero' else 0
                check(pre + 'expected business exit from wait', r.get('result', {}).get('exit_code') == expected_exit
                      and r.get('outcome') == ('NONZERO' if expected_exit else 'SUCCEEDED')
                      and r.get('failure') is None and worker is not None and r.get('side_effect') == '2650100'
                      and r.get('s_wait') == 0 and r.get('monitor_wait') == 0 and bool(r.get('drained')))
            else:
                check(pre + 'fault never acknowledged successful', r.get('outcome') not in ('SUCCEEDED', 'NONZERO'))
            if case in ('cancel_queued', 'cancel_before_business', 'cancel_during_entry'):
                check(pre + 'cancel before business has no effect or permit', r.get('business') == 'NOT_EXECUTED'
                      and r.get('side_effect') is None and r.get('business_permit') is False and worker is None
                      and r.get('outcome') == 'CANCELLED')
                boundary = {'cancel_queued': 'PREPARED', 'cancel_before_business': 'WORKER_GATED',
                            'cancel_during_entry': 'ENTERED'}[case]
                check(pre + 'intended cancellation gate actually reached', boundary in etypes
                      and any(e.get('event') == 'CANCEL_REQUEST' and e.get('reason') == 'CANCELLED' for e in ev))
            if case == 'cancel_queued':
                check(pre + 'queued request irrevocably rejected late COMMIT', not forks
                      and r.get('late_commit_rejected') is True and 'COMMIT_REJECTED' in etypes
                      and r.get('s_state') == 'ABSENT' and r.get('cancel_acks', 0) >= 2)
            if case == 'double_cancel':
                check(pre + 'duplicate cancels including terminal cancel sealed',
                      r.get('cancel_acks', 0) >= 2 and r.get('terminal_duplicate_ack', {}).get('sealed') is True
                      and r.get('outcome') == 'CANCELLED' and worker is not None)
            if case == 'timeout':
                check(pre + 'actual timeout after business started', worker is not None
                      and r.get('outcome') == 'TIMED_OUT' and any(e.get('event') == 'CANCEL_REQUEST'
                      and e.get('reason') == 'TIMED_OUT' for e in ev))
            if case in ('zygote_death', 'pid1_death'):
                check(pre + 'requested live-process fault actually injected', worker is not None
                      and any(e.get('event') == 'FAULT' and e.get('case') == case for e in ev))
            if case == 'control_eof':
                check(pre + 'control close exercised after namespace entry', 'ENTERED' in etypes
                      and r.get('outcome') == 'STATUS_CHANNEL_LOST' and worker is None
                      and r.get('business_permit') is False)
            if case in ('pid_budget', 'second_budget'):
                field = 'spawn_errno' if case == 'pid_budget' else 'worker_errno'
                event_name = 'ACTUAL_TRANSITION_CLONE_REJECTED' if case == 'pid_budget' else 'ACTUAL_WORKER_CLONE_REJECTED'
                check(pre + 'EAGAIN classified as definite no execution', r.get(field) == 11
                      and r.get('business') == 'NOT_EXECUTED' and r.get('side_effect') is None
                      and r.get('w_state') == 'ABSENT' and event_name in ztypes)
                if case == 'pid_budget':
                    check(pre + 'first clone rejection never created S', not forks and r.get('s_state') == 'ABSENT')
                next_ = rows[index+1] if index+1 < len(rows) else {}
                if config.get('numpy_baseline') == 'cold':
                    check(pre + 'cold baseline preserves healthy rejected template until its normal stop',
                          r.get('zygote_post', {}).get('state_unchanged') is True
                          and any(e.get('pid') == r.get('zygote_pid') and e.get('wait_status') == 0 for e in cwaits))
                    if next_:
                        check(pre + 'cold next request uses a different successfully started template',
                              next_.get('case') == 'normal' and next_.get('zygote_pid') != r.get('zygote_pid')
                              and next_.get('outcome') == 'SUCCEEDED')
                elif next_:
                    check(pre + 'healthy template handles next normal request', next_.get('case') == 'normal'
                          and next_.get('zygote_pid') == r.get('zygote_pid') and next_.get('outcome') == 'SUCCEEDED')
                else:
                    check(pre + 'single budget case keeps template healthy; subsequent reuse not exercised',
                          r.get('zygote_post', {}).get('state_unchanged') is True
                          and any(e.get('pid') == r.get('zygote_pid') and e.get('wait_status') == 0 for e in cwaits))
            if case in ('created_drop', 'reaped_drop'):
                fault = 'FAULT_CREATED_RECEIPT_DROPPED' if case == 'created_drop' else 'FAULT_REAPED_RECEIPT_DROPPED'
                dropped = 'TRANSITION_CREATED' if case == 'created_drop' else 'TRANSITION_REAPED'
                check(pre + 'receipt genuinely omitted, state recovered', fault in ztypes and dropped not in etypes)
                if case == 'reaped_drop':
                    check(pre + 'snapshot returns retained real wait', any(e.get('event') == 'SNAPSHOT'
                          and e.get('s_state') == 'REAPED' and e.get('s_wait') == 0 for e in ev))
            if case == 'result_loss_side_effect':
                check(pre + 'lost result after effect stays UNKNOWN', 'FAULT_WORKER_WAIT_RECEIPT_DROPPED' in ztypes
                      and 'WORKER_WAITED' not in etypes and r.get('side_effect') == '2650100'
                      and r.get('business') == 'UNKNOWN' and r.get('result') is None)
            if case in ('fork_ack_loss', 'reap_ack_loss'):
                fault = 'FAULT_Z_DIES_BEFORE_CREATED' if case == 'fork_ack_loss' else 'FAULT_Z_DIES_BEFORE_REAPED'
                check(pre + 'historical creator death fault actually fired', fault in ztypes and any(
                      e.get('pid') == r.get('zygote_pid') and e.get('wait_status') == 9 for e in cwaits))
            if case == 'revoke_ack_loss':
                check(pre + 'revoke acknowledgment deliberately lost at business gate',
                      'FAULT_REVOKE_ACK_DROPPED' in ztypes and 'WORKER_GATED' in etypes
                      and 'CANCEL_ACK' not in etypes and 'REVOKE_ACK_TIMEOUT' in etypes)
                check(pre + 'creator genuinely waited after conservative stop', any(
                      e.get('pid') == r.get('zygote_pid') and e.get('wait_status') == 9 for e in cwaits)
                      and r.get('admission') == 'SEALED_CREATOR_WAITED')
                check(pre + 'missing revoke ACK cannot release business gate',
                      r.get('business') == 'NOT_EXECUTED' and r.get('business_permit') is False
                      and r.get('side_effect') is None and worker is None
                      and r.get('outcome') not in ('SUCCEEDED', 'NONZERO'))
        else:
            sa = next((a for a in sup.get('attempts', []) if a.get('nonce') == nonce), {})
            check(pre + 'supervisor owns UNKNOWN result and real release',
                  sa.get('business_result') == 'UNKNOWN' and sa.get('output_eof') is True
                  and sa.get('resources_removed') is True and sa.get('registered') is True)
            check(pre + 'registered before killed Controller', len(regs) == 1 and any(
                  (e.get('event') == 'FAULT' and e.get('case') == case)
                  or (counterexample and e.get('event') == 'COUNTEREXAMPLE_INJECTED')
                  for e in ev + z))
            if case == 'controller_death':
                check(pre + 'business effect retained in recovery evidence',
                      sa.get('side_effects', {}).get('result', {}).get('text_prefix') == '2650100')
        attempt_results.append({k: r.get(k) for k in ('case', 'nonce', 'zygote_pid', 's_pid', 'w_pid',
                                's_state', 'w_state', 'business', 'result', 'outcome', 'resources')})

    owned = {sup['pid']} if sup.get('pid') is not None else set()
    while True:
        added = {p for p, parent in edges.items() if parent in owned} - owned
        if not added:
            break
        owned.update(added)
    check('all supervised descendants have kernel exit events', bool(owned) and owned <= exits,
          {'owned': sorted(owned), 'missing_exit': sorted(owned - exits)})
    for zp in {r.get('zygote_pid') for r in rows} - {None}:
        check('Zygote single initial candidate-loader exec:' + str(zp),
              execs.get(zp) == [expected_loader])
    check('one runtime identity record per actual Zygote',
          len(runtime_records) == len({r.get('zygote_pid') for r in rows} - {None}))
    if config.get('numpy_baseline') == 'cold' and summary:
        zids = [r.get('zygote_pid') for r in rows]
        check('explicit cold baseline uses a fresh Z for every request',
              len(zids) == len(set(zids)) and None not in zids)
        for r in rows:
            zpid = r.get('zygote_pid')
            waits = [e for e in cwaits if e.get('pid') == zpid]
            stop = [e for e in events if e.get('event') == 'ZYGOTE_STOP'
                    and e.get('state', {}).get('born_pid') == zpid]
            alive_at_finish = bool(r.get('zygote_post'))
            check('cold Z has one real Controller wait:' + str(zpid), len(waits) == 1)
            if alive_at_finish:
                check('healthy cold Z stopped with unchanged state and zero exit:' + str(zpid),
                      len(stop) == 1 and stop[0].get('state_unchanged') is True
                      and len(waits) == 1 and waits[0].get('wait_status') == 0)
    failures = [c for c in checks if c['required'] and c['value'] is not True]
    return {'run': name, 'variant': variant, 'diagnostics': config.get('diagnostics'),
            'status': 'FAIL' if any(c['value'] is False for c in failures) else ('BLOCKED' if blockers else 'PASS'), 'checks': checks,
            'blockers': blockers,
            'verifier_sha256': sha(Path(__file__)),
            'failures': failures, 'attempts': attempt_results, 'security_source_sha': security_hashes,
            'security_binary_sha': binary_hashes, 'provenance_supplement': provenance_supplement, 'trace_forks': len(edges),
            'owned_processes': len(owned), 'trace_loss_checks': len(losses),
            'limitations': ['Controlled serial prototype qualification; performance group is not admitted here.',
                           'Instrumented binaries require separate source review and exact variant manifests.',
                           'Full/low independently run the same lifecycle matrix; a prior full PASS is not evidence for low.',
                           'Low omits intermediate RP FD snapshots; final business FD observation and template/controller/supervisor checks remain mandatory.',
                           'Post-forget fingerprint covers explicit STATE; FD number equality is not full object identity.',
                           'Guest monotonic timestamps only; no ftrace/user clock subtraction.',
                           'Trace exits corroborate process disappearance, not exit-status ownership.',
                           'Final /proc observations are non-atomic; real wait, empty cgroups and removal also required.',
                           'No result inferred from side-effect files after Controller loss.'],
            'evidence_sha256': {str(p.relative_to(run)): sha(p) for p in sorted(run.rglob('*'))
                               if p.is_file() and (p.suffix in ('.json', '.jsonl', '.txt', '.log', '.py', '.c', '.h', '.sh')
                                                   or p.name in ('bridge.so', 'native.so', 'domain_init'))}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs', nargs='+', help='frozen run basenames')
    parser.add_argument('--check-only', action='store_true', help='do not write or overwrite anything')
    parser.add_argument('--output-suffix', default='qualification', help='new exclusive analysis suffix; never overwrites earlier verification')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9-]+', args.output_suffix):parser.error('invalid output suffix')
    failed = False
    for name in args.runs:
        result = analyze(name)
        if not args.check_only:
            out = STUDY / 'analysis' / (name + '-' + args.output_suffix + '.json')
            out.parent.mkdir(exist_ok=True)
            with out.open('x') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
                f.write('\n')
        print(json.dumps({'run': name, 'status': result['status'], 'checks': len(result['checks']),
                          'failures': result['failures']}, ensure_ascii=False))
        failed |= result['status'] != 'PASS'
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
