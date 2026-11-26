#!/usr/bin/env python3
"""Read-only NumPy admission evidence checker; never imports NumPy or runs a task.

Numerical artifact decoding is deliberately independent of the tested runtime.
Raw numerical outputs and recorded boundary facts are checked independently.
Lifecycle and fork-runtime reports remain required; missing evidence is BLOCKED.
"""
import argparse
import ast
import hashlib
import json
import math
import re
from collections import Counter, defaultdict
import struct
import traceback
import zipfile
from pathlib import Path


STUDY = Path(__file__).resolve().parent.parent
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_ARRAY_ITEMS = 16 * 1024 * 1024
RTOL = 1e-12
ATOL = 1e-10


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def within_run(run, relative):
    """Evidence references must not escape the run or follow an outside symlink."""
    if not isinstance(relative, str) or not relative:
        raise ValueError('missing artifact path')
    rel = Path(relative)
    if rel.is_absolute() or '..' in rel.parts:
        raise ValueError('artifact path is not a relative run path')
    resolved = (run / rel).resolve(strict=True)
    resolved.relative_to(run.resolve(strict=True))
    if not resolved.is_file():
        raise ValueError('artifact is not a regular file')
    return resolved


def decode_npy(payload):
    """Decode bounded primitive arrays, rejecting object dtype and pickle."""
    if len(payload) > MAX_ARTIFACT_BYTES or payload[:6] != b'\x93NUMPY':
        raise ValueError('invalid or oversized NPY payload')
    if len(payload) < 10:
        raise ValueError('truncated NPY header')
    version = tuple(payload[6:8])
    if version == (1, 0):
        header_size = struct.unpack('<H', payload[8:10])[0]
        header_start = 10
        encoding = 'latin1'
    elif version in ((2, 0), (3, 0)):
        if len(payload) < 12:
            raise ValueError('truncated NPY v2/v3 header')
        header_size = struct.unpack('<I', payload[8:12])[0]
        header_start = 12
        encoding = 'utf8' if version == (3, 0) else 'latin1'
    else:
        raise ValueError('unsupported NPY version')
    if header_size > 1024 * 1024 or header_start + header_size > len(payload):
        raise ValueError('invalid NPY header length')
    header = ast.literal_eval(payload[header_start:header_start+header_size].decode(encoding).strip())
    if not isinstance(header, dict) or set(header) != {'descr', 'fortran_order', 'shape'}:
        raise ValueError('unsupported NPY header keys')
    dtype, shape, order = header['descr'], header['shape'], header['fortran_order']
    if not isinstance(dtype, str) or len(dtype) < 3 or dtype[0] not in '<>|=':
        raise ValueError('only explicit primitive NPY dtype accepted')
    if not isinstance(shape, tuple) or len(shape) > 8 or any(type(n) is not int or n < 0 for n in shape):
        raise ValueError('invalid NPY shape')
    if type(order) is not bool:
        raise ValueError('invalid NPY order')
    formats = {'f8': 'd', 'f4': 'f', 'i8': 'q', 'i4': 'i', 'i2': 'h', 'i1': 'b',
               'u8': 'Q', 'u4': 'I', 'u2': 'H', 'u1': 'B', 'b1': '?'}
    code = formats.get(dtype[1:])
    if code is None:
        raise ValueError('dtype is unsupported; object/structured/complex arrays are not silently decoded')
    if dtype[0] == '=':
        raise ValueError('native-endian data needs an explicit recorded producer byte order')
    if dtype[0] == '|' and struct.calcsize(code) != 1:
        raise ValueError('non-endian dtype used for a multi-byte primitive')
    count = math.prod(shape)
    if count > MAX_ARRAY_ITEMS:
        raise ValueError('array item budget exceeded')
    endian = '>' if dtype[0] == '>' else '<'
    item_size = struct.calcsize(endian + code)
    body = payload[header_start+header_size:]
    if len(body) != count * item_size:
        raise ValueError('NPY body length does not match shape/dtype')
    values = [value[0] for value in struct.iter_unpack(endian + code, body)]
    if order and len(shape) > 1 and count:
        # Normalize indexing to C logical order without NumPy execution.
        cstrides = [math.prod(shape[i+1:]) for i in range(len(shape))]
        fstrides = [math.prod(shape[:i]) for i in range(len(shape))]
        values = [values[sum(((i // cs) % dim) * fs for dim, cs, fs in zip(shape,cstrides,fstrides))]
                  for i in range(count)]
    return {'dtype': dtype, 'shape': list(shape), 'fortran_order': order, 'values': values,
            'payload_sha256': hashlib.sha256(payload).hexdigest()}


def read_npz(path):
    path = Path(path)
    if path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ValueError('oversized NPZ file')
    arrays = {}
    with zipfile.ZipFile(path, 'r') as source:
        infos = source.infolist()
        if not infos or len(infos) > 64 or sum(i.file_size for i in infos) > MAX_ARTIFACT_BYTES:
            raise ValueError('invalid NPZ member count or uncompressed size')
        for info in infos:
            name = info.filename
            if info.is_dir() or not name.endswith('.npy') or '/' in name or '\\' in name or name.startswith('.'):
                raise ValueError('unexpected NPZ member name')
            key = name[:-4]
            if key in arrays:
                raise ValueError('duplicate NPZ key')
            arrays[key] = decode_npy(source.read(info))
    return arrays


def compare_npz(actual, reference, *, rtol=RTOL, atol=ATOL):
    """Recompute shape, dtype, finiteness and allclose from actual saved arrays."""
    if rtol != RTOL or atol != ATOL:
        raise ValueError('numerical tolerances differ from the experiment contract')
    got, expected = read_npz(actual), read_npz(reference)
    rows = []
    keys_equal = set(got) == set(expected)
    for key in sorted(set(got) | set(expected)):
        a, b = got.get(key), expected.get(key)
        row = {'key': key, 'present_in_both': a is not None and b is not None}
        if a is None or b is None:
            row['passed'] = False
            rows.append(row)
            continue
        structure = a['shape'] == b['shape'] and a['dtype'] == b['dtype']
        row.update(actual_shape=a['shape'], reference_shape=b['shape'],actual_dtype=a['dtype'], reference_dtype=b['dtype'],
                   shape_dtype_equal=structure, actual_array_sha256=a['payload_sha256'], reference_array_sha256=b['payload_sha256'])
        if not structure:
            row['passed'] = False
            rows.append(row)
            continue
        integer = a['dtype'][1] in 'iub'
        mismatches = 0
        bad_finite = 0
        maximum = 0.0
        first_mismatches = []
        for index, (x, y) in enumerate(zip(a['values'], b['values'])):
            finite = math.isfinite(x) and math.isfinite(y)
            if not finite:
                bad_finite += 1
                ok = False
                error = None
            else:
                error = abs(x-y)
                maximum = max(maximum, error)
                ok = x == y if integer else error <= atol + rtol * abs(y)
            if not ok:
                mismatches += 1
                if len(first_mismatches) < 8:
                    first_mismatches.append({'index_C_order': index, 'actual': repr(x), 'reference': repr(y), 'absolute_error': error})
        row.update(items=len(a['values']), mismatches=mismatches, nonfinite_pairs=bad_finite,
                   max_abs_error=maximum, first_mismatches=first_mismatches, passed=mismatches == 0,
                   comparison='exact integer' if integer else 'abs(actual-reference) <= atol + rtol*abs(reference)')
        rows.append(row)
    return {'passed': keys_equal and bool(rows) and all(r['passed'] for r in rows), 'keys_equal': keys_equal,
            'actual_sha256': sha(actual), 'reference_sha256': sha(reference), 'rtol': rtol, 'atol': atol, 'arrays': rows}


THREAD_ENV = {k: '1' for k in ('OPENBLAS_NUM_THREADS', 'OMP_NUM_THREADS', 'MKL_NUM_THREADS',
                             'BLIS_NUM_THREADS', 'VECLIB_MAXIMUM_THREADS', 'NUMEXPR_NUM_THREADS')}
BUSINESS_CHECKS = {'marker', 'inherited', 'not_recreated', 'no_host_path', 'no_other_workspace',
                   'readonly', 'writable', 'setns_denied', 'unshare_denied', 'chroot_denied',
                   'exec_denied', 'caps_zero', 'nnp_seccomp', 'fd_allowlist', 'namespaces',
                   'cgroup', 'environment', 'cwd', 'root_identity'}
NUMERIC_CASES = {'normal', 'nonzero', 'created_drop', 'reaped_drop'}
NO_BUSINESS_CASES = {'pid_budget', 'second_budget', 'cancel_queued', 'cancel_before_business',
                     'cancel_during_entry', 'revoke_ack_loss', 'controller_during_entry'}


class Evidence:
    def __init__(self, run):
        self.run = run
        self.checks = []
        self.evidence = {}

    def check(self, name, value, detail=None):
        self.checks.append({'check': name, 'value': None if value is None else bool(value), 'detail': detail})

    def record(self, path):
        path = Path(path).resolve(strict=True)
        # Shared paired-session fixtures are allowed only inside this study.
        path.relative_to(STUDY.resolve())
        self.evidence[str(path.relative_to(STUDY))] = sha(path)
        return path

    def json(self, path, optional=False):
        path = Path(path)
        if not path.is_file():
            if not optional:
                self.check('present:' + str(path.relative_to(STUDY)), None)
            return {}
        try:
            self.record(path)
            return json.loads(path.read_text())
        except (OSError, ValueError) as error:
            self.check('valid JSON:' + str(path), False, repr(error))
            return {}

    def logs(self, paths):
        rows = []
        for path in paths:
            self.record(path)
            for line, raw in enumerate(path.read_text(errors='replace').splitlines(), 1):
                if '"NP_' not in raw:
                    continue
                try:
                    item = json.loads(raw)
                except ValueError as error:
                    self.check(f'NumPy raw record parses:{path.name}:{line}', None, repr(error))
                    continue
                if isinstance(item, dict) and str(item.get('event', '')).startswith('NP_'):
                    rows.append(dict(item, _file=path.name, _line=line))
        # A raw event can be both stdout and the controller's event journal.
        # Deduplicate identical payload only; conflicting same-identity events remain.
        unique = {}
        for row in rows:
            key = json.dumps({k: v for k, v in row.items() if not k.startswith('_')}, sort_keys=True)
            unique.setdefault(key, row)
        return list(unique.values())


def verify_related_report(e, path, kind, name):
    if path is None:
        key = name.replace('/', '-')
        candidates = ([STUDY / 'analysis' / (key + '.json'), STUDY / 'analysis' / (key + '-qualification.json')]
                      if kind == 'lifecycle' else [STUDY / 'analysis' / (key + '-runtime.json')])
        available = [p for p in candidates if p.is_file()]
        if available:
            path = available[0]
        else:
            e.check(kind + ':independent report supplied', None, [str(p.relative_to(STUDY)) for p in candidates])
            return None
    path = Path(path)
    if not path.is_absolute():
        path = STUDY / path
    report = e.json(path)
    if not report:
        return None
    e.check(kind + ':same actual run', report.get('run') == name)
    e.check(kind + ':independent qualification PASS', report.get('status') == 'PASS', report.get('status'))
    verifier = STUDY / 'runner' / ('verify_qualification.py' if kind == 'lifecycle' else 'verify_runtime.py')
    e.check(kind + ':current verifier source', report.get('verifier_sha256') == sha(verifier))
    values = report.get('evidence_sha256', {})
    e.check(kind + ':raw evidence hashes present', True if values else None)
    bad = []
    for relative, digest in values.items():
        try:
            target = within_run(e.run, relative)
            if sha(target) != digest:
                bad.append(relative)
        except (OSError, ValueError):
            bad.append(relative)
    e.check(kind + ':independent evidence unchanged', not bad, bad)
    return {'path': str(path.resolve().relative_to(STUDY)), 'sha256': sha(path), 'status': report.get('status')}


def package_evidence(e):
    shared = e.run
    link = e.json(e.run / 'numpy-package-link.json', optional=True)
    if link:
        expected = e.run.parent.parent
        valid = (e.run.parent.name == 'sessions' and expected.parent == STUDY / 'runs'
                 and link.get('package_manifest') == '../../numpy-package-manifest.json'
                 and link.get('install_receipt') == '../../numpy-install.json')
        e.check('paired fixture references restricted VM root', valid)
        if not valid:
            return {}, {}
        shared = expected
    manifest = e.json(shared / 'numpy-package-manifest.json')
    installed = e.json(shared / 'numpy-install.json')
    if not manifest or not installed:
        return manifest, installed
    if link:
        e.check('paired package manifest identity', link.get('package_manifest_sha256') == sha(shared / 'numpy-package-manifest.json'))
    frozen = e.json(STUDY / 'frozen/numpy-dependency-clean-assets.json')
    actual_files = manifest.get('file_sha256', {})
    frozen_files = {r['wheel_member']: r['sha256'] for r in frozen.get('files', [])}
    e.check('fixed package source matches official-wheel freeze',
            actual_files == frozen_files and bool(actual_files)
            and manifest.get('source_manifest_sha256') == sha(STUDY / 'frozen/numpy-dependency-clean-assets.json')
            and manifest.get('wheel_sha256') == frozen.get('wheel_sha256'))
    e.check('fixed NumPy ABI package and thread configuration',
            manifest.get('version') == '2.2.6' and manifest.get('guest_path') == '/opt/shimos-numpy'
            and manifest.get('thread_environment') == THREAD_ENV
            and 'cp310' in manifest.get('wheel', '') and 'x86_64' in manifest.get('wheel', ''))
    bad = []
    for relative, digest in actual_files.items():
        try:
            path = within_run(shared / 'numpy-package', relative)
            if sha(path) != digest:
                bad.append(relative)
        except (OSError, ValueError):
            bad.append(relative)
    e.check('frozen package bytes preserved', not bad, bad[:20])
    e.check('actual guest installation identity and readonly receipt',
            installed.get('status') == 'INSTALLED_READONLY'
            and installed.get('manifest_sha256') == sha(shared / 'numpy-package-manifest.json')
            and installed.get('guest_path') == '/opt/shimos-numpy'
            and installed.get('runtime_modified') is False)
    lines = installed.get('mountinfo', [])
    if isinstance(lines, str):
        lines = lines.splitlines()
    mounts = [line.split() for line in lines if len(line.split()) > 6 and line.split()[4] == '/opt/shimos-numpy']
    e.check('actual mount is ro nosuid nodev',
            bool(mounts) and {'ro', 'nosuid', 'nodev'} <= set(mounts[-1][5].split(',')))
    support = e.json(shared / 'numpy-support-manifest.json')
    support_freeze = e.json(STUDY / 'frozen/numpy-dependency-support-assets.json')
    support_files = support.get('file_sha256', {})
    e.check('support DSOs independently frozen without replacing D runtime',
            support_files == {k: v['sha256'] for k, v in support_freeze.get('files', {}).items()}
            and set(support_files) == {'libstdc++.so.6', 'libgcc_s.so.1'}
            and support.get('source_manifest_sha256') == sha(STUDY / 'frozen/numpy-dependency-support-assets.json')
            and support.get('runtime_modified') is False and support.get('guest_path') == '/opt/shimos-numpy-deps')
    support_bad = []
    for relative, digest in support_files.items():
        try:
            if sha(within_run(shared / 'numpy-support', relative)) != digest:
                support_bad.append(relative)
        except (OSError, ValueError):
            support_bad.append(relative)
    e.check('actual frozen support DSO content preserved', not support_bad, support_bad)
    receipt = installed.get('support_dependencies', {})
    e.check('support actual installation receipt bound',
            receipt.get('manifest_sha256') == sha(shared / 'numpy-support-manifest.json')
            and receipt.get('file_sha256') == support_files and receipt.get('guest_path') == '/opt/shimos-numpy-deps')
    support_mounts = [line.split() for line in receipt.get('mountinfo', [])
                      if len(line.split()) > 6 and line.split()[4] == '/opt/shimos-numpy-deps']
    e.check('support actual mount ro nosuid nodev',
            bool(support_mounts) and {'ro', 'nosuid', 'nodev'} <= set(support_mounts[-1][5].split(',')))
    manifest['_support_files'] = support_files
    return manifest, installed


def audit_check(e, audit, label, *, required=True):
    if not isinstance(audit, dict) or audit.get('schema') != 1:
        if required:
            e.check(label + ':actual native audit loaded', None, audit)
        return []
    e.check(label + ':audit identity and observation scope',
            audit.get('diagnostic_interposer') is True and audit.get('pid') == audit.get('tid')
            and audit.get('pid_scope') == 'current_pid_namespace' and audit.get('clock') == 'CLOCK_MONOTONIC')
    required_zero = ('event_overwritten', 'observation_errors', 'resolve_errors', 'registration_overlap',
                     'registration_in_progress', 'registration_failures_inherited_or_local',
                     'registration_overflow_inherited_or_local')
    e.check(label + ':audit complete without observed error',
            all(audit.get(field) == 0 for field in required_zero),
            {field: audit.get(field) for field in required_zero})
    pthread = audit.get('pthread_create', {})
    e.check(label + ':no observed native thread-creation attempt',
            pthread.get('attempts') == pthread.get('successes') == pthread.get('failures') == 0, pthread)
    registry, events = audit.get('registry'), audit.get('events')
    if not isinstance(registry, list) or not isinstance(events, list):
        e.check(label + ':actual audit arrays', None)
        return []
    e.check(label + ':successful recorded registrations',
            len(registry) == audit.get('registration_successes_inherited_or_local')
            == audit.get('registration_attempts_inherited_or_local')
            and all(r.get('state') == 2 and r.get('registration_rc') == 0 for r in registry))
    e.check(label + ':audit event sequence complete',
            len(events) == audit.get('event_total')
            and [r.get('seq') for r in events] == list(range(len(events))))
    slots = {r.get('slot'): r for r in registry}
    counters = Counter()
    outstanding = Counter()
    last = 0
    valid = True
    for record in events:
        key = (record.get('slot'), record.get('phase'))
        callback = slots.get(key[0], {}).get('callbacks', {}).get(key[1], {})
        timestamp = record.get('monotonic_ns', 0)
        valid &= (callback.get('present') is True and record.get('edge') in ('enter', 'exit')
                  and record.get('pid') == record.get('tid') == audit.get('pid')
                  and record.get('capget_rc') == record.get('clock_errno') == 0
                  and record.get('nnp') == 1 and record.get('seccomp') in (0, 2)
                  and int(record.get('cap_eff', '-1'), 16) == int(record.get('cap_prm', '-1'), 16) == 0
                  and isinstance(timestamp, int) and timestamp > 0 and timestamp >= last)
        last = timestamp
        counters[(key[0], key[1], record.get('edge'))] += 1
        outstanding[key] += 1 if record.get('edge') == 'enter' else -1
        valid &= outstanding[key] in (0, 1)
    e.check(label + ':real callbacks ordered and permissions observed', valid)
    e.check(label + ':all recorded callbacks returned', all(v == 0 for v in outstanding.values()))
    counts_match = True
    for slot in registry:
        for phase in ('prepare', 'parent', 'child'):
            callback = slot.get('callbacks', {}).get(phase, {})
            counts_match &= (callback.get('enter') == counters[(slot.get('slot'), phase, 'enter')]
                             and callback.get('exit') == counters[(slot.get('slot'), phase, 'exit')])
    e.check(label + ':registry counters match raw events', counts_match)
    return registry


def snapshot_check(e, snapshot, label, manifest, *, audit_required=True, numpy_expected=True):
    if not isinstance(snapshot, dict):
        e.check(label + ':snapshot exists', None)
        return []
    threads = snapshot.get('threads')
    e.check(label + ':actual single thread', isinstance(threads, list) and len(threads) == 1
            and threads[0] == str(snapshot.get('pid_namespace_local')))
    fds = snapshot.get('fds')
    e.check(label + ':FD object inventory', isinstance(fds, dict) and bool(fds)
            and all(str(k).isdigit() and isinstance(v, dict)
                    and set(v) >= {'target', 'dev', 'ino'} for k, v in (fds or {}).items()))
    e.check(label + ':signals and environment observed',
            isinstance(snapshot.get('environment'), dict)
            and set(snapshot.get('signals', {})) == {'SigBlk', 'SigIgn', 'SigCgt'}
            and set(snapshot.get('signal_handlers', {})) == {'17', '2', '15', '13'})
    security = snapshot.get('security')
    if not isinstance(security, dict):
        e.check(label + ':actual privilege boundary observed', None)
    else:
        e.check(label + ':actual unprivileged identity and NNP',
                security.get('uid') == security.get('euid') == 65534
                and security.get('gid') == security.get('egid') == 65534
                and security.get('nnp') == 1 and security.get('proc_no_new_privs') == '1')
        capabilities = security.get('capabilities', {})
        e.check(label + ':no active process capabilities',
                set(capabilities) == {'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'}
                and all(int(capabilities.get(k, '-1'), 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')))
    blas = snapshot.get('blas') or {}
    if numpy_expected:
        e.check(label + ':actual single-thread BLAS configuration observed',
                blas.get('status') == 'OBSERVED' and blas.get('observed_num_threads') == 1,
                {'status': blas.get('status'), 'observed_num_threads': blas.get('observed_num_threads')})
    maps = snapshot.get('maps')
    if not isinstance(maps, dict):
        e.check(label + ':DSO mappings observed', None)
        maps = {}
    numpy_dsos = {p: v for p, v in maps.items() if p.startswith('/opt/shimos-numpy/') and '.so' in p}
    if numpy_expected:
        e.check(label + ':actual NumPy extensions and BLAS mapped',
                any('_multiarray_umath' in p for p in numpy_dsos) and any('openblas' in p.lower() for p in numpy_dsos))
    e.check(label + ':loaded package DSOs belong to frozen readonly package',
            all(p.removeprefix('/opt/shimos-numpy/') in manifest.get('file_sha256', {})
                and v.get('inode', 0) > 0 and isinstance(v.get('dev'), str) for p, v in numpy_dsos.items()))
    e.check(label + ':no external NumPy DSO silently substituted',
            not any(('numpy' in p.lower() or 'openblas' in p.lower()) and '.so' in p
                    and not p.startswith(('/opt/shimos-numpy/', '/opt/shimos-numpy-deps/', '/state/cross-domain/prototype/', '/probe/')) for p in maps))
    support_dsos = {p: v for p, v in maps.items() if p.startswith('/opt/shimos-numpy-deps/')}
    e.check(label + ':mapped support DSO identity known',
            all(p.removeprefix('/opt/shimos-numpy-deps/') in manifest.get('_support_files', {})
                and v.get('inode', 0) > 0 for p, v in support_dsos.items()))
    registry = audit_check(e, snapshot.get('audit'), label, required=audit_required)
    if numpy_expected and audit_required and snapshot.get('audit', {}).get('schema') == 1:
        openblas = [r for r in registry if 'openblas' in str(r.get('callbacks', {}).get('prepare', {}).get('dso', '')).lower()]
        e.check(label + ':actual OpenBLAS prepare registration observed', bool(openblas))
        e.check(label + ':fixed OpenBLAS callback shape', all(
            r['callbacks']['prepare'].get('present') is True and r['callbacks']['parent'].get('present') is False
            and r['callbacks']['child'].get('present') is False for r in openblas))
    return numpy_dsos


def pair_state_check(e, before, after, label, *, compare_maps=False):
    if not isinstance(before, dict) or not isinstance(after, dict):
        e.check(label + ':both boundaries observed', None)
        return
    for field in ('fds', 'signals', 'signal_handlers', 'environment'):
        e.check(label + ':' + field + ' restored', field in before and field in after and before[field] == after[field])
    e.check(label + ':same single execution thread', before.get('threads') == after.get('threads')
            and len(before.get('threads', [])) == 1)
    if compare_maps:
        e.check(label + ':observed DSO identity retained', before.get('maps') == after.get('maps'))


def fingerprint_check(e, fingerprint, level, label):
    if not isinstance(fingerprint, dict):
        e.check(label + ':fingerprint observed', None)
        return
    e.check(label + ':correct initialized level and version',
            fingerprint.get('numpy_loaded') is True and fingerprint.get('level') == level
            and fingerprint.get('version') == '2.2.6' and isinstance(fingerprint.get('module_id'), int)
            and isinstance(fingerprint.get('origin_pid'), int) and isinstance(fingerprint.get('geterr'), dict))
    if level == 'import':
        e.check(label + ':import level has no secretly preallocated array',
                fingerprint.get('data_id') is None and fingerprint.get('data_sha256') is None
                and fingerprint.get('data_bytes') == 0)
    else:
        e.check(label + ':fixed readonly 8MiB prepared array',
                fingerprint.get('data_bytes') == 8 * 1024**2 and fingerprint.get('data_writeable') is False
                and isinstance(fingerprint.get('data_id'), int)
                and bool(re.fullmatch('[0-9a-f]{64}', fingerprint.get('data_sha256', ''))))


def performance_binding(e, path, config, variant):
    """Bind actual timing-request facts plus separately tested dependency scope.

    Qualification never substitutes for this run's wait/FD/gate/runtime data.
    Conversely trace-disabled timing is not a new namespace ancestry proof.
    """
    if path is None:
        e.check('performance:actual same-session verification supplied', None)
        return None
    path = Path(path)
    if not path.is_absolute():
        path = STUDY / path
    container = e.json(path)
    matches = [r for r in container.get('runs', []) if Path(r.get('run', '')).resolve() == e.run]
    e.check('performance:unique same actual run report', len(matches) == 1)
    if len(matches) != 1:
        return None
    report = matches[0]
    e.check('performance:actual request qualification PASS', report.get('status') == 'PASS')
    e.check('performance:current independent verifier',
            report.get('verifier_sha256') == sha(STUDY / 'runner/verify_performance.py'))
    raw = report.get('evidence_sha256', {})
    e.check('performance:actual evidence hashes recorded', True if raw else None)
    mismatches = []
    for filename, digest in raw.items():
        try:
            if sha(within_run(e.run, filename)) != digest:
                mismatches.append(filename)
        except (ValueError, OSError):
            mismatches.append(filename)
    e.check('performance:actual wait/gate/runtime/output evidence unchanged', not mismatches, mismatches[:20])
    review_name = variant.get('source_review_path', '')
    if not re.fullmatch(r'docs/variant-source-review(?:-v[0-9]+)?\.json', review_name):
        e.check('performance:restricted source-review path', False, review_name)
        return None
    review_path = STUDY / review_name
    review = e.json(review_path)
    e.check('performance:review hash pinned in actual run', variant.get('source_review_sha256') == sha(review_path))
    scope = review.get('numpy_admission_scope', {})
    e.check('performance:level/mode/case/audit explicitly qualified', review.get('performance_admitted') is True
            and config.get('numpy_level') in scope.get('levels', [])
            and config.get('numpy_baseline') in scope.get('baselines', [])
            and config.get('numpy_case') in scope.get('cases', [])
            and str(config.get('numpy_audit')) in scope.get('audit_modes', []))
    refs = scope.get('qualification_evidence', [])
    e.check('performance:concrete NumPy qualification references', True if isinstance(refs, list) and refs else None)
    native_found, boundary_found, proof_refs = False, False, []
    for index, item in enumerate(refs if isinstance(refs, list) else []):
        label = 'performance:scope-proof:' + str(index)
        if not isinstance(item, dict) or not isinstance(item.get('path'), str):
            e.check(label + ':explicit proof path and SHA', False, item)
            continue
        ref = Path(item['path'])
        if ref.is_absolute() or '..' in ref.parts or not ref.parts or ref.parts[0] != 'analysis':
            e.check(label + ':restricted proof path', False, item)
            continue
        full = STUDY / ref
        proof = e.json(full)
        if not proof:
            continue
        e.check(label + ':proof is frozen actual NumPy PASS', proof.get('status') == 'PASS'
                and sha(full) == item.get('sha256') and proof.get('verifier_sha256') == sha(Path(__file__)))
        proof_run = STUDY / 'runs' / proof.get('run', '')
        try:
            proof_run.resolve(strict=True).relative_to((STUDY / 'runs').resolve())
        except (ValueError, OSError):
            e.check(label + ':proof actual run path', False)
            continue
        proof_manifest = e.json(proof_run / 'variant-manifest.json')
        e.check(label + ':same executable source/runtime bytes',
                proof_manifest.get('source_sha256') == variant.get('source_sha256')
                and proof_manifest.get('binary_sha256') == variant.get('binary_sha256')
                and e.json(proof_run / 'candidate-runtime-sha.json') == e.json(e.run / 'candidate-runtime-sha.json'))
        bad = []
        for relative, digest in proof.get('evidence_sha256_study_relative', {}).items():
            try:
                if sha(within_run(STUDY, relative)) != digest:
                    bad.append(relative)
            except (ValueError, OSError):
                bad.append(relative)
        e.check(label + ':dependency raw evidence remains unchanged',
                bool(proof.get('evidence_sha256_study_relative')) and not bad, bad[:20])
        same_level = proof.get('numpy_level') == config.get('numpy_level')
        if item.get('purpose') == 'native_dependency_admission':
            accepted = (same_level and proof.get('full_dependency_admission') is True
                        and proof.get('verification_profile') == 'dependency-audit'
                        and proof.get('native_dependency_observation') == 'OBSERVED_AUDITED')
            e.check(label + ':actual same-level native dependency and reused state admission', accepted)
            native_found |= accepted
        elif item.get('purpose') == 'boundary_only':
            accepted = (same_level and proof.get('verification_profile') == 'boundary-only'
                        and proof.get('numpy_baseline') == config.get('numpy_baseline')
                        and proof.get('numeric_counts', {}).get('PASS', 0) >= 1)
            # Scope may carry both baseline proofs; only the current baseline
            # contributes to this check, the other remains an explicit reference.
            boundary_found |= accepted
        else:
            e.check(label + ':known qualification purpose', False, item.get('purpose'))
        proof_refs.append({'path': str(ref), 'sha256': sha(full), 'purpose': item.get('purpose')})
    e.check('performance:audited same-level hot dependency proof available', native_found)
    e.check('performance:actual audit-off baseline boundary proof available', boundary_found)
    return {'path': str(path.resolve().relative_to(STUDY)), 'sha256': sha(path),
            'status': report.get('status'), 'scope_proofs': proof_refs}


def admission_record(e, record, level, manifest, label, *, audit_required=True):
    e.check(label + ':actual initialization level', record.get('level') == level)
    before, imported, after = (record.get(k) for k in ('before', 'imported', 'after'))
    snapshot_check(e, before, label + ':before', manifest, audit_required=audit_required, numpy_expected=False)
    snapshot_check(e, imported, label + ':imported', manifest, audit_required=audit_required)
    snapshot_check(e, after, label + ':after', manifest, audit_required=audit_required)
    pair_state_check(e, before, after, label)
    e.check(label + ':thread settings actually active during import',
            isinstance(imported, dict) and all(imported.get('environment', {}).get(k) == v for k, v in THREAD_ENV.items()))
    e.check(label + ':all declared initialization checks true',
            set(record.get('checks', {})) == {'single_before', 'single_imported', 'single_after', 'fds_unchanged',
                                              'signals_unchanged', 'environment_restored'}
            and all(v is True for v in record.get('checks', {}).values()))
    fingerprint_check(e, record.get('fingerprint'), level, label)
    times = [record.get(k) for k in ('start_ns', 'import_ready_ns', 'initialized_ns', 'complete_ns')]
    e.check(label + ':same-clock actual initialization ordering',
            all(isinstance(t, int) and t > 0 for t in times) and times == sorted(times)
            and isinstance(record.get('cpu_ns'), int) and record['cpu_ns'] >= 0)


def phase_forks(e, phases, nonce, manifest, level):
    required = ('Z_before_first_fork', 'Z_after_first_parent', 'S_before_second_fork', 'S_after_second_parent')
    own = [r for r in phases if r.get('nonce') == nonce]
    by_stage = {r.get('stage'): r for r in own}
    e.check(nonce + ':two-fork actual dependency checkpoints',
            True if set(required) <= set(by_stage) else None, sorted(by_stage))
    if not set(required) <= set(by_stage):
        return
    for stage in required:
        row = by_stage[stage]
        # The transition has entered a new mount/PID-for-children namespace;
        # /proc/self is not reliably available there. This checkpoint exports
        # the real callback buffer, not invented /proc/FD snapshots.
        audit_check(e, row.get('snapshot', {}).get('audit'), nonce + ':' + stage)
        fingerprint_check(e, row.get('fingerprint'), level, nonce + ':' + stage)
    for before_stage, after_stage in zip(required[::2], required[1::2]):
        before, after = by_stage[before_stage]['snapshot'], by_stage[after_stage]['snapshot']
        old, new = before.get('audit', {}), after.get('audit', {})
        old_events = old.get('events', [])
        new_events = new.get('events', [])
        e.check(nonce + ':' + before_stage + ':same actual parent audit prefix',
                old.get('pid') == new.get('pid') and new_events[:len(old_events)] == old_events)
        delta = new_events[len(old_events):]
        registry = {r['slot']: r for r in new.get('registry', [])}
        blas_slots = {slot for slot, r in registry.items()
                      if 'openblas' in str(r.get('callbacks', {}).get('prepare', {}).get('dso', '')).lower()}
        events = [r for r in delta if r.get('slot') in blas_slots]
        e.check(nonce + ':' + before_stage + ':OpenBLAS prepare really entered and returned once',
                bool(blas_slots) and len(events) == 2 * len(blas_slots)
                and all([r.get('edge') for r in events if r.get('slot') == slot] == ['enter', 'exit']
                        and all(r.get('phase') == 'prepare' for r in events if r.get('slot') == slot)
                        for slot in blas_slots))
        e.check(nonce + ':' + before_stage + ':callback uses original role security phase',
                all(r.get('seccomp') == (0 if before_stage.startswith('Z_') else 2) for r in events))


def analyze(name, lifecycle=None, runtime=None, profile='dependency-audit', performance_report=None):
    rel = Path(name)
    if rel.is_absolute() or '..' in rel.parts:
        raise ValueError('expected run path relative to this study runs directory')
    run = (STUDY / 'runs' / rel).resolve(strict=True)
    run.relative_to((STUDY / 'runs').resolve())
    e = Evidence(run)
    config = e.json(run / 'review-config.json')
    variant = e.json(run / 'variant-manifest.json')
    sources = e.json(run / 'source-sha.json')
    e.check('explicit fixed NumPy configuration', config.get('numpy_level') in ('import', 'data', 'blas')
            and config.get('numpy_baseline') in ('hot', 'cold') and config.get('numpy_case') in ('normal', 'compute_failure', 'cow_all')
            and config.get('numpy_thread_environment') == THREAD_ENV)
    level, baseline = config.get('numpy_level'), config.get('numpy_baseline')
    audited = str(config.get('numpy_audit')) == '1'
    if profile == 'dependency-audit':
        e.check('actual native dependency audit enabled for admission', True if audited else None,
                'audit=0 is unobserved here; use explicit boundary-only scope for other correctness facts')
    elif profile == 'boundary-only':
        e.check('explicit boundary-only scope does not claim native registration qualification',
                profile == 'boundary-only')
    else:
        e.check('explicit performance observation scope', profile == 'performance' and config.get('case') == 'performance')
    fields = ('numpy_level', 'numpy_baseline', 'numpy_case', 'numpy_audit', 'variant', 'diagnostics')
    e.check('manifest records all request configuration fields',
            True if all(k in variant for k in fields) else None, [k for k in fields if k not in variant])
    e.check('recorded manifest and request configuration agree',
            all(config.get(k) == variant[k] for k in fields if k in variant))
    source_errors = []
    for filename, digest in sources.items():
        try:
            if sha(within_run(run / 'prototype', filename)) != digest:
                source_errors.append(filename)
        except (ValueError, OSError):
            source_errors.append(filename)
    e.check('frozen per-run source content preserved', bool(sources) and not source_errors, source_errors)
    if profile == 'performance':
        related = {'actual_performance': performance_binding(e, performance_report, config, variant)}
    else:
        related = {'lifecycle': verify_related_report(e, lifecycle, 'lifecycle', name),
                   'runtime': verify_related_report(e, runtime, 'runtime', name)}
    manifest, installed = package_evidence(e)
    reference = e.json(run / 'numpy-reference.json')
    command = e.json(run / 'numpy-reference-command.json')
    reference_path = run / 'numpy-reference.npz'
    e.check('cold numerical reference file saved', True if reference_path.is_file() else None)
    if reference_path.is_file():
        e.record(reference_path)
        e.check('reference raw artifact identity', reference.get('sha256') == sha(reference_path))
    e.check('reference fixed NumPy and tolerance', reference.get('event') == 'NP_COLD_REFERENCE'
            and reference.get('numpy') == '2.2.6' and reference.get('rtol') == RTOL and reference.get('atol') == ATOL)
    argv = command.get('argv', [])
    e.check('cold reference uses explicit candidate loader and separate Python',
            bool(argv) and argv[0] == '/opt/shimos-glibc/lib/ld-linux-x86-64.so.2'
            and '/usr/bin/python3' in argv and any(str(a).endswith('/numpy_reference.py') for a in argv)
            and command.get('uid') == 65534 and command.get('nnp') == 1 and command.get('performance_sample') is False)
    snapshot_check(e, reference.get('snapshot'), 'cold-reference', manifest, audit_required=False)
    # Runtime mappings and kernel fork/exec/wait remain separately qualified.
    # Actual UID/caps of the reference are checked if recorded, never inferred
    # solely from command-line uid configuration.
    reference_identity = reference.get('snapshot', {}).get('security')
    if reference_identity is None:
        e.check('cold-reference actual uid/NNP observed', None)
    else:
        e.check('cold-reference actual uid/NNP observed',
                reference_identity.get('uid') == 65534 and reference_identity.get('nnp') == 1)

    paths = list(run.glob('zygote-*.log')) + list(run.glob('[0-9]*-output.log')) + list(run.glob('supervisor-output-*.log'))
    if (run / 'events.jsonl').is_file():
        paths.append(run / 'events.jsonl')
    logs = e.logs(sorted(set(paths)))
    admissions = [r for r in logs if r['event'] == 'NP_ADMISSION']
    results = [r for r in logs if r['event'] == 'NP_RESULT']
    zchecks = [r for r in logs if r['event'] == 'NP_Z_CHECK']
    phases = [r for r in logs if r['event'] == 'NP_PHASE']
    z_admissions = {}
    for index, record in enumerate(admissions):
        label = f'admission:{record.get("location")}:{record.get("pid_namespace_local")}:{index}'
        admission_record(e, record, level, manifest, label, audit_required=audited)
        e.check(label + ':preload location matches execution mode',
                record.get('location') == ('Z' if baseline == 'hot' else 'W_cold'))
        if record.get('location') == 'Z':
            zpid = record.get('fingerprint', {}).get('origin_pid')
            e.check(label + ':unique initialization per live Z process', zpid not in z_admissions)
            z_admissions[zpid] = record
    if baseline == 'hot':
        e.check('actual prepared Z observation', True if z_admissions else None)
    else:
        e.check('cold mode does not initialize dependency in Z', not z_admissions)

    final_paths = sorted(run.glob('[0-9]*-*.json'), key=lambda p: int(p.name.split('-')[0]))
    rows = [e.json(p) for p in final_paths]
    rows = [r for r in rows if r.get('nonce') and 'case' in r]
    if not rows:
        rows = [e.json(p) for p in sorted(run.glob('attempt-*.json'))]
    e.check('actual attempt journals present', True if rows else None)
    nonces = [r.get('nonce') for r in rows]
    e.check('attempt identities unique', len(nonces) == len(set(nonces)) and all(nonces))
    result_nonces = [r.get('nonce') for r in results]
    e.check('no NumPy result from unknown or duplicate attempt',
            set(result_nonces) <= set(nonces) and len(result_nonces) == len(set(result_nonces)))
    observations = []
    released_by_z = defaultdict(list)
    for row in rows:
        nonce, case, zpid = row['nonce'], row.get('case'), row.get('zygote_pid')
        prefix = f'{nonce}:{case}'
        observed = [r for r in results if r.get('nonce') == nonce]
        record = observed[0] if len(observed) == 1 else None
        observation = {'nonce': nonce, 'case': case, 'zygote_host_pid': zpid,
                       'business_result_knowledge': row.get('business'), 'lifecycle_outcome': row.get('outcome'),
                       'resource_state': row.get('resources'), 'numeric_status': 'NOT_OBSERVED',
                       'numpy_result_logged': record is not None, 'result_file': None}
        if case in NO_BUSINESS_CASES:
            e.check(prefix + ':pre-business failure has no dependency execution',
                    not observed and not row.get('worker') and not row.get('numpy_output'))
            observation['numeric_status'] = 'NOT_EXECUTED'
        elif case in NUMERIC_CASES:
            e.check(prefix + ':required real NumPy execution record', True if record else None)
        if record:
            e.check(prefix + ':execution configuration matches', record.get('baseline') == baseline
                    and record.get('level') == level and record.get('initialized_in_this_worker') == (baseline == 'cold'))
            expected_checks = {'numerical', 'single_thread', 'fds_restored', 'signals_unchanged', 'env_unchanged', 'inherited', 'expected_failure'}
            e.check(prefix + ':all actual NumPy business checks true',
                    set(record.get('checks', {})) == expected_checks and all(v is True for v in record['checks'].values()))
            before, after = record.get('before'), record.get('after')
            snapshot_check(e, before, prefix + ':W-before', manifest, audit_required=audited)
            snapshot_check(e, after, prefix + ':W-after', manifest, audit_required=audited)
            pair_state_check(e, before, after, prefix + ':W-state')
            e.check(prefix + ':W environment/FD boundary maintained while using NumPy',
                    before.get('environment') == after.get('environment') == {'PATH': '/usr/bin:/bin'}
                    and set(before.get('fds', {})) <= {'0', '1', '2'} and set(after.get('fds', {})) <= {'0', '1', '2'})
            e.check(prefix + ':W final security policy remains installed',
                    all(s.get('security', {}).get('seccomp') == 2
                        and int(s.get('security', {}).get('capabilities', {}).get('CapBnd', '-1'), 16) == 0
                        for s in (before, after)))
            fp = record.get('initial_fingerprint')
            fingerprint_check(e, fp, level, prefix + ':W-initial')
            if baseline == 'hot':
                initial = z_admissions.get(zpid, {}).get('fingerprint')
                e.check(prefix + ':W inherited actual Z module and prepared data identity',
                        record.get('inherited_preload') is True and fp == initial and bool(initial))
                if audited:
                    phase_forks(e, phases, nonce, manifest, level)
            else:
                e.check(prefix + ':cold W did not inherit dependency preload', record.get('inherited_preload') is False)
                cold_admissions = [r for r in admissions if r.get('location') == 'W_cold'
                                   and r.get('pid_namespace_local') == before.get('pid_namespace_local')
                                   and r.get('complete_ns', 0) < before.get('monotonic_ns', 0)
                                   and r.get('start_ns', 0) >= record.get('call_start_ns', 0)]
                e.check(prefix + ':actual cold initialization inside this W', len(cold_admissions) == 1)
            after_fp = record.get('after_cow_fingerprint', {})
            if level in ('data', 'blas'):
                expected_write = 8 * 1024**2 if config.get('numpy_case') == 'cow_all' else 8
                e.check(prefix + ':bounded COW write happened only in W state',
                        after_fp.get('data_sha256') != fp.get('data_sha256')
                        and after_fp.get('data_id') == fp.get('data_id') and after_fp.get('module_id') == fp.get('module_id')
                        and after_fp.get('data_writeable') is False and record.get('requested_cow_write_bytes') == expected_write)
            else:
                e.check(prefix + ':import-only workload claims no template data COW',
                        after_fp == fp and record.get('requested_cow_write_bytes') == 0)
            if config.get('numpy_case') == 'compute_failure':
                failure = record.get('computation_failure') or {}
                e.check(prefix + ':real incompatible-shape operation raised ValueError',
                        failure.get('type') == 'ValueError' and failure.get('actual_operation') == 'incompatible-shape matmul')
            raw = row.get('numpy_output') or {}
            rawfile = raw.get('file')
            if rawfile and reference_path.is_file():
                try:
                    path = within_run(run, rawfile)
                    e.record(path)
                    compared = compare_npz(path, reference_path)
                    e.check(prefix + ':saved actual output identity',
                            sha(path) == raw.get('sha256') == record.get('output_sha256'))
                    e.check(prefix + ':independent all-array cold-reference comparison', compared['passed'], compared)
                    e.check(prefix + ':same raw cold reference consumed in W', record.get('reference_sha256') == sha(reference_path))
                    observation['numeric_status'] = 'PASS' if compared['passed'] else 'FAIL'
                    observation['result_file'] = rawfile
                    observation['numerical_comparison'] = compared
                except (ValueError, OSError, zipfile.BadZipFile) as error:
                    e.check(prefix + ':parse actual output artifact', False, repr(error))
                    observation['numeric_status'] = 'FAIL'
            elif case in NUMERIC_CASES:
                e.check(prefix + ':raw numerical output preserved', None)
            else:
                observation['numeric_status'] = 'UNKNOWN_RAW_OUTPUT_NOT_PRESERVED'
            worker = row.get('worker') or {}
            if case in NUMERIC_CASES:
                e.check(prefix + ':real business Worker boundary',
                        set(worker.get('checks', {})) == BUSINESS_CHECKS and all(v is True for v in worker.get('checks', {}).values())
                        and worker.get('nonce') == nonce and worker.get('numpy', {}).get('checks') == record.get('checks'))
        if row.get('resources') == 'RELEASED':
            e.check(prefix + ':per-request release has actual state evidence',
                    row.get('resources_removed') is True and row.get('domain_empty') is True
                    and row.get('output_eof') is True and row.get('controller_fd_after') == row.get('controller_fd_before')
                    and str(row.get('admission', '')).startswith('SEALED'))
        post = row.get('zygote_post')
        if post:
            zrecord = [r for r in zchecks if r.get('nonce') == nonce and r.get('pid_namespace_local') == zpid]
            e.check(prefix + ':actual post-request NumPy template observation', True if len(zrecord) == 1 else None)
            if len(zrecord) == 1:
                zrecord = zrecord[0]
                e.check(prefix + ':template integrity not merely a self-reported boolean',
                        zrecord.get('stable') is True and zrecord.get('fingerprint') == zrecord.get('baseline')
                        and post.get('state_unchanged') is True and post.get('active_attempts') == 0
                        and post.get('nonce') == nonce)
                snap = zrecord.get('snapshot')
                snapshot_check(e, snap, prefix + ':Z-post', manifest, audit_required=audited, numpy_expected=baseline == 'hot')
                if baseline == 'hot' and zpid in z_admissions:
                    original = z_admissions[zpid]
                    e.check(prefix + ':Z original dependency fingerprint restored', zrecord.get('fingerprint') == original.get('fingerprint'))
                    pair_state_check(e, original.get('after'), snap, prefix + ':Z-restore')
        if case in NUMERIC_CASES and observation['numeric_status'] == 'PASS' and row.get('resources') == 'RELEASED':
            released_by_z[zpid].append(nonce)
        if row.get('business') == 'UNKNOWN':
            e.check(prefix + ':unknown business is not promoted by a numeric artifact', row.get('outcome') != 'SUCCEEDED')
        observations.append(observation)

    if baseline == 'hot' and config.get('case') in ('control', 'runtime', 'performance') and len(rows) >= 2:
        e.check('same hot Z actually served at least two independently released domains',
                any(len(v) >= 2 and len(set(v)) == len(v) for v in released_by_z.values()), dict(released_by_z))
    if baseline == 'cold':
        e.check('cold baseline truly creates a new Z for each request', len({r.get('zygote_pid') for r in rows}) == len(rows))
    supervisor = e.json(run / 'supervisor.json')
    e.check('actual final H resource release, no observer cleanup',
            supervisor.get('release_state') == 'RELEASED' and supervisor.get('resources_removed') is True
            and supervisor.get('observer_cleanup_used') is False and not supervisor.get('errors')
            and not supervisor.get('remaining_cgroups') and not supervisor.get('remaining_workspaces')
            and supervisor.get('echild') is True and supervisor.get('fd_before') == supervisor.get('fd_after'))
    failures = [r for r in e.checks if r['value'] is False]
    blockers = [r for r in e.checks if r['value'] is None]
    status = 'FAIL' if failures else ('BLOCKED' if blockers else 'PASS')
    reuse_demonstrated = baseline == 'hot' and any(len(v) >= 2 for v in released_by_z.values())
    return {'run': name, 'status': status, 'verification_profile': profile,
            'full_dependency_admission': status == 'PASS' and profile == 'dependency-audit' and reuse_demonstrated,
            'hot_cross_domain_reuse_demonstrated': reuse_demonstrated,
            'native_dependency_observation': 'OBSERVED_AUDITED' if audited else 'NOT_OBSERVED',
            'numpy_level': level, 'numpy_baseline': baseline,
            'numpy_case': config.get('numpy_case'), 'dependency_audit': audited,
            'attempts': observations, 'numeric_counts': dict(Counter(r['numeric_status'] for r in observations)),
            'same_template_released_domains': dict(released_by_z), 'admission_count': len(admissions),
            'checks': e.checks, 'failures': failures, 'blockers': blockers,
            'related_reports': related, 'verifier_sha256': sha(Path(__file__)), 'evidence_sha256_study_relative': e.evidence,
            'limitations': [
                'Only pinned NumPy 2.2.6 CPU configuration at the recorded import/data/blas level; no arbitrary dependency approval.',
                'This numerical and dependency checker complements actual lifecycle and full fork-wrapper qualification.',
                'Boundary task snapshots and pthread_create interposition do not prove no hidden/direct clone thread ever existed.',
                'Atfork interposition observes dynamic registrations through the recorded symbol; hidden/internal routes remain outside that observation.',
                'Explicit ndarray/geterr/module identity and environment checks do not prove every byte of the Python heap unchanged.',
                'PSS, private/shared memory, faults and pagemap flags are observations, not an exact count of copied COW pages.',
                'A correct saved array after receipt loss or Controller failure never becomes a successful business result.',
                'Cold reference is a separate Python execution; shared source computes the same formulas, not an independent mathematical oracle.',
                'No performance claim is produced by this correctness verifier.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', help='path relative to this study runs directory')
    parser.add_argument('--lifecycle', help='same-run independent lifecycle report, study-relative or absolute')
    parser.add_argument('--runtime', help='same-run independent fork-runtime report, study-relative or absolute')
    parser.add_argument('--profile', choices=('dependency-audit', 'boundary-only', 'performance'), default='dependency-audit',
                        help='boundary-only/audit-off performance never grants new native dependency admission')
    parser.add_argument('--performance-report', help='same-session verify_performance report, required for performance profile')
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--output', help='new exclusive study-relative JSON output path')
    args = parser.parse_args()
    try:
        result = analyze(args.run, args.lifecycle, args.runtime, args.profile, args.performance_report)
    except (OSError, ValueError, TypeError, KeyError, AssertionError, struct.error, zipfile.BadZipFile):
        result = {'run': args.run, 'status': 'BLOCKED', 'verification_profile': args.profile,
                  'full_dependency_admission': False, 'numeric_counts': {}, 'failures': [],
                  'blockers': [{'check': 'evidence parsing did not complete', 'value': None,
                                'detail': traceback.format_exc()}],
                  'verifier_sha256': sha(Path(__file__))}
    if not args.check_only:
        destination = Path(args.output) if args.output else Path('analysis') / (args.run.replace('/', '-') + '-numpy.json')
        if destination.is_absolute() or '..' in destination.parts:
            parser.error('output must be a new relative path inside this study')
        destination = STUDY / destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('x') as out:
            json.dump(result, out, ensure_ascii=False, indent=2)
            out.write('\n')
    print(json.dumps({key: result[key] for key in ('run', 'status', 'numeric_counts', 'failures', 'blockers')}, ensure_ascii=False))
    return int(result['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
