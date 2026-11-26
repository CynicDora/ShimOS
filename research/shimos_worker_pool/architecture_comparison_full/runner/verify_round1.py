#!/usr/bin/env python3
"""Read-only G0/G1/G2 admission; missing evidence is never a successful run.

This does not run, signal or clean up a workload. Numerical arrays are decoded
with the independent stdlib reader from verify_numpy, never with tested NumPy.
G0 has its own actual parent/wait/exec proof, not imaginary Z/S observations.
"""
import argparse
import collections
import json
import re
import traceback
from pathlib import Path
import verify_numpy as npcheck
import verify_performance as perfcheck
import verify_qualification as lifecycle
import verify_runtime as runtimecheck

S = Path(__file__).resolve().parent.parent
CG = '/sys/fs/cgroup/cdz'
COMMON_CHECKS = npcheck.BUSINESS_CHECKS - {'inherited', 'not_recreated'}
GROUP_CHECKS = {'G0': COMMON_CHECKS | {'fresh_runtime', 'no_preloaded_numpy'},
                'G1': npcheck.BUSINESS_CHECKS, 'G2': npcheck.BUSINESS_CHECKS}
NORMAL = {'normal', 'nonzero', 'created_drop', 'reaped_drop'}
PREBUSINESS = set(npcheck.NO_BUSINESS_CASES) | {'control_eof', 'fork_ack_loss'}
sha = npcheck.sha


class Evidence(npcheck.Evidence):
    def records(self, paths):
        result = []
        for path in paths:
            if not path.is_file():
                continue
            self.record(path)
            for index, text in enumerate(path.read_text(errors='replace').splitlines(), 1):
                try:
                    value = json.loads(text)
                except ValueError:
                    # Ordinary traceback/plain output is allowed, malformed JSON
                    # evidence is not silently accepted as an absent event.
                    if text.lstrip().startswith('{'):
                        self.check(f'valid JSON record:{path.name}:{index}', None, text[:200])
                    continue
                if isinstance(value, dict):
                    result.append(dict(value, _file=path.name, _line=index))
        return result


def clean(record):
    return {k: v for k, v in record.items() if not k.startswith('_')}


def unique(records):
    return list({json.dumps(clean(x), sort_keys=True): x for x in records}.values())


def zero_cap(status, key):
    try:
        return int(status.get(key, '-1'), 16) == 0
    except (ValueError, TypeError):
        return False


def source_binding(e, config, manifest, group, profile):
    sources = e.json(e.run / 'source-sha.json')
    review_path = manifest.get('source_review_path', '')
    if not re.fullmatch(r'docs/(?:variant-source-review(?:-v[0-9]+)?|performance-source-review)\.json', review_path):
        e.check('source review restricted path', False, review_path)
        return {}, sources
    path = S / review_path
    review = e.json(path)
    if not review:
        return {}, sources
    pinned=manifest.get('source_review_sha256')
    if pinned is None and profile!='performance':
        frozen=e.json(S/'frozen/candidate-01.json')
        e.check('post-run source review binds exactly pre-run frozen candidate',
                frozen.get('prototype_sha256')==sources,
                {'review_timing':'POST_RUN_STATIC_REVIEW','manifest_left_unmodified':True,
                 'review_sha256':sha(path),'not_a_pre_run_review_claim':True})
    else:
        e.check('source review pinned by actual run', pinned == sha(path))
    entry = review.get('variants', {}).get(manifest.get('variant'), {})
    architecture = review.get('architectures', {}).get(group, {})
    e.check('particular architecture independently source-admitted', architecture.get('admitted') is True
            and bool(architecture.get('checks')) and all(x.get('passed') is True and x.get('evidence')
            for x in architecture.get('checks', {}).values()), architecture)
    e.check('explicit diagnostic mode consistent', config.get('variant') == manifest.get('variant') == 'low'
            and config.get('diagnostics') == manifest.get('diagnostics') == 'low')
    e.check('variant source admission complete', entry.get('admitted') is True)
    bad = []
    for name, digest in sources.items():
        try:
            if sha(npcheck.within_run(e.run / 'prototype', name)) != digest:
                bad.append(name)
        except (ValueError, OSError):
            bad.append(name)
    e.check('exact actual source bytes reviewed', bool(sources) and not bad
            and sources == manifest.get('source_sha256') == entry.get('source_sha256'), bad)
    binaries = manifest.get('binary_sha256', {})
    build = e.json(e.run / 'build.json')
    binary_bad = []
    for name, digest in binaries.items():
        try:
            if sha(npcheck.within_run(e.run, name)) != digest or build.get(name) != digest:
                binary_bad.append(name)
        except (ValueError, OSError):
            binary_bad.append(name)
    e.check('exact compiled binary bytes reviewed', bool(binaries) and not binary_bad
            and binaries == entry.get('binary_sha256'), binary_bad)
    runtime = e.json(e.run / 'candidate-runtime-sha.json')
    installed = e.json(e.run / 'candidate-runtime-install.json')
    original = e.json(S/'frozen/candidate-04-runtime-sha.json')
    provenance=e.json(S/'frozen/candidate-04-runtime-provenance.json')
    e.check('original fixed D runtime source copied byte-for-byte',provenance.get('copied_bytes_unchanged') is True
            and provenance.get('sha256')==sha(S/'frozen/candidate-04-runtime-sha.json'))
    bad_runtime = []
    for name, digest in runtime.items():
        try:
            if sha(npcheck.within_run(e.run / 'candidate-runtime', name)) != digest:
                bad_runtime.append(name)
        except (ValueError, OSError):
            bad_runtime.append(name)
    e.check('unchanged D candidate-04 runtime actually installed', bool(runtime) and runtime == original
            and installed.get('verified_sha256') == runtime and not bad_runtime, bad_runtime)
    if profile == 'performance':
        scope = review.get('numpy_admission_scope', {})
        e.check('exact architecture/workload explicitly performance-admitted', review.get('performance_admitted') is True
                and group in scope.get('architectures', []) and config.get('numpy_level') in scope.get('levels', [])
                and config.get('numpy_baseline') in scope.get('baselines', [])
                and config.get('numpy_case') in scope.get('cases', [])
                and str(config.get('numpy_audit')) in scope.get('audit_modes', []))
    return review, sources


def actual_trace(e, config, rows, sup, group, profile):
    if profile == 'performance':
        trace = e.json(e.run / 'trace-config.json')
        e.check('performance uses untraced samples', str(config.get('trace')) == '0'
                and str(trace.get('tracing_on', '')).strip() == '0')
        return
    path = e.run / 'process-trace.txt'
    if not path.is_file():
        e.check('actual qualification kernel process trace', None)
        return
    e.record(path)
    text = path.read_text(errors='replace')
    stats = e.json(e.run / 'trace-stats.json')
    e.check('trace covers actual guest CPUs', True if stats else None)
    for cpu, values in stats.items():
        loss = dict(re.findall(r'^(overrun|commit overrun|dropped events): (\d+)$', values, re.M))
        e.check('no trace loss:' + cpu, len(loss) == 3 and all(int(x) == 0 for x in loss.values()), loss)
    edges, execs, exits = {}, collections.defaultdict(list), set()
    for line in text.splitlines():
        if 'sched_process_fork:' in line:
            m = re.search(r' pid=(\d+) child_comm=.* child_pid=(\d+)', line)
            if m:
                child=int(m[2]);e.check('no reused trace PID ambiguity:'+str(child),child not in edges)
                edges[child] = int(m[1])
        elif 'sched_process_exec:' in line:
            m = re.search(r'filename=(.*?) pid=(\d+)', line)
            if m:
                execs[int(m[2])].append(m[1])
        elif 'sched_process_exit:' in line:
            m = re.search(r' pid=(\d+)', line)
            if m:
                exits.add(int(m[1]))
    e.check('actual H creates R', sup.get('controller_pid') in edges
            and edges[sup['controller_pid']] == sup.get('pid'))
    for row in rows:
        n = row['nonce']
        w = row.get('w_pid')
        if group == 'G0' and w:
            e.check(n + ':G0 W actual parent is target PID1', edges.get(w) == row.get('init_pid'),
                    {'worker': w, 'trace_parent': edges.get(w), 'init': row.get('init_pid')})
            e.check(n + ':G0 fixed cold runtime successful exec observed',
                    execs.get(w) == ['/opt/shimos-glibc/lib/ld-linux-x86-64.so.2'], execs.get(w))
        elif group != 'G0' and w:
            e.check(n + ':actual Z/S/W ancestry', edges.get(row.get('s_pid')) == row.get('zygote_pid')
                    and edges.get(w) == row.get('s_pid'))
            e.check(n + ':no successful interpreter re-exec in inherited W', not execs.get(w))
        if w and row.get('resources') == 'RELEASED':
            e.check(n + ':W kernel exit corroborates actual waiter', w in exits)


def common_release(e, rows, sup, ext, summary, logs, config):
    e.check('H survives to actual complete release', sup.get('release_state') == 'RELEASED'
            and sup.get('resources_removed') is True and sup.get('remaining_cgroups') == []
            and sup.get('remaining_workspaces') == [] and sup.get('errors') == []
            and sup.get('protocol_errors') == [] and sup.get('echild') is True)
    e.check('H actual FD inventory restored', sup.get('fd_before') is not None
            and sup.get('fd_before') == sup.get('fd_after'))
    e.check('actual H is unprivileged product supervisor',any(x.get('event')=='SUPERVISOR_STARTED'
            and x.get('uid')==65534 and x.get('pid')==sup.get('pid') for x in logs))
    realwait = [x for x in logs if x.get('event') == 'SUPERVISOR_REAL_WAIT']
    e.check('H truly waits Controller', any(x.get('pid') == sup.get('controller_pid')
            and x.get('wait_status') == sup.get('controller_wait_status') for x in realwait))
    for waiter in sup.get('wait_records', []):
        e.check('H wait record backed by event:' + str(waiter.get('pid')), any(
            x.get('pid') == waiter.get('pid') and x.get('wait_status') == waiter.get('wait_status') for x in realwait))
    e.check('external observer never substitutes product cleanup', sup.get('observer_cleanup_used') is False
            and ext.get('observer_killed_processes') is False and ext.get('observer_removed_product_resources') is False
            and ext.get('delegation_removed') is True and ext.get('supervisor_wait_status') == 0)
    for filename in ('observer-after.json', 'observer-later.json'):
        observer = e.json(e.run / filename)
        groups = observer.get('cgroups', {})
        e.check(filename + ':no actual product process/workspace', observer.get('uid65534_processes') == {}
                and observer.get('workspaces') == {})
        e.check(filename + ':remaining fixture cgroups empty', set(groups) == {CG, CG + '/client'} and all(
            not g.get('cgroup.procs', 'missing').strip() and not g.get('cgroup.threads', 'missing').strip()
            and g.get('pids.current', '').strip() == '0' and 'populated 0' in g.get('cgroup.events', '')
            for g in groups.values()))
    if summary:
        e.check('normal R reached actual ECHILD and done', summary.get('all_passed') is True
                and summary.get('controller_echild') is True and sup.get('done_received') is True
                and sup.get('controller_wait_status') == 0 and sup.get('failure_reason') is None)
    else:
        e.check('missing summary is only intentional Controller-death case',
                config.get('case') in ('controller_death', 'controller_during_entry', 'session_deadline'))
        e.check('Controller death retained UNKNOWN not success', sup.get('controller_wait_status') == 9
                and sup.get('done_received') is False and sup.get('business_result') == 'UNKNOWN'
                and isinstance(sup.get('recovery_started_ns'), int))
    if config.get('case')=='session_deadline':
        start=[x for x in logs if x.get('event')=='SUPERVISOR_STARTED']
        end=[x for x in logs if x.get('event')=='SUPERVISOR_RECOVERY_START']
        e.check('actual H deadline triggered rather than another fault',len(start)==len(end)==1
                and end[0].get('reason')==sup.get('failure_reason')=='CONTROLLER_DEADLINE'
                and end[0].get('monotonic_ns',0)-start[0].get('monotonic_ns',0)>=2_000_000_000)
    registered = {x.get('nonce'): x for x in sup.get('attempts', [])}
    e.check('H registration exact unique request inventory', len(registered) == len(sup.get('attempts', [])) == len(rows)
            and set(registered) == {r['nonce'] for r in rows})
    for row in rows:
        n = row['nonce']; h = registered.get(n, {}); own = [x for x in logs if x.get('nonce') == n]
        e.check(n + ':H owns registered domain', h.get('registered') is True)
        if row.get('response_committed'):
            e.check(n + ':physical release and EOF before final response', row.get('qualification') == 'PASS'
                    and row.get('resources') == 'RELEASED' and row.get('resources_removed') is True
                    and row.get('domain_empty') is True and row.get('output_eof') is True
                    and str(row.get('admission', '')).startswith('SEALED'))
            e.check(n + ':actual R read-to-EOF evidence', any(x.get('event') == 'OUTPUT_EOF' for x in own))
            e.check(n + ':all actual private cgroups empty', bool(row.get('stats')) and all(
                'populated 0' in g.get('cgroup.events', '') and g.get('pids.current', '').strip() == '0'
                for g in row.get('stats', {}).values()))
            e.check(n + ':R FD inventory restored', row.get('controller_fd_before') is not None
                    and row.get('controller_fd_before') == row.get('controller_fd_after'))
            e.check(n + ':H retirement mirrors R actual evidence', h.get('retired') is True
                    and h.get('resources_removed') is True and h.get('output_eof') is True
                    and h.get('outcome') == row.get('outcome'))
            e.check(n + ':monitor truly waited', any(x.get('event') == 'CONTROLLER_WAIT'
                    and x.get('pid') == row.get('monitor_pid') and x.get('wait_status') == row.get('monitor_wait') for x in logs))
        else:
            e.check(n + ':H recovery result and physical release', h.get('resources_removed') is True
                    and h.get('output_eof') is True and h.get('business_result') == 'UNKNOWN')
            # Actual H evidence stores output_eof only after os.read returns b'';
            # source admission pins that implementation. Not independent polling.
            e.check(n + ':recovery genuinely executed H read/drain path', isinstance(sup.get('recovery_started_ns'), int)
                    and any(x.get('event') == 'SUPERVISOR_RECOVERY_START' for x in logs))
        if row.get('business') == 'UNKNOWN':
            e.check(n + ':unknown business exit never invented', row.get('result') is None
                    and row.get('outcome') not in ('SUCCEEDED', 'NONZERO'))


def worker_boundary(e, row, group):
    worker = row.get('worker')
    if not worker:
        return
    n = row['nonce']; ident = worker.get('identity', {}); status = ident.get('status', {})
    e.check(n + ':actual 19 declared business checks', set(worker.get('checks', {})) == GROUP_CHECKS[group]
            and all(x is True for x in worker.get('checks', {}).values()))
    e.check(n + ':actual final six target namespaces', ident.get('ns') == row.get('target_ns')
            and set(ident.get('ns', {})) == {'user','mnt','pid','net','ipc','uts'})
    e.check(n + ':actual final unprivileged credentials and policy', ident.get('uid') == ident.get('gid') == 65534
            and all(zero_cap(status, k) for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
            and status.get('NoNewPrivs') == '1' and status.get('Seccomp') == '2')
    e.check(n + ':actual Worker business cgroup and FD boundary', ident.get('cgroup', '').strip() == '0::/cdz/d-'+n+'/business'
            and set(ident.get('fds', {})) == {'0','1','2'} and worker.get('nonce') == n)
    limits = row.get('limits', {})
    e.check(n + ':fixed task and business CPU/memory budgets', all(
        str(limits.get(role, {}).get('cpu.max','')).strip() == cpu and str(limits.get(role, {}).get('memory.max','')).strip() == memory
        for role,cpu,memory in (('task','400000 100000','536870912'),('business','200000 100000','268435456'))), limits)


def g0_runtime(e, row, logs):
    n = row['nonce']; own = [x for x in logs if x.get('nonce') == n]
    e.check(n + ':G0 does not fabricate Z/S participation', row.get('s_state') == 'NOT_APPLICABLE'
            and row.get('s_pid') is None and row.get('zygote_pid') is None)
    if row.get('worker'):
        snapshots = [x for x in own if x.get('event') == 'AB_RUNTIME_SNAPSHOT']
        snapshots += [row['worker'].get('runtime', {}), row.get('worker_gated', {}).get('runtime', {})]
        stages = {x.get('stage'): x for x in snapshots}
        e.check(n + ':G0 real gate and business runtime checkpoints',
                True if {'G0_W_gated', 'G0_W_business'} <= set(stages) else None)
        for stage in ('G0_W_gated', 'G0_W_business'):
            snap = stages.get(stage, {}); native = snap.get('native', {})
            e.check(n + ':' + stage + ':actual libc/TLS/TID/robust runtime',
                    set(snap.get('checks', {})) == runtimecheck.SNAP_CHECKS and all(snap.get('checks', {}).values())
                    and native.get('pid') == native.get('tid') == native.get('native_owner')
                    and native.get('cpuclock_rc') == 0 and native.get('cpuclock_tid') == native.get('tid')
                    and native.get('robust_rc') == 0 and native.get('robust_head', 0) > 0
                    and native.get('tls_cookie') == 0x51a7c0de)
    # G0 event spelling/schema will be frozen with implementation; no row-only
    # assertion substitutes for the actual waiter's record.
    waited = row.get('w_wait')
    if waited:
        matches = [x for x in own if x.get('event') == 'PID1_ACTUAL_WAIT']
        e.check(n + ':G0 PID1 actual wait corroborates result', any(
            x.get('wait_status') == waited.get('wait_status') and x.get('pid_local', x.get('worker_local_pid'))
            == waited.get('worker_local_pid') for x in matches), matches)
    if row.get('w_pid'):
        bound = [x for x in own if x.get('event') == 'G0_WORKER_BIND']
        e.check(n + ':kernel SCM_CREDENTIALS binds host identity and birth cgroup', any(
            x.get('host_pid') == row.get('w_pid') and x.get('credentials') == [row.get('w_pid'),65534,65534]
            and str(row.get('w_pid')) in x.get('business_cgroup_members', [])
            and x.get('business_cgroup') == CG+'/d-'+n+'/business'
            and x.get('parent_local') == 1 and x.get('pid_local') == row.get('worker_local_pid') for x in bound), bound)
        creations = [x for x in own if x.get('event') == 'PID1_ACTUAL_CLONE']
        e.check(n + ':G0 atomically born in business cgroup', len(creations) == 1 and all(
                x.get('clone_flags') == 0x200001000 and x.get('worker_local_pid') == row.get('worker_local_pid')
                and isinstance(x.get('clone_begin_ns'),int) and x.get('clone_begin_ns') <= x.get('clone_end_ns',0)
                for x in creations))
        metadata=e.json(e.run/'candidate-runtime.json');by_path={x.get('realpath'):x for x in metadata.get('dso_sha256',{}).values()}
        observed={}
        for line in row.get('worker_gated',{}).get('maps','').splitlines():
            fields=line.split(maxsplit=5)
            if len(fields)<6 or Path(fields[5]).name not in {Path(x).name for x in by_path if x}: continue
            expected=by_path.get(fields[5],{})
            e.check(n+':G0 actual candidate DSO:'+fields[5], bool(expected) and int(fields[4])==expected.get('inode')
                    and [int(v,16) for v in fields[3].split(':')]==expected.get('device'))
            observed[fields[5]]=True
        e.check(n+':G0 actual D runtime closure loaded',all(metadata.get('dso_sha256',{}).get(metadata.get('bundle','')+'/lib/'+lib,{}).get('realpath') in observed
                for lib in ('libc.so.6','libm.so.6','ld-linux-x86-64.so.2')))


def g0_faults(e,row,logs):
    n=row['nonce']; case=row.get('case'); own=[x for x in logs if x.get('nonce')==n]
    types={x.get('event') for x in own}
    if case in ('pid_budget','second_budget'):
        rejected=[x for x in own if x.get('event')=='WORKER_REJECTED']
        e.check(n+':actual G0 clone budget rejection with definite no execution', len(rejected)==1
                and rejected[0].get('errno')==row.get('worker_errno')==11
                and row.get('w_state')=='ABSENT' and row.get('business')=='NOT_EXECUTED'
                and row.get('outcome')=='RESOURCE_REJECTED' and row.get('business_permit') is False
                and not row.get('worker') and row.get('side_effect') is None and 'PID1_ACTUAL_CLONE' not in types)
        e.check(n+':budget rejection really exercised pids limit',
                row.get('limits',{}).get('business',{}).get('pids.max','').strip()=='0'
                and any(int(v)>0 for v in re.findall(r'max (\d+)',row.get('stats',{}).get('business',{}).get('pids.events',''))))
    if case in ('cancel_queued','cancel_before_business','cancel_during_entry','revoke_ack_loss','control_eof'):
        e.check(n+':G0 prebusiness failure never executed', row.get('business')=='NOT_EXECUTED'
                and row.get('business_permit') is False and row.get('side_effect') is None and not row.get('worker')
                and row.get('outcome') not in ('SUCCEEDED','NONZERO') and 'CANCEL_REQUEST' in types)
        if case=='cancel_queued':
            e.check(n+':sealed G0 creator rejects actual late start',row.get('late_start_sent') is True
                    and row.get('late_start_rejected') is True and 'START_REJECTED' in types
                    and 'PID1_ACTUAL_CLONE' not in types)
        elif case in ('cancel_before_business','cancel_during_entry','control_eof'):
            e.check(n+':fault reached actual final business gate','WORKER_GATED' in types)
    if case=='double_cancel':
        acks=unique([x for x in own if x.get('event')=='CANCEL_ACK'])
        e.check(n+':two actual cancellation acknowledgements preserve seal',True if len(acks)>=2 else None,
                {'actual_acknowledgements':len(acks),'note':'one ack plus final cleanup does not prove duplicate acknowledgement semantics'})
        e.check(n+':duplicate cancels never restart Worker',row.get('outcome')=='CANCELLED'
                and all(x.get('sealed') is True for x in acks)
                and len([x for x in own if x.get('event')=='PID1_ACTUAL_CLONE'])==1)
    if case=='timeout':
        e.check(n+':timeout occurs after actual Worker business',bool(row.get('worker'))
                and row.get('outcome')=='TIMED_OUT' and any(x.get('event')=='CANCEL_REQUEST'
                and x.get('reason')=='TIMED_OUT' for x in own))
    if case in ('pid1_death','controller_death'):
        e.check(n+':intended live-process fault truly injected',bool(row.get('worker'))
                and any(x.get('event')=='FAULT' and x.get('case')==case for x in own))
    if case=='result_loss_side_effect':
        waits=[x for x in own if x.get('event')=='PID1_ACTUAL_WAIT' and x.get('pid_local')==row.get('worker_local_pid')]
        e.check(n+':lost exit result remains UNKNOWN despite real effect/wait',bool(waits)
                and row.get('side_effect')=='2650100' and row.get('business')=='UNKNOWN'
                and row.get('result') is None and row.get('outcome')=='RESULT_UNKNOWN'
                and 'WORKER_WAITED' not in types)
    if case not in NORMAL and row.get('response_committed'):
        e.check(n+':fault never emitted successful response',row.get('outcome') not in ('SUCCEEDED','NONZERO'))


def numpy_evidence(e, rows, logs, config, group, package):
    level = config.get('numpy_level'); audit = str(config.get('numpy_audit')) == '1'
    reference = e.json(e.run / 'numpy-reference.json'); command = e.json(e.run / 'numpy-reference-command.json')
    refpath = e.run / 'numpy-reference.npz'
    e.check('independent cold numerical artifact present', True if refpath.is_file() else None)
    if refpath.is_file():
        e.record(refpath); e.check('cold numerical reference SHA', reference.get('sha256') == sha(refpath))
    e.check('independent cold reference exact tolerances and runtime', reference.get('event') == 'NP_COLD_REFERENCE'
            and reference.get('numpy') == '2.2.6' and reference.get('rtol') == npcheck.RTOL
            and reference.get('atol') == npcheck.ATOL and command.get('argv', [None])[0] == '/opt/shimos-glibc/lib/ld-linux-x86-64.so.2'
            and command.get('performance_sample') is False)
    npcheck.snapshot_check(e, reference.get('snapshot'), 'cold_reference', package, audit_required=False)
    np = unique([x for x in logs if str(x.get('event','')).startswith('NP_')])
    admissions = [x for x in np if x.get('event') == 'NP_ADMISSION' and x.get('location') != 'cold_reference']
    results = [x for x in np if x.get('event') == 'NP_RESULT']
    zchecks = [x for x in np if x.get('event') == 'NP_Z_CHECK']
    for index, record in enumerate(admissions):
        npcheck.admission_record(e, record, level, package, 'admission:' + str(index), audit_required=audit)
        e.check('admission location agrees:' + str(index), record.get('location') == ('Z' if group == 'G2' else 'W_cold'))
    zadmissions = {x.get('fingerprint', {}).get('origin_pid'): x for x in admissions if x.get('location') == 'Z'}
    e.check('no fabricated preload in cold architectures', bool(zadmissions) if group == 'G2' else not zadmissions)
    e.check('numerical attempt identities unique and real', len(results) == len({x.get('nonce') for x in results})
            and {x.get('nonce') for x in results} <= {x['nonce'] for x in rows})
    observations = []
    for row in rows:
        n = row['nonce']; own = [x for x in results if x.get('nonce') == n]
        record = own[0] if len(own) == 1 else None
        observation = {'nonce': n, 'case': row.get('case'), 'numeric_status': 'NOT_OBSERVED'}
        if row.get('business') == 'NOT_EXECUTED':
            e.check(n + ':no executed NumPy represented as unexecuted', not own and not row.get('numpy_output') and not row.get('worker'))
            observation['numeric_status'] = 'NOT_EXECUTED'
        elif row.get('case') in NORMAL:
            e.check(n + ':actual numerical execution record', True if record else None)
        if record:
            before, after = record.get('before', {}), record.get('after', {})
            e.check(n + ':workload and initialization semantics', record.get('baseline') == ('hot' if group == 'G2' else 'cold')
                    and record.get('level') == level and record.get('initialized_in_this_worker') == (group != 'G2')
                    and record.get('inherited_preload') == (group == 'G2'))
            expected = {'numerical','single_thread','fds_restored','signals_unchanged','env_unchanged','inherited','expected_failure'}
            e.check(n + ':NumPy business checks actual and complete', set(record.get('checks', {})) == expected
                    and all(v is True for v in record.get('checks', {}).values()))
            for label, snap in (('before', before), ('after', after)):
                npcheck.snapshot_check(e, snap, n+':numpy:'+label, package, audit_required=audit)
                e.check(n + ':actual final NumPy privilege and FD boundary:' + label,
                        snap.get('security', {}).get('seccomp') == 2
                        and zero_cap(snap.get('security', {}).get('capabilities', {}), 'CapBnd')
                        and snap.get('environment') == {'PATH':'/usr/bin:/bin'} and set(snap.get('fds', {})) == {'0','1','2'})
            npcheck.pair_state_check(e, before, after, n+':numpy-runtime')
            fp = record.get('initial_fingerprint', {})
            npcheck.fingerprint_check(e, fp, level, n+':numpy-state')
            if group == 'G2':
                e.check(n + ':actual inherited prepared object identity', bool(zadmissions.get(row.get('zygote_pid')))
                        and fp == zadmissions.get(row.get('zygote_pid'), {}).get('fingerprint'))
                if audit:
                    npcheck.phase_forks(e, [x for x in np if x.get('event') == 'NP_PHASE'], n, package, level)
            else:
                matching = [x for x in admissions if x.get('location') == 'W_cold'
                    and x.get('pid_namespace_local') == before.get('pid_namespace_local')
                    and x.get('start_ns', 0) >= record.get('call_start_ns', 0)
                    and x.get('complete_ns', 0) < before.get('monotonic_ns', 0)]
                e.check(n + ':actual initialization in this fresh Worker', len(matching) == 1)
            afterfp = record.get('after_cow_fingerprint', {})
            e.check(n + ':same declared private one-element write', record.get('requested_cow_write_bytes') == 8
                    and afterfp.get('data_sha256') != fp.get('data_sha256')
                    and afterfp.get('data_id') == fp.get('data_id') and afterfp.get('data_writeable') is False)
            output = row.get('numpy_output', {})
            if output.get('file') and refpath.is_file():
                try:
                    actual = npcheck.within_run(e.run, output['file']); e.record(actual)
                    compared = npcheck.compare_npz(actual, refpath)
                    e.check(n + ':actual numerical output SHA', sha(actual) == output.get('sha256') == record.get('output_sha256'))
                    e.check(n + ':independent complete-array numerical comparison', compared['passed'], compared)
                    e.check(n + ':same independent reference consumed', record.get('reference_sha256') == sha(refpath))
                    observation.update(numeric_status='PASS' if compared['passed'] else 'FAIL', comparison=compared)
                except (ValueError, OSError) as error:
                    e.check(n + ':output artifact valid', False, repr(error))
            elif row.get('case') in NORMAL:
                e.check(n + ':required raw numerical output retained', None)
            else:
                observation['numeric_status'] = 'UNKNOWN_RAW_OUTPUT_NOT_PRESERVED'
        post = row.get('zygote_post')
        if group != 'G0' and post:
            z = [x for x in zchecks if x.get('nonce') == n and x.get('pid_namespace_local') == row.get('zygote_pid')]
            e.check(n + ':actual template integrity observation', True if len(z) == 1 else None)
            if len(z) == 1:
                e.check(n + ':NumPy template never polluted', z[0].get('stable') is True
                        and z[0].get('baseline') == z[0].get('fingerprint') and post.get('state_unchanged') is True)
            e.check(n + ':template request and FD inventory empty', post.get('nonce') == n
                    and post.get('active_attempts') == 0 and set(post.get('identity', {}).get('fds', {})) == {'0','1','2','3'})
        observations.append(observation)
    return observations


def measurement_evidence(e, rows, logs, config, profile):
    if profile != 'performance':
        return {'scope':'qualification diagnostics; not a performance sample'}
    records=unique([x for x in logs if x.get('event')=='COST'])
    enabled=str(config.get('timing'))=='1'
    result={'timing_enabled':enabled,'cost_records':len(records),'resource_observation':'NOT_OBSERVED'}
    e.check('no recorded timing instrumentation error',not any(x.get('kind')=='measurement_error'
            or x.get('name')=='measurement_error' or x.get('event')=='COST_ERROR' for x in records))
    if enabled:
        e.check('actual bounded cost stream observed',True if records else None)
        keys=set();duplicates=[]
        for x in records:
            key=(x.get('session'),x.get('role'),x.get('nonce'),x.get('pid'),x.get('seq'))
            if key in keys:duplicates.append(key)
            keys.add(key)
        e.check('cost identities are unambiguous',not duplicates,duplicates[:10])
        e.check('cost uses one guest monotonic clock',all(x.get('clock')=='CLOCK_MONOTONIC'
                and isinstance(x.get('ns'),int) and x['ns']>0 for x in records))
        flushed=[x for x in records if x.get('name')=='diagnostic_stream_flush']
        e.check('bounded stdout flushes actually recorded',True if flushed else None)
        e.check('no unconfirmed or over-limit cost records',all(x.get('stream_mode')=='bounded_stdout'
                and x.get('buffer_limit_rows')==128 and x.get('max_buffered_rows',129)<=128
                and x.get('unconfirmed_records')==0 for x in flushed))
        for row in rows:
            own=[x for x in records if x.get('nonce')==row['nonce'] and x.get('role')=='R']
            by=collections.defaultdict(list)
            for x in own:by[x.get('name')].append(x)
            required=('request_begin','domain_ready','domain_quiescent','resources_deleted','response_ready')
            e.check(row['nonce']+':complete same-clock R request boundaries',all(len(by[k])==1 for k in required))
            if all(len(by[k])==1 for k in required):
                times=[by[k][0]['ns'] for k in required]
                e.check(row['nonce']+':resource return follows actual release',times==sorted(times))
        result['stream_flushes']=len(flushed)
        result['max_buffered_records']=max([x.get('max_buffered_rows',0) for x in flushed] or [0])
    status=e.json(e.run/'resource-observer-status.json',optional=True)
    ledger=e.json(e.run/'session-resource-ledger.json',optional=True)
    resource_path=e.run/'resource-observer.jsonl'
    if status and resource_path.is_file():
        sampled=e.records([resource_path]);starts=[x for x in sampled if x.get('event')=='RESOURCE_OBSERVER_START']
        stops=[x for x in sampled if x.get('event')=='RESOURCE_OBSERVER_STOP']
        e.check('observer stopped itself without product cleanup',status.get('returncode')==0
                and status.get('product_cleanup_used') is False)
        e.check('read-only resource observer outside product cgroup',len(starts)==len(stops)==1
                and starts[0].get('observer_in_product_cgroup') is False)
        result.update(resource_observation='SAMPLED_NOT_ATOMIC',resource_batches=len([x for x in sampled if x.get('event')=='RESOURCE_BATCH']),
                      observer_cpu_ns=stops[0].get('observer_self_cpu_ns') if len(stops)==1 else None,
                      resource_ledger_present=bool(ledger))
    return result


def bind_qualification(e, review, manifest, group):
    refs = review.get('numpy_admission_scope', {}).get('qualification_evidence', [])
    relevant = [r for r in refs if r.get('architecture_group') == group]
    e.check('architecture has its own new actual qualification references', True if relevant else None)
    cases = set()
    for item in relevant:
        name = item.get('path', '')
        if not name.startswith('analysis/') or '..' in Path(name).parts:
            e.check('qualification restricted path', False, name); continue
        proof = e.json(S/name)
        e.check('qualification PASS and immutable hash:' + name, proof.get('status') == 'PASS'
                and item.get('sha256') == sha(S/name) and proof.get('architecture_group') == group
                and proof.get('verification_profile') == 'qualification'
                and proof.get('verifier_sha256') == sha(Path(__file__)))
        e.check('qualification dependency checkers unchanged:' + name,
                proof.get('dependency_verifier_sha256') == {p.name:sha(p) for p in
                    (Path(npcheck.__file__),Path(perfcheck.__file__),Path(lifecycle.__file__),Path(runtimecheck.__file__))})
        e.check('qualification same executable source/binary/runtime scope:' + name,
                proof.get('source_sha256') == manifest.get('source_sha256')
                and proof.get('binary_sha256') == manifest.get('binary_sha256'))
        bad = []
        for relative, digest in proof.get('evidence_sha256_study_relative', {}).items():
            try:
                if sha(npcheck.within_run(S, relative)) != digest:
                    bad.append(relative)
            except (ValueError, OSError):
                bad.append(relative)
        e.check('qualification underlying evidence unchanged:' + name,
                bool(proof.get('evidence_sha256_study_relative')) and not bad, bad[:20])
        cases.update(proof.get('cases', []))
    expected = {'normal','nonzero','cancel_before_business','double_cancel','timeout','pid_budget','pid1_death','controller_death','session_deadline'}
    if group != 'G0':
        expected |= {'second_budget','result_loss_side_effect','zygote_death'}
    else:
        expected.discard('pid_budget'); expected |= {'second_budget','result_loss_side_effect'}
    e.check('limited common regression scope actually completed', expected <= cases,
            {'required': sorted(expected), 'actual': sorted(cases)})


def analyze(name, profile):
    run = (S/'runs'/name).resolve(strict=True)
    run.relative_to((S/'runs').resolve())
    e = Evidence(run)
    config = e.json(run/'review-config.json'); manifest = e.json(run/'variant-manifest.json')
    group = config.get('architecture_group')
    e.check('explicit supported architecture', group in GROUP_CHECKS and manifest.get('architecture_group') == group)
    if group not in GROUP_CHECKS:
        return {'run': name, 'status':'BLOCKED', 'checks':e.checks, 'verifier_sha256':sha(Path(__file__))}
    review, sources = source_binding(e, config, manifest, group, profile)
    e.check('shared frozen deadline and workload flags actually recorded',
            config.get('session_deadline_seconds') == manifest.get('session_deadline_seconds')
            and (config.get('session_deadline_seconds') == 240 or (profile != 'performance'
                 and config.get('case') == 'session_deadline' and config.get('session_deadline_seconds') == 2))
            and bool(config.get('test_descendant')) == bool(manifest.get('test_descendant'))
            == (profile != 'performance'))
    e.check('fixed NumPy recipe and observation mode', config.get('numpy_level') == 'blas'
            and config.get('numpy_case') == 'normal' and str(config.get('numpy_audit')) in ('0','1')
            and config.get('numpy_baseline') == ('hot' if group == 'G2' else 'cold')
            and config.get('numpy_thread_environment') == npcheck.THREAD_ENV)
    result = e.json(run/'result.json'); summary = e.json(run/'summary.json', optional=True)
    sup = e.json(run/'supervisor.json'); ext = e.json(run/'external-final-release.json')
    e.check('actual VM/session completed without emergency timeout', result.get('complete') is True
            and result.get('timeout') is False and result.get('qemu_rc') == 0)
    if config.get('same_vm_pair'):
        execution=e.json(run/'session-execution.json');state=execution.get('after_product',{})
        e.check('actual paired session complete without observer cleanup',execution.get('complete') is True
                and execution.get('returncode')==0 and execution.get('observer_cleanup_performed') is False
                and state.get('state_root_is_private_directory') is True and state.get('cgroup_exists') is False
                and not state.get('uid65534_processes') and not state.get('workspaces') and not state.get('other_state_entries'))
        session=e.json(run/'guest-session-config.json')
        e.check('paired actual group/mode/timing configuration matches',session.get('architecture_group')==group
                and str(session.get('timing'))==str(config.get('timing'))==str(manifest.get('timing')))
    finals = sorted(run.glob('[0-9]*-*.json'), key=lambda p:int(p.name.split('-')[0]))
    rows = [e.json(p) for p in finals]
    rows = [r for r in rows if r.get('nonce') and 'case' in r]
    if not rows:
        rows = [e.json(p) for p in sorted(run.glob('attempt-*.json'))]
    e.check('nonempty actual unique attempt inventory', bool(rows) and len({r.get('nonce') for r in rows}) == len(rows)
            and all(re.fullmatch('[0-9a-f]{32}', r.get('nonce','')) for r in rows))
    if profile == 'performance':
        e.check('exact requested complete N, no prefix called success', config.get('case') == 'performance'
                and len(rows) == int(config.get('requests', -100)) + int(config.get('warmup', -100))
                and all(r.get('case') == 'normal' and r.get('outcome') == 'SUCCEEDED' for r in rows))
        bind_qualification(e, review, manifest, group)
    else:
        g0_cases={'control':['normal','normal','nonzero'],'budgets':['second_budget','normal'],
                  'cancels':['cancel_before_business','double_cancel','timeout','normal'],
                  'failures':['pid1_death','control_eof','normal'],
                  'receipts':['created_drop','reaped_drop','result_loss_side_effect','normal']}
        expected = (g0_cases if group=='G0' else lifecycle.GROUP_CASES).get(config.get('case'), [config.get('case')])
        e.check('entire intended qualification case sequence', [r.get('case') for r in rows] == expected)
    paths = list(run.glob('*.log')) + [run/'events.jsonl',run/'supervisor-events.jsonl']
    logs = e.records(sorted(set(paths)))
    common_release(e, rows, sup, ext, summary, logs, config)
    actual_trace(e, config, rows, sup, group, profile)
    for row in rows:
        n=row['nonce'];ready=row.get('domain_ready_record',{})
        e.check(n+':actual domain export bound to request',row.get('fd_metadata_validated') is True
                and ready.get('event')=='DOMAIN_READY' and ready.get('nonce')==n and ready.get('pid')==1
                and ready.get('uid')==65534 and set(row.get('target_ns',{}))=={'user','mnt','pid','net','ipc','uts'})
        worker_boundary(e,row,group)
        if group == 'G0':
            g0_runtime(e,row,logs)
            g0_faults(e,row,logs)
        elif row.get('case') in NORMAL and row.get('worker'):
            perfcheck.runtime_request(row, [clean(x) for x in unique(logs)], config.get('diagnostics'), config.get('timing','1'), e.check)
        if row.get('case') in NORMAL:
            e.check(row['nonce'] + ':normal/nonzero business exact result', row.get('business') == 'KNOWN'
                    and row.get('result',{}).get('exit_code') == (7 if row['case']=='nonzero' else 0)
                    and row.get('outcome') == ('NONZERO' if row['case']=='nonzero' else 'SUCCEEDED')
                    and row.get('side_effect') == '2650100' and row.get('response_committed') is True)
    related = {}
    if profile == 'qualification' and group != 'G0' and run.parent == S/'runs':
        # Existing verifiers still examine this run; historical PASS is never
        # substituted. Their implementation identity is in this report.
        for label, module in (('lifecycle',lifecycle),('fork_runtime',runtimecheck)):
            if config.get('case')=='session_deadline' and label=='lifecycle':
                related[label]={'scope':'new deadline case independently verified by common H/EOF/wait/UNKNOWN checks; not part of legacy29'}
                continue
            try:
                proof = module.analyze(run.name)
                related[label] = proof
                e.check('independent actual '+label+' qualification', proof.get('status') == 'PASS',
                        {'status':proof.get('status'), 'failures':proof.get('failures'), 'blockers':proof.get('blockers')})
            except Exception as error:
                e.check('independent actual '+label+' evidence readable', None, repr(error))
    measurement=measurement_evidence(e,rows,logs,config,profile)
    package,_ = npcheck.package_evidence(e)
    numeric = numpy_evidence(e, rows, logs, config, group, package)
    if group == 'G1':
        zids = [r.get('zygote_pid') for r in rows]
        e.check('G1 each request has fresh cold template', None not in zids and len(zids)==len(set(zids)))
    elif group == 'G2' and all(r.get('case') in NORMAL for r in rows):
        e.check('G2 actual same live prepared template', len({r.get('zygote_pid') for r in rows}) == 1
                and rows[0].get('zygote_pid') is not None)
    failures = [x for x in e.checks if x['value'] is False]
    blockers = [x for x in e.checks if x['value'] is None]
    return {'schema':1, 'run':str(run.relative_to(S/'runs')), 'architecture_group':group,
            'verification_profile':profile, 'status':'FAIL' if failures else 'BLOCKED' if blockers else 'PASS',
            'checks':e.checks,'failures':failures,'blockers':blockers,'attempts':len(rows),
            'cases':[r.get('case') for r in rows], 'numeric':numeric,
            'numeric_counts':dict(collections.Counter(x['numeric_status'] for x in numeric)),
            'measurement':measurement,'source_sha256':sources,'binary_sha256':manifest.get('binary_sha256'),
            'related_actual_verifications':related,'verifier_sha256':sha(Path(__file__)),
            'dependency_verifier_sha256':{p.name:sha(p) for p in (Path(npcheck.__file__),Path(perfcheck.__file__),
                                                                 Path(lifecycle.__file__),Path(runtimecheck.__file__))},
            'evidence_sha256_study_relative':e.evidence,
            'scope':'Fixed trusted single-thread NumPy recipe; shared old H alive and trusted R/private ordinary directories. '
                    'No H-death/OOM/hostile filesystem guarantee. Numeric NOT_EXECUTED/NOT_OBSERVED never means completed business. '
                    'G0 cold exec is explicit; G1/G2 inherited Python fork obligations are separate. No performance claim from qualification.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', help='Path relative to this study runs directory')
    parser.add_argument('--profile',choices=['qualification','performance','pilot'],required=True)
    parser.add_argument('--out',type=Path,required=True)
    args = parser.parse_args()
    try:
        report = analyze(args.run,args.profile)
    except Exception:
        report = {'run':args.run,'verification_profile':args.profile,'status':'BLOCKED',
                  'blockers':[{'check':'evidence could not be fully inspected','detail':traceback.format_exc()}],
                  'verifier_sha256':sha(Path(__file__))}
    out = args.out if args.out.is_absolute() else S/args.out
    out.resolve().relative_to(S.resolve())
    out.parent.mkdir(parents=True,exist_ok=True)
    with out.open('x') as stream:
        json.dump(report,stream,ensure_ascii=False,indent=2);stream.write('\n')
    print(json.dumps({'run':args.run,'status':report['status'],'report':str(out),
                      'failures':len(report.get('failures',[])),'blockers':len(report.get('blockers',[]))},ensure_ascii=False))
    return 0 if report['status']=='PASS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
