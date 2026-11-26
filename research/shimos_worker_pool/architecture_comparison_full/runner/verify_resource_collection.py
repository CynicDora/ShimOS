#!/usr/bin/env python3
"""Independent finite-pressure collection review, not workload qualification.

Read-only. This does not import the collector's decision functions, start VMs,
signal processes, or remove resources. Numeric/protocol performance admission
remains the responsibility of verify_concurrent.py and source qualification.
"""
import argparse
import json
import traceback
from pathlib import Path
import verify_full_mechanism as evidence
import verify_round1 as old
import verify_numpy as npcheck

S=Path(__file__).resolve().parent.parent


def state_empty(value):
    return (isinstance(value,dict) and value.get('state_root_is_private_directory') is True
            and value.get('cgroup_exists') is False and value.get('uid65534_processes')=={}
            and value.get('workspaces')==[] and value.get('other_state_entries')==[])


def verdict(checks):
    return 'FAIL' if any(x['value'] is False for x in checks) else 'BLOCKED' if any(x['value'] is None for x in checks) else 'PASS'


def session_check(e,directory,planned):
    execute=e.json(directory/'session-execution.json',optional=True)
    if not execute:
        return dict(session=planned.get('session'),started=False,workload_status='NOT_RUN',
                    release_status='NOT_OBSERVED',safe_to_continue=False)
    start=len(e.checks)
    full=e.json(directory/'full-session.json');config=full.get('configuration',{});env=config.get('env',{})
    expected=f'CONCURRENT-V1:{config.get("group")}:C4:M{env.get("FULL_MEMORY_MIB")}:N16:v1:blas:8:readonly:light'
    e.check('explicit finite pressure configuration:'+directory.name,
            config.get('resource_trial') is True and config.get('qualification') is False
            and full.get('resource_trial') is True and full.get('configuration')==planned.get('configuration')
            and config.get('group') in ('G2','G3') and env.get('FULL_MODE')==config.get('group')+'_CONCURRENT'
            and env.get('FULL_CONCURRENCY')=='4' and env.get('FULL_MEMORY_MIB') in ('192','96')
            and config.get('requests')==full.get('requests')==16 and config.get('admission_key')==expected
            and env.get('FULL_PROFILE')=='v1:blas:8:readonly:light'
            and env.get('NP_LEVEL')=='blas' and env.get('NP_BASELINE')=='hot' and env.get('NP_CASE')=='normal'
            and env.get('RELIABILITY_CASE')=='performance' and env.get('FULL_CONCURRENT_FAULT','none')=='none'
            and not env.get('FULL_CONCURRENT_CASES') and env.get('COST_WARMUP','0')=='0')
    budget=e.json(directory/'root-budget-readback.json')
    e.check('common root memory budget actually read back:'+directory.name,
            env.get('FULL_MEMORY_MIB') in ('192','96') and budget.get('path')=='/sys/fs/cgroup/cdz'
            and budget.get('changes_limits') is False
            and str(budget.get('actual_limits',{}).get('memory.max','')).strip()==str(int(env['FULL_MEMORY_MIB'])*1024**2))
    sup=e.json(directory/'supervisor.json');ext=e.json(directory/'external-final-release.json')
    later=e.json(directory/'observer-later.json');census=e.json(directory/'resource-trial-final-census.json')
    summary=e.json(directory/'summary.json',optional=True)
    logs=e.records([directory/'supervisor-events.jsonl',directory/'events.jsonl'])
    waits=old.unique([x for x in logs if x.get('event')=='SUPERVISOR_REAL_WAIT'])
    e.check('H actually released all owned resources:'+directory.name,
            sup.get('release_state')=='RELEASED' and sup.get('resources_removed') is True
            and sup.get('echild') is True and sup.get('errors')==[] and sup.get('protocol_errors')==[]
            and sup.get('remaining_cgroups')==[] and sup.get('remaining_workspaces')==[])
    e.check('true H wait R backed by original log:'+directory.name,
            isinstance(sup.get('controller_pid'),int) and isinstance(sup.get('controller_wait_status'),int)
            and any(x.get('pid')==sup['controller_pid'] and x.get('wait_status')==sup['controller_wait_status']
                    and x.get('role')=='controller' for x in waits))
    for w in sup.get('wait_records',[]):
        e.check('H adopted wait backed by original log:'+directory.name+':'+str(w.get('pid')),
                any(x.get('pid')==w.get('pid') and x.get('wait_status')==w.get('wait_status')
                    and x.get('role')==w.get('role') for x in waits))
    e.check('H FD identity inventory truly restored:'+directory.name,
            isinstance(sup.get('fd_before'),dict) and sup.get('fd_before')==sup.get('fd_after'))
    e.check('actual H wait and no external product rescue:'+directory.name,
            ext.get('supervisor_wait_status')==0 and ext.get('delegation_removed') is True
            and ext.get('observer_killed_processes') is False and ext.get('observer_removed_product_resources') is False
            and sup.get('observer_cleanup_used') is False and execute.get('observer_cleanup_performed') is False)
    attempts=sup.get('attempts',[])
    e.check('unique registered or discovered H identities:'+directory.name,
            isinstance(attempts,list) and len({x.get('nonce') for x in attempts})==len(attempts)
            and all(evidence.valid_nonce(x.get('nonce')) for x in attempts))
    for a in attempts:
        nonce=a.get('nonce');registered=a.get('registered') is True
        e.check('H actual final resources removed:'+str(nonce),a.get('resources_removed') is True)
        if registered:
            e.check('registered stream actually reaches EOF:'+str(nonce),a.get('output_eof') is True)
            if a.get('retired'):
                e.check('R retirement is in original H event stream:'+str(nonce),any(
                    x.get('event')=='ATTEMPT_RETIRED' and x.get('nonce')==nonce
                    and x.get('outcome')==a.get('outcome') for x in logs))
                # On the normal path H trusts the final R EOF receipt. It does
                # not separately read the already-consumed pipe; do not invent
                # SUPERVISOR_OUTPUT_EOF for that path.
            else:
                e.check('H itself drained nonretired stream to EOF:'+str(nonce),any(
                    x.get('event')=='SUPERVISOR_OUTPUT_EOF' and x.get('nonce')==nonce for x in logs))
        else:
            e.check('unregistered stream remains explicitly unobserved:'+str(nonce),a.get('output_eof') is None,
                    'Unregistered output is not promoted to captured response; final quiescence/resource deletion is separate.')
    e.check('late read-only observer has no private products:'+directory.name,
            later.get('uid65534_processes')=={} and later.get('workspaces')=={})
    e.check('collector final actual empty census, not a cleanup action:'+directory.name,
            census.get('cleanup_performed') is False and state_empty(census.get('product_state'))
            and census.get('root_cgroup_exists') is False and not census.get('product_state_error'))
    e.check('before/after product census independently empty:'+directory.name,
            state_empty(execute.get('before_fixture_reset')) and state_empty(execute.get('after_product'))
            and execute.get('final_census')==census)
    e.check('collector completed root fixture without timeout rescue:'+directory.name,
            execute.get('returncode')==0 and execute.get('required_receipt_errors')==[])
    cleanup_status=verdict(e.checks[start:])
    actual_rows=summary.get('rows',[])
    success=(bool(summary) and summary.get('all_passed') is True and summary.get('controller_echild') is True
             and len(actual_rows)==16 and all(x.get('qualification')=='PASS' and x.get('outcome')=='SUCCEEDED'
                 and x.get('resources')=='RELEASED' for x in actual_rows)
             and sup.get('done_received') is True and sup.get('controller_wait_status')==0 and cleanup_status=='PASS')
    e.check('full N success kept distinct from clean failed collection:'+directory.name,
            execute.get('complete')==execute.get('workload_complete')==success
            and execute.get('product_release_verified')==(cleanup_status=='PASS')
            and execute.get('collection_complete') is True and execute.get('safe_to_continue')==(cleanup_status=='PASS')
            and (execute.get('workload_status')=='SUCCEEDED' if success else execute.get('workload_status') in ('FAILED','RESULT_UNKNOWN')))
    if not summary:
        e.check('lost result stays UNKNOWN after H recovery:'+directory.name,
                sup.get('done_received') is False and sup.get('business_result')=='UNKNOWN'
                and execute.get('workload_status')=='RESULT_UNKNOWN' and isinstance(sup.get('recovery_started_ns'),int))
    e.check('collector makes no independent numerical validation claim:'+directory.name,
            execute.get('executed_numerical_validated') is None)
    return dict(session=planned.get('session'),started=True,release_status=cleanup_status,
                collector_success_candidate=success,workload_status=execute.get('workload_status'),
                planned_requests=16,summary_rows=len(actual_rows),observed_attempts=execute.get('observed_attempt_count'),
                numerical_validation='REQUIRES_SEPARATE_INDEPENDENT_VERIFIER',safe_to_continue=execute.get('safe_to_continue'),
                actual_root_budget=budget,
                root_budget_evidence=str((directory/'root-budget-readback.json').relative_to(S)),
                started_ns=execute.get('started_ns'),finished_ns=execute.get('finished_ns'),
                H_failure_reason=sup.get('failure_reason'),controller_wait_status=sup.get('controller_wait_status'))


def analyze(name):
    run=(S/'runs'/name).resolve(strict=True);run.relative_to((S/'runs').resolve());e=evidence.Evidence(run)
    config=e.json(run/'batch-config.json');result=e.json(run/'result.json');guest=e.json(run/'batch-guest-result.json')
    review=e.json(run/'source-review.json');fixtures=e.json(run/'fixture-source-sha.json')
    for filename in ('paired_vm.py','batch-guest.py','resource_trial_contract.py'):
        path=run/filename;e.check('actual frozen collector source:'+filename,path.is_file() and fixtures.get(filename)==npcheck.sha(path))
    e.check('explicit finite collector status contract',result.get('collector_contract')==guest.get('collector_contract')=='finite-pressure-collection-v1')
    e.check('host did not terminate VM to substitute cleanup',result.get('timeout') is False
            and result.get('host_timeout_intervention_used') is False and result.get('qemu_rc')==0
            and result.get('infrastructure_complete') is True)
    if config.get('pilot') is not True:
        scope=review.get('resource_trial_scope',{})
        e.check('formal collector exact reviewed source binding',scope.get('admitted') is True
                and scope.get('contract')=='finite-pressure-collection-v1' and bool(scope.get('qualification_evidence'))
                and scope.get('collector_sha256')=={'resource_vm.py':npcheck.sha(run/'paired_vm.py'),
                    'resource_trial_contract.py':npcheck.sha(run/'resource_trial_contract.py')})
    sessions=[];previous=None
    for planned in config.get('sessions',[]):
        directory=(run/planned.get('relative_dir','')).resolve(strict=True)
        directory.relative_to(run.resolve())
        if not directory.is_dir():raise ValueError('session artifact is not a directory')
        current=session_check(e,directory,planned)
        if previous and current['started']:
            e.check('later session only after prior actual release:'+str(current['session']),
                    previous.get('release_status')=='PASS' and previous.get('safe_to_continue') is True
                    and isinstance(previous.get('finished_ns'),int) and isinstance(current.get('started_ns'),int)
                    and previous['finished_ns']<=current['started_ns'])
        sessions.append(current);previous=current
    all_collected=bool(sessions) and all(x['started'] and x.get('release_status')=='PASS' for x in sessions)
    all_work=all_collected and all(x.get('collector_success_candidate') is True for x in sessions)
    expected_exit=0 if all_work else 2 if all_collected else 1
    e.check('0/2/1 never conflates clean failure with business success',result.get('driver_exit_code')==expected_exit
            and result.get('complete')==result.get('workload_complete')==result.get('all_workloads_succeeded')==all_work
            and result.get('collection_complete')==all_collected)
    e.check('same compiled candidate binaries in collected sessions',bool(result.get('same_shared_C_binaries'))
            and all(value is True for value in result.get('same_shared_C_binaries',{}).values()))
    return dict(run=name,status=verdict(e.checks),scope='COLLECTION_AND_RELEASE_ONLY_NOT_WORKLOAD_OR_PERFORMANCE_ADMISSION',
                sessions=sessions,expected_collector_exit_code=expected_exit,all_workloads_collector_success_candidate=all_work,
                independent_numerical_validation=None,checks=e.checks,failed=[x for x in e.checks if x['value'] is False],
                missing=[x for x in e.checks if x['value'] is None],verifier_sha256=npcheck.sha(Path(__file__)),
                evidence_sha256_study_relative=e.evidence,
                limits=['H must survive and provide actual wait/EOF/resource evidence',
                        'A PASS here does not repair failed/unknown/missing requests or admit performance ranking',
                        'Normal retired stream EOF is trusted R evidence; H independently drains nonretired streams',
                        'Missing terminal evidence or H OOM remains FAIL/BLOCKED; VM teardown is not product recovery'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run');p.add_argument('--out',required=True);a=p.parse_args()
    try:value=analyze(a.run)
    except Exception as error:value=dict(run=a.run,status='BLOCKED',verifier_error=repr(error),traceback=traceback.format_exc(),verifier_sha256=npcheck.sha(Path(__file__)))
    path=Path(a.out);path=path if path.is_absolute() else S/path;path.resolve().relative_to(S.resolve());path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x') as stream:json.dump(value,stream,ensure_ascii=False,indent=2);stream.write('\n')
    print(json.dumps(dict(run=a.run,status=value['status'],scope='collection/release only',failed=len(value.get('failed',[])),missing=len(value.get('missing',[])))))
    return 0 if value['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
