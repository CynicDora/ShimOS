"""Pure-data contract for collecting a finite failed resource trial safely.

No process signals, cgroup writes, cleanup or VM operations. Passing release
checks never turns an incomplete workload into a successful performance sample.
"""
CONTRACT = 'finite-pressure-collection-v1'
PROFILE = 'v1:blas:8:readonly:light'


def validate_item(item, review, pilot=False):
    if type(item.get('resource_trial', False)) is not bool:
        raise ValueError('resource_trial must be an explicit boolean')
    if not item.get('resource_trial', False):
        return
    env = item.get('env', {})
    group = item.get('group')
    if group not in ('G2', 'G3') or env.get('FULL_MODE') != group+'_CONCURRENT':
        raise ValueError('resource_trial only admits G2/G3 finite concurrent candidates')
    if env.get('FULL_CONCURRENCY') != '4' or env.get('FULL_MEMORY_MIB') not in ('192', '96'):
        raise ValueError('resource_trial requires C4 and the preregistered 192/96 MiB root limit')
    if type(item.get('requests')) is not int or item['requests'] != 16 or item.get('qualification', False):
        raise ValueError('resource_trial is N16, never a qualification bypass')
    if (env.get('FULL_PROFILE') != PROFILE or env.get('NP_LEVEL') != 'blas'
            or env.get('NP_BASELINE') != 'hot' or env.get('NP_CASE') != 'normal'
            or env.get('RELIABILITY_CASE') != 'performance'
            or env.get('FULL_CONCURRENT_FAULT', 'none') != 'none'
            or env.get('FULL_CONCURRENT_CASES') or env.get('COST_WARMUP', '0') != '0'):
        raise ValueError('resource_trial does not admit other work or explicit fault injection')
    expected=f'CONCURRENT-V1:{group}:C4:M{env["FULL_MEMORY_MIB"]}:N16:{PROFILE}'
    if item.get('admission_key') != expected:
        raise ValueError('resource_trial identity does not match the complete configuration')
    if pilot:
        return
    scope = review.get('resource_trial_scope', {})
    if (review.get('performance_admitted') is not True or scope.get('admitted') is not True
            or scope.get('contract') != CONTRACT
            or expected not in scope.get('allowed_admission_keys', [])
            or not scope.get('qualification_evidence')):
        raise ValueError('formal resource_trial lacks exact finite review and qualification evidence')


def product_state_released(state):
    return (isinstance(state, dict) and state.get('state_root_is_private_directory') is True
            and state.get('cgroup_exists') is False and state.get('uid65534_processes') == {}
            and state.get('workspaces') == [] and state.get('other_state_entries') == [])


def validate_collector(review, actual_sha256):
    """Formal admission binds the collector logic as well as product sources."""
    expected=review.get('resource_trial_scope',{}).get('collector_sha256')
    if (not isinstance(expected,dict) or expected!=actual_sha256
            or set(expected)!={'resource_vm.py','resource_trial_contract.py'}):
        raise ValueError('resource collector sources differ from finite reviewed collector')


def evaluate(*, resource_trial, process_returncode, original_checks, supervisor,
             final_release, observer, after_product, summary, attempt_rows,
             receipt_errors=(), resource_ledger=None, budget_readback=None):
    """Evaluate already collected values. No missing values become success."""
    sup=supervisor or {};final=final_release or {};obs=observer or {};summary=summary or {}
    original_success=(process_returncode==0 and bool(original_checks)
                     and all(value is True for value in original_checks.values())
                     and product_state_released(after_product) and not receipt_errors)
    waits=sup.get('wait_records') or []
    cs=sup.get('controller_wait_status');cpid=sup.get('controller_pid')
    fd_before=sup.get('fd_before');fd_after=sup.get('fd_after')
    attempts=sup.get('attempts')
    release_checks={
        'root_fixture_returned_zero':process_returncode==0,
        'actual_H_wait_zero':final.get('supervisor_wait_status')==0,
        'delegation_removed_after_empty':final.get('delegation_removed') is True,
        'H_release_state':sup.get('release_state')=='RELEASED' and sup.get('resources_removed') is True,
        'H_actual_echild':sup.get('echild') is True,
        'H_true_controller_wait':isinstance(cpid,int) and isinstance(cs,int) and any(
            w.get('pid')==cpid and w.get('wait_status')==cs and w.get('role')=='controller' for w in waits),
        'H_error_lists_empty':sup.get('errors')==[] and sup.get('protocol_errors')==[],
        'H_no_product_resources':sup.get('remaining_cgroups')==[] and sup.get('remaining_workspaces')==[],
        'H_FD_map_restored':isinstance(fd_before,dict) and isinstance(fd_after,dict) and fd_before==fd_after,
        'registered_output_EOF_and_resources':isinstance(attempts,list) and all(
            a.get('output_eof') is True and a.get('resources_removed') is True
            for a in attempts if a.get('registered')),
        'no_observer_product_cleanup':sup.get('observer_cleanup_used') is False
            and final.get('observer_killed_processes') is False
            and final.get('observer_removed_product_resources') is False,
        'late_observer_no_process_or_workspace':obs.get('uid65534_processes')=={} and obs.get('workspaces')=={},
        'fresh_product_census_empty':product_state_released(after_product),
        'required_terminal_receipts_present':not receipt_errors and bool(sup) and bool(final) and bool(obs),
    }
    product_release_verified=all(release_checks.values())
    strict_complete=original_success and product_release_verified
    collection_complete=not receipt_errors and bool(sup) and bool(final) and bool(obs) and isinstance(after_product,dict)
    safe_to_continue=strict_complete or (resource_trial is True and collection_complete and product_release_verified)
    # These are collector-level candidates, never independent numerical proof.
    unique={r.get('nonce'):r for r in attempt_rows if isinstance(r,dict) and isinstance(r.get('nonce'),str)}
    rows=list(unique.values())
    committed=sum(r.get('response_committed') is True and r.get('qualification')=='PASS'
                  and r.get('outcome')=='SUCCEEDED' for r in rows)
    numerical_candidates=sum(isinstance(r.get('worker'),dict)
        and isinstance(r['worker'].get('numpy',{}).get('checks'),dict)
        and bool(r['worker']['numpy']['checks']) and all(r['worker']['numpy']['checks'].values()) for r in rows)
    unknown=not summary or any(r.get('business')=='UNKNOWN' for r in rows)
    workload_status='SUCCEEDED' if strict_complete else ('RESULT_UNKNOWN' if unknown else 'FAILED')
    root=(resource_ledger or {}).get('session_parent',{})
    return {
        'contract':CONTRACT,'resource_trial':resource_trial is True,
        'complete':strict_complete,'workload_complete':strict_complete,
        'workload_status':workload_status,'collection_complete':collection_complete,
        'product_release_verified':product_release_verified,'safe_to_continue':safe_to_continue,
        'release_checks':release_checks,'required_receipt_errors':list(receipt_errors),
        'controller_wait_status':cs,'H_failure_reason':sup.get('failure_reason'),
        'business_result':sup.get('business_result'),'observed_attempt_count':len(rows),
        'responses_committed_success_candidate_count':committed,
        'executed_numerical_candidate_count':numerical_candidates,
        'executed_numerical_validated':None,
        'numerical_validation_note':'Independent verifier required; collector never validates arrays or missing results.',
        'memory_events_raw':root.get('memory.events'),'pids_events_raw':root.get('pids.events'),
        'budget_readback':budget_readback,
        'resource_cause_note':'SIGKILL alone is not OOM proof. Root events do not identify the exact killed PID.',
    }


def exit_status(*, collection_complete, workloads_succeeded, infrastructure_complete):
    """0 all success; 2 collected workload failure; 1 incomplete/unsafe export."""
    if not infrastructure_complete or not collection_complete:
        return 1
    return 0 if workloads_succeeded else 2
