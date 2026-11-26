#!/usr/bin/env python3
"""Pure JSON-contract checks: no VM, fork, cgroup writes or product execution."""
import copy
import json
import unittest
from resource_trial_contract import CONTRACT, PROFILE, evaluate, exit_status, validate_item, validate_collector


def fixture():
    return dict(resource_trial=True, process_returncode=0,
        original_checks={'original_check':False},
        supervisor={'controller_pid':101,'controller_wait_status':256,
          'wait_records':[{'pid':101,'wait_status':256,'role':'controller'}],
          'fd_before':{'0':'/dev/null'},'fd_after':{'0':'/dev/null'},
          'attempts':[{'registered':True,'output_eof':True,'resources_removed':True}],
          'release_state':'RELEASED','resources_removed':True,'echild':True,
          'errors':[],'protocol_errors':[],'remaining_cgroups':[],'remaining_workspaces':[],
          'observer_cleanup_used':False,'business_result':'UNKNOWN','failure_reason':'CONTROLLER_FAILED'},
        final_release={'supervisor_wait_status':0,'delegation_removed':True,
                       'observer_killed_processes':False,'observer_removed_product_resources':False},
        observer={'uid65534_processes':{},'workspaces':{}},
        after_product={'state_root_is_private_directory':True,'cgroup_exists':False,
                       'uid65534_processes':{},'workspaces':[],'other_state_entries':[]},
        summary={},attempt_rows=[],receipt_errors=[],resource_ledger={},budget_readback={})


def item():
    return {'resource_trial':True,'group':'G2','requests':16,'qualification':False,
        'admission_key':f'CONCURRENT-V1:G2:C4:M96:N16:{PROFILE}',
        'env':{'FULL_MODE':'G2_CONCURRENT','FULL_CONCURRENCY':'4','FULL_MEMORY_MIB':'96',
          'FULL_PROFILE':PROFILE,'NP_LEVEL':'blas','NP_BASELINE':'hot','NP_CASE':'normal',
          'RELIABILITY_CASE':'performance','COST_WARMUP':'0','FULL_CONCURRENT_FAULT':'none'}}


class ResourceTrialContract(unittest.TestCase):
    def test_clean_failed_work_is_not_success(self):
        result=evaluate(**fixture())
        self.assertTrue(result['safe_to_continue'])
        self.assertTrue(result['product_release_verified'])
        self.assertTrue(result['collection_complete'])
        self.assertFalse(result['complete'])
        self.assertFalse(result['workload_complete'])
        self.assertEqual(result['workload_status'],'RESULT_UNKNOWN')
        self.assertIsNone(result['executed_numerical_validated'])
        self.assertEqual(exit_status(collection_complete=True,workloads_succeeded=False,
                                     infrastructure_complete=True),2)

    def test_complete_requires_original_success_and_new_release(self):
        data=fixture();data['original_checks']={'passed':True}
        data['summary']={'all_passed':True}
        result=evaluate(**data)
        self.assertTrue(result['complete'])
        self.assertEqual(exit_status(collection_complete=True,workloads_succeeded=True,
                                     infrastructure_complete=True),0)
        data['supervisor']['fd_after']={'0':'/dev/null','8':'leaked'}
        self.assertFalse(evaluate(**data)['complete'])

    def test_no_resource_flag_cannot_continue_failed_work(self):
        data=fixture();data['resource_trial']=False
        self.assertFalse(evaluate(**data)['safe_to_continue'])

    def test_all_missing_or_bad_release_facts_stop_collection(self):
        changes=[('missing H',lambda x:x.update(supervisor={},receipt_errors=['missing supervisor.json'])),
          ('H SIGKILL',lambda x:x['final_release'].update(supervisor_wait_status=9)),
          ('R not waited',lambda x:x['supervisor'].update(wait_records=[])),
          ('no ECHILD',lambda x:x['supervisor'].update(echild=False)),
          ('FD residue',lambda x:x['supervisor'].update(fd_after={'8':'leak'})),
          ('missing EOF',lambda x:x['supervisor']['attempts'][0].update(output_eof=False)),
          ('missing resource removal',lambda x:x['supervisor']['attempts'][0].update(resources_removed=False)),
          ('H error',lambda x:x['supervisor'].update(errors=['cgroup busy'])),
          ('protocol error',lambda x:x['supervisor'].update(protocol_errors=['unknown nonce'])),
          ('residual process',lambda x:x['after_product'].update(uid65534_processes={'103':{}})),
          ('residual cgroup',lambda x:x['after_product'].update(cgroup_exists=True)),
          ('observer kill',lambda x:x['final_release'].update(observer_killed_processes=True)),
          ('missing H FD maps',lambda x:(x['supervisor'].pop('fd_before'),x['supervisor'].pop('fd_after'))),
          ('missing observer',lambda x:x.update(observer={},receipt_errors=['missing observer']))]
        for name,change in changes:
            with self.subTest(name=name):
                data=fixture();change(data);result=evaluate(**data)
                self.assertFalse(result['safe_to_continue'])
                self.assertFalse(result['product_release_verified'])
                self.assertFalse(result['complete'])

    def test_normal_failure_with_known_summary_stays_failed(self):
        data=fixture();data['summary']={'all_passed':False}
        data['attempt_rows']=[{'nonce':'a','business':'FAILED','outcome':'FAILED'}]
        self.assertEqual(evaluate(**data)['workload_status'],'FAILED')

    def test_exact_formal_scope(self):
        task=item();review={'performance_admitted':True,'resource_trial_scope':{
            'admitted':True,'contract':CONTRACT,'allowed_admission_keys':[task['admission_key']],
            'qualification_evidence':[{'status':'REFERENCE_ONLY_IN_SYNTHETIC_TEST'}]}}
        validate_item(task,review)
        validate_item(task,{},pilot=True)
        for replacement in ({},{'performance_admitted':True},
                             {'performance_admitted':True,'resource_trial_scope':{'admitted':True}}):
            with self.subTest(review=replacement),self.assertRaises(ValueError):validate_item(task,replacement)

    def test_refuses_other_scopes_even_in_pilot(self):
        changes=[lambda x:x.update(group='G4'),lambda x:x.update(requests=4),
          lambda x:x.update(requests=16.0),lambda x:x.update(qualification=True),
          lambda x:x.update(resource_trial='true'),lambda x:x['env'].update(FULL_CONCURRENCY='8'),
          lambda x:x['env'].update(FULL_MEMORY_MIB='512'),lambda x:x['env'].update(FULL_PROFILE='other'),
          lambda x:x['env'].update(FULL_CONCURRENT_FAULT='template_state'),
          lambda x:x['env'].update(FULL_CONCURRENT_CASES='normal,second_budget'),
          lambda x:x.update(admission_key='stale'),lambda x:x['env'].update(NP_BASELINE='cold')]
        for change in changes:
            data=item();change(data)
            with self.subTest(item=data),self.assertRaises(ValueError):validate_item(data,{},pilot=True)

    def test_missing_infrastructure_never_exit_zero_or_two(self):
        for collected,infra in ((False,False),(False,True),(True,False)):
            self.assertEqual(exit_status(collection_complete=collected,workloads_succeeded=True,
                                         infrastructure_complete=infra),1)

    def test_collector_source_binding(self):
        actual={'resource_vm.py':'a'*64,'resource_trial_contract.py':'b'*64}
        review={'resource_trial_scope':{'collector_sha256':actual}}
        validate_collector(review,dict(actual))
        for wrong in ({},{**actual,'resource_vm.py':'c'*64},{'resource_vm.py':'a'*64}):
            with self.subTest(expected=wrong),self.assertRaises(ValueError):
                validate_collector({'resource_trial_scope':{'collector_sha256':wrong}},actual)


if __name__=='__main__':unittest.main(verbosity=2)
