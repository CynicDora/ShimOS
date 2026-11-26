"""Synthetic parser checks only: no VM, runtime, workload or historical data."""
import json
from pathlib import Path
import tempfile
import unittest

from analyze_full import (elapsed,explain_resource_roles,observed_domains,one,request_timing)


def point(name,ns,nonce='a',**fields):
    return dict(event='COST',name=name,ns=ns,clock='CLOCK_MONOTONIC',
                role='R',nonce=nonce,**fields)


class BoundaryTests(unittest.TestCase):
    def test_serial_call_uses_index_not_stale_context_nonce(self):
        events=[point('numpy_call_begin',100,nonce='previous',call_index=1),
                point('request_begin',200,repeat=1),point('response_ready',800),
                point('numpy_call_complete',900,call_index=1),
                point('numpy_call_begin',950,nonce='a',call_index=2)]
        r=request_timing(events,'a',{'response_committed':True},1,None)
        self.assertEqual(r['call_begin_ns'],100)
        self.assertEqual(r['response_s'],700/1e9)
        self.assertEqual(r['call_complete_s'],800/1e9)
        self.assertEqual(r['request_setup_to_ready_s'],600/1e9)

    def test_concurrent_resource_completion_is_not_response(self):
        events=[point('numpy_call_begin',100,call_index=0),point('request_begin',200,repeat=0),
                point('attempt_resources_complete',700),point('response_ready',1200),
                point('numpy_call_complete',1300,call_index=0)]
        r=request_timing(events,'a',{'response_committed':True,'response_commit_ns':1100,
                                   'execution_resources_complete_ns':650},0,'G3_CONCURRENT')
        self.assertEqual(r['response_s'],1100/1e9)
        self.assertEqual(r['call_to_response_commit_s'],1000/1e9)
        self.assertEqual(r['call_to_resources_complete_s'],550/1e9)
        self.assertEqual(r['resources_to_commit_s'],450/1e9)
        self.assertTrue(r['domain_setup_in_call'])

    def test_uncommitted_resources_do_not_make_a_response(self):
        events=[point('numpy_call_begin',100,call_index=0),point('request_begin',200,repeat=0),
                point('request_complete',700),point('attempt_resources_complete',800)]
        r=request_timing(events,'a',{'response_committed':False,'execution_resources_complete_ns':750},0,'G2_CONCURRENT')
        self.assertIsNone(r['response_s']);self.assertIsNone(r['response_commit_ns'])
        self.assertEqual(r['call_to_resources_complete_s'],650/1e9)

    def test_missing_call_is_unknown_not_request_begin_fallback(self):
        r=request_timing([point('request_begin',200,repeat=0),point('response_ready',800)],
                         'a',{'response_committed':True},0,'G3')
        self.assertIsNone(r['response_s'])
        self.assertEqual(r['request_setup_to_ready_s'],600/1e9)
        self.assertFalse(r['domain_setup_in_call'])

    def test_bad_nonce_or_order_remains_unknown(self):
        events=[point('numpy_call_begin',100,nonce='wrong',call_index=0),point('request_begin',200,repeat=0),
                point('response_ready',800),point('numpy_call_complete',900,call_index=0)]
        r=request_timing(events,'a',{'response_committed':True,'response_commit_ns':700},0,'G2_CONCURRENT')
        self.assertIsNone(r['response_s'])
        self.assertTrue(any(x['problem']=='CONCURRENT_CALL_NONCE_MISMATCH' for x in r['timing_issues']))
        events[0]['nonce']='a'
        r=request_timing(events,'a',{'response_committed':True,'response_commit_ns':950},0,'G2_CONCURRENT')
        self.assertIsNone(r['response_s'])
        self.assertTrue(any(x['problem']=='REQUEST_BOUNDARY_ORDER_INVALID' for x in r['timing_issues']))

    def test_domain_counts_use_identities_not_requests(self):
        journals={'a':{'domain_nonce':'d1'},'b':{'domain_nonce':'d1'},
                  'c':{'domain_ready_record':{'nonce':'d2'}}}
        r=observed_domains({'domains':[{'domain_nonce':'d1'}]},journals,
                           [point('persistent_domain_ready',10,nonce='d3')])
        self.assertEqual(r['ids'],['d1','d2','d3']);self.assertEqual(r['count'],3)
        self.assertIsNone(observed_domains({}, {}, [])['count'])

    def test_g4_roles_keep_original_sampler_labels(self):
        tables={'resource_processes':[{'role':'Z','pid':4}],
                'resource_role_summary':[{'role':'Z','valid_sample_count':2,'status':'OBSERVED'},
                                         {'role':'W','valid_sample_count':0,'status':'NOT_OBSERVED'}],
                'resource_role_growth':[{'role':'Z','pid':4}]}
        explain_resource_roles(tables,{'group':'G4'})
        self.assertEqual(tables['resource_processes'][0]['role'],'W_PERSISTENT')
        self.assertEqual(tables['resource_processes'][0]['role_observed'],'Z')
        self.assertEqual(tables['resource_role_summary'][1]['status'],'NOT_APPLICABLE')

    def test_mixed_export_retains_actual_count_profiles_and_setup(self):
        with tempfile.TemporaryDirectory(prefix='shimos-analyzer-synthetic-') as tmp:
            d=Path(tmp)/'synthetic-vm'/'sessions'/'0';d.mkdir(parents=True)
            def put(name,obj): (d/name).write_text(json.dumps(obj))
            tokens=['v1:import:8:readonly:light','v1:blas:8:readonly:light']
            put('full-session.json',{'architecture_group':'G2','requests':2,'configuration':{},
                'extra_env':{'FULL_MODE':'G2_MIXED','FULL_DOMAINS':'999','FULL_PER_DOMAIN':'999',
                             'FULL_MIX_PROFILES_JSON':json.dumps(tokens)}})
            put('summary.json',{'all_passed':True,'rows':[{'nonce':'a','outcome':'SUCCEEDED'},
                                                         {'nonce':'b','outcome':'SUCCEEDED'}]})
            put('mixed-case-plan.json',{'profiles':[{'token':t} for t in tokens],'pattern':'alternating'})
            put('mixed-cache-ledger.json',{'hits':0,'misses':2,'initialized_templates':2,'capacity':1,
                'simultaneous_templates':1,'requests':[{'nonce':'a'},{'nonce':'b'}],'final_template_removed':True})
            events=[point('fixture_session_start',1,nonce=None),point('session_supervisor_waited',2000,nonce=None)]
            for index,n in enumerate(['a','b']):
                t=100+index*500
                put('attempt-'+n+'.json',{'nonce':n,'outcome':'SUCCEEDED','resources':'RELEASED',
                     'response_committed':True,'domain_ready_record':{'nonce':n},'qualification':'PASS',
                     'mixed_template_cache':{'index':index,'profile':{'token':tokens[index]},'profile_index':index,
                         'hit':False,'start_ns':t+1,'complete_ns':t+401,'current_pid':4+index}})
                events.extend([point('numpy_call_begin',t,nonce=None,call_index=index),
                    point('request_begin',t+100,nonce=n,repeat=index),point('response_ready',t+400,nonce=n),
                    point('numpy_call_complete',t+402,nonce=n,call_index=index)])
            (d/'synthetic.log').write_text(''.join(json.dumps(x)+'\n' for x in events))
            row,requests,*_=one(d)
            self.assertEqual((row['D'],row['Q'],row['N'],row['K']),(2,2,2,1.0))
            self.assertEqual(row['D_declared'],'999');self.assertEqual(row['mixed_initialized_templates'],2)
            self.assertEqual(row['mixed_profiles'],tokens)
            self.assertEqual([r['request_profile'] for r in requests],tokens)
            self.assertTrue(all(r['response_s']==400/1e9 for r in requests))

    def test_negative_or_missing_duration_is_unknown(self):
        for a,b in [(None,2),(2,None),(2,1),(0,3)]:self.assertIsNone(elapsed(a,b))


if __name__=='__main__':unittest.main()
