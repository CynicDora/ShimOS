#!/usr/bin/env python3
"""Independent G2/G3 fixed-burst concurrent candidate verifier; read-only.

Per-attempt resources complete is not response commit. No serial FD-count or
per-attempt PING assertion is silently reused. Missing H/OOM cleanup is never
accepted just because a VM collector exported the directory.
"""
import argparse
import collections
import hashlib
import re
import json
import os
import traceback
from pathlib import Path
import verify_full_mechanism as fullcheck
import verify_round1 as old
import verify_numpy as npcheck

S=Path(__file__).resolve().parent.parent
sha=npcheck.sha


class ConcurrentEvidence(fullcheck.Evidence):
    """Keep a killed Z's incomplete timing tail explicitly unobserved.

    General JSON, control receipts and lifecycle records keep their original
    strict parsing rule. This only classifies one incomplete final COST record
    after an independently proven H SIGKILL in an aborted qualification.
    """
    def records(self, paths):
        values=super().records(paths)
        self.interrupted_diagnostics=[]
        # Never reinterpret a complete successful/performance sample.
        if (self.run/'summary.json').exists():return values
        config=self.json(self.run/'review-config.json')
        if str(config.get('trace'))!='1':return values
        sup=self.json(self.run/'supervisor.json')
        if not(sup.get('done_received') is False and sup.get('business_result')=='UNKNOWN'
               and sup.get('release_state')=='RELEASED'):return values
        for check in self.checks:
            if check['value'] is not None:continue
            match=re.fullmatch(r'valid JSON record:(zygote-[0-9]+\.log):([0-9]+)',check['check'])
            if not match:continue
            path=self.run/match[1];payload=path.read_bytes();lines=payload.splitlines(keepends=True)
            if int(match[2])!=len(lines) or not lines or payload.endswith((b'\n',b'\r')):continue
            raw=lines[-1]
            try:text=raw.decode('utf-8')
            except UnicodeError:continue
            if not text.startswith('{"event":"COST",'):continue
            # Decode only fully present fields, never invent the missing tail.
            fields={};index=1;decoder=json.JSONDecoder();truncated=False
            try:
                while index<len(text):
                    key,end=decoder.raw_decode(text,index)
                    if not isinstance(key,str) or key in fields or text[end:end+1]!=':':break
                    value,end=decoder.raw_decode(text,end+1);fields[key]=value
                    if text[end:end+1]!=',':break
                    index=end+1
            except json.JSONDecodeError as error:
                truncated=error.msg.startswith('Unterminated string') or error.pos==len(text)
            if not(truncated and fields.get('event')=='COST' and fields.get('clock')=='CLOCK_MONOTONIC'
                    and fields.get('role')=='Z' and fields.get('variant')==fields.get('diagnostics')=='low'
                    and fields.get('kind') in ('c_span','span','point','aggregate','measurement_metadata','usage')
                    and isinstance(fields.get('name'),str) and isinstance(fields.get('seq'),int)
                    and isinstance(fields.get('ns'),int) and isinstance(fields.get('pid'),int)):continue
            pid=fields['pid'];stamp=fields['ns'];session=fields.get('session')
            ready=old.unique([x for x in values if x.get('event')=='ZYGOTE_READY' and x.get('identity',{}).get('pid')==pid])
            killed=old.unique([x for x in values if x.get('event')=='SUPERVISOR_REAL_WAIT' and x.get('pid')==pid
                               and x.get('wait_status')==9])
            if len(ready)!=1 or len(killed)!=1:continue
            identity=ready[0].get('identity',{})
            if not(ready[0].get('session')==session and identity.get('fds',{}).get('1')=='/evidence/'+path.name
                    and identity.get('cgroup','').strip()=='0::/cdz/template'
                    and ready[0].get('monotonic_ns',2**64)<=stamp<=sup.get('recovery_started_ns',-1)
                    <killed[0].get('monotonic_ns',0)
                    and any(w.get('pid')==pid and w.get('wait_status')==9 for w in sup.get('wait_records',[]))):continue
            detail=dict(status='NOT_OBSERVED_INTERRUPTED_DIAGNOSTIC',file=path.name,line=len(lines),
                        byte_offset=len(payload)-len(raw),raw_bytes_hex=raw.hex(),raw_bytes_sha256=hashlib.sha256(raw).hexdigest(),
                        file_sha256=sha(path),parsed_complete_prefix=fields,pid=pid,session=session,
                        actual_H_wait=old.clean(killed[0]),diagnostic_duration_ns=None,
                        reason='One non-newline-terminated final COST record in the actual SIGKILLed Z log; no repaired or synthesized event')
            self.interrupted_diagnostics.append(detail)
            check.update(check='aborted diagnostic tail explicitly unobserved:'+path.name,value=True,detail=detail)
        return values


def status(checks):
    return 'FAIL' if any(x['value'] is False for x in checks) else 'BLOCKED' if any(x['value'] is None for x in checks) else 'PASS'


def maximum_overlap(intervals):
    events=[(a,1) for a,b in intervals if isinstance(a,int) and isinstance(b,int) and b>a]
    events += [(b,-1) for a,b in intervals if isinstance(a,int) and isinstance(b,int) and b>a]
    active=peak=0
    for _,delta in sorted(events):active+=delta;peak=max(peak,active)
    return peak


def configuration(e,config,manifest,full):
    env=full.get('extra_env',{});conf=full.get('configuration',{})
    mode=env.get('FULL_MODE');group=mode.split('_')[0] if isinstance(mode,str) else None
    e.check('explicit separately qualified concurrent mechanism',mode in ('G2_CONCURRENT','G3_CONCURRENT'))
    e.check('configuration and actual declaration agree',conf.get('env')==env and conf.get('requests')==full.get('requests')
            and group==conf.get('group')==full.get('architecture_group')==config.get('architecture_group')==manifest.get('architecture_group'))
    e.check('fixed low mode and original single-thread package environment',config.get('variant')==manifest.get('variant')=='low'
            and config.get('diagnostics')==manifest.get('diagnostics')=='low'
            and config.get('numpy_thread_environment')==npcheck.THREAD_ENV)
    e.check('hot template baseline explicitly declared',config.get('numpy_baseline')==manifest.get('numpy_baseline')=='hot')
    width=int(env.get('FULL_CONCURRENCY','2'));requests=full.get('requests')
    e.check('finite complete bursts with no hidden warmup',width in (1,2,4,8) and isinstance(requests,int)
            and requests>0 and requests%width==0 and int(env.get('COST_WARMUP','0'))==0)
    level=env.get('NP_LEVEL',config.get('numpy_level'));token=env.get('FULL_PROFILE','legacy')
    if token!='legacy':
        parts=token.split(':');e.check('closed profile syntax',len(parts)==5 and parts[0]=='v1' and parts[1]==level
                and parts[2] in ('8','32','64','128') and parts[3] in ('readonly','element','sparse','many','full')
                and parts[4] in ('light','medium','heavy'))
    case=env.get('RELIABILITY_CASE','performance')
    presets={'control':['normal']*width,'runtime':['normal']*width,'performance':['normal']*requests,
             'concurrent_mixed':['cancel_before_business','normal','second_budget','normal'],
             'concurrent_cancel':['cancel_queued','normal','double_cancel','normal'],
             'concurrent_receipts':['created_drop','reaped_drop','normal','normal'],
             'concurrent_budget':['pid_budget','normal','second_budget','normal'],
             'concurrent_timeout':['timeout','normal','nonzero','normal']}
    intended=env.get('FULL_CONCURRENT_CASES','').split(',') if env.get('FULL_CONCURRENT_CASES') else presets.get(case)
    e.check('planned actual cases explicitly known',isinstance(intended,list) and bool(intended),case)
    return mode,group,env,width,requests,token,level,intended


def common_cleanup(e,rows,logs,sup,ext,summary,mode,intended,env):
    e.check('H survives and actually completes whole-session release',sup.get('release_state')=='RELEASED'
            and sup.get('resources_removed') is True and sup.get('remaining_cgroups')==[] and sup.get('remaining_workspaces')==[]
            and sup.get('errors')==[] and sup.get('protocol_errors')==[] and sup.get('echild') is True)
    e.check('H actual FD identity map restored',sup.get('fd_before') is not None and sup.get('fd_before')==sup.get('fd_after'))
    realwait=[x for x in logs if x.get('event')=='SUPERVISOR_REAL_WAIT']
    e.check('H truly waits its Controller',any(x.get('pid')==sup.get('controller_pid')
            and x.get('wait_status')==sup.get('controller_wait_status') for x in realwait))
    for x in sup.get('wait_records',[]):
        e.check('actual H adopted wait:'+str(x.get('pid')),any(y.get('pid')==x.get('pid')
                and y.get('wait_status')==x.get('wait_status') for y in realwait))
    e.check('observer never substitutes product recovery',sup.get('observer_cleanup_used') is False
            and ext.get('observer_killed_processes') is False and ext.get('observer_removed_product_resources') is False
            and ext.get('supervisor_wait_status')==0 and ext.get('delegation_removed') is True)
    for filename in ('observer-after.json','observer-later.json'):
        observation=e.json(e.run/filename);groups=observation.get('cgroups',{})
        e.check(filename+':no private process/workspace or populated groups',observation.get('uid65534_processes')=={}
                and observation.get('workspaces')=={} and set(groups)=={'/sys/fs/cgroup/cdz','/sys/fs/cgroup/cdz/client'}
                and all(not x.get('cgroup.procs','missing').strip() and not x.get('cgroup.threads','missing').strip()
                        and x.get('pids.current','').strip()=='0' and 'populated 0' in x.get('cgroup.events','') for x in groups.values()))
    registered={x.get('nonce'):x for x in sup.get('attempts',[])}
    e.check('H registration identities unique',len(registered)==len(sup.get('attempts',[]))
            and all(fullcheck.valid_nonce(x) for x in registered))
    if summary:
        e.check('R completed all cases, actual ECHILD and DONE',summary.get('all_passed') is True
                and summary.get('controller_echild') is True and sup.get('done_received') is True
                and sup.get('controller_wait_status')==0 and sup.get('failure_reason') is None)
        expected={r['nonce'] for r in rows}|(fullcheck.domains(rows)-{None} if mode=='G3_CONCURRENT' else set())
        e.check('H exact requests and domains registered',set(registered)==expected)
    else:
        deliberate={'controller_death','controller_during_entry','zygote_death','revoke_ack_loss'}
        injected=env.get('FULL_CONCURRENT_FAULT')
        e.check('no summary only explicitly injected shared-component fault',bool(set(intended or [])&deliberate)
                or injected in ('template_state','template_fd','reply_unknown_nonce','reply_retired_nonce','adoption_after_snapshot'),
                'Unexpected OOM/timeout has no successful-sequence admission; retain INCOMPLETE/FAIL/BLOCKED')
        e.check('batch abort no successful response invented',not any(r.get('response_committed') for r in rows)
                and sup.get('done_received') is False and sup.get('business_result')=='UNKNOWN'
                and isinstance(sup.get('recovery_started_ns'),int))
    for r in rows:
        n=r['nonce'];h=registered.get(n,{})
        e.check(n+':H owns this request cleanup scope',h.get('registered') is True)
        if r.get('business')=='UNKNOWN':
            e.check(n+':unknown result never promoted',r.get('result') is None and r.get('outcome') not in ('SUCCEEDED','NONZERO'))
        if r.get('resources')=='RELEASED':
            e.check(n+':actual request release EOF and sealed future execution',r.get('resources_removed') is True
                    and r.get('domain_empty') is True and r.get('output_eof') is True
                    and str(r.get('admission','')).startswith('SEALED'))
            e.check(n+':own FD objects closed without claiming global per-request equality',r.get('owned_fd_close_confirmed') is True
                    and bool(r.get('closed_fd_objects')) and bool(r.get('fd_assertion_scope')))
            e.check(n+':H retirement is deliberately provisional until batch check',h.get('retired') is True
                    and h.get('resources_removed') is True and h.get('output_eof') is True
                    and h.get('outcome')=='BATCH_CHECK_PENDING:'+str(r.get('outcome')))
            e.check(n+':actual private request cgroups empty',bool(r.get('stats')) and all(
                'populated 0' in g.get('cgroup.events','') and g.get('pids.current','').strip()=='0' for g in r.get('stats',{}).values()))
        elif not summary:
            e.check(n+':H recovery confirms release and unknown',h.get('resources_removed') is True and h.get('output_eof') is True
                    and h.get('business_result')=='UNKNOWN')
    return registered


def external_waits(e,rows,logs,config):
    for r in rows:
        n=r['nonce'];old.worker_boundary(e,r,'G2')
        rd=r.get('domain_ready_record',{})
        e.check(n+':fresh target bound to actual attempt',r.get('fd_metadata_validated') is True
                and rd.get('event')=='DOMAIN_READY' and rd.get('nonce')==n and rd.get('pid')==1 and rd.get('uid')==65534)
        if r.get('worker'):e.check(n+':actual inherited state identity',r['worker'].get('inherited')==r.get('expected_state'))
        for role,pidkey,value,kind in [('W','w_pid',(r.get('w_wait') or {}).get('wait_status'),'ACTUAL_WORKER_WAIT'),
                                     ('S','s_pid',r.get('s_wait'),'ACTUAL_TRANSITION_WAIT')]:
            if value is None:continue
            actual=[x for x in logs if (x.get('event')==kind and x.get('nonce')==n)
                    or (x.get('event')=='CONTROLLER_WAIT' and x.get('pid')==r.get(pidkey) and x.get('owner_nonce')==n)]
            e.check(n+':'+role+' actual permitted wait and nonce ownership',any(x.get('wait_status')==value for x in actual))
        if r.get('resources')=='RELEASED':
            e.check(n+':monitor actually waited by its R owner',any(x.get('event')=='CONTROLLER_WAIT'
                    and x.get('pid')==r.get('monitor_pid') and x.get('owner_nonce')==n
                    and x.get('wait_status')==r.get('monitor_wait') for x in logs))
            scoped=r.get('children_at_release',{})
            e.check(n+':no own or unclassified child remains at release',scoped.get('own')==[] and scoped.get('unknown')==[])
        if r.get('case') in fullcheck.NORMAL and r.get('worker') and r.get('resources')=='RELEASED':
            old.perfcheck.runtime_request(r,[old.clean(x) for x in old.unique(logs)],'low',str(config.get('timing','1')),e.check)


def controller_selected_waits(e,logs,sup,rows):
    selected=old.unique([x for x in logs if x.get('event')=='CONCURRENT_WAITID_SELECTED'])
    waited=old.unique([x for x in logs if x.get('event')=='CONTROLLER_WAIT'])
    owners={r['nonce'] for r in rows}|(fullcheck.domains(rows)-{None})|{'TEMPLATE'}
    for record in waited:
        pid=record.get('pid');identity=record.get('selected_identity',{})
        matches=[x for x in selected if x.get('pid')==pid and x.get('identity')==identity
                 and x.get('owner_nonce')==record.get('owner_nonce')
                 and x.get('monotonic_ns',0)<record.get('monotonic_ns',0)]
        e.check('R exact selected zombie wait:'+str(pid),len(matches)==1 and record.get('waited_exact_selected_pid') is True
                and identity.get('pid')==pid and identity.get('state')=='Z' and identity.get('ppid')==sup.get('controller_pid')
                and isinstance(identity.get('start_ticks'),int) and record.get('start_ticks')==identity['start_ticks'])
        if len(matches)!=1:continue
        pre=matches[0];owner=record.get('owner_nonce');cg=identity.get('cgroup','').strip()
        root='0::/cdz/template' if owner=='TEMPLATE' else '0::/cdz/d-'+str(owner)
        e.check('R current child cgroup supplies exact owner:'+str(pid),owner in owners
                and (cg==root or cg.startswith(root+'/')) and pre.get('not_yet_reaped') is True and pre.get('single_R_thread') is True)
        code=pre.get('si_code');sig=pre.get('si_status');raw=record.get('wait_status')
        expected=sig if code==os.CLD_EXITED else -sig if isinstance(sig,int) else None
        e.check('R waitid status agrees with actual waitpid:'+str(pid),code in (os.CLD_EXITED,os.CLD_KILLED,os.CLD_DUMPED)
                and isinstance(raw,int) and os.waitstatus_to_exitcode(raw)==expected
                and record.get('waitid_si_code')==code and record.get('waitid_si_status')==sig)
    return {'selected_count':len(selected),'actual_wait_count':len(waited),
            'identity_rejection_count':len(old.unique([x for x in logs if x.get('event')=='CONCURRENT_WAIT_IDENTITY_REJECTED'])),
            'scope':'Actual WNOWAIT-selected zombie plus exact waitpid. H recovery uses its own actual wait evidence, not this R protocol.'}


def injected_protocol_evidence(e,rows,logs,mode,sup):
    """Require actual fault observations, not just the requested case label."""
    for row in rows:
        n=row['nonce'];case=row.get('case');own=[x for x in logs if x.get('nonce')==n]
        messages=row.get('events',[]);types={x.get('event') for x in own};wire={x.get('event') for x in messages}
        if case in ('pid_budget','second_budget'):
            owner='transition' if mode=='G2_CONCURRENT' and case=='pid_budget' else 'business'
            limits=row.get('limits',{}).get(owner,{});statistics=row.get('stats',{}).get(owner,{})
            counts={}
            for line in statistics.get('pids.events','').splitlines():
                fields=line.split()
                if len(fields)==2:
                    try:counts[fields[0]]=int(fields[1])
                    except ValueError:pass
            e.check(n+':actual birth budget exercised rather than synthetic EAGAIN',str(limits.get('pids.max','')).strip()=='0'
                    and counts.get('max',0)>0)
        if mode=='G2_CONCURRENT':
            if case=='created_drop':
                e.check(n+':created receipt really omitted after actual S birth',
                        'FAULT_CREATED_RECEIPT_DROPPED' in types and 'ACTUAL_TRANSITION_FORK' in types
                        and 'TRANSITION_CREATED' not in wire and row.get('s_pid') is not None)
            elif case=='reaped_drop':
                e.check(n+':reaped receipt really omitted after actual Z wait',
                        'FAULT_REAPED_RECEIPT_DROPPED' in types and 'ACTUAL_TRANSITION_WAIT' in types
                        and 'TRANSITION_REAPED' not in wire and row.get('s_wait') is not None)
            elif case=='cancel_during_entry':
                e.check(n+':actual entered S revoked before W business',
                        'ENTERED' in wire and 'CANCEL_REQUEST' in types and row.get('business')=='NOT_EXECUTED'
                        and row.get('business_permit') is False and row.get('worker') is None and row.get('side_effect') is None)
            elif case=='revoke_ack_loss':
                e.check(n+':actual missing seal ACK triggers conservative creator stop',
                        'FAULT_REVOKE_ACK_DROPPED' in types and 'REVOKE_ACK_TIMEOUT' in types
                        and 'CANCEL_ACK' not in wire and row.get('business_permit') is False)
            elif case in ('controller_death','controller_during_entry','zygote_death','pid1_death'):
                e.check(n+':intended live fault branch actually recorded',
                        any(x.get('event')=='FAULT' and x.get('case')==case for x in own))
            elif case=='result_loss_side_effect':
                e.check(n+':actual Worker wait result dropped, not fabricated unknown',
                        'FAULT_WORKER_WAIT_RECEIPT_DROPPED' in types and 'ACTUAL_WORKER_WAIT' in types
                        and 'WORKER_WAITED' not in wire)
        else:
            if case=='created_drop':
                e.check(n+':local creation reply omitted while actual clone/gate observed',
                        'LOCAL_Z_ACTUAL_CLONE' in types and 'LOCAL_WORKER_BIND' in types and 'WORKER_CREATED' not in wire)
            elif case=='reaped_drop':
                e.check(n+':local wait reply omitted but actual wait and snapshot remain',
                        'LOCAL_Z_ACTUAL_WAIT' in types and 'WORKER_WAITED' not in wire
                        and 'SNAPSHOT' in wire and row.get('w_wait') is not None)
        if case in ('controller_death','controller_during_entry'):
            e.check(n+':R really died by SIGKILL and H owns UNKNOWN recovery',
                    sup.get('controller_wait_status')==9 and sup.get('business_result')=='UNKNOWN'
                    and sup.get('done_received') is False)


def counterexamples(e,rows,logs,env,summary):
    fault=env.get('FULL_CONCURRENT_FAULT')
    if fault in (None,'','none'):return
    e.check('explicit registered integrity counterexample',fault in ('template_state','template_fd','reply_unknown_nonce','reply_retired_nonce','adoption_after_snapshot'))
    e.check('integrity counterexample never commits any response',not summary and not any(r.get('response_committed') for r in rows)
            and any(x.get('event')=='CONCURRENT_BATCH_ABORT' for x in logs))
    if fault in ('template_state','template_fd'):
        event='CONCURRENT_TEST_TEMPLATE_STATE_CHANGED' if fault=='template_state' else 'CONCURRENT_TEST_TEMPLATE_FD_LEAKED'
        injected=old.unique([x for x in logs if x.get('event')==event])
        post=old.unique([x for x in logs if x.get('event')=='CONCURRENT_BATCH_TEMPLATE_SNAPSHOT'])
        e.check('actual template fault injected and original PONG retained',len(injected)==len(post)==1)
        if not injected or not post:return
        e.check('template fault rejected before response',post[0].get('response_committed') is False
                and post[0].get('template_post',{}).get('state_unchanged') is False)
        if fault=='template_state':
            x=injected[0];e.check('actual self-owned template byte changed when no active child',x.get('original_byte')!=x.get('changed_byte')
                                 and x.get('active_attempts')==0 and x.get('children')==0)
        else:
            x=injected[0]
            ready=old.unique([z for z in logs if z.get('event')=='ZYGOTE_READY'])
            before=ready[0].get('identity',{}).get('fds',{}) if len(ready)==1 else {}
            after=post[0].get('template_post',{}).get('identity',{}).get('fds',{})
            # unexpected_fd_count counts SCM_RIGHTS on PONG, not Z's open-FD
            # set. The injected leak is in Z; no descriptor need be transferred.
            e.check('actual new FD appears in unchanged PONG evidence',x.get('fd_target')=='/dev/null'
                    and bool(before) and str(x.get('fd')) not in before
                    and str(x.get('fd')) in after and set(before)!=set(after))
    elif fault in ('reply_unknown_nonce','reply_retired_nonce'):
        changed=old.unique([x for x in logs if x.get('event')=='CONCURRENT_TEST_REPLY_NONCE_CHANGED'])
        closed=old.unique([x for x in logs if x.get('event')=='CONCURRENT_TEST_REJECTED_REPLY_FDS_CLOSED'])
        e.check('real created reply carrying FD was faulted and router rejected it',len(changed)==len(closed)==1
                and any(x.get('event')=='ROUTER_FAILED' for x in logs))
        if not changed or not closed:return
        x,y=changed[0],closed[0];original=x.get('original',{})
        e.check('replacement is not same or imaginary source message',original.get('event')=='TRANSITION_CREATED'
                and original.get('nonce') in {r['nonce'] for r in rows} and original.get('pid') is not None
                and x.get('replacement_nonce')!=original.get('nonce') and bool(x.get('received_fd_objects')))
        e.check('rejected received FDs were really closed rather than leaked',y.get('all_received_fds_closed') is True
                and bool(y.get('actual_EBADF')) and all(x is True for x in y['actual_EBADF'])
                and y.get('router_failed') is not None and y.get('objects')==x.get('received_fd_objects')
                and y.get('replacement_nonce')==x.get('replacement_nonce')
                and len(y['actual_EBADF'])==len(x['received_fd_objects']))
        if fault=='reply_retired_nonce':
            retired=[z for z in logs if z.get('event')=='CONCURRENT_REQUEST_RESOURCES_RELEASED']
            e.check('late reply targets actual earlier retired attempt',x.get('replacement_was_retired') is True
                    and any(z.get('nonce')==x.get('replacement_nonce') and z.get('monotonic_ns',0)<x.get('monotonic_ns',0) for z in retired))
        else:e.check('unknown replacement is not a valid attempt',x.get('replacement_nonce') not in {r['nonce'] for r in rows})
    elif fault=='adoption_after_snapshot':
        before=old.unique([x for x in logs if x.get('event')=='CONCURRENT_TEST_ADOPTION_CHILD_SNAPSHOT'])
        after=old.unique([x for x in logs if x.get('event')=='CONCURRENT_TEST_ADOPTION_AFTER_CHILD_SNAPSHOT'])
        done=old.unique([x for x in logs if x.get('event')=='CONCURRENT_TEST_ADOPTION_TRUE_WAIT_COMPLETE'])
        e.check('controlled real adoption has all three observations',len(before)==len(after)==len(done)==1)
        if not before or not after or not done:return
        a,b,c=before[0],after[0],done[0];oldchild=a.get('transition',{});newchild=b.get('adopted',{});pid=oldchild.get('pid')
        e.check('child initially absent from R snapshot then actually adopted with same identity',a.get('nonce')==b.get('nonce')==c.get('nonce')
                and a.get('R_pid')==b.get('R_pid') and oldchild.get('state')==newchild.get('state')=='T'
                and oldchild.get('ppid')==a.get('Z_pid') and pid not in a.get('R_children',[])
                and newchild.get('pid')==pid and newchild.get('start_ticks')==oldchild.get('start_ticks')
                and newchild.get('ppid')==a.get('R_pid') and b.get('original')==oldchild and b.get('business_authorized') is False)
        actual=[x for x in logs if x.get('event')=='CONTROLLER_WAIT' and x.get('pid')==pid and x.get('owner_nonce')==a.get('nonce')]
        e.check('late adopted child really waited before completion evidence',any(x.get('start_ticks')==c.get('start_ticks')==oldchild.get('start_ticks')
                and x.get('wait_status')==c.get('wait_status') and x.get('waited_exact_selected_pid') is True
                and b.get('monotonic_ns',0)<x.get('monotonic_ns',0)<c.get('monotonic_ns',0) for x in actual)
                and c.get('wait_status')==9)


def batch_check(e,rows,summary,logs,mode,width):
    filename='concurrent-batch-check.json' if mode=='G2_CONCURRENT' else 'local-concurrent-batch-check.json'
    batch=e.json(e.run/filename,optional=True)
    if not summary:
        e.check('aborted batch never produces successful final integrity record',not batch or batch.get('status')!='PASS')
        return batch
    e.check('actual final batch integrity and full R FD identities',batch.get('status')=='PASS'
            and batch.get('single_R_thread') is True and bool(batch.get('R_fds_before'))
            and batch.get('R_fds_before')==batch.get('R_fds_after') and batch.get('width')==width)
    final=summary.get('batch_check',{})
    same_batch=final==batch
    if not same_batch and mode=='G2_CONCURRENT':
        # Frozen run_concurrent stores registry_history by reference. Its
        # on-disk batch snapshot is before Z STOP; summary is serialized after
        # the actual wait appends Z's zombie ownership. This is not permission
        # to ignore arbitrary differences or to rewrite either raw record.
        before=batch.get('ownership_registry');after=final.get('ownership_registry')
        unchanged={k:v for k,v in batch.items() if k!='ownership_registry'}=={
            k:v for k,v in final.items() if k!='ownership_registry'}
        prefix=isinstance(before,list) and isinstance(after,list) and after[:len(before)]==before
        extra=after[len(before):] if prefix else []
        stops=old.unique([x for x in logs if x.get('event')=='ZYGOTE_STOP'])
        selected=old.unique([x for x in logs if x.get('event')=='CONCURRENT_WAITID_SELECTED'
                             and x.get('pid')==batch.get('zygote_pid')])
        waited=old.unique([x for x in logs if x.get('event')=='CONTROLLER_WAIT'
                           and x.get('pid')==batch.get('zygote_pid')])
        bound=False
        if len(extra)==len(stops)==len(selected)==len(waited)==1:
            entry,stop,select,wait=extra[0],stops[0],selected[0],waited[0]
            identity=select.get('identity',{});previous=select.get('registry_previous',{})
            expected={**identity,'owner_nonce':'TEMPLATE','source':wait.get('identity_source'),
                      'pidfd':previous.get('pidfd')}
            bound=(entry==expected and select.get('not_yet_reaped') is True
                   and select.get('owner_nonce')==wait.get('owner_nonce')=='TEMPLATE'
                   and wait.get('waited_exact_selected_pid') is True and wait.get('wait_status')==0
                   and identity==wait.get('selected_identity') and identity.get('state')=='Z'
                   and identity.get('pid')==batch.get('zygote_pid')==previous.get('pid')
                   and identity.get('start_ticks')==previous.get('start_ticks')==wait.get('start_ticks')
                   and identity.get('cgroup')==previous.get('cgroup')=='0::/cdz/template\n'
                   and previous in before and stop.get('state_unchanged') is True
                   and stop.get('monotonic_ns',2**64)<select.get('monotonic_ns',0)<wait.get('monotonic_ns',0))
        same_batch=unchanged and prefix and bound
        e.check('only exact STOP-after-template-wait registry extension is allowed',same_batch,
                {'unchanged_other_fields':unchanged,'original_registry_retained_as_prefix':prefix,
                 'appended_records':len(extra),'actual_STOP_WNOWAIT_wait_binding':bound,
                 'scope':'batch JSON is before Z STOP; summary registry includes later actual Z wait'})
    e.check('summary binds exact final batch, count and mode',same_batch
            and summary.get('execution_mode')==mode and summary.get('concurrency')==width
            and summary.get('request_count')==len(rows))
    if mode=='G2_CONCURRENT':
        zs=old.unique([x for x in logs if x.get('event')=='ZYGOTE_READY']);z=zs[0] if len(zs)==1 else {}
        post=batch.get('template_post') or {};router=batch.get('router') or {}
        e.check('one actual shared ready Z for all requests',len(zs)==1 and len({r.get('zygote_pid') for r in rows})==1
                and batch.get('zygote_pid')==z.get('identity',{}).get('pid')==rows[0].get('zygote_pid'))
        e.check('actual final PONG equivalent state/FD/session/active assertions',post.get('event')=='PONG'
                and post.get('state_unchanged') is True and post.get('active_attempts')==0
                and post.get('nonce')==batch.get('batch_nonce') and post.get('session')==z.get('session')
                and post.get('identity',{}).get('pid')==batch.get('zygote_pid')
                and set(post.get('identity',{}).get('fds',{}))==set(z.get('identity',{}).get('fds',{})))
        e.check('single real router transferred all received responses with no failure',router.get('failed') is None
                and router.get('real_Z_responses')==router.get('private_response_packets')
                and isinstance(router.get('real_Z_commands'),int) and router['real_Z_commands']>0)
        command=[x for x in logs if x.get('event')=='ROUTER_TO_Z'];replies=[x for x in logs if x.get('event')=='ROUTER_FROM_Z']
        e.check('router actual command/response counts backed by trace',len(command)==router.get('real_Z_commands')
                and len(replies)==router.get('real_Z_responses'))
        pings=[x for x in command if x.get('operation')=='PING']
        forgotten=[x for x in replies if x.get('message')=='FORGOTTEN']
        e.check('exactly one batch PING after every request actually forgotten',len(pings)==1
                and {x.get('nonce') for x in forgotten}=={r['nonce'] for r in rows}
                and all(x.get('monotonic_ns',0)<pings[0].get('monotonic_ns',0) for x in forgotten))
        e.check('all routed responses belong to exact live request/control identity',all(
                x.get('nonce')==x.get('response_channel_nonce') and x.get('nonce') in {r['nonce'] for r in rows}|{batch.get('batch_nonce')} for x in replies))
        e.check('only template remained before real template STOP',batch.get('actual_R_children_before_Z_stop')==[batch.get('zygote_pid')])
    else:
        # Separate per-domain ready/SCM identity and terminal wait records are
        # verified by local_domain_evidence. A numerical host PID can legally be
        # reused after an earlier burst has completely exited; do not turn
        # globally unique PIDs into an invented lifetime requirement.
        e.check('separate local template for every fresh request domain',len(fullcheck.domains(rows))==len(rows)
                and all(isinstance(r.get('zygote_pid'),int) for r in rows) and batch.get('controller_echild') is True)
    releases=[r.get('execution_resources_complete_ns') for r in rows]
    if all(isinstance(t,int) for t in releases):
        for r in rows:
            e.check(r['nonce']+':actual response commit follows all resource endpoints',r.get('response_committed') is True
                    and r.get('qualification')=='PASS' and r.get('batch_check_file')==filename
                    and isinstance(r.get('response_commit_ns'),int) and r['response_commit_ns']>=max(releases))
    else:e.check('actual resource completion timestamps retained',None)
    return batch


def timing_metrics(e,rows,logs,width):
    costs=old.unique([x for x in logs if x.get('event')=='COST'])
    result=[];business=[];numeric=[];lifetimes=[]
    for r in rows:
        n=r['nonce'];own=[x for x in costs if x.get('nonce')==n]
        def point(name,role=None):
            values=[x.get('ns') for x in own if x.get('name')==name and (role is None or x.get('role')==role)]
            return values[0] if len(values)==1 else None
        start=point('numpy_call_begin','R');request=point('request_begin','R');begin=point('business_enter','W');end=point('business_end','W')
        complete=r.get('execution_resources_complete_ns');commit=r.get('response_commit_ns')
        if begin and end:business.append((begin,end))
        actual=[x for x in logs if x.get('event')=='NP_RESULT' and x.get('nonce')==n]
        if actual:
            x=actual[0];a,b=x.get('compute_begin_ns'),x.get('compute_end_ns')
            if isinstance(a,int) and isinstance(b,int):numeric.append((a,b))
        fork=point('fork_child_first_python_point','W') or point('worker_branch_enter','W')
        waited=[x.get('monotonic_ns') for x in logs if x.get('nonce')==n and x.get('event') in ('ACTUAL_WORKER_WAIT','LOCAL_Z_ACTUAL_WAIT')]
        if fork and waited:lifetimes.append((fork,min(waited)))
        def elapsed(a,b):return (b-a)/1e6 if isinstance(a,int) and isinstance(b,int) and b>=a else None
        result.append(dict(nonce=n,call_begin_ns=start,request_begin_ns=request,business_enter_ns=begin,business_end_ns=end,
            resources_complete_ns=complete,response_commit_ns=commit,
            call_to_response_ms=elapsed(start,commit),call_to_request_ms=elapsed(start,request),
            call_to_business_ms=elapsed(start,begin),business_ms=elapsed(begin,end),
            resources_to_commit_ms=elapsed(complete,commit),call_to_resources_ms=elapsed(start,complete)))
        if commit is not None:
            e.check(n+':response timing contains setup and batch tail',isinstance(start,int) and start<=request<=complete<=commit
                    if isinstance(request,int) and isinstance(complete,int) else None)
    return dict(configured_capacity=width,actual_business_overlap=maximum_overlap(business),
                actual_numeric_compute_overlap=maximum_overlap(numeric),observed_worker_lifetime_overlap=maximum_overlap(lifetimes),
                business_interval_count=len(business),numeric_interval_count=len(numeric),worker_lifetime_interval_count=len(lifetimes),requests=result,
                note='Finite closed bursts, not external arrival queue. call_to_business includes setup and gates; it is not pure queue time. '
                     'All response commits wait for final sequence integrity. Missing intervals are unobserved, not zero. '
                     'W lifetimes start at first observed Python point and end at real parent wait, not exact kernel birth/exit.')


def simultaneous_domains(e,rows,logs,mode):
    """Compare identities only while actual domain-live intervals overlap.

    Namespace inode reuse after a domain dies is legal. Configured C is not
    evidence that domains or calculations actually overlap.
    """
    costs=old.unique([x for x in logs if x.get('event')=='COST'])
    intervals={};worker_intervals={};pairs=[]
    for row in rows:
        nonce=row['nonce'];end=row.get('execution_resources_complete_ns')
        # Local request_begin is after verified LOCAL_READY, so this interval
        # conservatively excludes parallel initialization. External domain_ready
        # is after actual PID1 reference validation, never before mount setup.
        name='domain_ready' if mode=='G2_CONCURRENT' else 'request_begin'
        points=[x.get('ns') for x in costs if x.get('nonce')==nonce and x.get('role')=='R' and x.get('name')==name]
        start=points[0] if len(points)==1 else None
        if isinstance(start,int) and isinstance(end,int) and end>start:intervals[nonce]=(start,end)
        entered=[x.get('ns') for x in costs if x.get('nonce')==nonce and x.get('role')=='W' and x.get('name')=='business_enter']
        waited=[x.get('monotonic_ns') for x in logs if x.get('nonce')==nonce and x.get('event') in ('ACTUAL_WORKER_WAIT','LOCAL_Z_ACTUAL_WAIT')]
        if entered and waited and isinstance(entered[0],int) and all(isinstance(x,int) for x in waited):
            worker_intervals[nonce]=(entered[0],min(waited))
    for index,a in enumerate(rows):
        if a['nonce'] not in intervals:continue
        for b in rows[index+1:]:
            if b['nonce'] not in intervals:continue
            ai,bi=intervals[a['nonce']],intervals[b['nonce']]
            if max(ai[0],bi[0])>=min(ai[1],bi[1]):continue
            an,bn=a['nonce'],b['nonce'];left=a.get('target_ns',{});right=b.get('target_ns',{})
            different={kind:left.get(kind)!=right.get(kind) for kind in ('user','mnt','pid','net','ipc','uts')}
            e.check(an+'/'+bn+':actually simultaneous domains have independent six namespace identities',
                    set(left)==set(right)==set(different) and all(different.values()),different)
            aw=(a.get('worker') or {}).get('identity',{});bw=(b.get('worker') or {}).get('identity',{})
            if aw and bw:
                wi,wj=worker_intervals.get(an),worker_intervals.get(bn)
                if wi and wj and max(wi[0],wj[0])<min(wi[1],wj[1]):
                    af,bf=aw.get('fds',{}),bw.get('fds',{})
                    e.check(an+'/'+bn+':simultaneously live business outputs are distinct private pipe objects',
                            str(af.get('1','')).startswith('pipe:[') and str(bf.get('1','')).startswith('pipe:[')
                            and af['1']!=bf['1'] and af.get('1')==af.get('2') and bf.get('1')==bf.get('2'))
                e.check(an+'/'+bn+':observed Workers remain in own business cgroups',
                        aw.get('cgroup','').strip()=='0::/cdz/d-'+an+'/business'
                        and bw.get('cgroup','').strip()=='0::/cdz/d-'+bn+'/business')
            pairs.append({'left':an,'right':bn,'overlap_begin_ns':max(ai[0],bi[0]),'overlap_end_ns':min(ai[1],bi[1]),
                          'namespace_differences':different,'both_business_observed':bool(aw and bw)})
    return {'domain_interval_count':len(intervals),'observed_domain_overlap':maximum_overlap(intervals.values()),
            'simultaneous_domain_pairs':pairs,'interval_scope':'After actual ready/request entry until own resource completion; lower-bound domain lifetime overlap, not compute concurrency',
            'unobserved_intervals':len(rows)-len(intervals)}


def analyze(name,profile,review):
    run=(S/'runs'/name).resolve(strict=True);run.relative_to((S/'runs').resolve());e=ConcurrentEvidence(run)
    config=e.json(run/'review-config.json');manifest=e.json(run/'variant-manifest.json');full=e.json(run/'full-session.json')
    mode,group,env,width,requests,token,level,intended=configuration(e,config,manifest,full)
    reviewed,sources,binaries=fullcheck.source_binding(e,manifest,config,full,mode,review,profile)
    if group=='G3':e.check('local PID1 compiled binary explicitly bound',isinstance(binaries.get('domain_init_local'),str))
    result=e.json(run/'result.json');execution=e.json(run/'session-execution.json');sup=e.json(run/'supervisor.json')
    ext=e.json(run/'external-final-release.json');summary=e.json(run/'summary.json',optional=True)
    e.check('VM export is complete and no rescue, not itself qualification',result.get('complete') is True and result.get('timeout') is False
            and result.get('qemu_rc')==0 and execution.get('complete') is True and execution.get('observer_cleanup_performed') is False)
    rows=fullcheck.load_rows(e)
    e.check('actual nonempty unique attempt identities',bool(rows) and len({r.get('nonce') for r in rows})==len(rows)
            and all(fullcheck.valid_nonce(r.get('nonce')) for r in rows))
    if summary:e.check('complete exact intended cases, no successful-prefix admission',[r.get('case') for r in rows]==intended)
    else:e.check('observed prefix belongs to explicitly planned fault batch',all(r.get('case') in (intended or []) for r in rows))
    logs=e.records(sorted(set(list(run.glob('*.log'))+[run/'events.jsonl',run/'supervisor-events.jsonl'])))
    registered=common_cleanup(e,rows,logs,sup,ext,summary,mode,intended,env)
    selected_waits=controller_selected_waits(e,logs,sup,rows)
    ready={}
    if group=='G3':ready,_=fullcheck.local_domain_evidence(e,rows,logs,summary,'G3',registered)
    else:external_waits(e,rows,logs,config)
    fullcheck.fault_evidence(e,rows,logs,'G2_REUSE' if group=='G2' else 'G3')
    injected_protocol_evidence(e,rows,logs,mode,sup)
    batch=batch_check(e,rows,summary,logs,mode,width)
    counterexamples(e,rows,logs,env,summary)
    if profile=='boundary':
        trace=e.json(run/'trace-config.json');e.check('trace explicitly absent, not kernel lifecycle proof',str(config.get('trace'))=='0' and str(trace.get('tracing_on','')).strip()=='0')
    elif group=='G2':old.actual_trace(e,config,rows,sup,'G2',profile)
    else:fullcheck.trace_evidence(e,rows,logs,sup,ready,'G3',profile)
    package,_=npcheck.package_evidence(e)
    numeric=fullcheck.numeric(e,rows,logs,package,token,level,group,ready,require_normal_results=bool(summary))
    metrics=timing_metrics(e,rows,logs,width)
    metrics['isolation_overlap']=simultaneous_domains(e,rows,logs,mode)
    ledger=e.json(run/'session-resource-ledger.json',optional=True)
    budget_mib=env.get('FULL_MEMORY_MIB')
    if budget_mib:
        budget=e.json(run/'root-budget-readback.json',optional=True)
        e.check('requested common root memory limit actually read back',True if str(budget.get('actual_limits',{}).get('memory.max','')).strip()==str(int(budget_mib)*1024**2)
                and budget.get('path')=='/sys/fs/cgroup/cdz' and budget.get('changes_limits') is False else None,
                {'requested_mib':budget_mib,'observed':budget,'scope':'charged cgroup memory; inherited pages may remain charged outside'})
    failed=[x for x in e.checks if x['value'] is False];missing=[x for x in e.checks if x['value'] is None]
    return dict(run=name,status=status(e.checks),mechanism_observations_status=status([x for x in e.checks if x.get('section')!='source_admission']),
                verification_profile=profile,mode=mode,configuration_width=width,planned_requests=requests,attempts=len(rows),
                actual_cases=[r.get('case') for r in rows],full_profile=token,numeric=numeric,metrics=metrics,controller_selected_waits=selected_waits,
                requested_memory_mib=budget_mib,session_resource_ledger=ledger,source_sha256=sources,binary_sha256=binaries,
                interrupted_diagnostics=getattr(e,"interrupted_diagnostics",[]),
                checks=e.checks,failed=failed,missing=missing,verifier_sha256=sha(Path(__file__)),
                dependency_verifier_sha256={Path(m.__file__).name:sha(Path(m.__file__)) for m in (fullcheck,npcheck,old)},
                evidence_sha256_study_relative=e.evidence,scope=['Same trusted single-thread workload and final policy, new fixed-burst protocol qualification',
                    'Request-owned FDs close per request; global FD identities and template integrity precede all final commits',
                    'H must survive; root OOM that defeats H is not successful cleanup',
                    'C is configured capacity; observed numerical/business overlap is reported separately',
                    'G3 local setup remains charged; external Z cold preparation charged at full-session boundary'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run');p.add_argument('--profile',choices=('qualification','boundary','performance'),default='qualification')
    p.add_argument('--source-review');p.add_argument('--out',required=True);a=p.parse_args()
    try:r=analyze(a.run,a.profile,a.source_review)
    except Exception as error:r=dict(run=a.run,status='BLOCKED',verifier_error=repr(error),traceback=traceback.format_exc(),verifier_sha256=sha(Path(__file__)))
    out=Path(a.out);out=out if out.is_absolute() else S/out;out.resolve().relative_to(S.resolve());out.parent.mkdir(parents=True,exist_ok=True)
    with out.open('x') as f:json.dump(r,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(dict(run=a.run,status=r['status'],mechanism=r.get('mechanism_observations_status'),failed=len(r.get('failed',[])),missing=len(r.get('missing',[])),out=str(out))))
    return 0 if r['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
