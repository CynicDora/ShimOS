#!/usr/bin/env python3
"""Run frozen, independently initialized sessions in one private VM.

The session order is explicit, not secretly chosen after results are available.
This runner never changes production/old evidence. --prepare-only freezes a
new run without starting QEMU. The embedded guest helper refuses to start the
next session unless the previous product has released all owned resources.
Default: cold/hot NumPy sessions in one guest, low diagnostics for both.
The dependency fixture is identical and read-only. Initialization and final
Supervisor release remain charged to each complete session. No host cache reset.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from host_monitor import HostMonitor
from numpy_fixture import freeze as freeze_numpy, THREAD_ENV


VARIANTS = ('cold', 'hot')
BINARIES = ('bridge.so', 'native.so', 'domain_init', 'bridge_d.so', 'libab_probe.so', 'numpy_atfork_audit.so')

# Executed ONLY by the fixed private-VM init, never evaluated by this host script.
GUEST_DRIVER = r'''"""Trusted paired-session fixture; not a product cleanup owner."""
import hashlib,json,os,shutil,subprocess,time,traceback
from pathlib import Path

MARKER=Path('/run/native-benchmark-lab')
assert MARKER.read_text().strip()=='private-stock-linux-benchmark-vm'
assert os.getuid()==0
BASE=Path('/batch-evidence');CURRENT=Path('/evidence')
R=Path('/state/cross-domain');PROTO=R/'prototype';RUNTIME=Path('/opt/shimos-glibc')
CG=Path('/sys/fs/cgroup/cdz')

def dump(path,value):
    tmp=path.with_name(path.name+'.tmp')
    tmp.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n');os.replace(tmp,path)

def load(path):return json.loads(path.read_text())
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def command(argv):subprocess.run(argv,check=True)

def product_state():
    alive={}
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():continue
        try:
            status=(process/'status').read_text()
            fields=dict(line.split(':',1) for line in status.splitlines() if ':' in line)
            if int(fields['Uid'].split()[0])==65534:
                alive[process.name]={'status':status,'cgroup':(process/'cgroup').read_text()}
        except FileNotFoundError:continue
    root_ok=R.is_dir() and not R.is_symlink()
    work=[str(path) for path in R.glob('work-*')] if root_ok else []
    unknown=[str(path) for path in R.iterdir() if path.name not in ('src','prototype')] if root_ok else []
    return {'monotonic_ns':time.monotonic_ns(),'cgroup_exists':CG.exists(),
            'uid65534_processes':alive,'workspaces':work,'other_state_entries':unknown,
            'state_root_is_private_directory':root_ok,
            'sampling_not_atomic':True}

def released(state):
    return state['state_root_is_private_directory'] and not(state['cgroup_exists'] or state['uid65534_processes']
               or state['workspaces'] or state['other_state_entries'])

def inspect_receipts(directory,expected):
    final=load(directory/'external-final-release.json')
    supervisor=load(directory/'supervisor.json')
    summary=load(directory/'summary.json')
    observer=load(directory/'observer-later.json')
    checks={
      'fixture_waited_supervisor_zero':final.get('supervisor_wait_status')==0,
      'delegation_removed':final.get('delegation_removed') is True,
      'no_observer_kill':final.get('observer_killed_processes') is False,
      'no_observer_product_cleanup':final.get('observer_removed_product_resources') is False,
      'H_released':supervisor.get('release_state')=='RELEASED' and supervisor.get('resources_removed') is True,
      'H_real_wait_echild':supervisor.get('echild') is True and supervisor.get('controller_wait_status')==0,
      'H_no_errors':not(supervisor.get('errors') or supervisor.get('protocol_errors')),
      'H_no_resources':not(supervisor.get('remaining_cgroups') or supervisor.get('remaining_workspaces')),
      'H_fd_restored':supervisor.get('fd_before')==supervisor.get('fd_after'),
      'controller_summary':summary.get('all_passed') is True and summary.get('controller_echild') is True,
      'expected_attempt_count':len(summary.get('rows',[]))==expected,
      'attempts_passed':all(row.get('qualification')=='PASS' and row.get('resources')=='RELEASED'
                            and row.get('outcome')=='SUCCEEDED' for row in summary.get('rows',[])),
      'observer_no_processes_or_workspaces':not(observer.get('uid65534_processes') or observer.get('workspaces')),
    }
    return checks

def reset_fixture(previous):
    state=product_state()
    assert released(state),('product residue blocks fixture reset',state)
    if previous is not None:
        assert previous['complete'] is True,previous
        # Only our two known fixture directories. Never delete product work or
        # cgroups, and never resolve an unexpected symlink before deleting.
        for path in (RUNTIME,PROTO):
            assert path.is_dir() and not path.is_symlink(),('unexpected fixture path',str(path))
            shutil.rmtree(path)
    else:
        assert not RUNTIME.exists() and not PROTO.exists(),'first session must start fresh'
    return state

def restore_evidence():
    command(['umount','/evidence']) # Exposes the original 9p mount underneath.

def main():
    assert not BASE.exists(),'unexpected previous batch-evidence'
    BASE.mkdir();command(['mount','--bind','/evidence',str(BASE)])
    config=load(BASE/'batch-config.json')
    command(['/usr/bin/python3','-B',str(BASE/'numpy_fixture.py'),'--install',str(BASE)])
    R.mkdir(exist_ok=True)
    assert R.is_dir() and not R.is_symlink(),'unexpected state root'
    result={'same_vm':True,'order':config['order'],'sessions':[],
            'observer_killed_processes':False,'observer_removed_product_resources':False,
            'fixture_reset_only':['/opt/shimos-glibc','/state/cross-domain/prototype'],
            'shared_readonly_numpy_fixture':'/opt/shimos-numpy','shared_readonly_support_fixture':'/opt/shimos-numpy-deps',
            'complete':False}
    previous=None
    for session in config['sessions']:
        target=BASE/session['relative_dir'];mounted=False
        row={'session':session['session'],'numpy_baseline':session['baseline'],'numpy_level':config['numpy_level'],'diagnostics':session['variant'],'variant':session['variant'],'timing':session['timing'],'complete':False,
             'started_ns':time.monotonic_ns(),'returncode':None,'observer_cleanup_performed':False}
        try:
            row['before_fixture_reset']=reset_fixture(previous)
            assert target.is_dir() and not target.is_symlink()
            command(['mount','--bind',str(target),'/evidence']);mounted=True
            row['load_before']=Path('/proc/loadavg').read_text()
            (CURRENT/'guest-memory-before.txt').write_text(Path('/proc/meminfo').read_text())
            (CURRENT/'guest-vmstat-before.txt').write_text(Path('/proc/vmstat').read_text())
            started=time.monotonic_ns();shutil.copytree(CURRENT/'prototype',PROTO,symlinks=True)
            row['prototype_copy_ns']=time.monotonic_ns()-started
            expected=load(CURRENT/'source-sha.json')
            assert all(digest(PROTO/name)==sha for name,sha in expected.items()),'prototype copy hash mismatch'
            dump(target/'guest-machine.json',{'cpuinfo':Path('/proc/cpuinfo').read_text(),'meminfo':Path('/proc/meminfo').read_text(),'kernel':os.uname().release,'affinity':sorted(os.sched_getaffinity(0)),'pressure':{k:Path('/proc/pressure/'+k).read_text() for k in ('cpu','memory','io') if Path('/proc/pressure/'+k).exists()}})
            env=os.environ.copy()
            for name in ('LD_LIBRARY_PATH','PYTHONPATH','LD_PRELOAD','LD_AUDIT'):env.pop(name,None)
            env.update(PYTHONDONTWRITEBYTECODE='1',RELIABILITY_CASE='performance',
                COST_ENABLED=str(session['timing']),COST_VARIANT=session['variant'],
                ARCH_DIAGNOSTICS=session['variant'],COST_SESSION=session['session'],COST_REQUESTS=str(config['requests']),
                COST_WARMUP=str(config['warmup']),COST_TRACE=str(config['trace']),COST_SYSCALL_TRACE='0',
                NP_BASELINE=session['baseline'],NP_LEVEL=config['numpy_level'],NP_CASE=config['numpy_case'],
                NP_AUDIT=config['numpy_audit'])
            env.update(config['numpy_thread_environment'])
            dump(CURRENT/'numpy-package-link.json',{'package_manifest':'../../numpy-package-manifest.json',
                'package_manifest_sha256':digest(BASE/'numpy-package-manifest.json'),
                'install_receipt':'../../numpy-install.json','guest_path':'/opt/shimos-numpy',
                'support_manifest':'../../numpy-support-manifest.json','support_manifest_sha256':digest(BASE/'numpy-support-manifest.json'),
                'support_guest_path':'/opt/shimos-numpy-deps'})
            with (CURRENT/'install-output.log').open('wb') as log:
                started=time.monotonic_ns()
                subprocess.run(['/usr/bin/python3','-B',str(PROTO/'install_runtime.py')],
                               env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
                row['runtime_install_verify_ns']=time.monotonic_ns()-started
            with (CURRENT/'guest-output.log').open('wb') as log:
                row['fixture_run_begin_ns']=time.monotonic_ns()
                process=subprocess.run(['/usr/bin/python3','-B',str(PROTO/'run.py')],
                                       env=env,stdout=log,stderr=subprocess.STDOUT)
                row['fixture_run_end_ns']=time.monotonic_ns();row['returncode']=process.returncode
            row['release_checks']=inspect_receipts(CURRENT,config['requests']+config['warmup'])
            row['after_product']=product_state()
            row['load_after']=Path('/proc/loadavg').read_text()
            (CURRENT/'guest-memory-after.txt').write_text(Path('/proc/meminfo').read_text())
            (CURRENT/'guest-vmstat-after.txt').write_text(Path('/proc/vmstat').read_text())
            row['complete']=process.returncode==0 and all(row['release_checks'].values()) and released(row['after_product'])
            assert row['complete'],('session failed; next session will not start',row)
            # run.py leaves its fixture tracefs mount. Unmount only after all
            # original trace/stat evidence is saved; do not stack a second one.
            if any(line.split()[1]=='/sys/kernel/tracing' for line in Path('/proc/mounts').read_text().splitlines()):
                command(['umount','/sys/kernel/tracing'])
                row['fixture_tracefs_unmounted']=True
        except BaseException:
            row['complete']=False;row['failure']=traceback.format_exc()
        finally:
            row['finished_ns']=time.monotonic_ns()
            dump(target/'session-execution.json',row)
            if mounted:
                try:restore_evidence()
                except BaseException:
                    row['complete']=False;row['evidence_restore_failure']=traceback.format_exc()
                    dump(target/'session-execution.json',row)
            result['sessions'].append(row);dump(BASE/'batch-guest-result.json',result)
        if not row['complete']:
            print(json.dumps({'event':'PAIRED_SESSION_FAILED','row':row}),flush=True)
            return 1
        previous=row
        print(json.dumps({'event':'PAIRED_SESSION_COMPLETE','session':row['session']}),flush=True)
    # Last-session fixture runtime/prototype remain until VM teardown. They are
    # not product residuals or free asynchronous product cleanup.
    result['complete']=True;result['finished_ns']=time.monotonic_ns()
    dump(BASE/'batch-guest-result.json',result)
    command(['umount',str(BASE)])
    return 0

if __name__=='__main__':raise SystemExit(main())
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def put(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False)+'\n')


def source_inventory(directory):
    return {path.name:sha(path) for path in sorted(directory.iterdir()) if path.is_file()}


def validate_variant_sources(study, order, review):
    for variant in order:
        entry=review.get('variants',{}).get(variant,{})
        assert entry.get('admitted') is True,variant+' not admitted by selected source review'
        expected=entry.get('source_sha256')
        assert isinstance(expected,dict) and expected,variant+' has no reviewed source inventory'
        assert all(Path(name).name==name for name in expected),'source review contains non-flat path'
        actual=source_inventory(study/'prototype')
        mismatch={name:{'reviewed':expected.get(name),'actual':actual.get(name)}
                  for name in expected.keys()|actual.keys() if expected.get(name)!=actual.get(name)}
        assert not mismatch,(variant+' differs from selected source review',mismatch)


def validate_numpy_scope(review, args, order):
    """A source hash alone cannot qualify every NumPy preload/audit level."""
    scope=review.get('numpy_admission_scope',{})
    required={'levels':args.np_level,'cases':args.np_case,'audit_modes':args.np_audit}
    for key,value in required.items():
        assert value in scope.get(key,[]),('NumPy configuration outside reviewed scope',key,value)
    assert set(order)<=set(scope.get('baselines',[])),('baseline outside reviewed scope',order)
    assert scope.get('qualification_evidence'), 'NumPy scope must reference independent qualification evidence'


def session_layout(name, order, timing):
    return [{'index':index,'variant':'low','baseline':baseline,'timing':timing,
             'session':name+'-'+str(index)+'-'+baseline,
             'relative_dir':'sessions/'+str(index).zfill(2)+'-'+baseline}
            for index,baseline in enumerate(order)]


def freeze_session(study, project, destination, session, args, meta, review, review_bytes):
    destination.mkdir(parents=True, exist_ok=False)
    shutil.copytree(study/'prototype', destination/'prototype',
                    ignore=shutil.ignore_patterns('__pycache__'))
    bundle=project/'research/shimos_worker_pool/fork_runtime_compat/build/glibc-bundle-no-legacy-crypt/opt/shimos-glibc'
    aliases={}
    for item in bundle.rglob('*'):
        if item.is_symlink():
            assert item.resolve().is_relative_to(bundle),'runtime alias escaped bundle'
            aliases[str(item.relative_to(bundle))]=os.readlink(item)
    shutil.copytree(bundle,destination/'candidate-runtime',symlinks=False)
    inventory={str(item.relative_to(destination/'candidate-runtime')):sha(item)
               for item in sorted((destination/'candidate-runtime').rglob('*')) if item.is_file()}
    expected=json.loads((project/'research/shimos_worker_pool/fork_runtime_compat/runs/candidate-04/candidate-runtime-sha.json').read_text())
    assert inventory==expected,'candidate runtime differs from candidate-04'
    put(destination/'candidate-runtime-sha.json',inventory)
    put(destination/'candidate-packaging.json',{'source':str(bundle),'symlink_aliases_materialized':aliases,'elf_bytes_changed':False})
    inventory=source_inventory(destination/'prototype')
    assert inventory==review['variants'][session['variant']]['source_sha256'],'source changed during freeze'
    put(destination/'source-sha.json',inventory)
    (destination/'source-review.json').write_bytes(review_bytes)
    put(destination/'lab-manifest.json',meta)
    put(destination/'review-config.json',{'case':'performance','performance_benchmark':True,
        'diagnostics':session['variant'],'variant':session['variant'],'timing':session['timing'],
        'numpy_baseline':session['baseline'],'numpy_level':args.np_level,'numpy_case':args.np_case,'numpy_audit':args.np_audit,
        'numpy_thread_environment':THREAD_ENV,'pilot':args.pilot,
        'trace':args.trace,'syscall_trace':False,
        'requests':args.requests,'warmup':args.warmup,'isolated_reliability_repairs':True,
        'integration_ab':True,'runtime_candidate':'candidate-04','runtime_probe':True,
        'observer_cleanup_performed':False,'same_vm_pair':args.name,'session_order':session['index'],
        'cache_policy':'natural cache; no cache dropping; order explicitly recorded'})
    put(destination/'guest-session-config.json',{**session,
        'install_argv':['/usr/bin/python3','-B','/state/cross-domain/prototype/install_runtime.py'],
        'execution_argv':['/usr/bin/python3','-B','/state/cross-domain/prototype/run.py'],
        'explicit_environment':{'PYTHONDONTWRITEBYTECODE':'1','RELIABILITY_CASE':'performance',
            'ARCH_DIAGNOSTICS':session['variant'],'COST_ENABLED':session['timing'],'COST_VARIANT':session['variant'],'COST_SESSION':session['session'],
            'COST_REQUESTS':str(args.requests),'COST_WARMUP':str(args.warmup),'COST_TRACE':args.trace,
            'COST_SYSCALL_TRACE':'0','NP_LEVEL':args.np_level,'NP_BASELINE':session['baseline'],
            'NP_CASE':args.np_case,'NP_AUDIT':args.np_audit,**THREAD_ENV},'unset_environment':['LD_LIBRARY_PATH','PYTHONPATH','LD_PRELOAD','LD_AUDIT'],
        'vm_command':'../../command.json','guest_driver':'../../batch-guest.py'})


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('name')
    parser.add_argument('--order',default=','.join(VARIANTS),help='explicit permutation of the two variants')
    parser.add_argument('--requests',type=int,default=1,help='sequence count; planned N=1/10/50/100; pilot counts allowed')
    parser.add_argument('--warmup',type=int,default=0,help='default zero: do not give hot baseline free prewarming')
    parser.add_argument('--np-audit',choices=['0','1'],default='0')
    parser.add_argument('--np-level',choices=['import','data','blas'],default='import')
    parser.add_argument('--np-case',choices=['normal','compute_failure','cow_all'],default='normal')
    parser.add_argument('--pilot',action='store_true',help='freeze unqualified source for diagnostic admission; never a qualified performance result')
    parser.add_argument('--timing',choices=['0','1'],default='1')
    parser.add_argument('--trace',choices=['0','1'],default='0')
    parser.add_argument('--timeout',type=int,default=600)
    parser.add_argument('--prepare-only',action='store_true')
    parser.add_argument('--source-review',type=Path,default=Path('docs/variant-source-review.json'),
                        help='review path relative to numpy_admission; required unless --pilot')
    args=parser.parse_args()
    order=args.order.split(',')
    if sorted(order)!=sorted(VARIANTS):parser.error('--order must list each supported variant exactly once')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',args.name):parser.error('invalid run name')
    if args.requests<1 or args.warmup<0 or args.timeout<1:parser.error('invalid request/warmup/timeout count')
    study=Path(__file__).resolve().parents[1];project=study.parents[2]
    lab=project/'.build/benchmark-lab';out=study/'runs'/args.name
    source_review=(args.source_review if args.source_review.is_absolute() else study/args.source_review).resolve()
    if not source_review.is_relative_to(study):parser.error('--source-review must be inside numpy_admission')
    if args.pilot:
        review={'purpose':'unqualified NumPy admission pilot','variants':{'low':{
            'admitted':False,'source_sha256':source_inventory(study/'prototype')}}}
        review_bytes=(json.dumps(review,indent=2)+'\n').encode()
        review_relative='source-review.json (frozen pilot snapshot, not qualification)'
    else:
        if not source_review.is_file():parser.error('source review not yet available: '+str(source_review))
        review_bytes=source_review.read_bytes();review=json.loads(review_bytes)
        review_relative=str(source_review.relative_to(study))
        validate_variant_sources(study,['low'],review)
        validate_numpy_scope(review,args,order)
    review_sha=hashlib.sha256(review_bytes).hexdigest()
    meta=json.loads((lab/'manifest.json').read_text())
    for name,key in [('bzImage','kernel_sha256'),('initramfs.cpio.gz','initramfs_sha256')]:
        assert sha(lab/name)==meta[key],name+' differs from frozen VM manifest'
    for variant in order:assert (study/'prototype'/'run.py').is_file(),variant+' unavailable'
    out.mkdir(parents=True,exist_ok=False)
    shutil.copy2(lab/'manifest.json',out/'lab-manifest.json');shutil.copy2(lab/'root/init',out/'init.sh')
    shutil.copy2(Path(__file__),out/'paired_vm.py')
    freeze_numpy(project,out)
    sessions=session_layout(args.name,order,args.timing)
    for session in sessions:freeze_session(study,project,out/session['relative_dir'],session,args,meta,review,review_bytes)
    if not args.pilot:assert source_review.read_bytes()==review_bytes,'source review changed during freeze'
    (out/'source-review.json').write_bytes(review_bytes)
    config={'name':args.name,'same_vm':True,'order':order,'sessions':sessions,
            'requests':args.requests,'warmup':args.warmup,
            'timing':args.timing,'trace':args.trace,'diagnostics':'low','pilot':args.pilot,
            'numpy_level':args.np_level,'numpy_case':args.np_case,'numpy_audit':args.np_audit,'numpy_thread_environment':THREAD_ENV,
            'numpy_package_manifest_sha256':sha(out/'numpy-package-manifest.json'),
            'numpy_support_manifest_sha256':sha(out/'numpy-support-manifest.json'),
            'timing_level_scope':'per-session; timing=0 retains forced endpoints and original RP correctness diagnostics',
            'syscall_trace':False,'timeout_s':args.timeout,'independent_physical_hardware':False,
            'source_review_path':review_relative,'source_review_sha256':review_sha,
            'session_initialization':'new H/R/Z, product cgroups, target domains and workspaces each session',
            'shared_vm_state':'kernel, VM memory, filesystem/page cache; session order may bias results'}
    put(out/'batch-config.json',config)
    (out/'batch-guest.py').write_text(GUEST_DRIVER)
    (out/'guest-command.sh').write_text('#!/bin/sh\nset -eu\n'
        'test "$(cat /run/native-benchmark-lab)" = private-stock-linux-benchmark-vm\n'
        'unset LD_LIBRARY_PATH PYTHONPATH LD_PRELOAD LD_AUDIT\nexport PYTHONDONTWRITEBYTECODE=1\n'
        'exec /usr/bin/python3 -B /evidence/batch-guest.py\n')
    put(out/'fixture-source-sha.json',{name:sha(out/name) for name in ('paired_vm.py','batch-guest.py','guest-command.sh','init.sh','numpy_fixture.py')})
    put(out/'host-environment.json',{'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'kernel':os.uname().release,'loadavg':Path('/proc/loadavg').read_text(),
        'qemu':subprocess.check_output(['qemu-system-x86_64','--version'],text=True),'lscpu':subprocess.check_output(['lscpu','-J'],text=True),'meminfo':Path('/proc/meminfo').read_text(),'affinity':sorted(os.sched_getaffinity(0)),'pressure':{k:Path('/proc/pressure/'+k).read_text() for k in ('cpu','memory','io')}})
    disk=out/'disk.raw'
    argv=['qemu-system-x86_64','-enable-kvm','-cpu','host','-smp','4','-m','4096',
          '-nodefaults','-display','none','-monitor','none','-serial','stdio','-no-reboot','-net','none',
          '-kernel',str(lab/'bzImage'),'-initrd',str(lab/'initramfs.cpio.gz'),
          '-append','console=ttyS0 panic=-1 rdinit=/init cgroup_no_v1=all lsm=landlock',
          '-drive',f'file={disk},format=raw,if=none,id=state,cache=none,aio=threads',
          '-device','virtio-blk-pci,drive=state']
    for tag,path,ro in [('project',project,True),('evidence',out,False),
                        ('assets',project/'research/b_group_architecture_20261016/assets',True)]:
        argv+=['-fsdev',f'local,id={tag},path={path},security_model=mapped-xattr'+(',readonly=on' if ro else ''),
               '-device',f'virtio-9p-pci,fsdev={tag},mount_tag={tag}']
    put(out/'command.json',argv)
    if args.prepare_only:
        put(out/'result.json',{'status':'PREPARED_ONLY','complete':False,'vm_started':False})
        print(json.dumps({'directory':str(out),'vm_started':False}));return 0
    with disk.open('xb') as stream:stream.truncate(3*1024**3)
    timed=False;started=time.monotonic()
    with (out/'serial.log').open('wb') as log:
        process=subprocess.Popen(argv,stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,start_new_session=True)
        (out/'host-pid').write_text(str(process.pid))
        monitor=HostMonitor(out);monitor.start()
        try:process.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            timed=True;process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        finally:monitor.stop()
    guest=json.loads((out/'batch-guest-result.json').read_text()) if (out/'batch-guest-result.json').exists() else {}
    complete=not timed and process.returncode==0 and guest.get('complete') is True and 'BENCHMARK_LAB_COMPLETE rc=0' in (out/'serial.log').read_text(errors='replace')
    result={'qemu_rc':process.returncode,'timeout':timed,'wall_s':time.monotonic()-started,
            'complete':complete,'same_vm':True,'session_results':guest.get('sessions',[]),
            'host_timeout_intervention_used':timed,'not_product_cleanup_evidence':timed}
    manifests=[]
    for session in sessions:
        target=out/session['relative_dir'];execution=target/'session-execution.json'
        record=json.loads(execution.read_text()) if execution.exists() else {'complete':False,'status':'NOT_RUN'}
        put(target/'result.json',{'complete':record.get('complete') is True,'returncode':record.get('returncode'),
            'timing':session['timing'],'numpy_baseline':session['baseline'],'numpy_level':args.np_level,
            'pilot':args.pilot,
            'qemu_rc':process.returncode,'qemu_rc_scope':'shared enclosing VM, not a second VM',
            'timeout':timed and not record.get('complete'),'same_vm_pair':args.name,
            'session_order':session['index'],'top_level_vm_result':'../../result.json',
            'requires_independent_qualification':True,'requires_independent_numpy_qualification':True})
        manifest={'diagnostics':session['variant'],'variant':session['variant'],'timing':session['timing'],
        'numpy_baseline':session['baseline'],'numpy_level':args.np_level,'numpy_case':args.np_case,'numpy_audit':args.np_audit,
        'numpy_thread_environment':THREAD_ENV,'pilot':args.pilot,
            'same_vm_pair':args.name,'session_order':session['index'],
            'source_sha256':json.loads((target/'source-sha.json').read_text()),
            'binary_sha256':{name:sha(target/name) for name in BINARIES if (target/name).exists()},
            'source_review_path':review_relative,'source_review_sha256':review_sha,
            'frozen_source_review':'source-review.json','numpy_package_manifest_sha256':sha(out/'numpy-package-manifest.json'),
            'numpy_support_manifest_sha256':sha(out/'numpy-support-manifest.json')}
        put(target/'variant-manifest.json',manifest);manifests.append(manifest)
    result['same_shared_C_binaries']={name:len({m['binary_sha256'].get(name) for m in manifests})==1
                                     and all(name in m['binary_sha256'] for m in manifests) for name in BINARIES }
    if complete and not all(result['same_shared_C_binaries'].values()):
        result['complete']=False;result['failure']='shared C binary hashes differ; no equivalent-binary comparison admission'
    if result['complete']:
        disk.unlink();result['private_disk_removed']=True
    else:result['private_disk_removed']=False
    put(out/'result.json',result)
    print(json.dumps(result,indent=2));return 0 if result['complete'] else 1


if __name__=='__main__':raise SystemExit(main())
