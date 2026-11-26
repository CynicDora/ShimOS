#!/usr/bin/env python3
"""New outputs only; original frozen private VM and source tree remain read-only."""
import argparse,datetime,hashlib,json,os,re,shutil,subprocess,time
from pathlib import Path
from host_monitor import HostMonitor, snapshot
from numpy_fixture import freeze as freeze_numpy, THREAD_ENV
def main():
    a=argparse.ArgumentParser();a.add_argument('name');a.add_argument('--case',choices=['performance','counter_state_corruption','counter_fd_leak','counter_forgotten_drop','counter_late_ack','counter_post_ack_controller_death','counter_post_forget_zygote_death','runtime','control','budgets','receipts','cancels','failures','controller_death','controller_during_entry','normal','nonzero','pid_budget','second_budget','fork_ack_loss','reap_ack_loss','created_drop','reaped_drop','result_loss_side_effect','cancel_queued','cancel_before_business','cancel_during_entry','double_cancel','cancel','timeout','zygote_death','pid1_death','control_eof','revoke_ack_loss'],default='control');a.add_argument('--np-audit',choices=['0','1'],default='0');a.add_argument('--np-level',choices=['import','data','blas'],default='import');a.add_argument('--np-baseline',choices=['hot','cold'],default='hot');a.add_argument('--np-case',choices=['normal','compute_failure','cow_all'],default='normal');a.add_argument('--prepare-only',action='store_true');a.add_argument('--timeout',type=int,default=600);a.add_argument('--source-review',default='docs/variant-source-review.json');a.add_argument('--variant',choices=['full','low'],default='low');a.add_argument('--requests',type=int,default=1);a.add_argument('--warmup',type=int,default=0);a.add_argument('--timing',choices=['0','1'],default='1');a.add_argument('--trace',choices=['0','1'],default='1');a.add_argument('--syscall-trace',action='store_true');a.add_argument('--bad-export',action='store_true');a.add_argument('--normal-stop',action='store_true');args=a.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',args.name):a.error('invalid run name')
    study=Path(__file__).resolve().parents[1];proto=study/'prototype';project=study.parents[2]
    lab=project/'.build/benchmark-lab';out=study/'runs'/args.name;out.mkdir(parents=True,exist_ok=False)
    assert args.requests>0 and args.warmup>=0 and args.timeout>0
    meta=json.loads((lab/'manifest.json').read_text())
    for name,key in [('bzImage','kernel_sha256'),('initramfs.cpio.gz','initramfs_sha256')]:assert hashlib.sha256((lab/name).read_bytes()).hexdigest()==meta[key]
    shutil.copytree(proto,out/'prototype',ignore=shutil.ignore_patterns('__pycache__'))
    freeze_numpy(project,out)
    shutil.copy2(Path(__file__),out/'vm.py')
    bundle=project/'research/shimos_worker_pool/fork_runtime_compat/build/glibc-bundle-no-legacy-crypt/opt/shimos-glibc'
    for item in bundle.rglob('*'):
        if item.is_symlink(): assert item.resolve().is_relative_to(bundle)
    aliases={str(item.relative_to(bundle)):os.readlink(item) for item in bundle.rglob('*') if item.is_symlink()}
    shutil.copytree(bundle,out/'candidate-runtime',symlinks=False)
    (out/'candidate-packaging.json').write_text(json.dumps({'source':str(bundle),'symlink_aliases_materialized':aliases,'elf_bytes_changed':False},indent=2)+'\n')
    (out/'candidate-runtime-sha.json').write_text(json.dumps({str(item.relative_to(out/'candidate-runtime')):hashlib.sha256(item.read_bytes()).hexdigest() for item in sorted((out/'candidate-runtime').rglob('*')) if item.is_file()},indent=2)+'\n')
    frozen=json.loads((project/'research/shimos_worker_pool/fork_runtime_compat/runs/candidate-04/candidate-runtime-sha.json').read_text())
    assert json.loads((out/'candidate-runtime-sha.json').read_text())==frozen,'runtime differs from candidate-04'
    shutil.copy2(lab/'manifest.json',out/'lab-manifest.json');shutil.copy2(lab/'root/init',out/'init.sh')
    (out/'host-environment.json').write_text(json.dumps({'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'snapshot':snapshot(),'kernel':os.uname().release,'loadavg':Path('/proc/loadavg').read_text(),'qemu':subprocess.check_output(['qemu-system-x86_64','--version'],text=True),'lscpu':subprocess.check_output(['lscpu','-J'],text=True),'meminfo':Path('/proc/meminfo').read_text(),'affinity':sorted(os.sched_getaffinity(0))},indent=2)+'\n')
    (out/'source-sha.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (out/'prototype').iterdir() if p.is_file()},indent=2)+'\n')
    script='''#!/bin/sh
set -eu
test "$(cat /run/native-benchmark-lab)" = private-stock-linux-benchmark-vm
mkdir -p /state/cross-domain
cp -a /evidence/prototype /state/cross-domain/prototype
unset LD_LIBRARY_PATH PYTHONPATH LD_PRELOAD LD_AUDIT
export PYTHONDONTWRITEBYTECODE=1
python3 -B /state/cross-domain/prototype/install_runtime.py
python3 -B /evidence/numpy_fixture.py --install /evidence
'''+''.join('export '+key+'='+value+'\n' for key,value in THREAD_ENV.items())+f'export NP_AUDIT={args.np_audit} NP_LEVEL={args.np_level} NP_BASELINE={args.np_baseline} NP_CASE={args.np_case}\n'+f'export RELIABILITY_CASE={args.case}\n'+('export CDZ_BAD_EXPORT=1\n' if args.bad_export else '')+('export CDZ_NORMAL_STOP=1\n' if args.normal_stop else '')+f'export ARCH_DIAGNOSTICS={args.variant} COST_ENABLED={args.timing} COST_VARIANT={args.variant} COST_SESSION={args.name} COST_REQUESTS={args.requests} COST_WARMUP={args.warmup} COST_TRACE={args.trace} COST_SYSCALL_TRACE={int(args.syscall_trace)}\n'+'exec python3 -B /state/cross-domain/prototype/run.py\n'
    (out/'guest-command.sh').write_text(script)
    disk=out/'disk.raw'
    with disk.open('xb') as f:f.truncate(3*1024**3)
    argv=['qemu-system-x86_64','-enable-kvm','-cpu','host','-smp','4','-m','4096','-nodefaults','-display','none','-monitor','none','-serial','stdio','-no-reboot','-net','none','-kernel',str(lab/'bzImage'),'-initrd',str(lab/'initramfs.cpio.gz'),'-append','console=ttyS0 panic=-1 rdinit=/init cgroup_no_v1=all lsm=landlock','-drive',f'file={disk},format=raw,if=none,id=state,cache=none,aio=threads','-device','virtio-blk-pci,drive=state']
    for tag,path,ro in [('project',project,True),('evidence',out,False),('assets',project/'research/b_group_architecture_20261016/assets',True)]:
        argv+=['-fsdev',f'local,id={tag},path={path},security_model=mapped-xattr'+(',readonly=on' if ro else ''),'-device',f'virtio-9p-pci,fsdev={tag},mount_tag={tag}']
    (out/'review-config.json').write_text(json.dumps({'case':args.case,'numpy_level':args.np_level,'numpy_baseline':args.np_baseline,'numpy_case':args.np_case,'numpy_audit':args.np_audit,'numpy_thread_environment':THREAD_ENV,'numpy_source_path':'/opt/shimos-numpy','performance_benchmark':args.case=='performance','diagnostics':args.variant,'variant':args.variant,'timing':args.timing,'trace':args.trace,'requests':args.requests,'warmup':args.warmup,'isolated_reliability_repairs':True,'integration_ab':True,'runtime_candidate':'candidate-04','runtime_probe':True,'observer_cleanup_performed':False},indent=2)+'\n')
    (out/'command.json').write_text(json.dumps(argv,indent=2)+'\n')
    (out/'fixture-source-sha.json').write_text(json.dumps({name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in ['vm.py','numpy_fixture.py','guest-command.sh','init.sh']},indent=2)+'\n')
    if args.prepare_only:
        disk.unlink()
        (out/'result.json').write_text(json.dumps({'status':'PREPARED_ONLY','complete':False,'vm_started':False},indent=2)+'\n')
        print(json.dumps({'directory':str(out),'vm_started':False}));return 0
    timed=False;t=time.monotonic()
    with (out/'serial.log').open('wb') as log:
        p=subprocess.Popen(argv,stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,start_new_session=True)
        (out/'host-pid').write_text(str(p.pid))
        monitor=HostMonitor(out);monitor.start()
        try:p.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            timed=True;p.terminate()
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()
        finally:monitor.stop()
    r={'qemu_rc':p.returncode,'timeout':timed,'wall_s':time.monotonic()-t,'host_timeout_intervention_used':timed,'not_product_cleanup_evidence':timed,'complete':not timed and p.returncode==0 and 'BENCHMARK_LAB_COMPLETE rc=0' in (out/'serial.log').read_text(errors='replace')}
    manifest={'diagnostics':args.variant,'variant':args.variant,'numpy_level':args.np_level,'numpy_baseline':args.np_baseline,'numpy_case':args.np_case,'numpy_audit':args.np_audit,'numpy_package_manifest_sha256':hashlib.sha256((out/'numpy-package-manifest.json').read_bytes()).hexdigest(),'numpy_support_manifest_sha256':hashlib.sha256((out/'numpy-support-manifest.json').read_bytes()).hexdigest(),'source_sha256':json.loads((out/'source-sha.json').read_text()),'binary_sha256':{n:hashlib.sha256((out/n).read_bytes()).hexdigest() for n in ['bridge.so','native.so','domain_init','bridge_d.so','libab_probe.so','numpy_atfork_audit.so'] if (out/n).exists()},'source_review_path':args.source_review,'source_review_sha256':hashlib.sha256((study/args.source_review).read_bytes()).hexdigest() if (study/args.source_review).exists() else None}
    (out/'variant-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    r['private_disk_removed']=bool(r['complete'])
    if r['complete']:disk.unlink()
    (out/'result.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r));return 0 if r['complete'] else 1
if __name__=='__main__':raise SystemExit(main())
