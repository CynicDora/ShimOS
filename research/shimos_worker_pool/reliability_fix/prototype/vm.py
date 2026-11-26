#!/usr/bin/env python3
"""New outputs only; original frozen private VM and source tree remain read-only."""
import argparse,datetime,hashlib,json,os,shutil,subprocess,time
from pathlib import Path
def main():
    a=argparse.ArgumentParser();a.add_argument('name');a.add_argument('--case',choices=['control','budgets','receipts','cancels','failures','controller_death','controller_during_entry','normal','nonzero','pid_budget','second_budget','fork_ack_loss','reap_ack_loss','created_drop','reaped_drop','result_loss_side_effect','cancel_queued','cancel_before_business','cancel_during_entry','double_cancel','cancel','timeout','zygote_death','pid1_death','control_eof','revoke_ack_loss'],default='control');a.add_argument('--bad-export',action='store_true');a.add_argument('--normal-stop',action='store_true');args=a.parse_args()
    proto=Path(__file__).resolve().parent;study=proto.parent;project=proto.parents[3]
    lab=project/'.build/benchmark-lab';out=study/'runs'/args.name;out.mkdir(parents=True,exist_ok=False)
    meta=json.loads((lab/'manifest.json').read_text())
    for name,key in [('bzImage','kernel_sha256'),('initramfs.cpio.gz','initramfs_sha256')]:assert hashlib.sha256((lab/name).read_bytes()).hexdigest()==meta[key]
    shutil.copytree(proto,out/'prototype',ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copy2(lab/'manifest.json',out/'lab-manifest.json');shutil.copy2(lab/'root/init',out/'init.sh')
    (out/'host-environment.json').write_text(json.dumps({'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'kernel':os.uname().release,'loadavg':Path('/proc/loadavg').read_text(),'qemu':subprocess.check_output(['qemu-system-x86_64','--version'],text=True)},indent=2)+'\n')
    (out/'source-sha.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (out/'prototype').iterdir() if p.is_file()},indent=2)+'\n')
    script='''#!/bin/sh
set -eu
test "$(cat /run/native-benchmark-lab)" = private-stock-linux-benchmark-vm
mkdir -p /state/cross-domain
cp -a /evidence/prototype /state/cross-domain/prototype
unset LD_LIBRARY_PATH PYTHONPATH
export PYTHONDONTWRITEBYTECODE=1
'''+f'export RELIABILITY_CASE={args.case}\n'+('export CDZ_BAD_EXPORT=1\n' if args.bad_export else '')+('export CDZ_NORMAL_STOP=1\n' if args.normal_stop else '')+'exec python3 -B /state/cross-domain/prototype/run.py\n'
    (out/'guest-command.sh').write_text(script)
    disk=out/'disk.raw'
    with disk.open('xb') as f:f.truncate(3*1024**3)
    argv=['qemu-system-x86_64','-enable-kvm','-cpu','host','-smp','4','-m','4096','-nodefaults','-display','none','-monitor','none','-serial','stdio','-no-reboot','-net','none','-kernel',str(lab/'bzImage'),'-initrd',str(lab/'initramfs.cpio.gz'),'-append','console=ttyS0 panic=-1 rdinit=/init cgroup_no_v1=all lsm=landlock','-drive',f'file={disk},format=raw,if=none,id=state,cache=none,aio=threads','-device','virtio-blk-pci,drive=state']
    for tag,path,ro in [('project',project,True),('evidence',out,False),('assets',project/'research/b_group_architecture_20261016/assets',True)]:
        argv+=['-fsdev',f'local,id={tag},path={path},security_model=mapped-xattr'+(',readonly=on' if ro else ''),'-device',f'virtio-9p-pci,fsdev={tag},mount_tag={tag}']
    (out/'review-config.json').write_text(json.dumps({'case':args.case,'performance_benchmark':False,'isolated_reliability_repairs':True,'observer_cleanup_performed':False},indent=2)+'\n')
    (out/'command.json').write_text(json.dumps(argv,indent=2)+'\n')
    timed=False;t=time.monotonic()
    with (out/'serial.log').open('wb') as log:
        p=subprocess.Popen(argv,stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,start_new_session=True)
        (out/'host-pid').write_text(str(p.pid))
        try:p.wait(timeout=180)
        except subprocess.TimeoutExpired:
            timed=True;p.terminate()
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()
    r={'qemu_rc':p.returncode,'timeout':timed,'wall_s':time.monotonic()-t,'complete':'BENCHMARK_LAB_COMPLETE rc=0' in (out/'serial.log').read_text(errors='replace')}
    (out/'result.json').write_text(json.dumps(r,indent=2)+'\n');disk.unlink();print(json.dumps(r));return 0 if r['complete'] else 1
if __name__=='__main__':raise SystemExit(main())
