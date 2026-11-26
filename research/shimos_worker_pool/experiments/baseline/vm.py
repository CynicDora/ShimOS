#!/usr/bin/env python3
"""Read-only historical VM image; every writable resource is local to B-Group."""
import argparse,hashlib,json,os,subprocess,time,shutil,signal
from pathlib import Path
B=Path(__file__).resolve().parents[1];P=B.parents[1];V=P/'.build/benchmark-lab'
a=argparse.ArgumentParser();a.add_argument('name');a.add_argument('--mode',default='all');a=a.parse_args()
o=B/'experiments'/a.name;o.mkdir(exist_ok=False)
manifest=json.loads((V/'manifest.json').read_text())
for f,k in [('bzImage','kernel_sha256'),('initramfs.cpio.gz','initramfs_sha256')]:
 assert hashlib.sha256((V/f).read_bytes()).hexdigest()==manifest[k]
shutil.copy2(V/'manifest.json',o/'lab-manifest.json');shutil.copy2(V/'root/init',o/'init.sh')
shutil.copytree(B/'minimal-prototypes',o/'prototype')
script='''#!/bin/sh
set -eu
mkdir -p /state/bgap
cp -a /assets/. /state/bgap/assets
cp -a /evidence/prototype /state/bgap/prototype
export BG_ROOT=/state/bgap
export BG_OUT=/evidence
export PATH=/state/bgap/assets/bin:$PATH
set +e
python3 -B /state/bgap/prototype/suite.py '''+a.mode+"""
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
    rmdir /sys/fs/cgroup/bgap/client
    rmdir /sys/fs/cgroup/bgap
    echo '{"private_cgroup_root_removed":true,"python_controller_exited":true}' > /evidence/external-final-release.json
fi
exit "$rc"
"""
(o/'guest-command.sh').write_text(script)
disk=o/'disk.raw'
with disk.open('xb')as f:f.truncate(3*1024**3)
argv=['qemu-system-x86_64','-enable-kvm','-cpu','host','-smp','4','-m','4096','-nodefaults','-display','none','-monitor','none','-serial','stdio','-no-reboot','-net','none','-kernel',str(V/'bzImage'),'-initrd',str(V/'initramfs.cpio.gz'),'-append','console=ttyS0 panic=-1 rdinit=/init cgroup_no_v1=all lsm=landlock','-drive',f'file={disk},format=raw,if=none,id=state,cache=none,aio=threads','-device','virtio-blk-pci,drive=state']
for tag,p,ro in [('project',P,True),('evidence',o,False),('assets',P/'research/b_group_architecture_20261016/assets',True)]:
 argv+=['-fsdev',f'local,id={tag},path={p},security_model=mapped-xattr'+(',readonly=on'if ro else ''),'-device',f'virtio-9p-pci,fsdev={tag},mount_tag={tag}']
(o/'command.json').write_text(json.dumps(argv,indent=2)+'\n')
t=time.monotonic();timed=False
with (o/'serial.log').open('wb')as log:
 p=subprocess.Popen(argv,stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,start_new_session=True)
 (o/'host-pid').write_text(str(p.pid))
 try:p.wait(timeout=900)
 except subprocess.TimeoutExpired:
  timed=True;p.terminate()
  try:p.wait(10)
  except subprocess.TimeoutExpired:p.kill();p.wait()
result={'qemu_rc':p.returncode,'timeout':timed,'wall_s':time.monotonic()-t,'complete':'BENCHMARK_LAB_COMPLETE rc=0'in(o/'serial.log').read_text(errors='replace')}
(o/'result.json').write_text(json.dumps(result,indent=2)+'\n')
disk.unlink();print(json.dumps(result));raise SystemExit(0 if result['complete'] else 1)
