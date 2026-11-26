#!/usr/bin/env python3
"""Reuse frozen private KVM image; only this study's fresh run directory is writable."""
import argparse,hashlib,json,subprocess,time,shutil,os,datetime
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('name');p.add_argument('--session',type=int,default=1);p.add_argument('--repeats',type=int,default=1);p.add_argument('--counts',default='1,4');p.add_argument('--mode',choices=['cost','layout','qualify'],default='cost');p.add_argument('--resources',action='store_true');a=p.parse_args()
    b=Path(__file__).resolve().parents[1];project=b.parents[1];v=project/'.build/benchmark-lab'
    out=b/'experiments/runs'/a.name;out.mkdir(parents=True,exist_ok=False)
    host={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'kernel':os.uname().release,'cpuinfo':Path('/proc/cpuinfo').read_text(),'meminfo':Path('/proc/meminfo').read_text(),'loadavg':Path('/proc/loadavg').read_text(),'affinity':sorted(os.sched_getaffinity(0)),'qemu_version':subprocess.check_output(['qemu-system-x86_64','--version'],text=True),'pressure':{q.name:q.read_text() for q in Path('/proc/pressure').iterdir()}}
    (out/'host-environment.json').write_text(json.dumps(host,indent=2)+'\n')
    m=json.loads((v/'manifest.json').read_text())
    for f,k in [('bzImage','kernel_sha256'),('initramfs.cpio.gz','initramfs_sha256')]:assert hashlib.sha256((v/f).read_bytes()).hexdigest()==m[k]
    shutil.copy2(v/'manifest.json',out/'lab-manifest.json');shutil.copy2(v/'root/init',out/'init.sh')
    shutil.copytree(b/'experiments/baseline',out/'baseline');shutil.copy2(Path(__file__),out/'vm.py')
    shutil.copy2(b/'experiments/run.py',out/'run.py')
    shutil.copytree(b/'experiments/workers',out/'workers',ignore=shutil.ignore_patterns('runtime-additions','__pycache__'))
    source_rows=[]
    for q in sorted(out.rglob('*')):
        if q.is_file():source_rows.append({'path':str(q.relative_to(out)),'sha256':hashlib.sha256(q.read_bytes()).hexdigest()})
    (out/'input-snapshot.json').write_text(json.dumps(source_rows,indent=2)+'\n')
    script='''#!/bin/sh
set -eu
test "$(cat /run/native-benchmark-lab)" = private-stock-linux-benchmark-vm
mkdir -p /state/pool /runtime/pool-workers
cp -a /assets /state/pool/assets
cp -a /evidence/baseline /state/pool/prototype
cp -a /evidence/workers/. /runtime/pool-workers/
cp -a /opt/native-mvp/research/shimos_worker_pool/experiments/workers/runtime-additions/. /runtime/
python3 -B - <<'PY'
import pathlib,json,hashlib,time
t=time.monotonic_ns();m=json.loads(pathlib.Path('/runtime/pool-workers/runtime-manifest.json').read_text())
for name,expected in m['runtime_files'].items():
 p=pathlib.Path('/runtime')/name
 assert hashlib.sha256(p.read_bytes()).hexdigest()==expected,name
for source in m.get('bytecode',{}).get('source_validation',[]):
 p=pathlib.Path('/runtime')/source['path']
 assert hashlib.sha256(p.read_bytes()).hexdigest()==source['sha256'],source['path']
pathlib.Path('/evidence/runtime-verification.json').write_text(json.dumps({'verified':len(m['runtime_files']),'wall_ns':time.monotonic_ns()-t,'all_match':True})+'\\n')
PY
export BG_ROOT=/state/pool BG_OUT=/evidence
export PATH=/state/pool/assets/bin:$PATH
export PYTHONDONTWRITEBYTECODE=1
exec python3 -B /evidence/run.py '''+f'--session {a.session} --repeats {a.repeats} --counts {a.counts} --mode {a.mode}'+(' --resources' if a.resources else '')+'\n'
    (out/'guest-command.sh').write_text(script)
    disk=out/'disk.raw'
    with disk.open('xb') as f:f.truncate(3*1024**3)
    argv=['qemu-system-x86_64','-enable-kvm','-cpu','host','-smp','4','-m','4096','-nodefaults','-display','none','-monitor','none','-serial','stdio','-no-reboot','-net','none','-kernel',str(v/'bzImage'),'-initrd',str(v/'initramfs.cpio.gz'),'-append','console=ttyS0 panic=-1 rdinit=/init cgroup_no_v1=all lsm=landlock','-drive',f'file={disk},format=raw,if=none,id=state,cache=none,aio=threads','-device','virtio-blk-pci,drive=state']
    for tag,path,ro in [('project',project,True),('evidence',out,False),('assets',project/'research/b_group_architecture_20261016/assets',True)]:
        argv+=['-fsdev',f'local,id={tag},path={path},security_model=mapped-xattr'+(',readonly=on' if ro else ''),'-device',f'virtio-9p-pci,fsdev={tag},mount_tag={tag}']
    (out/'command.json').write_text(json.dumps(argv,indent=2)+'\n')
    t=time.monotonic();timed=False
    with (out/'serial.log').open('wb') as log:
        proc=subprocess.Popen(argv,stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,start_new_session=True)
        (out/'host-pid').write_text(str(proc.pid))
        try:proc.wait(timeout=900)
        except subprocess.TimeoutExpired:
            timed=True;proc.terminate()
            try:proc.wait(10)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
    result={'qemu_rc':proc.returncode,'timeout':timed,'wall_s':time.monotonic()-t,'complete':'BENCHMARK_LAB_COMPLETE rc=0' in (out/'serial.log').read_text(errors='replace')}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');disk.unlink()
    print(json.dumps(result));return 0 if result['complete'] else 1
if __name__=='__main__':raise SystemExit(main())
