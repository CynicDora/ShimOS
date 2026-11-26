#!/usr/bin/python3
"""Package only runtime ELF DSOs/gconv; no host install or loader replacement."""
from pathlib import Path
import shutil,hashlib,json,subprocess,datetime
root=Path(__file__).resolve().parents[3]
src=root/'build/glibc-stage/opt/shimos-glibc/lib'
bundle=root/'build/glibc-bundle/opt/shimos-glibc'
dst=bundle/'lib'
dst.mkdir(parents=True,exist_ok=True)
for p in sorted(src.glob('*.so*')):
    if p.resolve().read_bytes()[:4]!=b'\x7fELF': continue
    q=dst/p.name
    if p.is_symlink():
        if q.exists() or q.is_symlink():q.unlink()
        q.symlink_to(p.readlink())
    else:shutil.copy2(p,q)
if (src/'gconv').exists():shutil.copytree(src/'gconv',dst/'gconv',dirs_exist_ok=True)
records=[]
for p in sorted(bundle.rglob('*')):
    if p.is_symlink():
        assert p.resolve().is_relative_to(bundle.resolve())
        records.append({'path':str(p.relative_to(bundle)),'symlink':str(p.readlink())})
    elif p.is_file():
        b=p.read_bytes(); rec={'path':str(p.relative_to(bundle)),'size':len(b),'sha256':hashlib.sha256(b).hexdigest()}
        if b[:4]==b'\x7fELF':
            out=subprocess.check_output(['readelf','-n',str(p)],text=True)
            rec['build_id']=next((l.strip().split(': ',1)[1] for l in out.splitlines() if 'Build ID:' in l),None)
        records.append(rec)
manifest={'kind':'experimental vendor glibc source-integration candidate D','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':'Ubuntu glibc 2.35-0ubuntu3.15 with all distribution patches','guest_prefix':'/opt/shimos-glibc','abi':'pid_t shimos_fork_into_cgroup(int cgroup_fd, int *pidfd)','export_node':'GLIBC_2.35 (vendor-only symbol, absent from stock glibc)','architecture':'Linux x86_64','compiler':subprocess.check_output(['/usr/bin/gcc','--version'],text=True).splitlines()[0],'configure_args':['--prefix=/opt/shimos-glibc','--disable-werror','--enable-kernel=3.2','--enable-stack-protector=strong','--enable-stackguard-randomization','--enable-cet','--enable-multi-arch','--enable-static-pie','--with-pkgversion=ShimOS candidate D; Ubuntu source 2.35-0ubuntu3.15','CC=/usr/bin/gcc','CXX=/usr/bin/g++'],'not_binary_identical_to_distribution':True,'full_glibc_regression_suite_run':False,'files':records}
patch=root/'sources/runtime-source/patches/shimos-fork-into-cgroup.patch'
manifest['patch_sha256']=hashlib.sha256(patch.read_bytes()).hexdigest()
(bundle/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(bundle)
print(len(records),'runtime files/symlinks')
