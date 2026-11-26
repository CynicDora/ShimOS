#!/usr/bin/env python3
"""Copy existing, pinned worker dependencies into a new research-only tree."""
import hashlib,json,pathlib,re,shutil,subprocess,sys
P=pathlib.Path(__file__).resolve().parent
ROOT=P.parents[3]
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def main():
 out=P/'runtime-additions';out.mkdir(exist_ok=False)
 base=ROOT/'.build/benchmark-lab/root/runtime'
 retained=[]
 for lib in ['/lib/x86_64-linux-gnu/libc.so.6','/lib64/ld-linux-x86-64.so.2']:
  a,b=pathlib.Path(lib),base/lib.lstrip('/')
  assert sha(a)==sha(b),(a,b,'glibc mismatch')
  retained.append({'source':str(a),'runtime':str(b),'sha256':sha(a),'not_copied':True})
 (out/'usr/local/lib/python3.10/dist-packages').mkdir(parents=True)
 for name in ['numpy','numpy.libs','numpy-2.2.6.dist-info']:
  src=pathlib.Path('/usr/local/lib/python3.10/dist-packages')/name
  shutil.copytree(src,out/'usr/local/lib/python3.10/dist-packages'/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
 (out/'usr/bin').mkdir(parents=True)
 shutil.copy2('/usr/bin/clangd',out/'usr/bin/clangd',follow_symlinks=True)
 deps=out/'usr/local/lib/worker-deps';deps.mkdir(parents=True)
 linked=subprocess.check_output(['ldd','/usr/bin/clangd'],text=True)
 exclusions={'libc.so.6','ld-linux-x86-64.so.2','libm.so.6','libpthread.so.0','libdl.so.2','librt.so.1'}
 for name in re.findall(r'(?:=>\s+|^\s*)(/[^\s]+)',linked,re.M):
  src=pathlib.Path(name)
  if src.name in exclusions:continue
  shutil.copy2(src,deps/src.name,follow_symlinks=True)
 # NumPy's bundled OpenBLAS links the glibc compatibility pthread soname,
 # absent from this VM's minimal runtime although libc itself is compatible.
 shutil.copy2('/lib/x86_64-linux-gnu/libpthread.so.0',deps/'libpthread.so.0',follow_symlinks=True)
 # Builtin headers only, no unneeded static compiler runtimes.
 shutil.copytree('/usr/lib/llvm-14/lib/clang/14.0.0/include',out/'usr/lib/llvm-14/lib/clang/14.0.0/include')
 fixture=P/'fixture';fixture.mkdir(exist_ok=False)
 zlib=ROOT/'research/b_group_architecture_20261016/assets/zlib-1.3.1'
 for name in ['adler32.c','zutil.h','zlib.h','zconf.h','README']:
  shutil.copy2(zlib/name,fixture/name)
 manifest={'source_python':subprocess.check_output(['/usr/bin/python3','-c','import sys,numpy;print(sys.version);print(numpy.__version__)'],text=True),'source_clangd':subprocess.check_output(['/usr/bin/clangd','--version'],text=True),'source_ldd':linked,'glibc_compatibility':retained,'runtime_files':{str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file()},'fixture_source':str(zlib),'fixture_sha256':{p.name:sha(p) for p in sorted(fixture.iterdir()) if p.is_file()},'no_host_install_or_runtime_overwrite':True}
 (P/'runtime-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 print(json.dumps({'runtime_files':len(manifest['runtime_files']),'bytes':sum(p.stat().st_size for p in out.rglob('*') if p.is_file()),'output':str(out)}))
if __name__=='__main__':main()
