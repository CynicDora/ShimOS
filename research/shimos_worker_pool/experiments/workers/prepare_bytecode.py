#!/usr/bin/python3
"""Prepare equivalent normal bytecode for all arms, without altering base/source.

Run with the exact Python 3.10 runtime version. Output is only research overlay
__pycache__ entries; checked-hash pyc cannot silently override a changed source.
"""
import hashlib,importlib.util,json,pathlib,py_compile,shutil,sys,time
P=pathlib.Path(__file__).resolve().parent
PROJECT=P.parents[3]

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 assert sys.version_info[:3]==(3,10,12),sys.version
 out=P/'runtime-additions';base=PROJECT/'.build/benchmark-lab/root/runtime'
 receipt=P/'bytecode-preparation.json';assert not receipt.exists()
 original=P/'runtime-manifest-before-bytecode.json';assert not original.exists();shutil.copy2(P/'runtime-manifest.json',original)
 wall=time.monotonic_ns();cpu=time.process_time_ns();rows=[]
 for root,where in [(base/'usr/lib/python3.10','usr/lib/python3.10'),(out/'usr/local/lib/python3.10/dist-packages/numpy','usr/local/lib/python3.10/dist-packages/numpy')]:
  for source in sorted(root.rglob('*.py')):
   runtime_source=pathlib.Path(where)/source.relative_to(root)
   runtime_pyc=pathlib.Path(importlib.util.cache_from_source(str(runtime_source)))
   target=out/runtime_pyc;assert not target.exists(),target;target.parent.mkdir(parents=True,exist_ok=True)
   before=sha(source)
   py_compile.compile(str(source),cfile=str(target),dfile='/'+str(runtime_source),doraise=True,invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH)
   assert sha(source)==before
   data=target.read_bytes();assert data[:4]==importlib.util.MAGIC_NUMBER and int.from_bytes(data[4:8],'little')==3
   assert data[8:16]==importlib.util.source_hash(source.read_bytes())
   rows.append({'source':str(source),'runtime_source':str(runtime_source),'source_sha256':before,'runtime_pyc':str(runtime_pyc),'pyc_sha256':sha(target),'checked_source_hash':data[8:16].hex(),'bytes':len(data)})
 data={'schema':1,'reason':'pilot04 repeated source compilation is not a necessary Worker initialization cost; precompile once equally for A/B/C','python':sys.version,'cache_tag':sys.implementation.cache_tag,'magic_hex':importlib.util.MAGIC_NUMBER.hex(),'invalidation_mode':'CHECKED_HASH','optimization_level':0,'stable_dfile':'/usr/... guest path, not host build directory','wall_ns':time.monotonic_ns()-wall,'process_cpu_ns':time.process_time_ns()-cpu,'files':rows,'file_count':len(rows),'bytes':sum(r['bytes'] for r in rows),'base_and_sources_unchanged':True,'script_entry_still_compiled_each_process':True,'scope':'same-host build preparation; charged separately, not hidden per-worker optimization'}
 receipt.write_text(json.dumps(data,indent=2)+'\n')
 m=json.loads((P/'runtime-manifest.json').read_text());m['runtime_files']={str(f.relative_to(out)):sha(f) for f in sorted(out.rglob('*')) if f.is_file()}
 m['bytecode']={'receipt':receipt.name,'sha256':sha(receipt),'mode':'CHECKED_HASH','count':len(rows),'python':sys.version,'cache_tag':sys.implementation.cache_tag,'magic_hex':importlib.util.MAGIC_NUMBER.hex(),'source_validation':[{'path':r['runtime_source'],'sha256':r['source_sha256']} for r in rows]}
 (P/'runtime-manifest.json').write_text(json.dumps(m,indent=2)+'\n')
 print(json.dumps({k:data[k] for k in ('file_count','bytes','wall_ns','process_cpu_ns','cache_tag','magic_hex')}))
if __name__=='__main__':main()
