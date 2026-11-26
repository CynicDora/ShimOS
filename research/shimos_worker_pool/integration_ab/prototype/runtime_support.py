"""Candidate-04 loader/DSO integration, copied from task B with fixed paths.
Controller and Supervisor retain stock libc; only Z and descendants use D.
"""
import os,json,hashlib,ctypes,errno
from pathlib import Path
from common import bridge
P=Path(__file__).resolve().parent
O=Path('/evidence')
BUNDLE=Path('/opt/shimos-glibc')
SELECTED_BRIDGE=P/'bridge_d.so'
CANDIDATE_OVERLAYS=[]
CANDIDATE_METADATA=None
def dump(name,data):
    (O/name).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
def prepare_candidate():
    """Validate explicit DSO sources before root drops privileges; no loader fallback."""
    global CANDIDATE_OVERLAYS,CANDIDATE_METADATA
    lib=BUNDLE/'lib'
    required=['ld-linux-x86-64.so.2','libc.so.6','libm.so.6','libresolv.so.2']
    assert all((lib/name).is_file() for name in required),'candidate libc bundle incomplete'
    binaries={}
    for src in sorted(lib.iterdir()):
        if not src.is_file() or '.so' not in src.name:continue
        with src.open('rb') as stream:elf=stream.read(4)==b'\x7fELF'
        if not elf:continue
        assert src.resolve().is_relative_to(BUNDLE),'candidate symlink escapes bundle'
        info=src.stat()
        binaries[str(src)]={'sha256':hashlib.sha256(src.read_bytes()).hexdigest(),'realpath':str(src.resolve()),
                            'device':[os.major(info.st_dev),os.minor(info.st_dev)],'inode':info.st_ino}
        for parent in ['/lib/x86_64-linux-gnu','/usr/lib/x86_64-linux-gnu','/lib64']:
            target=parent+'/'+src.name
            if (Path('/runtime')/target.lstrip('/')).is_file():CANDIDATE_OVERLAYS.append((str(src),target))
    destinations={target for _,target in CANDIDATE_OVERLAYS}
    assert {'/lib/x86_64-linux-gnu/libc.so.6','/lib/x86_64-linux-gnu/libm.so.6','/lib64/ld-linux-x86-64.so.2'}<=destinations
    (Path('/runtime')/str(BUNDLE).lstrip('/')).mkdir(parents=True,exist_ok=True)
    CANDIDATE_METADATA={'bundle':str(BUNDLE),'dso_sha256':binaries,'readonly_domain_overlays':CANDIDATE_OVERLAYS,
                        'public_api':'shimos_fork_into_cgroup(int,int*)','controller_libc':'stock guest',
                        'zygote_and_descendants_libc':'explicit candidate loader and bundle','full_compatibility_claim':False}
    dump('candidate-runtime.json',CANDIDATE_METADATA)

def check_candidate_mappings(maps):
    """Match actual map inode/device identities; reject same-name stock DSOs."""
    manifest=CANDIDATE_METADATA['dso_sha256']
    by_realpath={entry['realpath']:entry for entry in manifest.values()}
    glibc_names={Path(path).name for path in [*manifest,*by_realpath]}
    observed={}
    for line in maps.splitlines():
        fields=line.split(maxsplit=5)
        if len(fields)<6 or not fields[5].startswith('/'):continue
        path=fields[5]
        if Path(path).name not in glibc_names:continue
        assert path in by_realpath,('unexpected glibc DSO mapping',path)
        record=by_realpath[path]
        device=[int(value,16) for value in fields[3].split(':')]
        assert int(fields[4])==record['inode'] and device==record['device'],('mapping identity differs from bundle',path)
        observed[path]={'device':device,'inode':int(fields[4]),'sha256':record['sha256']}
    for name in ['libc.so.6','libm.so.6','ld-linux-x86-64.so.2']:
        assert str((BUNDLE/'lib'/name).resolve()) in observed,('required DSO not mapped',name)
    return {'mapped_glibc':observed,'same_name_stock_glibc_rejected':True,'all_mapped_glibc_inode_devices_match_manifest':True}

def probe_missing_candidate_api():
    """Controlled stock-libc fixture: missing public API must fail before fork."""
    assert not hasattr(ctypes.CDLL(None),'shimos_fork_into_cgroup'),'controller unexpectedly uses candidate libc'
    b=bridge(str(SELECTED_BRIDGE));pf=ctypes.c_int(-1);ctypes.set_errno(0)
    result=b.py_fork_cgroup(-1,ctypes.byref(pf));error=ctypes.get_errno()
    record={'context':'stock-libc root fixture before Controller creation','symbol_present':False,
            'return_value':result,'errno':error,'pidfd':pf.value,'expected_errno':errno.ENOSYS,
            'fallback_allowed':False,'passed':result==-1 and error==errno.ENOSYS and pf.value==-1}
    dump('candidate-missing-api.json',record)
    assert record['passed'],record

