#!/usr/bin/env python3
"""Check exact historical VM inputs; does not start QEMU or mutate cgroups."""
import hashlib,json,os,shutil
from pathlib import Path
R=Path(__file__).resolve().parents[1]
P=R/'research/shimos_worker_pool'
items={
 'vm_manifest':R/'.build/benchmark-lab/manifest.json',
 'kernel':R/'.build/benchmark-lab/bzImage',
 'initramfs':R/'.build/benchmark-lab/initramfs.cpio.gz',
 'guest_init_source':R/'.build/benchmark-lab/root/init',
 'bwrap_assets':R/'research/b_group_architecture_20261016/assets',
 'candidate_D_bundle':P/'fork_runtime_compat/build/glibc-bundle-no-legacy-crypt/opt/shimos-glibc',
 'candidate_D_identity':P/'fork_runtime_compat/runs/candidate-04/candidate-runtime-sha.json',
 'numpy_package':P/'numpy_admission/assets/numpy',
 'numpy_support_DSO':P/'numpy_admission/assets/numpy-deps',
 'kvm_device':Path('/dev/kvm'),
}
checks={k:{'path':str(v.relative_to(R)) if v.is_relative_to(R) else str(v),'present':v.exists()} for k,v in items.items()}
checks['qemu']={'present':shutil.which('qemu-system-x86_64') is not None}
checks['compiler']={'present':shutil.which('gcc') is not None}
verified={}
if all(items[x].is_file() for x in ['vm_manifest','kernel','initramfs']):
    m=json.loads(items['vm_manifest'].read_text())
    for name,key in [('kernel','kernel_sha256'),('initramfs','initramfs_sha256')]:
        verified[name]=hashlib.sha256(items[name].read_bytes()).hexdigest()==m[key]
ready=all(v['present'] for v in checks.values()) and all(verified.values())
print(json.dumps({'status':'ASSETS_PRESENT_NOT_QUALIFIED' if ready else 'BLOCKED',
                  'checks':checks,'image_hash_matches':verified,
                  'note':'Additional runtime/DSO/source-review checks remain in the historical runner. No experiment launched.'},indent=2))
raise SystemExit(0 if ready else 2)
