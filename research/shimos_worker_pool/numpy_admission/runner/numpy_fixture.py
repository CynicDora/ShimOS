#!/usr/bin/env python3
"""Freeze the existing NumPy wheel; install only inside the private test VM.

No Python dependency is imported by this fixture. It never alters the frozen
candidate-D runtime or installs a system package. The target namespace bind is
the prototype's responsibility; this fixture supplies one read-only source.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

PACKAGE_NAMES = ('numpy', 'numpy-2.2.6.dist-info', 'numpy.libs')
GUEST_TARGET = Path('/opt/shimos-numpy')
DEPS_TARGET = Path('/opt/shimos-numpy-deps')
DEPS_NAMES = ('libstdc++.so.6', 'libgcc_s.so.1')
THREAD_ENV = {name: '1' for name in (
    'OPENBLAS_NUM_THREADS', 'OMP_NUM_THREADS', 'MKL_NUM_THREADS',
    'NUMEXPR_NUM_THREADS', 'VECLIB_MAXIMUM_THREADS', 'BLIS_NUM_THREADS')}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root):
    assert sorted(p.name for p in root.iterdir()) == sorted(PACKAGE_NAMES)
    result = {}
    for path in sorted(root.rglob('*')):
        assert not path.is_symlink(), ('unexpected dependency symlink', str(path))
        if path.is_file():
            result[str(path.relative_to(root))] = sha(path)
        else:
            assert path.is_dir(), ('unexpected dependency object', str(path))
    return result


def dependency_inventory(root):
    assert sorted(p.name for p in root.iterdir()) == sorted(DEPS_NAMES)
    result = {}
    for name in DEPS_NAMES:
        path=root/name
        assert path.is_file() and not path.is_symlink(),('unexpected support DSO',str(path))
        result[name]=sha(path)
    return result


def freeze(project, destination):
    study = project / 'research/shimos_worker_pool/numpy_admission'
    source = study / 'assets/numpy'
    original = study / 'frozen/numpy-dependency-clean-assets.json'
    source_hashes = inventory(source)
    frozen = json.loads(original.read_text())
    original_hashes = {entry['wheel_member']:entry['sha256'] for entry in frozen['files']}
    assert original_hashes == source_hashes, 'NumPy differs from official wheel extraction manifest'
    target = destination / 'numpy-package'
    target.mkdir(exist_ok=False)
    for name in PACKAGE_NAMES:
        shutil.copytree(source / name, target / name)
    assert inventory(target) == source_hashes, 'NumPy changed during freeze'
    manifest = {
        'source': str(source), 'source_manifest': str(original),
        'source_manifest_sha256': sha(original), 'source_manifest_matches': True,
        'wheel_sha256': frozen['wheel_sha256'], 'source_url': frozen['source_url'],
        'version': '2.2.6', 'directories': list(PACKAGE_NAMES),
        'file_sha256': source_hashes, 'file_count': len(source_hashes),
        'file_bytes': sum((source / name).stat().st_size for name in source_hashes),
        'wheel': (source / 'numpy-2.2.6.dist-info/WHEEL').read_text(),
        'guest_path': str(GUEST_TARGET), 'thread_environment': THREAD_ENV,
        'runtime_modified': False, 'host_dependency_imported': False,
        'bytecode': 'only original wheel supplied bytecode retained; no host-generated or guest-written pyc',
    }
    (destination / 'numpy-package-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    deps_source=study/'assets/numpy-deps'
    deps_original=study/'frozen/numpy-dependency-support-assets.json'
    deps_frozen=json.loads(deps_original.read_text())
    deps_hashes=dependency_inventory(deps_source)
    assert deps_hashes == {name:item['sha256'] for name,item in deps_frozen['files'].items()}, 'support DSOs differ from frozen sources'
    assert deps_frozen['install_path'] == str(DEPS_TARGET)
    deps_destination=destination/'numpy-support'
    shutil.copytree(deps_source,deps_destination)
    assert dependency_inventory(deps_destination)==deps_hashes, 'support DSOs changed during freeze'
    deps_manifest={'source':str(deps_source),'source_manifest':str(deps_original),
        'source_manifest_sha256':sha(deps_original),'file_sha256':deps_hashes,
        'file_count':len(deps_hashes),'file_bytes':sum((deps_source/name).stat().st_size for name in deps_hashes),
        'guest_path':str(DEPS_TARGET),'files':deps_frozen['files'],'runtime_modified':False,
        'loader_contract':'explicit candidate-D loader path: D/lib first, then this read-only support directory; prototype-owned',
        'no_worker_deps_directory':True}
    (destination/'numpy-support-manifest.json').write_text(json.dumps(deps_manifest,indent=2)+'\n')
    shutil.copy2(Path(__file__), destination / 'numpy_fixture.py')
    return manifest


def readonly_bind(path):
    subprocess.run(['mount', '--bind', str(path), str(path)], check=True)
    subprocess.run(['mount', '-o', 'remount,bind,ro,nosuid,nodev', str(path)], check=True)
    records=[line for line in Path('/proc/self/mountinfo').read_text().splitlines()
             if line.split()[4]==str(path)]
    assert records and {'ro','nosuid','nodev'}<=set(records[-1].split()[5].split(',')), records
    return records


def install(evidence):
    assert Path('/run/native-benchmark-lab').read_text().strip() == 'private-stock-linux-benchmark-vm'
    assert os.getuid() == 0
    started = time.monotonic_ns()
    manifest = json.loads((evidence / 'numpy-package-manifest.json').read_text())
    assert not GUEST_TARGET.exists() and not DEPS_TARGET.exists(), 'refuse to overwrite existing guest dependency fixture'
    source = evidence / 'numpy-package'
    assert inventory(source) == manifest['file_sha256']
    shutil.copytree(source, GUEST_TARGET)
    assert inventory(GUEST_TARGET) == manifest['file_sha256']
    records=readonly_bind(GUEST_TARGET)
    deps_manifest=json.loads((evidence/'numpy-support-manifest.json').read_text())
    assert dependency_inventory(evidence/'numpy-support')==deps_manifest['file_sha256']
    shutil.copytree(evidence/'numpy-support',DEPS_TARGET)
    assert dependency_inventory(DEPS_TARGET)==deps_manifest['file_sha256']
    deps_records=readonly_bind(DEPS_TARGET)
    receipt = {
        'status': 'INSTALLED_READONLY', 'guest_path': str(GUEST_TARGET),
        'manifest_sha256': sha(evidence / 'numpy-package-manifest.json'),
        'file_count': manifest['file_count'], 'file_bytes': manifest['file_bytes'],
        'copy_and_hash_and_mount_ns': time.monotonic_ns() - started,
        'mountinfo': records, 'runtime_modified': False,
        'support_dependencies':{'guest_path':str(DEPS_TARGET),'file_sha256':deps_manifest['file_sha256'],
            'manifest_sha256':sha(evidence/'numpy-support-manifest.json'),'mountinfo':deps_records,
            'file_count':deps_manifest['file_count'],'file_bytes':deps_manifest['file_bytes']},
        'scope': 'VM fixture setup, excluded from request timing but explicitly recorded',
        'guest_python': subprocess.check_output(['/usr/bin/python3', '--version'], text=True).strip(),
    }
    (evidence / 'numpy-install.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--install', type=Path, help='private-VM evidence directory')
    args = parser.parse_args()
    if args.install is None:
        parser.error('only --install is available as a command; host freeze is a Python API')
    print(json.dumps(install(args.install)))


if __name__ == '__main__':
    main()
