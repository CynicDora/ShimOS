#!/usr/bin/python3
"""Derive a task-local runtime closure without glibc's legacy libcrypt.

No rebuild, no ELF mutation, no source-bundle mutation, no in-place overwrite.
The original configure enabled crypt; this packaging change DOES NOT claim it
was rebuilt with --disable-crypt. Ubuntu's system libxcrypt remains the provider.
"""
from pathlib import Path
import argparse, hashlib, json, shutil, datetime

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def verify(root, records):
    for entry in records:
        p = root / entry['path']
        if 'symlink' in entry:
            assert p.is_symlink() and str(p.readlink()) == entry['symlink'], str(p)
            assert p.resolve().is_relative_to(root.resolve()), str(p)
        else:
            assert p.is_file() and sha(p) == entry['sha256'], str(p)
            assert p.stat().st_size == entry['size'], str(p)

root = Path(__file__).resolve().parents[3]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path, default=root/'build/glibc-bundle/opt/shimos-glibc')
parser.add_argument('--destination', type=Path, default=root/'build/glibc-bundle-no-legacy-crypt/opt/shimos-glibc')
args = parser.parse_args()
source, destination = args.source.resolve(), args.destination.resolve()
assert source != destination and not destination.is_relative_to(source), 'destination must be independent'
assert not destination.exists(), 'refusing to overwrite an existing candidate bundle'
original_manifest = source/'manifest.json'
original = json.loads(original_manifest.read_text())
verify(source, original['files'])
excluded_paths = {'lib/libcrypt.so', 'lib/libcrypt.so.1'}
excluded = [entry for entry in original['files'] if entry['path'] in excluded_paths]
assert {entry['path'] for entry in excluded} == excluded_paths
retained = [entry for entry in original['files'] if entry['path'] not in excluded_paths]

# Copy exact runtime members; do not copy and then silently reuse old manifest.
destination.mkdir(parents=True)
for entry in retained:
    src, dst = source/entry['path'], destination/entry['path']
    dst.parent.mkdir(parents=True, exist_ok=True)
    if 'symlink' in entry:
        dst.symlink_to(src.readlink())
    else:
        shutil.copy2(src, dst)
verify(destination, retained)
for rel in excluded_paths:
    p = destination/rel
    assert not p.exists() and not p.is_symlink()

manifest = dict(original)
manifest['created_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
manifest['files'] = retained
manifest['packaging_revision'] = 'exclude-glibc-legacy-libcrypt-v1'
manifest['source_bundle_manifest_sha256'] = sha(original_manifest)
manifest['source_bundle_relative_path'] = 'build/glibc-bundle/opt/shimos-glibc'
manifest['excluded_source_manifest_entries'] = excluded
manifest['retained_runtime_members_identical_to_source'] = True
manifest['retained_runtime_member_count'] = len(retained)
manifest['fork_implementation_changed'] = False
manifest['recompiled'] = False
manifest['provider_contract'] = {
    'libcrypt.so.1': 'Retain stock guest Ubuntu libxcrypt. Do not overlay it with a same-name glibc-built DSO.',
    'distribution_basis': 'Ubuntu glibc 2.35-0ubuntu3.15 debian/rules crypt=no and rules.d/build.mk --disable-crypt',
    'candidate_build_fact': 'Original ELF build still used its recorded configure options; only packaging removes its legacy libcrypt outputs.',
    'pending_runtime_validation': 'Fresh guest run must verify _crypt resolves required XCRYPT_2.0 from the stock guest provider and rerun the bounded fork/namespace/cgroup checks.'
}
manifest['packaging_script'] = {
    'relative_path': 'sources/runtime-source/patches/package-no-legacy-crypt.py',
    'sha256': sha(Path(__file__).resolve())
}
(destination/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
# Check that source artifacts and original manifest remained unchanged.
verify(source, original['files'])
assert sha(original_manifest) == manifest['source_bundle_manifest_sha256']
print(json.dumps({'destination':str(destination),'manifest_sha256':sha(destination/'manifest.json'),
                  'source_manifest_sha256':manifest['source_bundle_manifest_sha256'],
                  'retained_members':len(retained),'excluded_paths':sorted(excluded_paths),
                  'all_retained_bytes_and_symlinks_identical':True},indent=2))
