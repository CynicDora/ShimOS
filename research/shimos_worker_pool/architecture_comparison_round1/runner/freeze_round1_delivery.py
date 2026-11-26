#!/usr/bin/env python3
"""Freeze final reports, source, analysis and raw evidence without changing runs."""
import datetime
import hashlib
import json
import os
from pathlib import Path

S=Path(__file__).resolve().parents[1]
SKIP={'__pycache__','plot-env','candidate-runtime','numpy-package','numpy-support'}

def main():
    output=S/'frozen/delivery-sha256.json'
    assert not output.exists(), 'never overwrite delivery inventory'
    assert json.loads((S/'analysis/formal-driver.json').read_text())['complete'] is True
    files={};aliases={};nbytes=0
    for root,dirs,names in os.walk(S):
        dirs[:]=sorted(d for d in dirs if d not in SKIP)
        for name in sorted(names):
            path=Path(root)/name;relative=str(path.relative_to(S))
            if path==output or name.endswith(('.pyc','.raw')):continue
            if path.is_symlink():aliases[relative]=os.readlink(path);continue
            h=hashlib.sha256()
            with path.open('rb') as stream:
                for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
            size=path.stat().st_size;nbytes+=size
            files[relative]={'sha256':h.hexdigest(),'bytes':size}
    result={'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'files':files,'aliases':aliases,'file_count':len(files),'bytes':nbytes,
            'excluded_directories':sorted(SKIP),
            'excluded_file_suffixes':['.pyc','.raw'],
            'dependency_inventory_note':'Repeated candidate-runtime, NumPy and support copies are bound by included per-run candidate-runtime-sha.json and package/support manifests; independent qualification/performance verifier checks actual runtime evidence. Plot environment versions are in frozen/plot-requirements.txt.',
            'manifest_does_not_claim':'Exact full physical memory, unobserved production guarantees, or integrity of unrelated project files.'}
    with output.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps({'output':str(output),'files':len(files),'bytes':nbytes}))

if __name__=='__main__':main()
