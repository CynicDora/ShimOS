#!/usr/bin/env python3
"""Validate source provenance, Python syntax and local Markdown links without importing guest code."""
import ast,hashlib,json,re,sys,subprocess
from pathlib import Path
R=Path(__file__).resolve().parents[1]
errors=[];count=0
for p in R.rglob('*.py'):
    if '.git' in p.parts:continue
    try:ast.parse(p.read_text(),filename=str(p.relative_to(R)))
    except SyntaxError as e:errors.append({'file':str(p.relative_to(R)),'syntax':str(e)})
    count+=1
manifest=json.loads((R/'docs/source-manifest.json').read_text())
tracked=None
if (R/'.git').exists():
    tracked=set(subprocess.check_output(['git','ls-files','-z'],cwd=R).decode().split('\0'))
for row in manifest['entries']:
    if tracked is not None and row['release'] not in tracked:
        errors.append({'untracked_manifest_member':row['release']})
    p=R/row['release']
    if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=row['release_sha256']:
        errors.append({'provenance_mismatch':row['release']})
for p in R.rglob('*.md'):
    for target in re.findall(r'\[[^\]\n]*\]\(([^)\n]+)\)',p.read_text()):
        target=target.split('#')[0]
        if not target or re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:',target):continue
        if not (p.parent/target).exists():errors.append({'file':str(p.relative_to(R)),'missing_link':target})
print(json.dumps({'status':'PASS' if not errors else 'FAIL','python_sources_parsed':count,
                  'imported_files_verified':len(manifest['entries']),'errors':errors},indent=2))
sys.exit(bool(errors))
