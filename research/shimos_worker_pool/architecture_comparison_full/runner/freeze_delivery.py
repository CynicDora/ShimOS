#!/usr/bin/env python3
"""Freeze delivered evidence after all VM/analysis/doc writes have finished."""
import argparse,datetime,hashlib,json,os
from pathlib import Path
S=Path(__file__).resolve().parents[1]
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def main():
 a=argparse.ArgumentParser();a.add_argument('--out',type=Path,required=True);o=a.parse_args().out
 assert not o.exists(),'refuse overwrite'
 inventory={};excluded=[]
 for p in sorted(S.rglob('*')):
  if p.is_dir():continue
  rel=p.relative_to(S).as_posix()
  if p.resolve()==o.resolve():continue
  if p.suffix=='.raw':
   excluded.append({'path':rel,'size':p.stat().st_size,'reason':'mutable failed-VM private disk retained, not a frozen boot input; boot kernel/initramfs covered by input-freeze'})
  elif 'candidate-runtime' in p.relative_to(S).parts:
   # Every run already pins all copied bundle bytes and installed guest bytes.
   # Do not re-read dozens of identical 35 MiB bundles for a log manifest.
   excluded.append({'path':rel,'reason':'copied bundle; use adjacent candidate-runtime-sha.json and candidate-runtime-install.json plus input-freeze'})
  elif p.is_symlink():inventory[rel]={'symlink':os.readlink(p)}
  elif p.is_file():inventory[rel]={'sha256':digest(p),'size':p.stat().st_size}
 report={'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
   'scope':'new source, binaries except duplicate runtime bundles, configs, raw logs, analysis, docs and Feishu readbacks; exclusions explicit',
   'files':inventory,'excluded':excluded,'count':len(inventory),'excluded_count':len(excluded)}
 with o.open('x') as f:json.dump(report,f,ensure_ascii=False,indent=2);f.write('\n')
 print(json.dumps({'files':len(inventory),'excluded':len(excluded),'sha256':digest(o)}))
if __name__=='__main__':main()
