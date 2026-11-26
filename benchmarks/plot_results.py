#!/usr/bin/env python3
"""Render descriptive historical medians. Optional dependency: matplotlib."""
import sys
sys.dont_write_bytecode=True
import csv,statistics
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from reproduce_tables import results,R
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':11,'axes.spines.top':False,'axes.spines.right':False,'svg.fonttype':'none'})
out=R/'docs/figures';out.mkdir(exist_ok=True)
d=results();fig,ax=plt.subplots(1,2,figsize=(11,4.4),layout='constrained')
a=ax[0];x=[0,1];width=.34
for shift,key,col,label in [(-width/2,'fresh','#7596b5','Fresh Worker'),(width/2,'reused','#39846c','Reused Worker')]:
 bars=a.bar([i+shift for i in x],[r[key] for r in d['worker_sequences']],width,color=col,label=label)
 a.bar_label(bars,fmt='%.0f',padding=3)
a.set_xticks(x,['NumPy','clangd']);a.set_ylim(0,790);a.set_ylabel('Complete four-request sequence (ms)');a.set_title('Persistent domain; 6 sequences/cell');a.legend(frameon=False)
a=ax[1];bars=a.bar([r['architecture'] for r in d['independent_domains']],[r['median'] for r in d['independent_domains']],color=['#7596b5','#a7adb7','#39846c'],width=.6)
a.bar_label(bars,fmt='%.3f',padding=4);a.set_ylim(0,74);a.set_ylabel('Complete N=100 sequence (s)');a.set_title('New domain per request; 3 paired VM blocks')
fig.suptitle('Controlled results: preparation and final product cleanup included',fontsize=13)
fig.savefig(out/'sequence-costs.svg');fig.savefig(out/'sequence-costs.png',dpi=130);plt.close(fig)
p=R/'research/shimos_worker_pool/architecture_comparison_full/analysis/density-v2-paired-preliminary-02/sessions.csv'
with p.open() as f: rows=list(csv.DictReader(f))
fig,a=plt.subplots(figsize=(7.5,4.5),layout='constrained');ks=[1,2,5,10,25,50]
for group,color in [('G2','#39846c'),('G3','#7596b5')]:
 values=[]
 for k in ks:
  cells=[r for r in rows if r['group']==group and float(r['K'])==k and r['stage']=='density']
  assert len(cells)==3
  values.append(statistics.median(float(r['full_s']) for r in cells))
 a.plot(range(len(ks)),values,'o-',label=group,color=color,lw=2)
a.set_xticks(range(len(ks)),ks);a.set_xlabel('Requests per domain K (N=50, same domain-retention policy)');a.set_ylabel('Complete sequence median (s)');a.set_title('Shared versus domain-local Zygote: tested crossing at K=5–10');a.legend(frameon=False);a.grid(axis='y',alpha=.2)
fig.savefig(out/'reuse-density.svg');fig.savefig(out/'reuse-density.png',dpi=130);plt.close(fig)
print('Rendered two figures from included numeric exports; no new measurements.')

# Preserve clean text diffs without changing SVG geometry.
for path in out.glob('*.svg'):
    path.write_text('\n'.join(line.rstrip() for line in path.read_text().splitlines())+'\n')
