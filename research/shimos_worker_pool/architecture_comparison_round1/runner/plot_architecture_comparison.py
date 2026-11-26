#!/usr/bin/env python3
"""Six requested plots from one explicit architecture-cost analysis directory.

No raw run discovery, no hidden sample filtering, no admission decisions.
Requires matplotlib in a separate host plotting environment, not the guest.
"""
import argparse
from collections import defaultdict
import csv
import hashlib
import json
from pathlib import Path
import statistics
from analysis_admission import load_admission

GROUPS=('G0','G1','G2')
COLORS={'G0':'#3265a8','G1':'#df8b22','G2':'#368662'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('analysis',type=Path);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--profile',choices=('formal','pilot','sensitivity'),required=True)
    parser.add_argument('--admission',type=Path,help='explicit final independent matrix; required for formal figures')
    args=parser.parse_args()
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    names=('sessions','paired','session_resource_ledger','resource_integrals','adjacent_partition')
    tables={};hashes={}
    for name in names:
        path=args.analysis/(name+'.csv')
        with path.open() as stream:tables[name]=list(csv.DictReader(stream))
        hashes[path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
    sessions=tables['sessions'];by_run={r['run']:r for r in sessions}
    admission={};admission_binding=None
    if args.profile=='formal':
        import re
        assert all(re.fullmatch(r'round1-n(?:1|2|5|10|25|50|100)-b[123]',r['pair'] or '') for r in sessions), 'formal plot inputs must be explicit registered round1 blocks'
        assert all(r['case']=='performance' and r['test_descendant']=='False' for r in sessions)
        if args.admission is None:parser.error('--admission is required for formal figures')
        admission,admission_binding=load_admission(args.admission,by_run)
    args.out.mkdir(parents=True,exist_ok=False)
    numbers=sorted({int(r['declared_N']) for r in sessions if r.get('declared_N')})
    def num(row,key):
        try:return float(row.get(key,''))
        except (TypeError,ValueError):return None
    def completed(row):
        s=by_run.get(row['run'],row)
        admitted=args.profile!='formal' or admission.get(s['run'],{}).get('status')=='PASS'
        return admitted and s.get('complete')=='True' and s.get('actual_attempts')==s.get('declared_N')
    def decorate(ax,ylabel,title):
        ax.set_title(title);ax.set_xlabel('Requested calls N');ax.set_ylabel(ylabel)
        ax.set_xscale('log');ax.set_xticks(numbers);ax.set_xticklabels(numbers)
        ax.grid(alpha=.2);ax.legend(fontsize=8)
    def save(fig,name,bottom=0,center='median line + raw VM points + observed range'):
        fig.suptitle('ShimOS fixed NumPy CPU workload — '+args.profile+'; '+center,fontsize=11)
        fig.tight_layout(rect=(0,bottom,1,.94))
        for extension in ('svg','png','pdf'):fig.savefig(args.out/(name+'.'+extension),dpi=170,bbox_inches='tight')
        plt.close(fig)
    def curves(ax,rows,value,scale=1,label_suffix='',failure=True):
        for group in GROUPS:
            grouped=defaultdict(list);failed=[]
            for row in rows:
                if row.get('architecture_group')!=group:continue
                n=int(row['declared_N']);v=value(row)
                if v is None:continue
                if completed(row):grouped[n].append(v/scale)
                else:failed.append((n,v/scale))
            all_xs=sorted(grouped)
            xs=[x for x in all_xs if args.profile!='formal' or len(grouped[x])==3]
            if xs:
                medians=[statistics.median(grouped[x]) for x in xs]
                ax.plot(xs,medians,color=COLORS[group],label=group+label_suffix+' median',lw=1.6)
                ax.fill_between(xs,[min(grouped[x]) for x in xs],[max(grouped[x]) for x in xs],color=COLORS[group],alpha=.12)
            for x in all_xs:
                    values=grouped[x]
                    for i,y in enumerate(values):
                        ax.scatter(x*(1+.025*(i-(len(values)-1)/2)),y,edgecolors=COLORS[group],
                                   facecolors=COLORS[group] if x in xs else 'none',s=22,zorder=3)
            if failure and failed:
                ax.scatter([x for x,y in failed],[y for x,y in failed],color=COLORS[group],marker='x',s=55,label=group+' incomplete/not admitted')
    fig,ax=plt.subplots(figsize=(8,4.5))
    curves(ax,sessions,lambda r:num(r,'full_sequence_ns'),1e9)
    decorate(ax,'Complete sequence wall (s)','1. Full sequence through actual wait(H)')
    save(fig,'01-full-sequence')
    fig,ax=plt.subplots(figsize=(8,4.5))
    curves(ax,sessions,lambda r:num(r,'full_sequence_ns')/int(r['declared_N']) if num(r,'full_sequence_ns') is not None and completed(r) else None,1e6)
    decorate(ax,'Full sequence / N (ms)','2. Average call cost, including setup and final cleanup')
    save(fig,'02-average-task-cost')
    fig,ax=plt.subplots(figsize=(8,4.5))
    roots=[r for r in tables['session_resource_ledger'] if r['group']=='session_parent']
    curves(ax,roots,lambda r:num(r,'cpu_usage_us'),1e6)
    decorate(ax,'Product parent cgroup CPU (s)','3. Cumulative product CPU; no child-counter addition')
    save(fig,'03-product-cpu')
    fig,axes=plt.subplots(2,2,figsize=(12,7.5))
    for column,metric,scale,title in [
        (0,'product_root_charged_memory_time',1024**2,'Root cgroup charged memory'),
        (1,'product_batch_PSS_time',1024,'Near-synchronous process PSS batches')]:
        ax=axes[0,column]
        rows=[r for r in tables['resource_integrals'] if r['metric']==metric]
        curves(ax,rows,lambda r:num(r,'integral_trapezoid'),scale)
        decorate(ax,'Observed-span integral (MiB·s)',title)
        ax=axes[1,column]
        curves(ax,rows,lambda r:num(r,'covered_fraction'),1,failure=False)
        decorate(ax,'Fraction of full session covered','Coverage; missing intervals are NOT filled')
        ax.set_ylim(0,1.03)
    fig.text(.5,.015,'Different memory ledgers. No extrapolation across missing batches or outside sampled endpoints; coverage is in CSV.',ha='center',fontsize=8)
    save(fig,'04-memory-time',bottom=.055)
    fig,ax=plt.subplots(figsize=(8,4.8));break_even=[]
    for left,color in [('G0',COLORS['G0']),('G1',COLORS['G1'])]:
        grouped=defaultdict(list);blocks=defaultdict(list)
        for row in tables['paired']:
            if row['left_group']!=left or row['right_group']!='G2':continue
            if not completed(by_run[row['left_run']]) or not completed(by_run[row['right_run']]):continue
            value=num(row,'left_minus_right_ns')
            if value is None:continue
            n=int(row['declared_N']);grouped[n].append(value/1e9);blocks[n].append(row['pair'])
        all_xs=sorted(grouped)
        xs=[x for x in all_xs if args.profile!='formal' or len(grouped[x])==3]
        if xs:
            ax.plot(xs,[statistics.median(grouped[x]) for x in xs],color=color,label=left+' − G2 median')
            ax.fill_between(xs,[min(grouped[x]) for x in xs],[max(grouped[x]) for x in xs],color=color,alpha=.15)
        for x in all_xs:
            for i,y in enumerate(grouped[x]):ax.scatter(x*(1+.025*(i-(len(grouped[x])-1)/2)),y,edgecolors=color,facecolors=color if x in xs else 'none',s=22)
        positive=[n for n in xs if len(grouped[n])>=3 and min(grouped[n])>0]
        break_even.append({'comparison':left+' minus G2','first_tested_N_with_three_positive_pairs':min(positive) if positive else None,
                           'raw_seconds':dict(grouped),'blocks':dict(blocks),
                           'scope':'first observed tested-grid point only; not a continuous threshold or general break-even guarantee'})
    ax.axhline(0,color='black',lw=.8);decorate(ax,'Positive: G2 saves sequence time (s)','5. Within-VM cumulative savings')
    save(fig,'05-paired-savings')
    (args.out/'observed-break-even.json').write_text(json.dumps(break_even,indent=2)+'\n')
    fig,ax=plt.subplots(figsize=(max(10,len(numbers)*1.8),5.3))
    stages=('session_prefix','G2_single_Z_preparation','request_sequence','final_close')
    palette=('#8aa7c8','#dfba72','#67a88b','#aa8cb7');x=0;ticks=[];labels=[]
    for n in numbers:
        for group in GROUPS:
            eligible=[r for r in sessions if r['architecture_group']==group and int(r['declared_N'])==n and completed(r)]
            runs={r['run'] for r in eligible} if args.profile!='formal' or len(eligible)==3 else set();bottom=0;have=False
            for stage,color in zip(stages,palette):
                values=[float(r['wall_ns'])/1e9 for r in tables['adjacent_partition'] if r['run'] in runs and r['stage']==stage]
                if not values:continue
                height=statistics.mean(values);ax.bar(x,height,bottom=bottom,width=.76,color=color,label=stage if x==0 else None);bottom+=height;have=True
            if have:
                for r in eligible:ax.scatter(x,float(r['full_sequence_ns'])/1e9,c='black',s=10,zorder=4)
            else:ax.text(x,0,'N/A',ha='center',fontsize=7,rotation=90)
            ticks.append(x);labels.append(f'{group}\nN={n}\nn={len(eligible)}');x+=1
        x+=.6
    ax.set_xticks(ticks);ax.set_xticklabels(labels,fontsize=7)
    ax.set_ylabel('Mean adjacent sequence components (s)');ax.set_title('6. Non-overlapping setup / repeated requests / final close')
    ax.grid(axis='y',alpha=.2);ax.legend(fontsize=7)
    save(fig,'06-adjacent-partition',center='mean adjacent components; raw VM totals')
    failures=[r for r in sessions if not completed(r)]
    manifest={'profile':args.profile,'analysis':str(args.analysis.resolve()),'source_sha256':hashes,
              'plotter_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'matplotlib':matplotlib.__version__,
              'admission_binding_helper_sha256':hashlib.sha256(Path(__file__).with_name('analysis_admission.py').read_bytes()).hexdigest(),
              'session_count':len(sessions),'noncomplete_sessions':failures,
              'qualification':'not granted by plotting; formal curve membership bound to explicit independent admission',
              'admission_binding':admission_binding,
              'limits':['same physical host VM repetitions are not independent hardware',
                        'no imputation of failed complete-N results','PSS and cgroup charge are different ledgers',
                        'figures 1–5 use medians across complete three-block points; figure 6 uses means so adjacent components add',
                        'points are raw VM sessions; range is not a confidence interval']}
    (args.out/'figure-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'output':str(args.out),'figures':6,'sessions':len(sessions),'noncomplete':len(failures)}))


if __name__=='__main__':main()
