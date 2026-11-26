#!/usr/bin/env python3
"""Read-only paired timing-on/off analysis, bound to separate safety admission.

No VM, tracing, process control, changes to runs, or estimated overhead subtraction.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import statistics
import analyze_cost


def load(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def describe(values):
    values = list(values)
    center = statistics.median(values)
    return {'n': len(values), 'median_ms': center, 'min_ms': min(values),
            'max_ms': max(values),
            'mad_ms': statistics.median(abs(v-center) for v in values)}


def analyze(runs, admission_paths):
    admissions = {}
    for path in admission_paths:
        for row in load(path)['runs']:
            key = Path(row['run']).resolve()
            assert key not in admissions, 'duplicate admission for '+str(key)
            admissions[key] = (row, path)
    sessions, comparisons, raw = [], [], []
    for run in runs:
        run = run.resolve()
        config = load(run/'batch-config.json')
        result = load(run/'result.json')
        assert config['timing_overhead'] and config['same_vm']
        assert result['complete'] and result['qemu_rc'] == 0 and not result['timeout']
        local = []
        for planned in config['sessions']:
            path = run/planned['relative_dir']
            admission, admission_file = admissions[path]
            assert admission['status'] == 'PASS' and not admission['failures']
            assert admission['variant'] == planned['variant']
            actual = load(path/'guest-session-config.json')
            assert actual['session'] == planned['session'] and actual['timing'] == planned['timing']
            data = analyze_cost.analyze_run(path, config['warmup'], config['requests'])
            assert not data['errors'] and not data['tracing_enabled']
            assert len(data['sessions']) == 1 and len(data['requests']) == config['requests']+config['warmup']
            assert all(r['timing_eligible'] and r['session'] == planned['session'] for r in data['requests'])
            measured = [r for r in data['requests'] if r['sample_class'] == 'measured']
            assert len(measured) == config['requests']
            by_repeat = {r['repeat']: r['response_ready_ms'] for r in measured}
            assert len(by_repeat) == len(measured)
            for r in data['requests']:
                raw.append({k: r.get(k) for k in ('run','session','variant','nonce','repeat','sample_class',
                           'start_ns','end_ns','response_ready_ms','timing_status')}
                           | {'vm': run.name, 'timing': planned['timing']})
            row = {'vm': run.name, 'session': planned['session'], 'variant': planned['variant'],
                   'timing': planned['timing'], 'order_index': planned['index'],
                   'admission': str(admission_file), 'admission_sha256': sha(admission_file),
                   'source_sha256': load(path/'source-sha.json'),
                   'binary_sha256': load(path/'variant-manifest.json')['binary_sha256'],
                   'measured_response': describe(by_repeat.values()), 'measured_by_repeat_ms': by_repeat,
                   'controller_session_ms': data['sessions'][0]['controller_session_ms'],
                   'product_session_through_supervisor_wait_ms': data['sessions'][0]['product_session_through_supervisor_wait_ms'],
                   'input_sources': data['input_sources'],
                   'config_sha256': sha(path/'review-config.json'),
                   'cpu_pss_comparison': 'N/A: timing=0 intentionally omits detailed resource samples'}
            sessions.append(row);local.append(row)
        for variant in config['order']:
            rows = [r for r in local if r['variant'] == variant]
            assert len(rows) == 2 and {r['timing'] for r in rows} == {'0','1'}
            on = next(r for r in rows if r['timing'] == '1')
            off = next(r for r in rows if r['timing'] == '0')
            assert on['source_sha256'] == off['source_sha256']
            assert on['binary_sha256'] == off['binary_sha256']
            a,b = on['measured_by_repeat_ms'],off['measured_by_repeat_ms']
            assert set(a) == set(b)
            differences = [{'repeat': i,'timing1_ms': a[i], 'timing0_ms': b[i],
                            'timing1_minus_0_ms': a[i]-b[i]} for i in sorted(a)]
            comparisons.append({'vm': run.name, 'variant': variant,
                'timing_order': [r['timing'] for r in sorted(rows,key=lambda r:r['order_index'])],
                'timing1_session': on['session'], 'timing0_session': off['session'],
                'timing1_response': on['measured_response'], 'timing0_response': off['measured_response'],
                'difference_of_session_medians_ms': on['measured_response']['median_ms']-off['measured_response']['median_ms'],
                'paired_differences': differences,
                'paired_difference_summary': describe(d['timing1_minus_0_ms'] for d in differences),
                'positive_paired_differences': sum(d['timing1_minus_0_ms']>0 for d in differences),
                'product_session_timing1_ms': on['product_session_through_supervisor_wait_ms'],
                'product_session_timing0_ms': off['product_session_through_supervisor_wait_ms']})
    return {'scope':'Detailed timing toggle; timing=0 still has original RP/FD/journal/security checks.',
            'unit':'ms','sign':'timing1 minus timing0; positive means detailed timing was slower',
            'samples_are_independent_hardware':False,
            'caution':'Serial sessions: matched repeat identifies input, not simultaneous cache/host state. No overhead subtraction or production-tail claim.',
            'analyzer_sha256':sha(Path(__file__)),
            'cost_analyzer_sha256':sha(Path(analyze_cost.__file__)),
            'sessions':sessions,'comparisons':comparisons,'raw_requests':raw}


def main():
    p=argparse.ArgumentParser();p.add_argument('runs',nargs='+',type=Path)
    p.add_argument('--admission',nargs='+',required=True,type=Path)
    p.add_argument('--out',required=True,type=Path);p.add_argument('--csv',required=True,type=Path)
    a=p.parse_args()
    assert not a.out.exists() and not a.csv.exists(),'refusing to overwrite evidence'
    result=analyze(a.runs,a.admission)
    with a.out.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    with a.csv.open('x',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(result['raw_requests'][0]));w.writeheader();w.writerows(result['raw_requests'])
    print(json.dumps([{k:v for k,v in r.items() if k!='paired_differences'} for r in result['comparisons']],indent=2))


if __name__=='__main__':main()
