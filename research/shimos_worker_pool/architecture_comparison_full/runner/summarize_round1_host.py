#!/usr/bin/env python3
"""Offline, plan-only host-pressure summary; never maps host to guest clocks.

Run only after formal-driver.json says the preregistered 21 VMs have ended.
Failed VMs stay in the output. No process control or runtime imports are used.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PSI_KEYS = tuple((resource, kind) for resource in ('cpu', 'memory', 'io')
                 for kind in ('some', 'full'))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pressure(raw):
    if not isinstance(raw, str):
        return {}
    result = {}
    for line in raw.splitlines():
        tokens = line.split()
        if not tokens or tokens[0] not in ('some', 'full'):
            continue
        fields = dict(token.split('=', 1) for token in tokens[1:])
        result[tokens[0]] = {'avg10': float(fields['avg10']),
                             'total_us': int(fields['total'])}
    return result


def summarize(study, block):
    run = study / 'runs' / block['name']
    file = run / 'host-pressure.jsonl'
    result_file = run / 'result.json'
    result = json.loads(result_file.read_text())
    row = dict(run=block['name'], N=block['N'], block=block['block'],
               execution_index=block['execution_index'],
               architecture_order='>'.join(block['order']),
               product_result_complete=result.get('complete'),
               qemu_rc=result.get('qemu_rc'), host_timeout=result.get('timeout'),
               host_driver_vm_wall_s=result.get('wall_s'),
               observation_scope='whole VM host samples, not guest/product phases',
               cpu_busy_status='UNKNOWN_NO_PROC_STAT', cpu_busy_percent=None,
               host_pressure_path=str(file.relative_to(study)),
               host_pressure_sha256=sha(file) if file.exists() else None,
               result_sha256=sha(result_file),
               host_environment_sha256=sha(run/'host-environment.json')
                   if (run/'host-environment.json').exists() else None)
    errors = []
    samples = []
    if not file.exists():
        errors.append('host-pressure.jsonl missing')
    else:
        for number, line in enumerate(file.read_text().splitlines(), 1):
            if not line.strip():
                continue
            try:
                sample = json.loads(line)
                timestamp = int(sample['host_monotonic_ns'])
                load = float(sample['loadavg'].split()[0])
                available = None
                for field in sample['meminfo'].splitlines():
                    parts = field.split()
                    if parts[0] == 'MemAvailable:':
                        if len(parts) != 3 or parts[2] != 'kB':
                            raise ValueError('unexpected MemAvailable units')
                        available = int(parts[1]) * 1024
                if available is None:
                    raise ValueError('MemAvailable missing')
                psi = {resource: pressure(sample.get('pressure', {}).get(resource))
                       for resource in ('cpu', 'memory', 'io')}
                samples.append(dict(ns=timestamp, load=load, available=available, psi=psi))
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                errors.append(f'line {number}: {type(exc).__name__}: {exc}')
    stamps = [sample['ns'] for sample in samples]
    ordered = all(b > a for a, b in zip(stamps, stamps[1:]))
    window = stamps[-1] - stamps[0] if len(stamps) >= 2 and ordered else None
    if len(stamps) < 2 or not ordered:
        errors.append('need at least two strictly increasing host monotonic samples')
    row.update(samples=len(samples), host_first_sample_ns=stamps[0] if stamps else None,
               host_last_sample_ns=stamps[-1] if stamps else None,
               host_observed_window_s=window / 1e9 if window else None,
               host_max_sample_gap_s=max((b-a)/1e9 for a,b in zip(stamps,stamps[1:]))
                   if len(stamps) >= 2 else None,
               load1_min=min((s['load'] for s in samples), default=None),
               load1_max=max((s['load'] for s in samples), default=None),
               mem_available_min_bytes=min((s['available'] for s in samples), default=None))
    for resource, kind in PSI_KEYS:
        key = f'{resource}_{kind}'
        records = [sample['psi'].get(resource, {}).get(kind) for sample in samples]
        present = [record for record in records if record is not None]
        avg = [record['avg10'] for record in present]
        delta = None
        valid_endpoints = bool(window and records and records[0] and records[-1])
        monotone = all(b['total_us'] >= a['total_us'] for a,b in zip(present,present[1:]))
        if valid_endpoints and monotone:
            delta = records[-1]['total_us'] - records[0]['total_us']
        if not valid_endpoints or not monotone or len(present) != len(samples):
            errors.append(f'{key}: missing/invalid pressure sample or nonmonotone total')
        row.update({key+'_samples': len(present),
                    key+'_avg10_min_percent': min(avg, default=None),
                    key+'_avg10_max_percent': max(avg, default=None),
                    key+'_total_delta_us': delta,
                    key+'_total_delta_fraction_of_host_window':
                        delta*1000/window if delta is not None and window else None,
                    key+'_total_delta_percent_of_host_window':
                        delta*100000/window if delta is not None and window else None})
    row['measurement_status'] = 'COMPLETE' if not errors else 'INCOMPLETE'
    row['measurement_errors'] = errors
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--study', type=Path, default=ROOT)
    parser.add_argument('--output-prefix', type=Path,
                        help='default: STUDY/analysis/formal-host-environment')
    args = parser.parse_args()
    study = args.study.resolve()
    plan_file = study/'frozen/formal-plan.json'
    driver_file = study/'analysis/formal-driver.json'
    plan = json.loads(plan_file.read_text())
    blocks = plan['blocks']
    names = [block['name'] for block in blocks]
    if len(names) != 21 or len(set(names)) != 21:
        raise SystemExit('this report requires the 21 unique preregistered VM names')
    if any(Path(name).name != name for name in names):
        raise SystemExit('invalid planned run name')
    driver = json.loads(driver_file.read_text())
    if driver.get('complete') is not True or {r['name'] for r in driver.get('rows', [])} != set(names):
        raise SystemExit('formal matrix has not finished; no partial aggregate is written')
    if driver.get('plan_sha256') != sha(plan_file):
        raise SystemExit('driver/plan identity mismatch')
    missing = [name for name in names if not (study/'runs'/name/'result.json').is_file()]
    if missing:
        raise SystemExit('missing final VM results: '+','.join(missing))
    prefix = args.output_prefix or study/'analysis/formal-host-environment'
    outputs = [prefix.with_suffix('.json'), prefix.with_suffix('.csv')]
    if any(path.exists() for path in outputs):
        raise SystemExit('refuse to overwrite existing aggregate; choose a new output prefix')
    rows = [summarize(study, block) for block in blocks]
    report = dict(status='COMPLETE' if all(r['measurement_status']=='COMPLETE' for r in rows)
                  else 'INCOMPLETE',
                  plan_path=str(plan_file.relative_to(study)), plan_sha256=sha(plan_file),
                  driver_sha256=sha(driver_file), script_sha256=sha(Path(__file__)),
                  planned_vms=21, included_vms=len(rows),
                  failed_product_vms=sum(r['product_result_complete'] is not True for r in rows),
                  host_clock='CLOCK_MONOTONIC; host-only differences',
                  scope=[
                      'Only the 21 formal-plan VM names; no pilot/qualification/sensitivity runs.',
                      'Each VM spans all three sequential groups plus boot and fixtures; not per-group attribution.',
                      'No host/guest clock subtraction or timestamp mapping.',
                      'PSI avg10 is a kernel rolling average; it may include activity before the VM.',
                      'PSI total_delta_us / host observed window is stall fraction, not CPU utilization.',
                      'System CPU full is recorded as exposed, not interpreted as a portable busy metric.',
                      'No /proc/stat was collected: CPU busy is Unknown, not zero.',
                      'First-to-last sample window omits unsampled edges; no extrapolation to QEMU wall.',
                      'Host readings are sequential, approximate and include unrelated host activity.',
                      'some/full and CPU/memory/IO pressure overlap; do not sum them.',
                      'Failed/incomplete product VMs remain included; pressure cannot prove causation.'],
                  rows=rows)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    with outputs[0].open('x') as stream:
        json.dump(report,stream,ensure_ascii=False,indent=2);stream.write('\n')
    with outputs[1].open('x',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]))
        writer.writeheader()
        for row in rows:
            writer.writerow({**row,'measurement_errors':json.dumps(row['measurement_errors'],ensure_ascii=False)})
    print(json.dumps({'status':report['status'],'included_vms':len(rows),
                      'outputs':[str(path) for path in outputs]}))
    return 0 if report['status']=='COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
