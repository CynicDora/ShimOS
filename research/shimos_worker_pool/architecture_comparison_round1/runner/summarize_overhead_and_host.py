#!/usr/bin/env python3
"""Offline endpoints-only probe comparison and host-pressure summary.

No phase costs are invented for timing=0. All inputs, warmups and failed
receipts remain in JSON/CSV; independent qualification is a separate artifact.
"""
import argparse
import collections
import csv
import json
from pathlib import Path
import statistics
import analyze_cost as a


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = ap.parse_args()
    root = args.root.resolve()
    out = root / 'analysis/measurement-overhead'
    out.mkdir(exist_ok=True)
    rows, sessions, errors = [], [], []
    for vm in ('overhead-pair-01', 'overhead-pair-02'):
        for run in sorted((root / 'runs' / vm / 'sessions').iterdir()):
            if not run.is_dir():
                continue
            cfg = a.read_metadata(run)['review-config.json']
            events, duplicates, malformed, sources = a.collect(run)
            receipts = a.records(run)
            grouped = collections.defaultdict(list)
            for event in events:
                if event.get('nonce'):
                    grouped[event['nonce']].append(event)
            local = []
            for nonce, ev in grouped.items():
                starts = [e for e in ev if e.get('name') == 'request_begin' and e.get('role') == 'R']
                ends = [e for e in ev if e.get('name') == 'response_ready' and e.get('role') == 'R']
                receipt = receipts.get(nonce, {})
                issue = []
                if len(starts) != 1 or len(ends) != 1:
                    issue.append('endpoint cardinality')
                if not issue and any(e.get('clock') != 'CLOCK_MONOTONIC' for e in starts + ends):
                    issue.append('clock mismatch')
                elapsed = None if issue else (ends[0]['ns'] - starts[0]['ns']) / 1e6
                if elapsed is not None and elapsed < 0:
                    issue.append('negative duration')
                if receipt.get('business') != 'KNOWN' or receipt.get('result', {}).get('exit_code') != 0:
                    issue.append('business not verified successful')
                if receipt.get('resources') != 'RELEASED' or receipt.get('output_eof') is not True:
                    issue.append('release/EOF not confirmed')
                row = dict(vm=vm, session=str(run.relative_to(root)), mode=cfg['diagnostics'],
                           timing=cfg['timing'], nonce=nonce,
                           repeat=starts[0].get('repeat') if starts else None,
                           warmup=starts[0].get('warmup') if starts else None,
                           response_ready_ms=elapsed, issues=issue,
                           business=receipt.get('business'), resources=receipt.get('resources'))
                local.append(row)
                rows.append(row)
            if malformed:
                errors.append(dict(run=str(run), malformed=malformed))
            if len(local) != cfg['requests'] + cfg['warmup']:
                errors.append(dict(run=str(run), actual=len(local), expected=cfg['requests'] + cfg['warmup']))
            measured = [r for r in local if r['warmup'] is False]
            if any(r['issues'] for r in local):
                errors.append(dict(run=str(run), bad_rows=[r for r in local if r['issues']]))
            sessions.append(dict(vm=vm, session=str(run.relative_to(root)), mode=cfg['diagnostics'],
                                 timing=cfg['timing'], requests=len(local), warmups=sum(r['warmup'] is True for r in local),
                                 response_ms=a.describe(r['response_ready_ms'] for r in measured if not r['issues']),
                                 malformed=malformed, sources=sources, identical_duplicate_events=len(duplicates)))
    pairs = []
    for vm in ('overhead-pair-01', 'overhead-pair-02'):
        for mode in ('full', 'low'):
            selected = {timing: [r for r in rows if r['vm'] == vm and r['mode'] == mode and
                                r['timing'] == timing and r['warmup'] is False] for timing in ('1', '0')}
            by_repeat = {k: {r['repeat']: r for r in v} for k, v in selected.items()}
            deltas = [by_repeat['1'][i]['response_ready_ms'] - by_repeat['0'][i]['response_ready_ms']
                      for i in sorted(by_repeat['1'].keys() & by_repeat['0'].keys())]
            pairs.append(dict(vm=vm, mode=mode,
                              timing_on=a.describe(r['response_ready_ms'] for r in selected['1']),
                              timing_off=a.describe(r['response_ready_ms'] for r in selected['0']),
                              matched_repeat_on_minus_off_ms=a.describe(deltas),
                              positive=sum(d > 0 for d in deltas), negative=sum(d < 0 for d in deltas),
                              note='serial sessions in one VM; not simultaneous pairs or independent hardware'))
    result = dict(status='COMPLETE' if not errors else 'INCOMPLETE', errors=errors,
                  requests=rows, sessions=sessions, pairs=pairs,
                  limitations=['timing=0 keeps mandatory and runtime qualification probes plus outer timestamps',
                               'two VMs on the same host; 8 measured requests per cell; no production tails',
                               'native timing=0 callback order is unobserved; actual callbacks and permission counts remain'])
    (out / 'overhead-results.json').write_text(json.dumps(result, indent=2) + '\n')
    with (out / 'overhead-requests.csv').open('w') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    host_rows = []
    for run in sorted((root / 'runs').iterdir()):
        file = run / 'host-pressure.jsonl'
        if not file.exists():
            continue
        samples = [json.loads(line) for line in file.read_text().splitlines() if line.strip()]
        metrics = collections.defaultdict(list)
        for rec in samples:
            try:
                metrics['load_1'].append(float(rec['loadavg'].split()[0]))
            except (KeyError, ValueError):
                pass
            for line in rec.get('meminfo', '').splitlines():
                key, *val = line.split()
                if key in ('MemAvailable:', 'Dirty:', 'Writeback:') and val:
                    metrics[key.rstrip(':') + '_KiB'].append(int(val[0]))
            for resource, raw in rec.get('pressure', {}).items():
                for line in raw.splitlines():
                    fields = line.split()
                    for token in fields[1:]:
                        key, val = token.split('=', 1)
                        if key == 'avg10':
                            metrics[f'{resource}_{fields[0]}_avg10_percent'].append(float(val))
        host_rows.append(dict(run=run.name, samples=len(samples),
                              metrics={key: a.describe(v) for key, v in metrics.items()}))
    (out / 'host-pressure-summary.json').write_text(json.dumps(host_rows, indent=2) + '\n')
    md = ['# 新增计时探针开销：小样本敏感度', '',
          '同一个 VM 内为每模式新建 H/R/Z 会话，交换顺序；每格 2 次热身 + 8 次正式请求。单位 ms。',
          'timing=0 仍保留原有资格与安全检查、最外层时间戳，不能称为无诊断生产路径。', '',
          '|VM|模式|计时开 median / p90|计时关 median / p90|配对 on−off median / 范围|正/负|',
          '|---|---|---|---|---|---|']
    for p in pairs:
        on, off, delta = p['timing_on'], p['timing_off'], p['matched_repeat_on_minus_off_ms']
        md.append(f"|{p['vm']}|{p['mode']}|{on['median']:.2f} / {on['p90']:.2f}|{off['median']:.2f} / {off['p90']:.2f}|{delta['median']:.2f} / {delta['minimum']:.2f}–{delta['maximum']:.2f}|{p['positive']}/{p['negative']}|")
    md += ['', '全部原始请求（包括热身）见 overhead-requests.csv，原日志及 SHA 见 overhead-results.json。',
           '这不是可统一扣除的校正常数：调度、日志、buffer 大小和时序会互相影响。不同模式的详细归因仍只能使用计时开启样本。',
           '宿主压力见 host-pressure-summary.json，仅用于环境说明，不把宿主和 guest 时间戳直接相减。']
    (out / 'README.md').write_text('\n'.join(md) + '\n')
    print(json.dumps(dict(status=result['status'], requests=len(rows), pairs=pairs), indent=2))


if __name__ == '__main__':
    main()
