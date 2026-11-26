#!/usr/bin/env python3
"""Serial resource blocks. A collected failed workload is never a PASS."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

p = argparse.ArgumentParser()
p.add_argument('prefix')
p.add_argument('matrices', nargs='+')
p.add_argument('--review', required=True)
p.add_argument('--prototype', required=True)
p.add_argument('--timeout', default='1200')
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
with (root/'analysis'/f'{a.prefix}-execution.jsonl').open('x') as ledger:
    for i, matrix in enumerate(a.matrices, 1):
        name = f'{a.prefix}-block-{i}'
        cmd = [sys.executable, '-B', str(root/'runner/resource_vm.py'), name,
               '--matrix', matrix, '--source-review', a.review,
               '--prototype-dir', a.prototype, '--np-level', 'blas',
               '--trace', '0', '--timeout', a.timeout]
        row = dict(name=name, matrix=matrix, argv=cmd, start_ns=time.monotonic_ns())
        with (root/'analysis'/f'{name}-driver.log').open('x') as log:
            result = subprocess.run(cmd, cwd=root, stdout=log, stderr=subprocess.STDOUT)
        row.update(returncode=result.returncode, end_ns=time.monotonic_ns())
        try:
            batch = json.loads((root/'runs'/name/'batch-guest-result.json').read_text())
            planned = json.loads((root/matrix).read_text())
            frozen = json.loads((root/'runs'/name/'batch-config.json').read_text())['sessions']
            rows = batch.get('sessions', [])
            safe = (batch.get('collection_complete') is True
                    and len(rows) == len(planned)
                    and len(frozen) == len(planned)
                    and len({r.get('session') for r in rows}) == len(rows)
                    and all(r.get('safe_to_continue') is True
                            and r.get('collection_complete') is True
                            and r.get('product_release_verified') is True
                            and r.get('session') == f.get('session')
                            and r.get('architecture_group') == f.get('architecture_group') == item['group']
                            and r.get('planned_requests') == f.get('requests') == item['requests']
                            and f.get('index') == j
                            and f.get('configuration') == item
                            for j, (r, f, item) in enumerate(zip(rows, frozen, planned))))
            row.update(collection_complete=batch.get('collection_complete'),
                       all_workloads_succeeded=batch.get('all_workloads_succeeded'),
                       safe_release_for_all_planned_sessions=safe,
                       independent_qualification='PENDING')
        except Exception as error:
            safe = False
            row['collection_read_error'] = repr(error)
        ledger.write(json.dumps(row)+'\n'); ledger.flush()
        print(json.dumps(row), flush=True)
        if result.returncode not in (0, 2) or not safe:
            raise SystemExit(1)
