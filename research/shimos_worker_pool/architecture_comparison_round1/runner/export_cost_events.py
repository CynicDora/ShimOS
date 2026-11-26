#!/usr/bin/env python3
"""Export existing COST records to pure JSONL; never run or alter experiments.

Repeated copies of the exact same event in serial/guest logs are deduplicated
within a run. Original timestamps and metadata remain unchanged. The added
_source field identifies the first source file/line; the manifest retains
duplicate origins and malformed-record diagnostics. Missing killed-process
buffers remain missing: this tool cannot reconstruct absent events.
"""
import argparse
import hashlib
import json
from pathlib import Path

from analyze_cost import collect


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('runs', nargs='+', type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--manifest', required=True, type=Path)
    a = p.parse_args()
    if a.output.exists() or a.manifest.exists():
        p.error('refusing to overwrite export or manifest')
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.manifest.parent.mkdir(parents=True, exist_ok=True)
    runs, count = [], 0
    digest = hashlib.sha256()
    with a.output.open('xb') as out:
        for run in a.runs:
            events, duplicates, errors, sources = collect(run)
            for event in events:
                row = dict(event)
                row['_source'] = dict(run=str(run), **row.pop('_origin'))
                raw = (json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n').encode()
                out.write(raw)
                digest.update(raw)
                count += 1
            runs.append(dict(run=str(run), exported_events=len(events),
                             duplicate_copies=len(duplicates), duplicates=duplicates,
                             parse_errors=errors, sources=sources))
    manifest = dict(scope='derivative export only, not new runtime evidence or qualification',
                    output=str(a.output), output_sha256=digest.hexdigest(), events=count,
                    exporter_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    runs=runs,
                    limitations=['R request_begin owns warmup/repeat classification; non-R defaults do not override it.',
                                 'PID values can repeat across namespace/attempts; nonce is required.',
                                 'Trace mode and qualification must be taken from each source run.',
                                 'No missing buffered event is inferred or reconstructed.'])
    with a.manifest.open('x') as out:
        json.dump(manifest, out, ensure_ascii=False, indent=2)
        out.write('\n')
    print(json.dumps(dict(events=count, output=str(a.output), manifest=str(a.manifest))))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
