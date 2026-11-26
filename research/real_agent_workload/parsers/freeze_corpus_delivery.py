#!/usr/bin/env python3
"""Snapshot this corpus subtask only; no history or other agents' outputs written."""
import datetime
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parents[1]
OUTPUT = ROOT / 'sources/trajectory_corpus/delivery-manifest.json'


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def main():
    files = set()
    for name in ('trajectories', 'parsers', 'workload_analysis', 'reuse_analysis', 'sources/trajectory_corpus'):
        for path in (ROOT / name).rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts and path != OUTPUT:
                files.add(path)
    for name in ('trajectory_manifest.csv', '03_trajectory_workload_analysis.md', '05_shimos_reuse_opportunities.md'):
        files.add(ROOT / name)
    artifacts = [{'path': str(path.relative_to(PROJECT)), 'bytes': path.stat().st_size,
                  'sha256': digest(path)} for path in sorted(files)]
    result = {
        'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'scope': 'Read-only public trajectory corpus and reuse evidence; no VM runs or model calls',
        'historical_inputs': 'Referenced and validated separately in workload_analysis/analysis_manifest.json',
        'files': artifacts,
        'bytes': sum(x['bytes'] for x in artifacts),
        'artifact_count': len(artifacts),
        'snapshot_note': 'This freezes this subtask at handoff; future explicit report edits require a new snapshot, not silent digest replacement.',
    }
    OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'artifact_count': result['artifact_count'], 'bytes': result['bytes'],
                      'manifest_sha256': digest(OUTPUT)}))


if __name__ == '__main__':
    main()
