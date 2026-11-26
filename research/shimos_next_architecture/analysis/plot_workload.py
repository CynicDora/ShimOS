#!/usr/bin/env python3
"""Offline standalone plots via installed gnuplot; keep failed plot evidence."""
import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--analysis', type=Path, required=True)
    a = ap.parse_args()
    root = a.analysis.resolve()
    data = json.loads((root / 'summary.json').read_text())
    batches = sorted(data['batches'], key=lambda x: (x['block'], x['C']))
    assert len(batches) == 6
    target = root / 'multisession-costs.png'
    assert not target.exists(), 'never replace a prior plot'
    fields = ['block', 'C', 'batch_wall_s', 'root_CPU_s', 'business_CPU_s',
              'business_memory_time_MiBs_observed_window']
    csvpath = root / 'multisession-plot-data.csv'
    assert not csvpath.exists()
    with csvpath.open('w', newline='') as f:
        w = csv.writer(f); w.writerow(fields)
        for b in batches:
            assert all(b[k] is not None for k in fields), 'missing data is not zero'
            w.writerow([b[k] for k in fields])
    program = '''set terminal pngcairo size 1500,530 font "DejaVu Sans,11"
set output "multisession-costs.png"
set datafile separator comma
set multiplot layout 1,3 title "B0_INIT: 13 fixed replay tasks, synthetic burst; two same-host VM blocks"
set key top right
set grid ytics
set xtics ("1" 1,"2" 2,"4" 4)
set xrange [0.7:4.3]
set yrange [0:*]
set xlabel "Admission concurrency C"
set ylabel "Batch wall time (s)"
plot "multisession-plot-data.csv" every ::1 using ($1==0?$2:1/0):3 with linespoints lw 2 pt 7 title "block 0", \\
     "" every ::1 using ($1==1?$2:1/0):3 with linespoints lw 2 pt 5 title "block 1"
set ylabel "Guest root CPU (CPU seconds)"
plot "multisession-plot-data.csv" every ::1 using ($1==0?$2:1/0):4 with linespoints lw 2 pt 7 title "block 0", \\
     "" every ::1 using ($1==1?$2:1/0):4 with linespoints lw 2 pt 5 title "block 1"
set ylabel "Business memcg integral (MiB s)"
plot "multisession-plot-data.csv" every ::1 using ($1==0?$2:1/0):6 with linespoints lw 2 pt 7 title "block 0", \\
     "" every ::1 using ($1==1?$2:1/0):6 with linespoints lw 2 pt 5 title "block 1"
unset multiplot
'''
    script = root / 'multisession-costs.gnuplot'
    script.write_text(program)
    q = subprocess.run(['gnuplot', str(script)], cwd=root, text=True, capture_output=True)
    version = subprocess.run(['gnuplot', '--version'], text=True, capture_output=True)
    manifest = dict(command=['gnuplot', str(script)], returncode=q.returncode,
                    stdout=q.stdout, stderr=q.stderr, version=version.stdout,
                    input_sha256=hashlib.sha256((root / 'summary.json').read_bytes()).hexdigest(),
                    script_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
                    caveat='Descriptive same-host VM blocks, not paired executor ranking; all 13 tasks retained including grade failures; memory is sampled business charge, not net physical memory')
    if target.exists():
        manifest['plot_sha256'] = hashlib.sha256(target.read_bytes()).hexdigest()
    (root / 'gnuplot-render-receipt.json').write_text(json.dumps(manifest, indent=2) + '\n')
    if q.returncode or not target.exists():
        raise SystemExit('Plot failed; receipt preserved')
    print(target)


if __name__ == '__main__':
    main()
