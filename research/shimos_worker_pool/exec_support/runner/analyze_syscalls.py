#!/usr/bin/env python3
"""Offline raw_syscalls inventory for fixed Tool workloads after target exec."""
import argparse
from collections import Counter
import csv
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re

STUDY = Path(__file__).resolve().parents[1]
PROJECT = STUDY.parents[2]


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def analyze(run, mapping):
    trace_path = run / "process-trace.txt"
    trace_stats = read(run / "trace-stats.json")
    loss = any(re.search(r"(?:^|\n)(?:overrun|commit overrun|dropped events):\s*[1-9]", text)
               for text in trace_stats.values())
    lines, forks, execs = [], [], []
    for line in trace_path.read_text(errors="replace").splitlines():
        m = re.search(r"-(\d+)\s+\[\d+\].*?\s(\d+\.\d+):\s+(.*)", line)
        if not m:
            continue
        pid, ns, body = int(m[1]), int(Decimal(m[2])*1000000000), m[3]
        raw = re.match(r"sys_enter: NR (\d+)\s*\(", body)
        if raw:
            lines.append((pid, ns, int(raw[1])))
        fork = re.match(r"sched_process_fork:.*?\bpid=(\d+) child_comm=.* child_pid=(\d+)", body)
        if fork:
            forks.append((int(fork[1]), int(fork[2]), ns))
        exe = re.match(r"sched_process_exec: filename=(.*?) pid=(\d+) old_pid=(\d+)", body)
        if exe:
            execs.append((int(exe[2]), ns, exe[1]))
    outputs = []
    for path in sorted(run.glob("[0-9]*-*.json")):
        row = read(path)
        if row.get("execution_mode") != "tool_exec":
            continue
        wpid = row["w_pid"]
        case = row["tool_case"]
        target = case["argv"][0]
        start = next((ns for pid, ns, filename in execs if pid == wpid and filename == target), None)
        end = row.get("timestamps", {}).get("domain_quiescent")
        pids = {wpid}
        while True:
            added = {child for parent, child, ns in forks
                     if parent in pids and start is not None and ns >= start and (end is None or ns <= end)} - pids
            if not added:
                break
            pids |= added
        counts = Counter(nr for pid, ns, nr in lines
                         if pid in pids and start is not None and ns >= start and (end is None or ns <= end))
        outputs.append({
            "run": run.name, "case": row["case"], "level": case.get("level"), "nonce": row["nonce"],
            "argv": case["argv"], "source_row": path.name, "source_sha256": sha(path),
            "target_exec_ns": start, "domain_quiescent_ns": end, "root_pid": wpid, "tree_pids": sorted(pids),
            "trace_loss": loss, "observed_entry_count": sum(counts.values()),
            "unique_syscall_numbers": len(counts), "raw_entries_in_complete_trace": len(lines),
            "status": "OBSERVED" if counts and not loss and start is not None else "INCOMPLETE",
            "syscalls": [{"number": n, "name": mapping.get(n, "unmapped_"+str(n)), "entries": c}
                         for n, c in sorted(counts.items())],
            "trace_sha256": sha(trace_path),
        })
    return outputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runs", nargs="+")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    header = PROJECT / ".build/benchmark-lab/root/runtime/usr/include/x86_64-linux-gnu/asm/unistd_64.h"
    mapping = {int(n): name for name, n in re.findall(r"^#define __NR_(\w+) (\d+)$", header.read_text(), re.M)}
    out = Path(args.output)
    if not out.is_absolute():
        out = STUDY / "analysis" / out
    out = out.resolve()
    if not out.is_relative_to((STUDY / "analysis").resolve()):
        raise SystemExit("new output must be under exec_support/analysis")
    out.mkdir(parents=True, exist_ok=False)
    rows = []
    for name in args.runs:
        run = Path(name)
        if not run.is_absolute():
            run = STUDY / "runs" / run
        run = run.resolve()
        if not run.is_relative_to((STUDY / "runs").resolve()):
            raise SystemExit("inputs must be saved exec_support/runs evidence")
        rows.extend(analyze(run, mapping))
    notes = [
        "Raw syscall entries in the observed fixed runs, not a minimal necessary syscall set or a seccomp allow-list.",
        "Scope begins at the main W's target sched_process_exec event; its earlier Python/D bootstrap and static launcher are excluded.",
        "All descendants created after target exec are included, including their pre-exec setup. The target execve entry itself precedes the kernel exec event and is therefore excluded from this counted set; it is separately proven by sched_process_exec.",
        "seccomp-rejected calls may not reach syscall tracepoints. Rejection evidence also lives in fixed negative-probe logs; absence here does not prove a call was not attempted.",
        "vDSO-served operations such as clock_gettime may avoid syscalls; other inputs, tool versions or failure paths may require additional calls.",
        "Raw argument words are not pointer dereferences. This analysis does not decode paths, clone3 structures, cgroup FDs, or memory contents.",
        "Fresh diagnostic VM traces include overhead; do not use these as low-interference performance samples.",
    ]
    result = {"schema": 1, "notes": notes, "mapping_source": str(header.relative_to(PROJECT)),
              "mapping_sha256": sha(header), "analyzer_sha256": sha(Path(__file__)), "rows": rows}
    (out / "syscall-inventory.json").write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n")
    with (out / "syscall-inventory.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["run", "case", "level", "number", "name", "entries"])
        writer.writeheader()
        for row in rows:
            for syscall in row["syscalls"]:
                writer.writerow({"run": row["run"], "case": row["case"], "level": row["level"], **syscall})
    text = ["# Fixed tool syscall observations", "", *["- "+n for n in notes], ""]
    for row in rows:
        text += ["## "+row["case"], "", f"Run `{row['run']}`: {row['observed_entry_count']} entries, {row['unique_syscall_numbers']} numbers, status {row['status']}, trace loss {row['trace_loss']}.", "",
                 ", ".join("`"+r["name"]+"`" for r in row["syscalls"]), ""]
    (out / "README.md").write_text("\n".join(text))
    print(json.dumps({"output": str(out), "rows": len(rows), "statuses": [r["status"] for r in rows]}))


if __name__ == "__main__":
    main()
