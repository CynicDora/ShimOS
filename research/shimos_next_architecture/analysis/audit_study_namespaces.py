#!/usr/bin/env python3
"""Offline namespace/identity coverage supplement; no workload operations.

Consumes a completed study lifecycle audit and its raw first-seen /proc records.
Namespace inode values are only comparable within one guest; serial reuse is
not evidence that two containers shared a live namespace.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
PROJECT = BASE.parents[1]
KINDS = ("user", "pid", "mnt", "net", "ipc", "uts")


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def status_fields(text):
    return dict(line.split(":", 1) for line in text.splitlines() if ":" in line)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.analysis = args.analysis.resolve()
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    summary = read(args.analysis / "study-process-summary.json")
    inputs = {str(Path(__file__).relative_to(PROJECT)): sha(Path(__file__))}
    results = []
    for entry in summary["runs"]:
        run = BASE / "runs" / entry["run"]
        detail_path = args.analysis / (run.name + "-study-audit.json")
        detail = read(detail_path)
        identities_path = run / "process-identities.jsonl"
        inputs[str(detail_path.relative_to(PROJECT))] = sha(detail_path)
        identities = []
        if identities_path.exists():
            inputs[str(identities_path.relative_to(PROJECT))] = sha(identities_path)
            for number, line in enumerate(identities_path.read_text().splitlines(), 1):
                if line.strip():
                    identities.append({**json.loads(line), "raw_identity_line": number})
        by_identity = {}
        for row in identities:
            by_identity.setdefault((row["pid"], str(row["start_ticks"])), []).append(row)
        sessions = []
        for session in detail["sessions"]:
            if "observation_row" not in session:
                continue
            sid = session["session"]
            container_path = run / "sessions" / sid / "container.json"
            container = read(container_path) if container_path.exists() else {}
            if container_path.exists():
                inputs[str(container_path.relative_to(PROJECT))] = sha(container_path)
            init = session.get("domain_init") or {}
            snapshots = []
            for ticks in init.get("sample_start_ticks", []):
                snapshots.extend(by_identity.get((init["pid"], str(ticks)), []))
            target = session.get("business_cgroup")
            snapshots = [row for row in snapshots if any(
                part.split(":", 2)[-1] == target for part in row.get("cgroup", "").splitlines())]
            fingerprints = {kind: sorted({row.get("namespaces", {}).get(kind)
                            for row in snapshots if row.get("namespaces", {}).get(kind)})
                            for kind in KINDS}
            security = []
            for row in snapshots:
                fields = status_fields(row.get("status", ""))
                security.append({"line": row["raw_identity_line"], "t_ns": row["t_ns"],
                                 "pid": row["pid"], "start_ticks": str(row["start_ticks"]),
                                 "cgroup": row.get("cgroup"), "namespaces": row.get("namespaces"),
                                 **{name: fields.get(name, "").strip() for name in
                                    ["NSpid", "Uid", "Gid", "CapEff", "CapPrm", "CapBnd", "NoNewPrivs", "Seccomp"]}})
            processes = {p["key"]: p for action in session["actions"] for p in action["processes"]}
            sampled = []
            missing = []
            for key, proc in processes.items():
                hits = [row for ticks in proc.get("sample_start_ticks", [])
                        for row in by_identity.get((proc["pid"], str(ticks)), [])]
                (sampled if hits else missing).append(key)
            host = container.get("HostConfig", {})
            sessions.append({"session": sid, "task_id": session.get("task_id"),
                             "container_id": container.get("Id"), "init": init,
                             "business_cgroup": target, "namespace_fingerprints": fingerprints,
                             "init_identity_snapshots": security,
                             "inspect_config": {name: host.get(name) for name in
                                ["NetworkMode", "UsernsMode", "PidMode", "IpcMode", "CgroupnsMode", "Init", "Privileged", "Memory", "NanoCpus", "PidsLimit"]},
                             "confirmed_business_process_count": len(processes),
                             "first_seen_identity_sample_count": len(sampled),
                             "first_seen_identity_sample_fraction": len(sampled) / len(processes) if processes else None,
                             "business_process_keys_without_identity_sample": missing})
        pairs = []
        for left, right in itertools.combinations(sessions, 2):
            li, ri = left["init"], right["init"]
            left_end = min(li.get("exit_ns", []), default=None)
            right_end = min(ri.get("exit_ns", []), default=None)
            if None in [li.get("birth_ns"), ri.get("birth_ns"), left_end, right_end]:
                overlap = None
            else:
                overlap = max(0, min(left_end, right_end) - max(li["birth_ns"], ri["birth_ns"]))
            if overlap is None or overlap > 0:
                comparisons = {}
                for kind in KINDS:
                    a = left["namespace_fingerprints"][kind]
                    b = right["namespace_fingerprints"][kind]
                    comparisons[kind] = ("SAME" if a == b else "DISTINCT") if len(a) == len(b) == 1 else "UNKNOWN"
                pairs.append({"left": left["session"], "right": right["session"],
                              "init_lifetime_overlap_ns": overlap, "namespaces": comparisons})
        results.append({"run": run.name, "sessions": sessions,
                        "overlapping_or_unknown_init_lifetime_pairs": pairs,
                        "distinct_container_ids": len({s["container_id"] for s in sessions if s["container_id"]}),
                        "initial_userns_scope": "Docker may share the guest initial user namespace. This neither proves nor refutes separate PID/mount/network domains; inspect actual namespace snapshots."})
    output = {"schema": "shimos.next.namespace-coverage.v1", "runs": results,
              "limits": ["Uses actual first-seen PID+startticks and cgroup-bound samples; missing snapshots remain UNKNOWN.",
                         "Namespace inode numbers are scoped to each guest; values can be recycled after all references close.",
                         "Only overlapping init lifetimes are compared for simultaneous namespace identity, with missing lifetimes marked UNKNOWN.",
                         "Different namespace references do not independently prove complete filesystem access policy or cleanup of every kernel reference.",
                         "No process-memory state, heap reuse admission or new security qualification is inferred."]}
    (args.out / "namespace-coverage.json").write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")
    (args.out / "input-sha256.json").write_text(json.dumps(inputs, indent=2) + "\n")
    print(json.dumps({"runs": len(results), "sessions": sum(len(r["sessions"]) for r in results)}))


if __name__ == "__main__":
    main()
