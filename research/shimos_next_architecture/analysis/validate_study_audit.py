#!/usr/bin/env python3
"""Read-only independent raw-line checks for study observation artifacts.

Missing waits, failed tasks and observer assistance are coverage/result facts,
not validator errors. This program checks evidence claims, not qualification.
It never starts, signals, waits for, or cleans a workload process.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
PROJECT = BASE.parents[1]


def load(path):
    return json.loads(path.read_text())


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--analysis", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    analysis = Path(args.analysis)
    out = Path(args.out)
    if out.exists():
        raise SystemExit("Refusing to replace validation: " + str(out))
    errors = []
    gaps = []
    counts = dict(input_files=0, frozen_source_files=0, runs=0, sessions=0,
                  actions=0, unique_business_processes=0, positive_waits=0,
                  action_exec_lines=0, unknown_tasks=0)
    for path, expected in load(analysis / "input-sha256.json").items():
        source = PROJECT / path
        if not source.exists() or sha(source) != expected:
            errors.append({"kind": "input_hash", "path": path})
        counts["input_files"] += 1
    summary = load(analysis / "study-process-summary.json")
    for run_summary in summary["runs"]:
        name = run_summary["run"]
        run = BASE / "runs" / name
        detail = load(analysis / (name + "-study-audit.json"))
        counts["runs"] += 1
        source_manifest = run / "source-sha.json"
        if source_manifest.exists():
            for path, expected in load(source_manifest).items():
                source = run / path
                if not source.exists() or sha(source) != expected:
                    errors.append({"kind": "frozen_source_hash", "run": name, "path": path})
                counts["frozen_source_files"] += 1
        if detail["trace"].get("status") == "MISSING":
            gaps.append({"run": name, "kind": "missing_trace"})
            continue
        raw = (run / "natural-trace" / "process.trace").read_text().splitlines()
        if not detail["trace"]["no_reported_loss"]:
            gaps.append({"run": name, "kind": "reported_trace_loss", "stats": detail["trace"]["stats"]})
        for session in detail["sessions"]:
            if "observation_row" not in session:
                gaps.append({"run": name, "session": session["session"], "kind": "unsupported_session"})
                continue
            row = session["observation_row"]
            counts["sessions"] += 1
            entities = {}
            unknown = {}
            for action in session["actions"]:
                counts["actions"] += 1
                if action["root_count"] != 1:
                    gaps.append({"run": name, "session": session["session"],
                                 "action_id": action["action_id"], "kind": "entry_root_not_unique",
                                 "count": action["root_count"]})
                if action["end_ns"] < action["start_ns"]:
                    errors.append({"kind": "action_time_order", "action_id": action["action_id"]})
                for entity in action["processes"]:
                    entities[entity["key"]] = entity
                    for event in entity["execs"]:
                        source_line = raw[event["line"] - 1]
                        match = re.search(r"sched_process_exec: filename=(.*?) pid=(\d+) old_pid=", source_line)
                        if not match or match[1] != event["path"] or int(match[2]) != entity["pid"]:
                            errors.append({"kind": "exec_raw_line", "run": name,
                                           "key": entity["key"], "line": event["line"]})
                        counts["action_exec_lines"] += 1
                unknown.update({e["key"]: e for e in action["unknown_tasks"]})
            counts["unique_business_processes"] += len(entities)
            counts["unknown_tasks"] += len(unknown)
            expected = {"K_tool_logged": len(session["actions"]),
                        "K_proc_confirmed": len(entities),
                        "K_proc_wait4_confirmed": sum(bool(e["wait4_evidence"]) for e in entities.values()),
                        "unknown_kernel_tasks": len(unknown)}
            for field, value in expected.items():
                if row[field] != value:
                    errors.append({"kind": "summary_count", "session": session["session"],
                                   "field": field, "expected": value, "actual": row[field]})
            for entity in entities.values():
                if not entity["wait4_evidence"]:
                    gaps.append({"run": name, "session": session["session"],
                                 "key": entity["key"], "kind": "no_bound_positive_wait"})
                for wait in entity["wait4_evidence"]:
                    source_line = raw[wait["exit_line"] - 1]
                    match = re.search(r"sys_wait4 -> (\S+)", source_line)
                    good = (match and int(match[1], 0) == wait["return_value"] > 0
                            and re.search(r"-" + str(wait["caller_tid"]) + r"\s", source_line)
                            and wait["bound_child"] == entity["key"]
                            and any(t <= wait["exit_ns"] for t in entity["exit_ns"]))
                    if not good:
                        errors.append({"kind": "positive_wait_raw_line", "run": name,
                                       "key": entity["key"], "line": wait["exit_line"]})
                    counts["positive_waits"] += 1
            if row["controller_status"] != "COMPLETED" or not row["product_release_receipt"] or row["observer_assistance"]:
                gaps.append({"run": name, "session": session["session"], "kind": "non_normal_receipt",
                             "status": row["controller_status"], "product_release": row["product_release_receipt"],
                             "observer_assistance": row["observer_assistance"]})
    result = {"status": "AUDIT_CONSISTENT" if not errors else "AUDIT_ERROR",
              "scope": "Offline evidence consistency only; gaps are preserved, not promoted to qualification.",
              "counts": counts, "errors": errors, "coverage_and_result_gaps": gaps,
              "validator_sha256": sha(Path(__file__)),
              "limitations": ["Checks claimed raw wait/exec events and content identities; it is not an independent kernel tracer.",
                              "Same-namespace and parent binding rules remain the explicitly recorded analyzer evidence model.",
                              "No wait claim is synthesized for a missing or ambiguous child; output EOF is a separate API receipt."]}
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "counts": counts,
                      "errors": len(errors), "preserved_gaps": len(gaps)}))


if __name__ == "__main__":
    main()
