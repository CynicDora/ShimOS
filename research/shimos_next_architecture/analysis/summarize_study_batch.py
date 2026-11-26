#!/usr/bin/env python3
"""Summarize a completed offline process audit and original score receipts."""
import argparse
import collections
import csv
import hashlib
import json
import re
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
PROJECT = BASE.parents[1]


def load(p):
    return json.loads(p.read_text())


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--analysis", type=Path, required=True)
    p.add_argument("--namespaces", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    summary = load(args.analysis / "study-process-summary.json")
    ns = load(args.namespaces / "namespace-coverage.json")
    identities = {(r["run"], s["session"]): s for r in ns["runs"] for s in r["sessions"]}
    inputs = {str(Path(__file__).relative_to(PROJECT)): sha(Path(__file__))}
    result = []
    for rs in summary["runs"]:
        run = BASE / "runs" / rs["run"]
        detail = load(args.analysis / (run.name + "-study-audit.json"))
        raw = (run / "natural-trace/process.trace").read_text().splitlines()
        batch = load(run / "batch-result.json")
        ledger = {r["session_id"]: r for r in batch["sessions"] if r.get("session_id")}
        executable = collections.Counter()
        tasks = []
        runtime_waits = []
        for s in detail["sessions"]:
            if "observation_row" not in s:
                continue
            row = s["observation_row"]
            sd = run / "sessions" / s["session"]
            score_path = sd / "validation/result.json"
            score = load(score_path) if score_path.exists() else {}
            inputs[str(score_path.relative_to(PROJECT))] = sha(score_path) if score_path.exists() else None
            process = {x["key"]: x for a in s["actions"] for x in a["processes"]}
            paths = collections.Counter(e["path"] for x in process.values() for e in x["execs"])
            executable.update(paths)
            labels = [z for group in score.get("required_labels", {}).values()
                      for z in group.get("labels", [])]
            n = identities[(run.name, s["session"])]
            tasks.append({**row, "historical_targeted_outcome": ledger[s["session"]].get("known_historical_targeted_result"),
                          "exec_events": sum(paths.values()), "actual_executable_events": dict(paths),
                          "processes_with_no_exec": sum(not x["execs"] for x in process.values()),
                          "first_seen_identity_samples": n["first_seen_identity_sample_count"],
                          "score_receipt": str(score_path.relative_to(PROJECT)),
                          "score_resource_released": score.get("resource_released"),
                          "pytest_collected": score.get("collected"), "pytest_returncode": score.get("pytest_returncode"),
                          "scoring_exception": score.get("exception"), "scoring_blockers": score.get("blockers"),
                          "required_labels_unresolved": [z["official_label"] for z in labels if not z["matching_nodeids"]],
                          "required_labels_matched_but_not_passed": [z["official_label"] for z in labels if z["matching_nodeids"] and not z["passed"]]})
            for role in ["domain_init", "monitor"]:
                entity = s.get(role) or {}
                for wait in entity.get("wait4_evidence", []):
                    source = raw[wait["exit_line"] - 1]
                    match = re.search(r"sys_wait4 -> (\S+)", source)
                    valid = bool(match and int(match[1], 0) == wait["return_value"] > 0
                                 and re.search(r"-" + str(wait["caller_tid"]) + r"\s", source)
                                 and wait["bound_child"] == entity["key"]
                                 and any(t <= wait["exit_ns"] for t in entity["exit_ns"]))
                    runtime_waits.append({"session": s["session"], "role": role,
                                          "entity": entity, "wait": wait, "raw_line": source,
                                          "raw_positive_wait_consistent": valid})
        result.append({"run": run.name, "all_registered_tasks": batch["denominator"],
                       "actual_sessions": len(tasks), "task_rows": tasks,
                       "actual_executable_events": dict(executable.most_common()),
                       "exec_event_count": sum(executable.values()),
                       "business_process_count": sum(t["K_proc_confirmed"] for t in tasks),
                       "business_wait_count": sum(t["K_proc_wait4_confirmed"] for t in tasks),
                       "python_process_count": sum(t["python_processes_exec_observed"] for t in tasks),
                       "action_count": sum(t["K_tool_logged"] for t in tasks),
                       "first_seen_identity_samples": sum(t["first_seen_identity_samples"] for t in tasks),
                       "task_score_counts": dict(collections.Counter(t["score"] for t in tasks)),
                       "runtime_waits": runtime_waits,
                       "all_claimed_runtime_waits_raw_consistent": all(w["raw_positive_wait_consistent"] for w in runtime_waits),
                       "trace": detail["trace"]})
        inputs[str((run / "batch-result.json").relative_to(PROJECT))] = sha(run / "batch-result.json")
    for folder, name in [(args.analysis, "study-process-summary.json"),
                         (args.namespaces, "namespace-coverage.json")]:
        path = (folder / name).resolve()
        inputs[str(path.relative_to(PROJECT))] = sha(path)
    output = {"scope": "Offline evidence summary; task score, execution release and fault qualification are separate.",
              "runs": result, "limits": ["Executable counts use actual sched_process_exec filename, not command-text process guesses.",
                  "Exec events and process birth identities differ: shell may exec another binary without a new PID.",
                  "exec argv pointers were not decoded; subcommand meaning remains source/trajectory evidence.",
                  "Each task is frozen real-decision replay, not a new online Agent run; K_heap/K_template unknown.",
                  "Matched-but-not-passed required labels and unresolved labels are separate; scoring errors do not imply executor failure."]}
    (args.out / "batch-evidence-summary.json").write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")
    (args.out / "input-sha256.json").write_text(json.dumps(inputs, indent=2) + "\n")
    fields = ["run", "task_id", "session", "K_tool_logged", "K_proc_confirmed", "K_proc_wait4_confirmed",
              "python_processes_exec_observed", "exec_events", "first_seen_identity_samples",
              "controller_status", "product_release_receipt", "observer_assistance", "score", "historical_targeted_outcome"]
    with (args.out / "task-counts.csv").open("w") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows({k: t.get(k) for k in fields} for r in result for t in r["task_rows"])
    print(json.dumps({"runs": len(result), "tasks": sum(len(r["task_rows"]) for r in result),
                      "runtime_wait_checks": sum(len(r["runtime_waits"]) for r in result)}))


if __name__ == "__main__":
    main()
