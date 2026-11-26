#!/usr/bin/env python3
"""Aggregate existing independent audits and completed replay evidence only."""
import argparse
import collections
import csv
import difflib
import hashlib
import json
from pathlib import Path
import re
import statistics

BASE = Path(__file__).resolve().parents[1]
PROJECT = BASE.parents[1]
SOURCES = [
    ("study-process-b0-c1-01", "study-namespaces-b0-c1-01"),
    ("study-process-b0-c2-01", "study-namespaces-b0-c2-01"),
    ("study-process-final-01", "study-namespaces-final-01"),
]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    inputs = {}

    def read(path):
        raw = path.read_bytes()
        inputs[str(path.relative_to(PROJECT))] = hashlib.sha256(raw).hexdigest()
        return json.loads(raw)

    inputs[str(Path(__file__).relative_to(PROJECT))] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    runs, all_tasks, runtime_checks, validation_index = [], [], [], []
    for proc_name, ns_name in SOURCES:
        proc = BASE / "analysis" / proc_name
        ns = read(BASE / "analysis" / ns_name / "namespace-coverage.json")
        by_run = {r["run"]: r for r in ns["runs"]}
        summary = read(proc / "study-process-summary.json")
        validation_path = proc / "independent-raw-validation.json"
        validation_index.append({"path": str(validation_path.relative_to(PROJECT)), "result": read(validation_path)})
        for metadata in summary["runs"]:
            name = metadata["run"]
            root = BASE / "runs" / name
            detail = read(proc / (name + "-study-audit.json"))
            raw_path = root / "natural-trace/process.trace"
            raw_bytes = raw_path.read_bytes()
            inputs[str(raw_path.relative_to(PROJECT))] = hashlib.sha256(raw_bytes).hexdigest()
            raw = raw_bytes.decode().splitlines()
            batch = read(root / "batch-result.json") if (root / "batch-result.json").exists() else None
            ledger = {e.get("session_id"): e for e in (batch or {}).get("sessions", [])}
            identities = {s["session"]: s for s in by_run[name]["sessions"]}
            tasks, executables = [], collections.Counter()
            release_counts = collections.Counter()
            for session in detail["sessions"]:
                if "observation_row" not in session:
                    continue
                row = session["observation_row"]
                sid = session["session"]
                processes = {p["key"]: p for action in session["actions"] for p in action["processes"]}
                paths = collections.Counter(e["path"] for process in processes.values() for e in process["execs"])
                executables.update(paths)
                score_path = root / "sessions" / sid / "validation/result.json"
                score = read(score_path) if score_path.exists() else {}
                release = session["release_evidence"]
                clean = release.get("cleanup") or {}
                cw = session.get("controller_wait") or {}
                control = release.get("control_leaf_at_controller_wait") or {}
                flags = {"container_absent": clean.get("container_absent") is True,
                         "business_cgroup_empty_or_removed": clean.get("cgroup_empty_or_removed") is True,
                         "controller_wait_receipt": cw.get("real_wait_controller") is True,
                         "controller_fd_inventory_restored": release.get("controller_fd_inventory_restored") is True,
                         "workspace_removed": release.get("workspace_removed") is True,
                         "controller_home_removed": release.get("controller_home_removed") is True,
                         "control_leaf_unpopulated_at_parent_wait": control.get("pids.current") == "0"
                            and "populated 0" in control.get("cgroup.events", "")}
                release_counts.update(key for key, value in flags.items() if value)
                nsrow = identities[sid]
                item = row | {"exec_events": sum(paths.values()), "actual_executable_events": dict(paths),
                    "first_seen_identity_samples": nsrow["first_seen_identity_sample_count"],
                    "historical_score": ledger.get(sid, {}).get("known_historical_targeted_result"),
                    "score_resource_released": score.get("resource_released"), "release_receipt_checks": flags,
                    "score_evidence": str(score_path.relative_to(PROJECT)),
                    "scope": "normal fixed-decision replay; fault qualification remains incomplete"}
                tasks.append(item)
                all_tasks.append(item)
                for role in ["domain_init", "monitor"]:
                    entity = session.get(role) or {}
                    evidences = entity.get("wait4_evidence", [])
                    if not evidences:
                        runtime_checks.append({"run": name, "session": sid, "role": role,
                                               "status": "UNKNOWN_NO_BOUND_WAIT", "entity": entity})
                    for wait in evidences:
                        line = raw[wait["exit_line"] - 1]
                        match = re.search(r"sys_wait4 -> (\S+)", line)
                        valid = bool(match and int(match[1], 0) == wait["return_value"] > 0
                                     and re.search(r"-" + str(wait["caller_tid"]) + r"\s", line)
                                     and wait["bound_child"] == entity["key"]
                                     and any(t <= wait["exit_ns"] for t in entity["exit_ns"]))
                        runtime_checks.append({"run": name, "session": sid, "role": role,
                                               "status": "RAW_WAIT_CONSISTENT" if valid else "AUDIT_MISMATCH",
                                               "entity_key": entity["key"], "wait": wait, "raw_line": line})
            runs.append({"run": name, "kind": metadata["config"].get("kind"),
                "source_audit": str((proc / (name + "-study-audit.json")).relative_to(PROJECT)),
                "namespace_audit": str((BASE / "analysis" / ns_name / "namespace-coverage.json").relative_to(PROJECT)),
                "sessions": len(tasks), "tasks": tasks,
                "actions": sum(t["K_tool_logged"] for t in tasks),
                "business_processes": sum(t["K_proc_confirmed"] for t in tasks),
                "business_positive_waits": sum(t["K_proc_wait4_confirmed"] for t in tasks),
                "python_exec_processes": sum(t["python_processes_exec_observed"] for t in tasks),
                "exec_events": sum(executables.values()), "actual_executable_events": dict(executables.most_common()),
                "unknown_kernel_tasks": sum(t["unknown_kernel_tasks"] for t in tasks),
                "identity_sample_processes": sum(t["first_seen_identity_samples"] for t in tasks),
                "release_receipt_counts": dict(release_counts),
                "score_counts": dict(collections.Counter(t["score"] for t in tasks)),
                "trace": detail["trace"], "namespace": by_run[name],
                "batch_denominator": (batch or {}).get("denominator"),
                "scope": "B0_INIT observations; not strict B0/B1 comparison or online Agent"})
    replay = read(BASE / "analysis/replay-comparison-01/replay-comparison.json")
    worktrees = read(BASE / "analysis/worktree-comparison-01/worktree-comparison.json")
    comparison = [c for t in replay["tasks"] for c in t["comparisons"] if c["run"] != t["reference_run"]]
    work = [s for t in worktrees["tasks"] for s in t["samples"]]
    diffs = []
    for task in replay["tasks"]:
        by_name = {s["run"]: s for s in task["samples"]}
        reference_path = PROJECT / by_name[task["reference_run"]]["actions_path"]
        left = [json.loads(line) for line in reference_path.read_text().splitlines() if line.strip()]
        for current in task["comparisons"]:
            if current["run"] == task["reference_run"]:
                continue
            sample_path = PROJECT / by_name[current["run"]]["actions_path"]
            right = [json.loads(line) for line in sample_path.read_text().splitlines() if line.strip()]
            for difference in current["differences"]:
                index = difference["index"] - 1
                if index >= min(len(left), len(right)):
                    diffs.append({"task_id": task["task_id"], "run": current["run"], **difference})
                    continue
                diff = list(difflib.unified_diff(left[index].get("output", "").splitlines(),
                     right[index].get("output", "").splitlines(), fromfile=str(reference_path.relative_to(PROJECT)),
                     tofile=str(sample_path.relative_to(PROJECT)), n=2))
                diffs.append({"task_id": task["task_id"], "run": current["run"], "action_index": index + 1,
                    "command": left[index].get("command"), "normalization": "NONE", "unified_output_diff": diff,
                    "reference_action_path": str(reference_path.relative_to(PROJECT)),
                    "sample_action_path": str(sample_path.relative_to(PROJECT))})
    batch_runs = [r for r in runs if r["batch_denominator"] is not None]
    pyc_runs = [r for r in runs if r["kind"] == "pyc_counterfactual"]
    def totals(group):
        return {key: sum(r[key] for r in group) for key in ["sessions", "actions", "business_processes",
            "business_positive_waits", "python_exec_processes", "exec_events", "unknown_kernel_tasks", "identity_sample_processes"]}
    overview = {"schema": "shimos.next.final-execution-audit.v1", "status": "OBSERVATION_NOT_FULL_QUALIFICATION",
        "runs": runs, "batch_totals": totals(batch_runs), "pyc_totals": totals(pyc_runs),
        "runtime_wait_check_counts": dict(collections.Counter(x["status"] for x in runtime_checks)),
        "independent_validation": validation_index,
        "replay": {"cross_run_session_comparisons": len(comparison),
            "action_comparisons": sum(c["sample_actions"] for c in comparison),
            "equal_commands": sum(c["command_equal_count"] for c in comparison),
            "equal_result_structures": sum(c["result_structure_equal_count"] for c in comparison),
            "equal_decoded_outputs": sum(c["decoded_output_exact_equal_count"] for c in comparison),
            "equal_submissions": sum(c["submission_exact_equal"] for c in comparison),
            "equal_targeted_scores": sum(c["score_equal"] for c in comparison),
            "source_content_equal_sessions": sum(s["source_content_equal_reference"] is True for s in work),
            "additional_code_equal_sessions": sum(s["added_code_content_equal_reference"] is True for s in work),
            "validation_candidate_unchanged": sum(s["validation"]["candidate_bytes_unchanged"] is True for s in work),
            "validation_candidate_unknown": sum(s["validation"]["candidate_bytes_unchanged"] is None for s in work),
            "validation_unknown_tasks": sorted({t["task_id"] for t in worktrees["tasks"] if any(s["validation"]["candidate_bytes_unchanged"] is None for s in t["samples"])})},
        "limits": ["Same physical host, 2 batch blocks, frozen real-decision replay; not online Agent/general workload distribution.",
            "Positive waits bind observed PID birth identities, not merely process disappearance; unsampled metadata and untraced kernel-reference release remain outside coverage.",
            "Docker action EOF is completed subprocess.communicate plus returned API output, not independent per-FD kernel EOF decoding.",
            "Controller FD restoration and cgroup/workspace receipts are checked; there is no exhaustive FD/mount reference inventory for every short-lived process.",
            "Shared Docker initial userns differs from B-strict security; independent PID/mount namespaces do not imply equal security policies.",
            "All scoring failures and missing manifests retained. No final score is inferred from executor release.",
            "K_heap and K_template remain UNKNOWN; ordinary Python exec and pyc caching do not inherit a warm Python heap.",
            "Recorded prior offline-analysis/VM overlap is retained in offline-analysis-overlap-note.json; nice priority is not zero disturbance."]}
    def save(name, obj):
        (args.out / name).write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")
    save("final-execution-audit.json", overview)
    save("runtime-positive-waits.json", runtime_checks)
    save("exact-output-differences.json", diffs)
    save("input-sha256.json", inputs)
    fields = ["run", "session", "task_id", "cohort", "K_tool_logged", "K_proc_confirmed", "K_proc_wait4_confirmed",
              "python_processes_exec_observed", "exec_events", "first_seen_identity_samples", "score", "historical_score"]
    with (args.out / "task-process-counts.csv").open("w") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows({k: r.get(k) for k in fields} for r in all_tasks)
    print(json.dumps({"batch_totals": overview["batch_totals"], "pyc_totals": overview["pyc_totals"],
                      "runtime_wait_checks": overview["runtime_wait_check_counts"], "replay": overview["replay"]}))


if __name__ == "__main__":
    main()
