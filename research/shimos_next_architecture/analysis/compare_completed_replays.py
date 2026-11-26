#!/usr/bin/env python3
"""Compare completed frozen-action batches without replaying any workload.

Raw decoded API output is compared exactly, never silently stripped of timing
or random fields. Differing outputs stay referenced by action/path and hash.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
PROJECT = BASE.parents[1]


def read(path, default=None):
    return json.loads(path.read_text()) if path.exists() else default


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="append", required=True)
    parser.add_argument("--expected-runs", type=int, default=6)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if len(set(args.run)) != args.expected_runs:
        raise SystemExit("Require all expected distinct completed runs; no hidden partial comparison")
    inputs = {str(Path(__file__).relative_to(PROJECT)): hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}

    def source(path):
        if path.exists():
            inputs[str(path.relative_to(PROJECT))] = hashlib.sha256(path.read_bytes()).hexdigest()

    by_task = collections.defaultdict(dict)
    runs = []
    fields = ["returncode", "returncode_posix", "wait_status", "exception_type", "timed_out", "cancelled"]
    for name in args.run:
        run = (BASE / "runs" / name).resolve() if not Path(name).is_dir() else Path(name).resolve()
        if not (run / "result.json").exists():
            raise SystemExit("Not completed: " + str(run))
        batch = read(run / "batch-result.json")
        if not batch:
            raise SystemExit("Not a registered batch: " + str(run))
        source(run / "result.json")
        source(run / "batch-result.json")
        runs.append(run.name)
        for entry in batch["sessions"]:
            sid = entry.get("session_id")
            sd = run / "sessions" / str(sid)
            sr = read(sd / "session-result.json", {})
            score = read(sd / "validation/result.json", {})
            path = sd / "actions.jsonl"
            actions = [json.loads(s) for s in path.read_text().splitlines() if s.strip()] if path.exists() else []
            for p in [path, sd / "session-result.json", sd / "validation/result.json", sd / "config.json"]:
                source(p)
            by_task[entry["task_id"]][run.name] = {
                "run": run.name, "session": sid, "actions_path": str(path.relative_to(PROJECT)),
                "final_receipt_present": bool(sr), "executor_status": entry["status"],
                "product_released": entry.get("product_released"), "agent_status": sr.get("agent_status"),
                "score": score.get("outcome", "BLOCKED"), "actions": actions,
                "submission_present": "submission" in sr, "submission": sr.get("submission"),
                "final_tree_digest": digest(sr["final_tree"]) if "final_tree" in sr else None}
    args.out.mkdir(parents=True, exist_ok=False)
    output = []
    for task, samples in sorted(by_task.items()):
        first_run = min(samples)
        reference = samples[first_run]
        row = {"task_id": task, "reference_run": first_run,
               "expected_runs": sorted(runs), "present_runs": sorted(samples),
               "all_runs_present": set(samples) == set(runs), "comparisons": [], "samples": []}
        for name, current in sorted(samples.items()):
            row["samples"].append({k: v for k, v in current.items() if k not in {"actions", "submission"}} | {
                "action_count": len(current["actions"]), "submission_sha256": digest(current["submission"])})
            a, b = reference["actions"], current["actions"]
            differences = []
            command_equal = result_equal = output_equal = 0
            for index in range(max(len(a), len(b))):
                left = a[index] if index < len(a) else None
                right = b[index] if index < len(b) else None
                if left is None or right is None:
                    differences.append({"index": index + 1, "kind": "MISSING_ACTION", "reference_present": left is not None,
                                        "sample_present": right is not None})
                    continue
                commands = left.get("command") == right.get("command")
                normal = all((key in left, left.get(key)) == (key in right, right.get(key)) for key in fields)
                normal &= bool(left.get("error")) == bool(right.get("error"))
                normal &= digest(left.get("failure_result")) == digest(right.get("failure_result"))
                observed_output = ("output" in left and "output" in right)
                same_output = observed_output and left["output"] == right["output"]
                command_equal += int(commands)
                result_equal += int(normal)
                output_equal += int(same_output)
                if not (commands and normal and same_output):
                    differences.append({"index": index + 1, "reference_action_id": left.get("action_id"),
                        "sample_action_id": right.get("action_id"), "command_equal": commands,
                        "result_structure_equal": normal, "output_present_both": observed_output,
                        "decoded_output_exact_equal": same_output,
                        "reference_output_sha256": digest(left.get("output")),
                        "sample_output_sha256": digest(right.get("output")),
                        "normalization": "NONE; timing/random/listing differences remain differences",
                        "reference_result": {k: left[k] for k in fields if k in left},
                        "sample_result": {k: right[k] for k in fields if k in right}})
            size = max(len(a), len(b))
            row["comparisons"].append({"run": name, "reference_actions": len(a), "sample_actions": len(b),
                "command_equal_count": command_equal, "result_structure_equal_count": result_equal,
                "decoded_output_exact_equal_count": output_equal,
                "all_commands_equal": bool(size) and command_equal == size,
                "all_results_equal": bool(size) and result_equal == size,
                "submission_exact_equal": reference["submission_present"] and current["submission_present"]
                    and reference["submission"] == current["submission"],
                "score_equal": reference["score"] == current["score"], "differences": differences})
        output.append(row)
    result = {"schema": "shimos.next.completed-replay-comparison.v1", "runs": sorted(runs), "tasks": output,
              "limits": ["Only fixed natural action replays; no online model quality or randomized Agent equivalence claim.",
                         "Submission is the Agent final-output patch text; it is not independently reconstructed from the workspace archive.",
                         "Final tree digests include generated files and therefore may differ even when submitted patch text is identical.",
                         "Output is decoded API string, not arbitrary byte-exact stdout/stderr. No timing or random value normalization.",
                         "Same command/returncode/patch does not upgrade the underlying incomplete fault/security qualification."]}
    (args.out / "replay-comparison.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    (args.out / "input-sha256.json").write_text(json.dumps(inputs, indent=2) + "\n")
    print(json.dumps({"runs": len(runs), "tasks": len(output)}))


if __name__ == "__main__":
    main()
