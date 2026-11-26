#!/usr/bin/env python3
"""Offline byte-content audit of completed replay worktrees.

Reads trusted final_tree/candidate manifests and original tar member bytes.
Never extracts a repository, runs git, imports workload code, or runs hooks.
Run only after every requested VM has a final result.json.
"""
import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile

BASE = Path(__file__).resolve().parents[1]
PROJECT = BASE.parents[1]
SOURCE_DIRS = [PROJECT / "research/real_agent_workload/sources/task_repositories",
               PROJECT / "research/shimos_worker_pool/real_agent_workload/02_process_tracing/sources/task-repositories"]
CODE_SUFFIXES = {".py", ".pyi", ".pyx", ".pxd", ".c", ".h", ".cc", ".cpp", ".hpp", ".rs", ".go",
                 ".java", ".js", ".jsx", ".ts", ".tsx", ".sh", ".bash", ".r", ".jl", ".ipynb"}


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def file_sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def safe_path(value):
    p = PurePosixPath(value)
    if not value or p.is_absolute() or ".." in p.parts or str(p) != value:
        raise ValueError("Noncanonical manifest path: " + repr(value))
    return value


def put_unique(result, path, value):
    safe_path(path)
    if path in result:
        raise ValueError("Duplicate manifest path: " + path)
    result[path] = value


def normalize_tree(rows):
    """Return content identity only; final_tree contains no mode evidence."""
    result = {}
    if not isinstance(rows, list):
        raise ValueError("Manifest must be a list")
    for row in rows:
        if isinstance(row, dict):
            path = row["path"]
            value = {"kind": "symlink", "target": row["symlink_target"]} if "symlink_target" in row else {
                "kind": "file", "bytes": row["bytes"], "sha256": row["sha256"]}
        elif len(row) == 3:
            path = row[0]
            value = {"kind": "symlink", "target": row[2]} if row[1] == "symlink" else {
                "kind": "file", "bytes": row[1], "sha256": row[2]}
        else:
            raise ValueError("Unsupported manifest row")
        put_unique(result, path, value)
    return result


def archive_tree(path):
    """Match guest_setup's single top-directory stripping, no extraction."""
    result, roots = {}, set()
    with tarfile.open(path, "r:*") as tf:
        for member in tf:
            parts = PurePosixPath(member.name).parts
            if not parts or PurePosixPath(member.name).is_absolute() or ".." in parts:
                raise ValueError("Unsafe source tar path")
            roots.add(parts[0])
            if len(parts) == 1:
                continue
            rel = str(PurePosixPath(*parts[1:]))
            if member.isdir():
                continue
            # These fixtures reject links and special entries when preparing the VM.
            if not member.isfile():
                raise ValueError("Source entry outside frozen fixture contract: " + member.name)
            source = tf.extractfile(member)
            h, count = hashlib.sha256(), 0
            for block in iter(lambda: source.read(1024 * 1024), b""):
                h.update(block)
                count += len(block)
            if count != member.size:
                raise ValueError("Short archive member")
            put_unique(result, rel, {"kind": "file", "bytes": count, "sha256": h.hexdigest()})
    if len(roots) != 1:
        raise ValueError("Expected one original source archive root")
    return result


def category(path, source_paths, task):
    parts = PurePosixPath(path).parts
    if ".git" in parts:
        return "git_metadata"
    if path in source_paths:
        return "frozen_source_path"
    if "__pycache__" in parts or PurePosixPath(path).suffix.lower() in {".pyc", ".pyo"}:
        return "python_bytecode"
    if task.startswith("pytest-dev__pytest-") and path == "src/_pytest/_version.py":
        return "fixture_generated_version_code"
    if any(p in {".pytest_cache", ".mypy_cache", ".ruff_cache", ".cache"} or p.endswith(".egg-info")
           or p.startswith("pytest-of-") for p in parts):
        return "runtime_or_build_cache"
    if PurePosixPath(path).suffix.lower() in CODE_SUFFIXES or PurePosixPath(path).name in {
            "Makefile", "CMakeLists.txt", "Dockerfile", "meson.build"}:
        return "additional_code_candidate"
    return "additional_other_file"


def changes(left, right, source_paths, task, selected=None):
    result = []
    for path in sorted(set(left) | set(right)):
        if selected is not None and path not in selected:
            continue
        if left.get(path) != right.get(path):
            result.append({"path": path, "category": category(path, source_paths, task),
                           "change": "ADDED" if path not in left else "MISSING" if path not in right else "CONTENT_CHANGED",
                           "before": left.get(path), "after": right.get(path)})
    return result


def counts(rows):
    return dict(sorted(collections.Counter(row["category"] for row in rows).items()))


def validation_audit(final, before_rows, after_rows, source_paths, task):
    if before_rows is None or after_rows is None:
        return {"status": "UNKNOWN_MISSING_VALIDATION_MANIFEST", "candidate_bytes_unchanged": None,
                "frozen_source_bytes_unchanged": None, "all_recorded_metadata_unchanged": None,
                "receipt_matches_before_excluding_git": None}
    before, after = normalize_tree(before_rows), normalize_tree(after_rows)
    diff = changes(before, after, source_paths, task)
    no_git = lambda mapping: {p: v for p, v in mapping.items() if ".git" not in PurePosixPath(p).parts}
    content = [x for x in diff if x["category"] != "git_metadata"]
    source_changes = [x for x in diff if x["category"] == "frozen_source_path"]
    left_mode = {x["path"]: x.get("mode") for x in before_rows}
    right_mode = {x["path"]: x.get("mode") for x in after_rows}
    mode_changes = [{"path": p, "before_mode": left_mode.get(p), "after_mode": right_mode.get(p),
                     "category": category(p, source_paths, task)} for p in sorted(set(left_mode) | set(right_mode))
                    if left_mode.get(p) != right_mode.get(p)]
    receipt_diff = changes(final, no_git(before), source_paths, task) if final is not None else None
    return {"status": "RECORDED_MANIFESTS_COMPARED", "candidate_bytes_unchanged": not content,
            "frozen_source_bytes_unchanged": not source_changes,
            "all_recorded_metadata_unchanged": not diff and not mode_changes,
            "receipt_matches_before_excluding_git": not receipt_diff if receipt_diff is not None else None,
            "content_changes": diff, "content_change_categories": counts(diff), "mode_changes": mode_changes,
            "receipt_to_validation_before_changes": receipt_diff}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--run", action="append", required=True)
    p.add_argument("--expected-runs", type=int, default=6)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    if len(set(args.run)) != args.expected_runs:
        raise SystemExit("Require every expected distinct completed batch")
    inputs, source_cache, samples, registered = {}, {}, collections.defaultdict(dict), []

    def record(path):
        if path.exists():
            inputs[str(path.relative_to(PROJECT))] = file_sha(path)

    def read(path, default=None):
        if not path.exists():
            return default
        record(path)
        return json.loads(path.read_text())

    record(Path(__file__))
    runs = []
    for name in args.run:
        run = Path(name).resolve() if Path(name).is_dir() else (BASE / "runs" / name).resolve()
        if not (run / "result.json").exists() or not (run / "batch-result.json").exists():
            raise SystemExit("No completed batch receipt: " + str(run))
        runs.append((run, read(run / "batch-result.json")))
        record(run / "result.json")
    if len({r.name for r, _ in runs}) != args.expected_runs:
        raise SystemExit("Duplicate run identities")
    for run, batch in runs:
        for entry in batch["sessions"]:
            task, sid = entry["task_id"], entry.get("session_id")
            if task in samples and run.name in samples[task]:
                raise ValueError("Duplicate task within batch")
            registered.append({"run": run.name, "task_id": task, "session_id": sid, "status": entry["status"]})
            sd = run / "sessions" / str(sid)
            sr = read(sd / "session-result.json", {})
            fixture = read(run / "fixtures" / task / "fixture.json", {})
            score = read(sd / "validation/result.json", {})
            if task not in source_cache:
                archive = next((d / (task + ".tar.gz") for d in SOURCE_DIRS if (d / (task + ".tar.gz")).exists()), None)
                if archive is None:
                    source_cache[task] = (None, None, None)
                else:
                    record(archive)
                    source_cache[task] = (archive_tree(archive), file_sha(archive), str(archive.relative_to(PROJECT)))
            source, sha, archive_path = source_cache[task]
            final = normalize_tree(sr["final_tree"]) if "final_tree" in sr else None
            source_paths = set(source or {})
            source_match = sha is not None and sha == entry.get("source_archive_sha256") == fixture.get("source_archive_sha256")
            before_rows = read(sd / "validation/candidate-before.json")
            after_rows = read(sd / "validation/candidate-after.json")
            difference = changes(source, final, source_paths, task) if source is not None and final is not None else None
            validation = validation_audit(final, before_rows, after_rows, source_paths, task)
            samples[task][run.name] = {
                "run": run.name, "session_id": sid, "executor_status": entry["status"],
                "targeted_outcome": score.get("outcome", "BLOCKED"),
                "final_tree_path": str((sd / "session-result.json").relative_to(PROJECT)),
                "source_archive": archive_path, "source_archive_sha256": sha,
                "source_identity_matches_ledger_and_fixture": source_match,
                "source_path_count": len(source_paths) if source is not None else None,
                "final_tree_present": final is not None, "final_tree_count": len(final) if final is not None else None,
                "final_tree_digest": digest(final) if final is not None else None,
                "changes_from_original_archive": difference,
                "change_categories": counts(difference) if difference is not None else None,
                "validation": validation, "_final": final}
    output, csv_rows = [], []
    for task, observed in sorted(samples.items()):
        reference_run = min(observed)
        reference = observed[reference_run]
        ref = reference["_final"]
        source = source_cache[task][0]
        task_rows = []
        for run, sample in sorted(observed.items()):
            final = sample.pop("_final")
            valid = ref is not None and final is not None and source is not None \
                and reference["source_identity_matches_ledger_and_fixture"] \
                and sample["source_identity_matches_ledger_and_fixture"]
            cross = changes(ref, final, set(source or {}), task) if valid else None
            source_cross = [x for x in cross if x["category"] == "frozen_source_path"] if valid else None
            added_code_cross = [x for x in cross if x["category"] in {"additional_code_candidate", "fixture_generated_version_code"}] if valid else None
            task_rows.append(sample | {"reference_run": reference_run, "cross_run_changes": cross,
                "cross_run_change_categories": counts(cross) if valid else None,
                "source_content_equal_reference": not source_cross if valid else None,
                "added_code_content_equal_reference": not added_code_cross if valid else None})
            csv_rows.append({"run": run, "task_id": task, "session_id": sample["session_id"],
                "source_archive_verified": sample["source_identity_matches_ledger_and_fixture"],
                "final_tree_present": sample["final_tree_present"], "source_paths": sample["source_path_count"],
                "source_changed_vs_reference": len(source_cross) if valid else None,
                "additional_code_changed_vs_reference": len(added_code_cross) if valid else None,
                "validation_source_bytes_unchanged": sample["validation"]["frozen_source_bytes_unchanged"],
                "validation_all_candidate_bytes_unchanged": sample["validation"]["candidate_bytes_unchanged"],
                "validation_metadata_unchanged": sample["validation"]["all_recorded_metadata_unchanged"],
                "receipt_matches_validation_before": sample["validation"]["receipt_matches_before_excluding_git"]})
        output.append({"task_id": task, "reference_run": reference_run,
                       "all_expected_runs_present": set(observed) == {r.name for r, _ in runs}, "samples": task_rows})
    result = {"schema": "shimos.next.completed-worktree-content.v1", "runs": [r.name for r, _ in runs],
        "registered": registered, "tasks": output,
        "limits": [
            "Source baseline is the complete frozen repository tar member set, verified against ledger and fixture SHA; no host git/index reconstruction.",
            "Content identities come from trusted Controller final_tree and validation manifests, compared to independently hashed original tar bytes; final tar is not rehashed by this analyzer.",
            "Every missing original source path is retained. Added code is a candidate category, not proof of Agent authorship; pytest _version.py is fixture-generated.",
            "Git metadata and Python bytecode/cache are reported separately, not silently normalized or called business source differences.",
            "final_tree does not record modes, ownership, directories, hard-link identities, or every process state; byte equality is not full filesystem/execution-contract equality.",
            "Candidate-before/after byte and mode comparison concerns the original submitted snapshot, not official test changes in a separate scoring copy.",
            "No repository checkout, workload import, git hook, task command or VM is executed by this analyzer."]}
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "worktree-comparison.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    with (args.out / "worktree-summary.csv").open("w") as f:
        writer = csv.DictWriter(f, fieldnames=list(csv_rows[0]) if csv_rows else ["run"])
        writer.writeheader()
        writer.writerows(csv_rows)
    (args.out / "input-sha256.json").write_text(json.dumps(inputs, indent=2) + "\n")
    print(json.dumps({"runs": len(runs), "tasks": len(output), "sessions": len(csv_rows)}))


if __name__ == "__main__":
    main()
