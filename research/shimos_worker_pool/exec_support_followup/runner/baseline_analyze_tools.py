#!/usr/bin/env python3
"""Offline analysis of saved exec_support evidence; never executes workloads.

Writes a new analysis directory. Missing observations remain null. Fixture
diagnostics never become business receipts or repair missing wait results.
"""
import argparse
import csv
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import statistics


STUDY = Path(__file__).resolve().parents[1]


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def read_json(path, default=None):
    if not path.exists():
        return default
    return json.loads(path.read_text())


def json_records(path):
    if not path.exists():
        return []
    records = []
    with path.open(errors="replace") as stream:
        for number, line in enumerate(stream, 1):
            try:
                value = json.loads(line)
            except (json.JSONDecodeError, UnicodeError):
                continue
            if isinstance(value, dict):
                records.append({**value, "_source_line": number})
    return records


def kv(text):
    result = {}
    if not isinstance(text, str):
        return result
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                result[parts[0]] = int(parts[1])
            except ValueError:
                result[parts[0]] = parts[1]
    return result


def number(value):
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def elapsed_ms(start, end):
    if not isinstance(start, int) or not isinstance(end, int) or end < start:
        return None
    return (end - start) / 1e6


def maximum(values):
    values = [v for v in values if isinstance(v, (int, float))]
    return max(values) if values else None


def process_trace(run):
    path = run / "process-trace.txt"
    edges, execs, exits, raw = {}, {}, {}, []
    if path.exists():
        with path.open(errors="replace") as stream:
            for line in stream:
                match = re.search(r"\s(\d+\.\d+):\s+(sched_process_(?:fork|exec|exit)):\s+(.*)", line)
                if not match:
                    continue
                ns = int(Decimal(match[1]) * Decimal(1000000000))
                kind, body = match[2], match[3]
                record = {"event": kind, "monotonic_ns": ns, "body": body}
                if kind == "sched_process_fork":
                    item = re.search(r"\bpid=(\d+) child_comm=.* child_pid=(\d+)", body)
                    if item:
                        parent, child = map(int, item.groups())
                        edges.setdefault(child, []).append({"parent": parent, "ns": ns})
                        record.update(pid=parent, child_pid=child)
                elif kind == "sched_process_exec":
                    item = re.search(r"filename=(.*?) pid=(\d+) old_pid=(\d+)", body)
                    if item:
                        path_name, pid, old_pid = item[1], int(item[2]), int(item[3])
                        entry = {"filename": path_name, "ns": ns, "old_pid": old_pid}
                        execs.setdefault(pid, []).append(entry)
                        record.update(pid=pid, **entry)
                else:
                    item = re.search(r"\bpid=(\d+)\b", body)
                    if item:
                        pid = int(item[1]); exits.setdefault(pid, []).append(ns)
                        record["pid"] = pid
                raw.append(record)
    trace_stats = read_json(run / "trace-stats.json", {})
    loss = any(re.search(r"(?:^|\n)(?:overrun|commit overrun|dropped events):\s*[1-9]", str(v))
               for v in trace_stats.values())
    config = read_json(run / "trace-config.json", {})
    enabled = str(config.get("tracing_on", "")).strip() == "1"
    return {"edges": edges, "execs": execs, "exits": exits, "raw": raw,
            "enabled": enabled, "loss": loss, "config": config}


def descendants(root, edges, start_ns, end_ns):
    if root is None:
        return []
    found = {root}
    while True:
        new = {child for child, records in edges.items()
               if any(r["parent"] in found and (start_ns is None or r["ns"] >= start_ns)
                      and (end_ns is None or r["ns"] <= end_ns) for r in records)} - found
        if not new:
            break
        found |= new
    return sorted(found)


def resource_record(stats):
    result = {}
    for group, values in (stats or {}).items():
        if not isinstance(values, dict):
            continue
        result[group] = {
            "cpu": kv(values.get("cpu.stat")),
            "memory_events": kv(values.get("memory.events")),
            "pids_events": kv(values.get("pids.events")),
            "memory_current_bytes": number(values.get("memory.current")),
            "memory_peak_bytes": number(values.get("memory.peak")),
            "pids_current": number(values.get("pids.current")),
            "cgroup_events": kv(values.get("cgroup.events")),
        }
    return result


def locate_rows(run):
    by_nonce = {}
    for path in sorted(run.glob("attempt-*.json")):
        row = read_json(path)
        if isinstance(row, dict) and row.get("execution_mode") == "tool_exec":
            by_nonce[row["nonce"]] = (row, path, False)
    for path in sorted(run.glob("[0-9]*-*.json")):
        row = read_json(path)
        if isinstance(row, dict) and row.get("execution_mode") == "tool_exec" and row.get("nonce"):
            by_nonce[row["nonce"]] = (row, path, True)
    return sorted(by_nonce.values(), key=lambda item: item[0].get("timestamps", {}).get("request_begin", 0))


def analyze_run(run):
    trace = process_trace(run)
    supervisor = read_json(run / "supervisor.json", {})
    recovery_by_nonce = {a["nonce"]: a for a in supervisor.get("attempts", [])}
    final = read_json(run / "external-final-release.json", {})
    run_result = read_json(run / "result.json", {})
    config = read_json(run / "review-config.json", {})
    cohort_source = hashlib.sha256(json.dumps({
        "prototype": read_json(run / "source-sha.json"),
        "tools": read_json(run / "tools-source-sha.json"),
        "runtime": read_json(run / "candidate-runtime-sha.json"),
    }, sort_keys=True).encode()).hexdigest()
    events = json_records(run / "events.jsonl")
    supervisor_events = json_records(run / "supervisor-events.jsonl")
    cost = [item for item in json_records(run / "guest-output.log") if item.get("event") == "COST"]
    rows = []
    for row, path, response_file in locate_rows(run):
        nonce, name = row["nonce"], row["case"]
        case = row.get("tool_case") or {}
        times = row.get("timestamps", {}).copy()
        wait_record = row.get("w_wait") or {}
        if isinstance(wait_record.get("wait_begin_ns"), int):
            times["S_wait_begin"] = wait_record["wait_begin_ns"]
        if isinstance(wait_record.get("wait_end_ns"), int):
            times["S_wait_return"] = wait_record["wait_end_ns"]
        h_attempt = recovery_by_nonce.get(nonce, {})
        recovery = bool(h_attempt and not h_attempt.get("retired"))
        parsed_resources = resource_record(row.get("stats"))
        outpath = run / (path.stem + "-stdout.log") if response_file else None
        errpath = run / (path.stem + "-stderr.log") if response_file else None
        stdout_records = json_records(outpath) if outpath else []
        # These records originate in tool stdout. Used only as labelled fixture
        # diagnostics, never to infer permission, successful execution, or wait.
        preexec = next((r for r in stdout_records if r.get("event") == "TOOL_LAUNCHER_PRE_EXEC"), {})
        diagnostic_start = next((r for r in stdout_records if r.get("event") in ("TOOL_STARTED", "UNITTEST_STARTED")), {})
        times["fixture_launcher_preexec"] = preexec.get("monotonic_ns")
        times["fixture_workload_output_start"] = diagnostic_start.get("monotonic_ns")
        wpid, spid = row.get("w_pid"), row.get("s_pid")
        expected_target = (case.get("argv") or [None])[0]
        worker_execs = [r for r in trace["execs"].get(wpid, [])
                        if r["ns"] >= times.get("request_begin", 0)]
        target_exec = next((r for r in worker_execs if r["filename"] == expected_target), None)
        if target_exec:
            times["target_exec_kernel_event"] = target_exec["ns"]
        # Boundary timestamps come from trusted R/H events; they measure when
        # the controller observed wait/EOF, not the earliest kernel occurrence.
        request_events = [e for e in events if e.get("nonce") == nonce]
        first_cancel = next((e for e in request_events if e.get("event") == "CANCEL_REQUEST"), {})
        times["cancel_request"] = first_cancel.get("monotonic_ns")
        request_cost = [e for e in cost if e.get("nonce") == nonce and e.get("role") == "R"]
        for key in ("resources_deleted", "response_ready", "request_begin"):
            value = next((r.get("ns") for r in request_cost if r.get("name") == key), None)
            if key not in times and value is not None:
                times[key] = value
        for event_name, timestamp_name in (("SUPERVISOR_RECOVERY_START", "supervisor_recovery_start"),
                                            ("SUPERVISOR_QUIESCENCE", "supervisor_quiescence"),
                                            ("SUPERVISOR_FINISHED", "supervisor_finished")):
            found = next((e.get("monotonic_ns") for e in supervisor_events if e.get("event") == event_name), None)
            if recovery:
                times[timestamp_name] = found
        eof_times = [times.get("stdout_eof"), times.get("stderr_eof")]
        times["both_streams_eof"] = max(eof_times) if all(isinstance(t, int) for t in eof_times) else None
        memory = row.get("memory_samples") or []
        target_memory = [m for m in memory if target_exec and m.get("monotonic_ns", 0) >= target_exec["ns"]]
        members = descendants(wpid, trace["edges"], times.get("request_begin"), times.get("domain_quiescent"))
        child_members = [p for p in members if p != wpid]
        trace_end = times.get("domain_quiescent") or times.get("supervisor_quiescence")
        kernel_exits = [t for p in members for t in trace["exits"].get(p, [])
                        if t >= times.get("request_begin", 0) and (trace_end is None or t <= trace_end)]
        if kernel_exits:
            times["last_observed_tree_exit"] = max(kernel_exits)
        exit_code = (row.get("result") or {}).get("exit_code")
        business = "UNKNOWN" if recovery else row.get("business")
        stream_eof = ({k: v.get("output_eof") for k, v in h_attempt.get("output_streams", {}).items()}
                      if recovery else row.get("stream_eof", {}))
        stream_complete = ({k: v.get("complete") for k, v in h_attempt.get("output_streams", {}).items()}
                           if recovery else row.get("stream_complete", {}))
        resources_removed = h_attempt.get("resources_removed") if recovery else row.get("resources_removed")
        cpu_before = next((e for e in request_cost if e.get("name") == "request_cpu_begin"), {})
        cpu_after = next((e for e in request_cost if e.get("name") == "request_cpu_end"), {})
        controller_cpu_ns = None
        cpu_keys = ("cpu_user_ns", "cpu_system_ns")
        if all(isinstance(e.get(k), int) for e in (cpu_before, cpu_after) for k in cpu_keys):
            controller_cpu_ns = sum(cpu_after[k] - cpu_before[k] for k in cpu_keys)
        metrics = {
            "request_to_kernel_target_exec_ms": elapsed_ms(times.get("request_begin"), times.get("target_exec_kernel_event")),
            "request_to_fixture_launcher_preexec_ms": elapsed_ms(times.get("request_begin"), times.get("fixture_launcher_preexec")),
            "kernel_target_exec_to_wait_receipt_ms": elapsed_ms(times.get("target_exec_kernel_event"), times.get("worker_wait_received")),
            "kernel_target_exec_to_S_wait_return_ms": elapsed_ms(times.get("target_exec_kernel_event"), times.get("S_wait_return")),
            "fixture_launcher_preexec_to_wait_receipt_ms": elapsed_ms(times.get("fixture_launcher_preexec"), times.get("worker_wait_received")),
            "fixture_launcher_preexec_to_S_wait_return_ms": elapsed_ms(times.get("fixture_launcher_preexec"), times.get("S_wait_return")),
            "S_wait_blocking_duration_ms": elapsed_ms(times.get("S_wait_begin"), times.get("S_wait_return")),
            "S_wait_return_to_R_receipt_ms": elapsed_ms(times.get("S_wait_return"), times.get("worker_wait_received")),
            "gate_release_to_wait_receipt_ms": elapsed_ms(times.get("business_release"), times.get("worker_wait_received")),
            "wait_receipt_to_both_eof_ms": elapsed_ms(times.get("worker_wait_received"), times.get("both_streams_eof")),
            "request_to_both_eof_ms": elapsed_ms(times.get("request_begin"), times.get("both_streams_eof")),
            "request_to_domain_quiescent_ms": elapsed_ms(times.get("request_begin"), times.get("domain_quiescent")),
            "quiescent_to_response_ready_ms": elapsed_ms(times.get("domain_quiescent"), times.get("response_ready")),
            "request_to_response_ready_ms": elapsed_ms(times.get("request_begin"), times.get("response_ready")),
            "cancel_to_quiescent_ms": elapsed_ms(times.get("cancel_request"), times.get("domain_quiescent")),
            "supervisor_recovery_to_release_ms": elapsed_ms(times.get("supervisor_recovery_start"), times.get("supervisor_finished")),
            "controller_cpu_ns": controller_cpu_ns,
            "main_w_sampled_rss_max_kib": maximum(m.get("Rss_kib") for m in memory),
            "main_w_sampled_pss_max_kib": maximum(m.get("Pss_kib") for m in memory),
            "main_w_after_exec_sampled_rss_max_kib": maximum(m.get("Rss_kib") for m in target_memory),
            "main_w_after_exec_sampled_pss_max_kib": maximum(m.get("Pss_kib") for m in target_memory),
        }
        for group in ("task", "business"):
            resource = parsed_resources.get(group, {})
            usec = resource.get("cpu", {}).get("usage_usec")
            metrics[group + "_cgroup_cpu_ms"] = usec / 1000 if isinstance(usec, int) else None
            metrics[group + "_cgroup_memory_peak_bytes"] = resource.get("memory_peak_bytes")
        result = {
            "run": run.name, "case": name, "nonce": nonce, "level": case.get("level"),
            "source_evidence": str(path.relative_to(run)), "source_sha256": sha(path),
            "response_file_present": response_file, "response_committed": row.get("response_committed", False),
            "qualification": row.get("qualification"), "fixture_checks": row.get("fixture_checks"),
            "execution_mode": row.get("execution_mode"), "diagnostics": row.get("diagnostics"),
            "timing_enabled": str(config.get("timing")) == "1",
            "resource_sampling_enabled": str(config.get("resource_samples", "1")) == "1",
            "cohort_source_sha256": cohort_source,
            "business": business, "outcome": "CONTROLLER_LOST_UNKNOWN" if recovery else row.get("outcome"),
            "last_controller_business": row.get("business"), "last_controller_exit_code": exit_code,
            "controller_reported_failure": row.get("failure"), "business_exit_code": None if recovery else exit_code,
            "business_signal": -exit_code if isinstance(exit_code, int) and exit_code < 0 and not recovery else None,
            "business_wait_source": (row.get("result") or {}).get("source") if not recovery else None,
            "business_permit": row.get("business_permit"), "admission": row.get("admission"),
            "main_w_pid": wpid, "transition_pid": spid, "zygote_pid": row.get("zygote_pid"),
            "stream_eof": stream_eof, "stream_complete": stream_complete,
            "output_content_completeness_note": "Supervisor recovery suffix cannot prove the Controller-read prefix survived" if recovery else
                "retained stream bytes; termination can end output before a semantic application result",
            "output_ended_by_termination": row.get("output_ended_by_termination"),
            "stream_bytes": row.get("stream_bytes"), "stream_truncated": row.get("stream_truncated"),
            "domain_empty": row.get("domain_empty"), "resources_removed": resources_removed,
            "supervisor_release_state": supervisor.get("release_state"), "supervisor_recovery": recovery,
            "supervisor_echild": supervisor.get("echild"), "supervisor_business_result": supervisor.get("business_result"),
            "observer_cleanup_used": supervisor.get("observer_cleanup_used"),
            "delegation_removed": final.get("delegation_removed"),
            "timestamps_ns": times, "metrics": metrics, "resources": parsed_resources,
            "memory_sample_count": len(memory), "memory_successful_sample_count": sum("unavailable" not in m for m in memory),
            "memory_samples": memory,
            "trace": {"enabled": trace["enabled"], "loss": trace["loss"], "worker_execs": worker_execs,
                      "worker_tree_pids": members, "worker_descendants": child_members,
                      "tree_exit_events_observed": len(kernel_exits),
                      "all_observed_tree_members_have_exit_event": (all(any(t >= times.get("request_begin", 0)
                          and (trace_end is None or t <= trace_end) for t in trace["exits"].get(p, [])) for p in members)
                                                                    if trace["enabled"] and members else None)},
            "tool_security_checks": (row.get("tool_security") or {}).get("checks"),
            "tool_security_identity": (row.get("tool_security") or {}).get("identity"),
            "workspace_snapshot": row.get("workspace_snapshot", h_attempt.get("side_effects")),
            "supervisor_attempt": h_attempt,
        }
        rows.append(result)
    manifest = {p.name: sha(p) for p in run.iterdir() if p.is_file() and p.suffix in (".json", ".jsonl", ".log", ".txt")}
    meta = {"run": run.name, "path": str(run), "run_result": run_result, "review_config": config,
            "row_count": len(rows), "trace_enabled": trace["enabled"], "trace_loss": trace["loss"],
            "supervisor_release_state": supervisor.get("release_state"), "supervisor_failure": supervisor.get("failure_reason"),
            "summary": read_json(run / "summary.json"), "source_sha256": read_json(run / "source-sha.json"),
            "tool_source_sha256": read_json(run / "tools-source-sha.json"),
            "tool_build_sha256": read_json(run / "tool-build-sha256.json"),
            "evidence_sha256": manifest}
    return rows, meta


def csv_rows(rows):
    flat = []
    for row in rows:
        item = {k: row.get(k) for k in (
            "run", "case", "nonce", "level", "qualification", "response_committed", "diagnostics", "business",
            "timing_enabled", "resource_sampling_enabled", "cohort_source_sha256",
            "outcome", "business_exit_code", "business_signal", "business_wait_source", "resources_removed",
            "domain_empty", "supervisor_recovery", "supervisor_release_state", "supervisor_echild", "delegation_removed",
            "memory_sample_count", "memory_successful_sample_count")}
        item.update(row["metrics"])
        for name, value in row["timestamps_ns"].items():
            item[name + "_ns"] = value
        for name in ("stdout", "stderr"):
            item[name + "_eof"] = row["stream_eof"].get(name)
            item[name + "_content_complete"] = row["stream_complete"].get(name)
        for group in ("task", "control", "transition", "business"):
            resource = row["resources"].get(group, {})
            for key in ("memory_peak_bytes", "memory_current_bytes", "pids_current"):
                item[group + "_" + key] = resource.get(key)
            for field in ("usage_usec", "user_usec", "system_usec", "nr_throttled", "throttled_usec"):
                item[group + "_cpu_" + field] = resource.get("cpu", {}).get(field)
            item[group + "_pids_max_events"] = resource.get("pids_events", {}).get("max")
            for field in ("max", "oom", "oom_kill"):
                item[group + "_memory_" + field + "_events"] = resource.get("memory_events", {}).get(field)
        flat.append(item)
    return flat


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runs", nargs="+", help="run names under exec_support/runs, or absolute run directories")
    parser.add_argument("--output", required=True, help="new directory under exec_support/analysis; never overwrite")
    args = parser.parse_args()
    out = Path(args.output)
    if not out.is_absolute():
        out = STUDY / "analysis" / out
    out = out.resolve()
    if not out.is_relative_to((STUDY / "analysis").resolve()):
        raise SystemExit("analysis output must be below exec_support/analysis")
    out.mkdir(parents=True, exist_ok=False)
    all_rows, runs = [], []
    for name in args.runs:
        path = Path(name)
        if not path.is_absolute():
            path = STUDY / "runs" / path
        path = path.resolve()
        if not path.is_relative_to((STUDY / "runs").resolve()):
            raise SystemExit("inputs must be saved exec_support/runs evidence")
        rows, meta = analyze_run(path); all_rows.extend(rows); runs.append(meta)
    notes = [
        "Offline evidence analysis only. No experiments or imported workload/catalogue code are executed.",
        "A resources-removed/EOF/ECHILD result never proves business success. UNKNOWN stays UNKNOWN.",
        "TOOL_LAUNCHER_PRE_EXEC is fixture self-reported stdout diagnostic, not actual tool first instruction and not a trusted receipt.",
        "sched_process_exec is a kernel exec event, not a first-userspace-instruction timestamp. Only present when tracing was enabled and recorded.",
        "Wait-received timestamps include S wait and R observation/IPC delay; they are not pure tool CPU or exact exit time.",
        "RSS/PSS are sparse main-W samples, not process-tree peaks; missing short-process samples remain null. Pre-exec samples can contain the inherited Python image.",
        "cgroup memory.peak covers charged pages and descendants, not summed RSS/PSS; parent and child cgroup statistics overlap and must not be added.",
        "Low-instrumentation and full-trace measurements are separate cohorts. No cold Bubblewrap equivalence or speedup claim is made here.",
        "W still originates from two D-wrapper Z→S→W forks into target cgroups. exec then replaces the Python process image; no Python heap warm benefit is claimed.",
        "Trace can confirm observed edges/exits but does not substitute for actual wait, authenticated protocol, cgroup emptiness or cleanup evidence.",
    ]
    result = {"schema": 1, "notes": notes, "runs": runs, "rows": all_rows,
              "analyzer_sha256": sha(Path(__file__)), "business_success_count": sum(r["outcome"] == "SUCCEEDED" for r in all_rows),
              "known_nonzero_count": sum(r["outcome"] == "NONZERO" for r in all_rows),
              "unknown_business_count": sum(r["business"] == "UNKNOWN" for r in all_rows),
              "resources_removed_count": sum(r["resources_removed"] is True for r in all_rows)}
    (out / "tool-evidence.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    flat = csv_rows(all_rows)
    columns = list(dict.fromkeys(key for row in flat for key in row))
    with (out / "tool-evidence.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns or ["run", "case"])
        writer.writeheader(); writer.writerows(flat)
    cohorts = {}
    for row in all_rows:
        key = (row["case"], row["diagnostics"], row["trace"]["enabled"], row["outcome"],
               row["timing_enabled"], row["resource_sampling_enabled"], row["cohort_source_sha256"])
        cohorts.setdefault(key, []).append(row)
    summary = []
    for key, values in sorted(cohorts.items(), key=lambda x: repr(x[0])):
        metrics = {}
        for metric in values[0]["metrics"]:
            measured = [v["metrics"][metric] for v in values if v["metrics"][metric] is not None]
            metrics[metric] = {"count": len(measured), "min": min(measured), "median": statistics.median(measured), "max": max(measured)} if measured else {"count": 0}
        summary.append({"case": key[0], "diagnostics": key[1], "trace_enabled": key[2], "outcome": key[3],
                        "timing_enabled": key[4], "resource_sampling_enabled": key[5],
                        "cohort_source_sha256": key[6], "runs": sorted({v["run"] for v in values}),
                        "n": len(values), "metrics": metrics})
    (out / "tool-cohorts.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    lines = ["# Tool evidence aggregation", "", "These are saved evidence summaries, not new qualifications or performance claims.", "",
             "| Run | Case | Business | Outcome | Exit | EOF stdout/stderr | Resources removed |", "| --- | --- | --- | --- | --- | --- | --- |"]
    for row in all_rows:
        lines.append(f"| {row['run']} | {row['case']} | {row['business']} | {row['outcome']} | {row['business_exit_code']} | {row['stream_eof'].get('stdout')}/{row['stream_eof'].get('stderr')} | {row['resources_removed']} |")
    lines += ["", *["- " + n for n in notes], ""]
    (out / "README.md").write_text("\n".join(lines))
    print(json.dumps({"output": str(out), "runs": len(runs), "rows": len(all_rows),
                      "resources_removed_count": result["resources_removed_count"], "unknown_business_count": result["unknown_business_count"]}))


if __name__ == "__main__":
    main()
