#!/usr/bin/env python3
"""Read-only final presentation/source checks; never runs product code."""
import datetime
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import unquote, urlparse

S = Path(__file__).resolve().parents[1]
DOCS = ["README.md", "architecture-baselines.md", "fairness-and-qualification.md",
        "experiment-design.md", "benchmark-results.md", "cpu-memory-analysis.md",
        "round1-final-report.md", "docs/delivery-review.md"]


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    output = S / "analysis/delivery-review.json"
    assert not output.exists(), "do not overwrite delivery evidence"
    errors = []
    plan = json.loads((S / "frozen/formal-plan.json").read_text())
    checked = {}
    sources = [("prototype/" + p, h) for p, h in plan["source_sha256"].items()]
    sources += [("runner/" + p, h) for p, h in plan["runner_sha256"].items()]
    sources.append((plan["review_path"], plan["review_sha256"]))
    for name, expected in sources:
        actual = sha(S / name)
        checked[name] = actual
        if actual != expected:
            errors.append({"source_changed": name})
    pending = {output.resolve(), (S / "frozen/delivery-sha256.json").resolve()}
    links = 0
    for doc in DOCS:
        p = S / doc
        if not p.is_file():
            errors.append({"missing_document": doc})
            continue
        for target in re.findall(r"\]\(([^)]+)\)", p.read_text()):
            target = target.strip("<>")
            if target.startswith("#") or urlparse(target).scheme:
                continue
            path = (p.parent / unquote(target.split("#")[0])).resolve()
            links += 1
            if not path.exists() and path not in pending:
                errors.append({"broken_link": doc, "target": target})
    figures = ["01-full-sequence", "02-average-task-cost", "03-product-cpu",
               "04-memory-time", "05-paired-savings", "06-adjacent-partition"]
    for name in figures:
        for suffix in ("png", "svg", "pdf"):
            if not (S / "figures/formal-cost-01" / (name + "." + suffix)).is_file():
                errors.append({"missing_figure": name + "." + suffix})
    matrix = json.loads((S / "analysis/performance-final-01/final-summary.json").read_text())
    sessions = [x for block in matrix["blocks"] for x in block["sessions"]]
    if (len(matrix["blocks"]), len(sessions), sum(x["attempts"] for x in sessions)) != (21, 63, 1737):
        errors.append({"matrix_count": "not 21/63/1737"})
    if matrix["status"] != "PASS" or any(x["status"] != "PASS" for x in sessions):
        errors.append({"matrix_status": "not all PASS"})
    for file in ["analysis/formal-cost-01/independent-primary-cross-check.json",
                 "analysis/formal-cost-01/presentation-consistency-02.json",
                 "analysis/historical-inputs-after-formal.json"]:
        if json.loads((S / file).read_text())["status"] != "PASS":
            errors.append({"check_failed": file})
    result = {"created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status": "FAIL" if errors else "PASS", "errors": errors,
              "documents": DOCS, "local_links_checked": links,
              "source_review_hashes": checked, "figure_formats_checked": 18,
              "formal_blocks": 21, "formal_sessions": 63, "formal_attempts": 1737,
              "pending_manifest": "frozen/delivery-sha256.json created immediately after this check",
              "scope": "presentation/source consistency; qualification remains the independent VM evidence matrix"}
    with output.open("x") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(json.dumps({"status": result["status"], "errors": errors, "links": links}))
    raise SystemExit(bool(errors))


if __name__ == "__main__":
    main()
