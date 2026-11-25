"""Quantify SPF's core claim: it replaces manual cross-referencing of raw
Volatility plugin tables with a few ranked, explained findings.

Without SPF an analyst reads every row of ten separate plugin tables
(process list, memory maps, open files, sockets, command lines, environment,
modules, syscall table, PID hash table, hidden-module scan) and correlates them
by hand. SPF reduces that to the processes it flags, each with a reason.

This reads the feature cache (which records each plugin's row count) and reports
the reduction per image.

  python eval/compare_vs_raw.py --features eval/features --out eval/results/triage_reduction.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from spf.ml.model import SPFModel

# images to report, with the human-readable scenario label
IMAGES = {
    "diamorphine": "Diamorphine rootkit (kernel)",
    "userland_malware": "Userland agent (/dev/shm + LD_PRELOAD)",
    "clean_test_02_all": "Clean, busy workload",
}


def run(features_dir: Path, model_path: str | None = None):
    model = SPFModel.load(model_path) if model_path and Path(model_path).exists() else None
    rows = []
    for stem, label in IMAGES.items():
        f = features_dir / f"{stem}.json"
        if not f.exists():
            continue
        d = json.loads(f.read_text())
        raw = d.get("raw_plugin_rows", {})
        raw_total = sum(raw.values())
        n_rules = len(d.get("rule_findings", []))
        n_ml = 0
        if model is not None:
            n_ml = len(model.detect([p["features"] for p in d["processes"]]))
        n_findings = n_rules + n_ml  # everything SPF surfaces for review
        rows.append({
            "image": stem,
            "scenario": label,
            "raw_plugin_rows_total": raw_total,
            "raw_rows_by_plugin": raw,
            "spf_rule_findings": n_rules,
            "spf_ml_findings": n_ml,
            "spf_findings_total": n_findings,
            "reduction_factor": round(raw_total / n_findings, 1) if n_findings else None,
        })
    return {"note": "raw rows = lines an analyst reads across all plugin tables; "
                    "SPF findings = ranked, explained results (rules + ML)", "images": rows}


def as_table(report) -> str:
    head = f"{'Scenario':<42} {'Raw plugin rows':>16} {'SPF findings':>13} {'Reduction':>10}"
    lines = [head, "-" * len(head)]
    for r in report["images"]:
        red = f"{r['reduction_factor']:.0f}x" if r["reduction_factor"] else "0 to review"
        lines.append(f"{r['scenario']:<42} {r['raw_plugin_rows_total']:>16} "
                     f"{r['spf_findings_total']:>13} {red:>10}")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", default="eval/features")
    ap.add_argument("--model", default="baseline/models/spf.joblib")
    ap.add_argument("--out", default="eval/results/triage_reduction.json")
    args = ap.parse_args()
    report = run(Path(args.features), args.model)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2))
    print(as_table(report))
    print(f"\n[+] written -> {args.out}")


if __name__ == "__main__":
    main()
