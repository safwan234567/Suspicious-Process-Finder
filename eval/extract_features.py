"""Extract per-process feature vectors from ONE memory image and cache them to
JSON, so the slow Volatility extraction runs once and every downstream
experiment (training, algorithm comparison, threshold sweeps) reads the cache.

  python eval/extract_features.py --image <img.lime> --symbols symbols --out eval/features/<stem>.json

The cached file records, for every process: pid, ppid, comm and the 9-feature
vector. It also records which plugins were unavailable, so a run on a degraded
image is not silently treated as complete.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from spf.extraction.volatility import extract
from spf.ml.features import features_for_processes
from spf.ml.model import SPFModel
from spf.pipeline import find_anomalies
from spf.report.builder import build_report, render_html
from spf.rules.checks import run_rules


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--symbols", default="symbols")
    ap.add_argument("--out", required=True)
    ap.add_argument("--model", default=None,
                    help="if given, also write a per-image SPF report (rules + ML) next to --out's results dir")
    ap.add_argument("--report-dir", default="eval/results")
    args = ap.parse_args()

    t0 = time.perf_counter()
    ev = extract(args.image, args.symbols)
    extract_s = time.perf_counter() - t0

    # optional: full per-image report artifact (needs the whole evidence, which
    # we have here but the compact feature cache does not keep)
    rule_objs = run_rules(ev)
    if args.model and Path(args.model).exists():
        model = SPFModel.load(args.model)
        anomaly_objs = find_anomalies(ev.tasks_list, model)
        report = build_report(ev, rule_objs, anomaly_objs)
        stem = Path(args.image).stem
        rd = Path(args.report_dir); rd.mkdir(parents=True, exist_ok=True)
        (rd / f"{stem}.json").write_text(json.dumps(report, indent=2, default=str))
        render_html(report, rd / f"{stem}.html")
        print(f"    report -> {rd / (stem + '.html')}")

    pid_features = features_for_processes(ev.tasks_list)
    by_pid = {p.pid: p for p in ev.tasks_list}
    rows = [
        {
            "pid": pid,
            "ppid": by_pid[pid].ppid if pid in by_pid else None,
            "comm": by_pid[pid].comm if pid in by_pid else "",
            "features": feats,
        }
        for pid, feats in pid_features
    ]
    rule_findings = [
        {"rule": f.rule, "pid": f.pid, "evidence": f.evidence} for f in rule_objs
    ]

    out = {
        "image": args.image,
        "extract_seconds": round(extract_s, 1),
        "n_processes": len(rows),
        "unavailable_plugins": ev.unavailable_plugins,
        "raw_plugin_rows": ev.raw_plugin_rows,
        "rule_findings": rule_findings,
        "processes": rows,
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=2, default=str))
    print(f"[+] {args.image}: {len(rows)} processes, {len(rule_findings)} rule findings, "
          f"extract {extract_s:.1f}s -> {args.out}")


if __name__ == "__main__":
    main()
