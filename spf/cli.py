"""Command-line entry point.

  spf train   --images baseline/images --symbols symbols --out baseline/models/spf.joblib
  spf analyse --image eval/images/infected/x.lime --symbols symbols --model baseline/models/spf.joblib --mode both
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from spf.extraction.volatility import extract, SUPPORTED_FORMATS
from spf.ml.features import features_for_processes
from spf.ml.model import SPFModel
from spf.rules.checks import run_rules
from spf.pipeline import find_anomalies
from spf.report.builder import build_report, render_html


def _iter_images(images_dir: Path):
    for p in sorted(Path(images_dir).rglob("*")):
        if p.suffix.lower() in SUPPORTED_FORMATS:
            yield p


def cmd_train(args) -> None:
    rows: list[dict] = []
    n_images = 0
    for image in _iter_images(args.images):
        ev = extract(image, args.symbols)
        rows.extend(f for _pid, f in features_for_processes(ev.tasks_list))
        n_images += 1
    if not rows:
        raise SystemExit(f"No .raw/.lime images found under {args.images}")
    model = SPFModel(percentile=args.percentile).fit(rows)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    model.save(args.out)
    print(f"[+] trained on {len(rows)} processes from {n_images} image(s); "
          f"cutoff={model.threshold:.3f} -> {args.out}")
    if model.invariant:
        print("[!] constant on the baseline (any other value will be reported as unseen): "
              + ", ".join(f"{f}={v:g}" for f, v in model.invariant.items()))
        print("    Add clean images that exercise these (e.g. a Java/Node.js workload for "
              "unbacked executable memory) to reduce false positives.")


def cmd_analyse(args) -> None:
    ev = extract(args.image, args.symbols)

    rule_findings = run_rules(ev) if args.mode in ("rules", "both") else []
    anomaly_findings = []
    if args.mode in ("ml", "both"):
        if not args.model:
            raise SystemExit("--model is required for --mode ml/both")
        model = SPFModel.load(args.model)
        anomaly_findings = find_anomalies(ev.tasks_list, model)

    report = build_report(ev, rule_findings, anomaly_findings)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str))
    html_path = out.with_suffix(".html")
    render_html(report, html_path)
    print(f"[+] {report['summary']['rule_findings']} rule findings, "
          f"{report['summary']['anomalies']} anomalies -> {out} and {html_path}")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="spf", description="Suspicious Process Finder")
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("train", help="Train the Isolation Forest on clean baseline images")
    t.add_argument("--images", required=True)
    t.add_argument("--symbols", required=True)
    t.add_argument("--out", required=True)
    t.add_argument("--percentile", type=float, default=100.0,
                   help="cutoff = this percentile of clean-baseline scores (default 100: the highest clean score)")
    t.set_defaults(func=cmd_train)

    a = sub.add_parser("analyse", help="Analyse one memory image")
    a.add_argument("--image", required=True)
    a.add_argument("--symbols", required=True)
    a.add_argument("--model")
    a.add_argument("--mode", choices=["rules", "ml", "both"], default="both")
    a.add_argument("--out", default="report.json")
    a.set_defaults(func=cmd_analyse)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
