"""Evaluation: rules only vs ML only vs both, against ground-truth images.

Metrics: detection rate, false-positive rate, run time.
Ground truth for each infected image is recorded in eval/ground_truth.yaml.

  python eval/run_experiments.py --symbols symbols --model baseline/models/spf.joblib

Needs a trained model (see `spf train`) and the ground-truth file filled in.
Runs the full extraction, so it requires the images to be present.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import yaml

from spf.extraction.volatility import extract
from spf.ml.features import features_for_processes
from spf.ml.model import SPFModel
from spf.rules.checks import run_rules

CONFIGURATIONS = ["rules", "ml", "both"]


def _detected_pids(ev, model, mode: str) -> set[int]:
    pids: set[int] = set()
    if mode in ("rules", "both"):
        pids |= {f.pid for f in run_rules(ev) if f.pid not in (None, -1)}
    if mode in ("ml", "both") and model is not None:
        for pid, feats in features_for_processes(ev.tasks_list):
            if float(model.score([feats])[0]) >= model.threshold:
                pids.add(pid)
    return pids


def evaluate(symbols: str, model_path: str | None, gt_path: str, out_path: str) -> dict:
    gt = yaml.safe_load(Path(gt_path).read_text()) or {}
    images = gt.get("images", [])
    model = SPFModel.load(model_path) if model_path else None

    results = {cfg: {"tp": 0, "fp": 0, "malicious_total": 0, "runtime_s": 0.0, "images": 0}
               for cfg in CONFIGURATIONS}

    for entry in images:
        image = entry["image"]
        malicious = set(entry.get("malicious_pids", []))
        for cfg in CONFIGURATIONS:
            t0 = time.perf_counter()
            ev = extract(image, symbols)
            detected = _detected_pids(ev, model, cfg)
            dt = time.perf_counter() - t0
            r = results[cfg]
            r["tp"] += len(detected & malicious)
            r["fp"] += len(detected - malicious)
            r["malicious_total"] += len(malicious)
            r["runtime_s"] += dt
            r["images"] += 1

    for cfg, r in results.items():
        total = r["malicious_total"] or 1
        r["detection_rate"] = round(r["tp"] / total, 4)
        r["false_positives_per_image"] = round(r["fp"] / (r["images"] or 1), 4)
        r["avg_runtime_s"] = round(r["runtime_s"] / (r["images"] or 1), 3)

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))
    return results


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--symbols", required=True)
    ap.add_argument("--model")
    ap.add_argument("--ground-truth", default="eval/ground_truth.yaml")
    ap.add_argument("--out", default="eval/results/metrics.json")
    args = ap.parse_args()
    evaluate(args.symbols, args.model, args.ground_truth, args.out)


if __name__ == "__main__":
    main()
