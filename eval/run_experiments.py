"""Evaluation: rules only vs ML only vs both, against ground-truth images.

Metrics (Multi-Level Scoring):
  1. Process-Level Metrics (PIDs): TP, FP, Detection Rate, FP/Image
  2. Kernel Rootkit Metrics: Hidden Modules and Hooked Syscalls (TP, FP, Detection Rate)
  3. Comprehensive Security Indicator Metrics: All threat indicators combined
  4. Latency / Runtime: Extraction and inference time per image

Ground truth for each image is recorded in eval/ground_truth.yaml.
Usage:
  python eval/run_experiments.py --symbols symbols --model baseline/models/spf.joblib --out eval/results/metrics.json
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import yaml

from spf.extraction.volatility import extract
from spf.pipeline import find_anomalies
from spf.ml.model import SPFModel
from spf.rules.checks import run_rules
from spf.report.builder import build_report, render_html

CONFIGURATIONS = ["rules", "ml", "both"]

SYSCALL_NAMES = {
    62: "__x64_sys_kill",
    217: "__x64_sys_getdents64",
}


def _evaluate_image_data(rule_findings, anomalies, gt_entry: dict, runtime_s: float = 0.0):
    # Rule PIDs
    rule_pids = {f["pid"] for f in rule_findings if f.get("pid") not in (None, -1)}
    
    # ML PIDs
    ml_pids = {a["pid"] for a in anomalies if a.get("pid") not in (None, -1)}
    
    gt_malicious_pids = set(gt_entry.get("malicious_pids", []))
    
    # Kernel modules
    detected_modules = {f.get("evidence", {}).get("name") for f in rule_findings if f.get("rule") == "HIDDEN_KERNEL_MODULE"}
    gt_modules = set(gt_entry.get("hidden_modules", []))
    
    # Syscalls
    detected_syscalls = set()
    for f in rule_findings:
        if f.get("rule") == "HOOKED_SYSCALL":
            idx = f.get("evidence", {}).get("index")
            name = SYSCALL_NAMES.get(idx, f.get("evidence", {}).get("symbol") or f"syscall_{idx}")
            detected_syscalls.add(name)
    gt_syscalls = set(gt_entry.get("hooked_syscalls", []))
    
    return {
        "pids": {
            "rules": rule_pids,
            "ml": ml_pids,
            "both": rule_pids | ml_pids,
            "gt": gt_malicious_pids,
        },
        "modules": {
            "rules": detected_modules,
            "ml": set(),
            "both": detected_modules,
            "gt": gt_modules,
        },
        "syscalls": {
            "rules": detected_syscalls,
            "ml": set(),
            "both": detected_syscalls,
            "gt": gt_syscalls,
        },
        "runtime_s": runtime_s,
    }


def _detect_from_cache(cache: dict, model):
    """Rule findings + ML anomalies for one image from its cached feature file
    (eval/extract_features.py output). Lets the evaluation run without touching
    the 4 GB images, so it is fast and reproducible."""
    from spf.ml.features import FEATURE_NAMES
    rule_findings = cache.get("rule_findings", [])
    anomalies = []
    if model is not None:
        rows = [p["features"] for p in cache["processes"]]
        for d in model.detect(rows):
            p = cache["processes"][d.index]
            anomalies.append({"pid": p["pid"], "reason": d.reason,
                              "novel_features": d.novel_features, "score": d.score})
    return rule_findings, anomalies


def evaluate(symbols: str | None, model_path: str | None, gt_path: str, out_path: str,
             reports_dir: str = "eval/results", features_dir: str | None = None) -> dict:
    gt = yaml.safe_load(Path(gt_path).read_text()) or {}
    images = gt.get("images", [])
    model = SPFModel.load(model_path) if model_path and Path(model_path).exists() else None
    fdir = Path(features_dir) if features_dir else None

    metrics = {
        cfg: {
            "pid_tp": 0,
            "pid_fp": 0,
            "pid_malicious_total": 0,
            "kernel_tp": 0,
            "kernel_fp": 0,
            "kernel_malicious_total": 0,
            "overall_tp": 0,
            "overall_fp": 0,
            "overall_total": 0,
            "runtime_s": 0.0,
            "images": 0,
        }
        for cfg in CONFIGURATIONS
    }

    per_image_results = []
    rdir = Path(reports_dir)
    rdir.mkdir(parents=True, exist_ok=True)
    runtimes = {}  # image -> {"extract","rules","ml"} seconds, measured on this run

    for entry in images:
        image = entry["image"]
        stem = Path(image).stem
        cache_file = fdir / f"{stem}.json" if fdir else None

        if cache_file and cache_file.exists():
            # reproducible path: use the committed feature cache, no extraction
            print(f"[*] Using feature cache for {image}")
            cache = json.loads(cache_file.read_text())
            rule_findings, anomalies = _detect_from_cache(cache, model)
            t_ext = float(cache.get("extract_seconds", 0.0))
            t_rules = t_ml = 0.0
        else:
            # One real extraction per image, timed. No assumed runtime.
            print(f"[*] Extracting {image} ...")
            t0 = time.perf_counter()
            ev = extract(image, symbols or "symbols")
            t_ext = time.perf_counter() - t0
            t0 = time.perf_counter()
            rule_objs = run_rules(ev)
            t_rules = time.perf_counter() - t0
            rule_findings = [f.__dict__ for f in rule_objs]
            anomaly_objs = []
            t_ml = 0.0
            if model is not None:
                t0 = time.perf_counter()
                anomaly_objs = find_anomalies(ev.tasks_list, model)
                t_ml = time.perf_counter() - t0
            anomalies = [a.__dict__ for a in anomaly_objs]
            report = build_report(ev, rule_objs, anomaly_objs)
            (rdir / f"{stem}.json").write_text(json.dumps(report, indent=2, default=str))
            render_html(report, rdir / f"{stem}.html")

        runtimes[image] = {"extract": t_ext, "rules": t_rules, "ml": t_ml}
        print(f"    extract {t_ext:.1f}s  rules {t_rules:.2f}s  ml {t_ml:.2f}s  "
              f"({len(rule_findings)} rule findings, {len(anomalies)} anomalies)")

        eval_data = _evaluate_image_data(rule_findings, anomalies, entry, t_ext)
        gt_pids = eval_data["pids"]["gt"]
        gt_mods = eval_data["modules"]["gt"]
        gt_sys = eval_data["syscalls"]["gt"]
        total_indicators = len(gt_pids) + len(gt_mods) + len(gt_sys)

        image_summary = {
            "image": image,
            "ground_truth": {
                "malicious_pids": sorted(gt_pids),
                "hidden_modules": sorted(gt_mods),
                "hooked_syscalls": sorted(gt_sys),
            },
            "detections": {},
        }

        for cfg in CONFIGURATIONS:
            det_pids = eval_data["pids"][cfg]
            det_mods = eval_data["modules"][cfg]
            det_sys = eval_data["syscalls"][cfg]

            m = metrics[cfg]
            pid_tp = len(det_pids & gt_pids)
            pid_fp = len(det_pids - gt_pids)
            m["pid_tp"] += pid_tp
            m["pid_fp"] += pid_fp
            m["pid_malicious_total"] += len(gt_pids)

            k_tp = len(det_mods & gt_mods) + len(det_sys & gt_sys)
            k_fp = len(det_mods - gt_mods) + len(det_sys - gt_sys)
            m["kernel_tp"] += k_tp
            m["kernel_fp"] += k_fp
            m["kernel_malicious_total"] += len(gt_mods) + len(gt_sys)

            m["overall_tp"] += (pid_tp + k_tp)
            m["overall_fp"] += (pid_fp + k_fp)
            m["overall_total"] += total_indicators
            rt = runtimes[image]
            cfg_rt = rt["extract"] + (rt["rules"] if cfg in ("rules", "both") else 0.0) \
                + (rt["ml"] if cfg in ("ml", "both") else 0.0)
            m["runtime_s"] += cfg_rt
            m["images"] += 1

            image_summary["detections"][cfg] = {
                "detected_pids": sorted(det_pids),
                "detected_modules": sorted(det_mods),
                "detected_syscalls": sorted(det_sys),
                "pid_tp": pid_tp,
                "pid_fp": pid_fp,
                "kernel_tp": k_tp,
                "kernel_fp": k_fp,
            }

        per_image_results.append(image_summary)

    summary = {}
    for cfg, m in metrics.items():
        n_img = m["images"] or 1
        pid_total = m["pid_malicious_total"] or 1
        kernel_total = m["kernel_malicious_total"] or 1
        overall_total = m["overall_total"] or 1

        summary[cfg] = {
            "process_level": {
                "tp": m["pid_tp"],
                "fp": m["pid_fp"],
                "malicious_total": m["pid_malicious_total"],
                "detection_rate": round(m["pid_tp"] / pid_total, 4),
                "fp_per_image": round(m["pid_fp"] / n_img, 4),
            },
            "kernel_rootkit_level": {
                "tp": m["kernel_tp"],
                "fp": m["kernel_fp"],
                "malicious_total": m["kernel_malicious_total"],
                "detection_rate": round(m["kernel_tp"] / kernel_total, 4),
                "fp_per_image": round(m["kernel_fp"] / n_img, 4),
            },
            "overall_indicators": {
                "tp": m["overall_tp"],
                "fp": m["overall_fp"],
                "malicious_total": m["overall_total"],
                "detection_rate": round(m["overall_tp"] / overall_total, 4),
                "fp_per_image": round(m["overall_fp"] / n_img, 4),
            },
            "avg_runtime_s": round(m["runtime_s"] / n_img, 3),
            "total_images": m["images"],
        }

    final_report = {
        "summary": summary,
        "per_image": per_image_results,
    }

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(final_report, indent=2))
    print(json.dumps(final_report, indent=2))
    return final_report


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--symbols", default="symbols")
    ap.add_argument("--model", default="baseline/models/spf.joblib")
    ap.add_argument("--ground-truth", default="eval/ground_truth.yaml")
    ap.add_argument("--out", default="eval/results/metrics.json")
    ap.add_argument("--features", default=None,
                    help="feature-cache dir (eval/features); if set, evaluate from cache without extraction")
    args = ap.parse_args()
    evaluate(args.symbols, args.model, args.ground_truth, args.out, features_dir=args.features)


if __name__ == "__main__":
    main()
