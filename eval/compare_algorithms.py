"""Empirical comparison of unsupervised anomaly-detection algorithms on the real
SPF feature vectors, to back Annex A of the proposal with evidence rather than
argument.

It answers two questions:
  1. Among Isolation Forest, One-Class SVM and Local Outlier Factor, which best
     fits Linux memory triage on identical feature vectors? (algorithm choice)
  2. Does the SPF augmentation (log scaling + baseline-invariant novelty + a
     max-score cutoff) matter, or is a plain detector enough? (the fix)

Protocol (unsupervised, trained on clean data only):
  - TRAIN  on clean baseline images (idle + JIT), clean processes only.
  - TEST   for false positives on a HELD-OUT clean image (browser) the model
           never saw, and for detection on the userland-malware image, whose
           one malicious process (the /dev/shm + LD_PRELOAD agent) is the only
           behaviourally ML-visible threat (the Diamorphine decoy is a plain
           sleeper caught by the rule stage, not by behaviour).

Reads the feature cache written by eval/extract_features.py; no memory image is
touched here, so the comparison is fast and reproducible.

  python eval/compare_algorithms.py --features eval/features --out eval/results/algorithm_comparison.json
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM

from spf.ml.features import FEATURE_NAMES

# which cached images play which role
TRAIN_IMAGES = ["clean_train_01_idle", "clean_train_02_jit", "clean_train_03_browser"]
MALWARE_IMAGE = "userland_malware"            # contains the agent among 259 benign processes
MALICIOUS_PID = 2508                          # the /dev/shm + LD_PRELOAD agent (ground truth)
N_SEEDS = 10                                  # repeat randomised models to report variance
# training-data sensitivity: does the clean baseline need a browser workload?
SENSITIVITY_SETS = {
    "idle+jit only": ["clean_train_01_idle", "clean_train_02_jit"],
    "idle+jit+browser": ["clean_train_01_idle", "clean_train_02_jit", "clean_train_03_browser"],
}


def load(features_dir: Path, stem: str):
    d = json.loads((features_dir / f"{stem}.json").read_text())
    pids = [p["pid"] for p in d["processes"]]
    X = np.array([[p["features"][f] for f in FEATURE_NAMES] for p in d["processes"]], float)
    return pids, X


def log_scale(X):
    return np.log1p(np.clip(X, 0.0, None))


def invariant_novelty(train_X, test_X):
    """SPF's baseline-invariant rule: flag a test row whose value differs from a
    feature that never varied across the clean training set."""
    const = {i: train_X[0, i] for i in range(train_X.shape[1]) if np.all(train_X[:, i] == train_X[0, i])}
    return np.array([any(row[i] != v for i, v in const.items()) for row in test_X])


def fp_and_detect(flags, mal_index):
    """(agent detected?, false positives) for a boolean flag array over the
    malware image. Every process except the agent is benign, so every other flag
    is a false positive."""
    detected = bool(flags[mal_index])
    return detected, int(flags.sum() - (1 if detected else 0))


def run(features_dir: Path):
    # TRAIN on all clean workloads (idle + JIT + browser), the real deployment
    # baseline. TEST on the userland-malware image: PID 2508 is the one
    # ML-visible threat; the other 259 processes are benign, so any flag on them
    # is a false positive on unseen clean behaviour.
    train_X = np.vstack([load(features_dir, s)[1] for s in TRAIN_IMAGES])
    mal_pids, mal_X = load(features_dir, MALWARE_IMAGE)
    mal_index = mal_pids.index(MALICIOUS_PID)

    results = []

    def with_seeds(make_flags):
        """Run a randomised model N_SEEDS times; average detection and FP."""
        out = [make_flags(seed) for seed in range(N_SEEDS)]  # (detected, fp, fit_s, score_s)
        return {
            "agent_detection_rate": round(float(np.mean([o[0] for o in out])), 3),
            "false_positives": round(float(np.mean([o[1] for o in out])), 2),
            "fit_ms": round(float(np.mean([o[2] for o in out])) * 1000, 1),
            "score_ms": round(float(np.mean([o[3] for o in out])) * 1000, 1),
        }

    # ---- Isolation Forest, pure: raw features, 99th-percentile cutoff (original design) ----
    def if_pure(seed):
        t = time.perf_counter(); f = IsolationForest(n_estimators=200, random_state=seed).fit(train_X)
        fit_s = time.perf_counter() - t
        thr = np.percentile(-f.score_samples(train_X), 99)
        t = time.perf_counter(); flags = -f.score_samples(mal_X) > thr
        det, fp = fp_and_detect(flags, mal_index)
        return det, fp, fit_s, time.perf_counter() - t
    results.append({"algorithm": "Isolation Forest (pure: raw features, 99th pct cutoff)", **with_seeds(if_pure)})

    # ---- Isolation Forest + SPF augmentation: log scaling + max cutoff + novelty ----
    nov_m = invariant_novelty(train_X, mal_X)
    def if_spf(seed):
        lt, lm = log_scale(train_X), log_scale(mal_X)
        t = time.perf_counter(); f = IsolationForest(n_estimators=200, random_state=seed).fit(lt)
        fit_s = time.perf_counter() - t
        thr = (-f.score_samples(lt)).max()
        t = time.perf_counter(); flags = (-f.score_samples(lm) > thr) | nov_m
        det, fp = fp_and_detect(flags, mal_index)
        return det, fp, fit_s, time.perf_counter() - t
    results.append({"algorithm": "Isolation Forest + SPF augmentation (log + max cutoff + novelty)", **with_seeds(if_spf)})

    # ---- One-Class SVM (deterministic), raw and log-scaled ----
    for scale_name, tf in (("raw", lambda a: a), ("log-scaled", log_scale)):
        t = time.perf_counter(); oc = OneClassSVM(kernel="rbf", nu=0.05, gamma="scale").fit(tf(train_X))
        fit_s = time.perf_counter() - t
        t = time.perf_counter(); flags = oc.predict(tf(mal_X)) == -1
        score_s = time.perf_counter() - t
        det, fp = fp_and_detect(flags, mal_index)
        results.append({"algorithm": f"One-Class SVM (RBF, nu=0.05, {scale_name})",
                        "agent_detection_rate": 1.0 if det else 0.0, "false_positives": fp,
                        "fit_ms": round(fit_s * 1000, 1), "score_ms": round(score_s * 1000, 1)})

    # ---- Local Outlier Factor (novelty mode, deterministic), raw and log-scaled ----
    for scale_name, tf in (("raw", lambda a: a), ("log-scaled", log_scale)):
        t = time.perf_counter(); lof = LocalOutlierFactor(n_neighbors=20, novelty=True).fit(tf(train_X))
        fit_s = time.perf_counter() - t
        t = time.perf_counter(); flags = lof.predict(tf(mal_X)) == -1
        score_s = time.perf_counter() - t
        det, fp = fp_and_detect(flags, mal_index)
        results.append({"algorithm": f"Local Outlier Factor (k=20, {scale_name})",
                        "agent_detection_rate": 1.0 if det else 0.0, "false_positives": fp,
                        "fit_ms": round(fit_s * 1000, 1), "score_ms": round(score_s * 1000, 1)})

    # ---- Ablation: the baseline-invariant novelty rule alone, no forest ----
    det, fp = fp_and_detect(nov_m, mal_index)
    results.append({"algorithm": "Baseline-invariant novelty only (no model)",
                    "agent_detection_rate": 1.0 if det else 0.0, "false_positives": fp,
                    "fit_ms": 0.0, "score_ms": 0.0})

    # ---- Training-data sensitivity: does the clean baseline need a browser? ----
    # Firefox child processes legitimately set LD_PRELOAD. If the baseline has no
    # browser, has_ld_preload is constant 0 and the novelty rule flags every
    # Firefox child. Adding a browser image to training removes that feature from
    # the invariant set (the agent is still caught by /dev/shm execution).
    sensitivity = []
    for label, sets in SENSITIVITY_SETS.items():
        tr = np.vstack([load(features_dir, s)[1] for s in sets])
        nm = invariant_novelty(tr, mal_X)
        const = [FEATURE_NAMES[i] for i in range(tr.shape[1]) if np.all(tr[:, i] == tr[0, i])]
        det, fp = fp_and_detect(nm, mal_index)
        sensitivity.append({"baseline": label, "invariant_features": const,
                            "agent_detected": det, "false_positives": fp})

    return {
        "protocol": {
            "train_images": TRAIN_IMAGES,
            "malware_image": MALWARE_IMAGE,
            "malicious_pid": MALICIOUS_PID,
            "train_processes": int(len(train_X)),
            "malware_processes": int(len(mal_X)),
            "benign_in_malware_image": int(len(mal_X) - 1),
            "seeds": N_SEEDS,
        },
        "results": results,
        "training_data_sensitivity": sensitivity,
    }


def as_table(report: dict) -> str:
    p = report["protocol"]
    head = f"{'Algorithm':<60} {'Detect':>7} {'FalsePos':>9} {'fit ms':>7} {'score ms':>9}"
    lines = [head, "-" * len(head)]
    for r in report["results"]:
        det = f"{r['agent_detection_rate']:.0%}"
        lines.append(f"{r['algorithm']:<60} {det:>7} {r['false_positives']:>9} "
                     f"{r['fit_ms']:>7} {r['score_ms']:>9}")
    lines.append("")
    lines.append(f"Trained on {p['train_processes']} clean processes ({'+'.join(p['train_images'])}). "
                 f"Tested on {p['malware_image']}: Detect = agent PID {p['malicious_pid']} found; "
                 f"FalsePos = flags among {p['benign_in_malware_image']} benign processes "
                 f"(IF rows: mean over {p['seeds']} random seeds).")
    lines.append("")
    lines.append("Training-data sensitivity (novelty rule):")
    for s in report["training_data_sensitivity"]:
        lines.append(f"  baseline {s['baseline']:<20} invariant={s['invariant_features']}  "
                     f"agent_detected={s['agent_detected']}  false_positives={s['false_positives']}")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", default="eval/features")
    ap.add_argument("--out", default="eval/results/algorithm_comparison.json")
    args = ap.parse_args()
    report = run(Path(args.features))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2,
                              default=lambda o: o.item() if hasattr(o, "item") else str(o)))
    print(as_table(report))
    print(f"\n[+] written -> {args.out}")


if __name__ == "__main__":
    main()
