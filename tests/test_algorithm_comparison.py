"""Locks in the algorithm-comparison conclusions (eval/compare_algorithms.py)
against the cached real feature vectors, so a change to the ML stage that
silently breaks the headline results fails CI.

Skips if the feature cache is absent (it is produced by eval/extract_features.py
from the real memory images and committed under eval/features/).
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FEATURES = ROOT / "eval" / "features"
sys.path.insert(0, str(ROOT / "eval"))

pytestmark = pytest.mark.skipif(
    not (FEATURES / "userland_malware.json").exists(),
    reason="real feature cache not present (run eval/extract_features.py)",
)


@pytest.fixture(scope="module")
def report():
    import compare_algorithms  # noqa: E402
    return compare_algorithms.run(FEATURES)


def by_name(report, needle):
    return next(r for r in report["results"] if needle in r["algorithm"])


def test_pure_isolation_forest_misses_the_agent(report):
    """The proposal's original design (raw features, percentile cutoff) must be
    shown to fail, which is the whole motivation for the fix."""
    assert by_name(report, "pure")["agent_detection_rate"] == 0.0


def test_spf_augmented_if_detects_with_near_zero_fp(report):
    r = by_name(report, "SPF augmentation")
    assert r["agent_detection_rate"] == 1.0
    assert r["false_positives"] <= 2


def test_novelty_only_is_exact(report):
    r = by_name(report, "novelty only")
    assert r["agent_detection_rate"] == 1.0
    assert r["false_positives"] == 0


def test_one_class_svm_is_unusable(report):
    """Either flags almost everything (raw) or detects nothing (log-scaled):
    validates Annex A's rejection for parameter/scale sensitivity."""
    raw = by_name(report, "One-Class SVM (RBF, nu=0.05, raw)")
    log = by_name(report, "One-Class SVM (RBF, nu=0.05, log-scaled)")
    assert raw["false_positives"] > 100 or log["agent_detection_rate"] == 0.0


def test_lof_does_not_beat_spf(report):
    """LOF is unstable across scalings and never matches SPF's detect+low-FP."""
    for scale in ("raw", "log-scaled"):
        r = by_name(report, f"Local Outlier Factor (k=20, {scale})")
        assert not (r["agent_detection_rate"] == 1.0 and r["false_positives"] <= 2)


def test_browser_in_baseline_removes_ld_preload_false_positives(report):
    """Firefox legitimately uses LD_PRELOAD; a baseline without a browser flags
    its children. Adding a browser image drops has_ld_preload from the invariant
    set and removes those false positives, while the agent stays detected."""
    sens = {s["baseline"]: s for s in report["training_data_sensitivity"]}
    no_browser = sens["idle+jit only"]
    with_browser = sens["idle+jit+browser"]
    assert "has_ld_preload" in no_browser["invariant_features"]
    assert no_browser["false_positives"] > 0
    assert "has_ld_preload" not in with_browser["invariant_features"]
    assert with_browser["false_positives"] == 0
    assert with_browser["agent_detected"]
