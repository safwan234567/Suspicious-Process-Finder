"""Regression tests for the ML stage, built to mirror the real Kali evaluation
(docs/final_evaluation_evidence.md sections 4.5-4.7):

- the clean baseline never shows unbacked executable memory, /tmp or /dev/shm
  execution, or LD_PRELOAD, so those features are constant (always 0);
- a few desktop daemons (wireplumber, lightdm-gtk-greeter, vmware-vmblock-fuse)
  sit far in the tail on VMA / fd / socket counts;
- the userland agent (PID 5717) looks ordinary on the structural features but
  runs from /dev/shm with LD_PRELOAD set.

With the old model (raw features, 99th-percentile cutoff) the agent scored
below the cutoff and the daemons were flagged on every image.
"""

import numpy as np
import pytest

from spf.explain.shap_explainer import explain
from spf.ml.features import FEATURE_NAMES
from spf.ml.model import SPFModel


def row(vma, ratio, fds, socks, uid_diff=0.0, ux_count=0.0, ux_bytes=0.0, tmp=0.0, preload=0.0):
    return dict(zip(FEATURE_NAMES, [vma, ratio, ux_count, ux_bytes, fds, socks, uid_diff, tmp, preload]))


# real feature values from the evidence document
WIREPLUMBER = row(836, 2.0, 264, 96)
LIGHTDM_GREETER = row(620, 1.5, 100, 4, uid_diff=1.0)
VMBLOCK_FUSE = row(40, 59.55, 12, 0)
USERLAND_AGENT = row(22, 1.1, 4, 1, tmp=1.0, preload=1.0)       # PID 5717
CLEAN_JIT = row(18, 0.67, 3, 0, ux_count=1.0, ux_bytes=1048576.0)  # PID 4631


def kali_baseline(seed: int = 0, n: int = 227) -> list[dict]:
    """~230 clean processes: mostly small daemons and kernel threads, plus the
    three heavy desktop processes. IOC features are always 0."""
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(n):
        if rng.random() < 0.45:                      # kernel threads: no user memory
            rows.append(row(0, 0.0, 0, 0))
            continue
        vma = float(rng.integers(15, 180))
        rows.append(row(
            vma,
            float(rng.uniform(0.2, 3.0)),
            float(rng.integers(3, 40)),
            float(rng.integers(0, 6)),
            uid_diff=float(rng.random() < 0.05),
        ))
    return rows + [WIREPLUMBER, LIGHTDM_GREETER, VMBLOCK_FUSE]


@pytest.fixture(scope="module")
def model():
    return SPFModel().fit(kali_baseline())


def flagged(model, rows):
    return {d.index for d in model.detect(rows)}


def test_invariant_features_recorded(model):
    assert set(model.invariant) == {
        "unbacked_exec_count", "unbacked_exec_bytes", "runs_from_tmp_or_shm", "has_ld_preload",
    }


def test_userland_agent_is_detected(model):
    test_image = kali_baseline(seed=1) + [USERLAND_AGENT]
    hits = model.detect(test_image)
    agent = [d for d in hits if d.index == len(test_image) - 1]
    assert agent, "the /dev/shm + LD_PRELOAD agent must be reported"
    assert set(agent[0].novel_features) == {"runs_from_tmp_or_shm", "has_ld_preload"}


def test_agent_explanation_names_the_unseen_behaviour(model):
    novel = model.novel_features(USERLAND_AGENT)
    _contrib, sentence = explain(model, USERLAND_AGENT, novel=novel)
    assert "/dev/shm" in sentence
    assert "LD_PRELOAD" in sentence
    assert "never seen" in sentence


def test_known_desktop_daemons_are_not_false_positives(model):
    """Re-analysing the same clean machine must not flag its own daemons."""
    assert flagged(model, [WIREPLUMBER, LIGHTDM_GREETER, VMBLOCK_FUSE]) == set()


def test_clean_rerun_has_no_false_positives(model):
    assert flagged(model, kali_baseline(seed=0)) == set()


def test_fresh_clean_image_has_few_false_positives(model):
    """A new draw from the same clean distribution: at most 1 FP in ~230
    processes (the old 99th-percentile cutoff produced 3-4 per image)."""
    assert len(flagged(model, kali_baseline(seed=7))) <= 1


def test_jit_flagged_only_when_baseline_never_had_jit(model):
    # baseline without JIT: unbacked executable memory has never been seen -> reported
    hits = model.detect([CLEAN_JIT])
    assert hits and "unbacked_exec_bytes" in hits[0].novel_features

    # baseline that includes JIT-style processes: the feature varies, the forest
    # learns it, and an ordinary JIT process is no longer reported
    rng = np.random.default_rng(3)
    jit_rows = [
        row(float(rng.integers(15, 60)), float(rng.uniform(0.3, 2.0)), float(rng.integers(3, 30)), 0,
            ux_count=float(rng.integers(1, 4)), ux_bytes=float(rng.integers(1, 64)) * 65536)
        for _ in range(25)
    ]
    with_jit = SPFModel().fit(kali_baseline() + jit_rows)
    assert "unbacked_exec_bytes" not in with_jit.invariant
    assert with_jit.detect([CLEAN_JIT]) == []


def test_old_model_file_is_rejected(tmp_path):
    m = SPFModel().fit(kali_baseline())
    m.version = 1
    path = tmp_path / "old.joblib"
    m.save(path)
    with pytest.raises(SystemExit):
        SPFModel.load(path)


def test_save_load_roundtrip(tmp_path, model):
    explain(model, USERLAND_AGENT, novel=model.novel_features(USERLAND_AGENT))  # populates the cache
    path = tmp_path / "m.joblib"
    model.save(path)
    loaded = SPFModel.load(path)
    assert loaded.threshold == model.threshold
    assert loaded.invariant == model.invariant
    assert {d.index for d in loaded.detect([USERLAND_AGENT])} == {0}
