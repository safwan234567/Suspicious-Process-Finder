"""Stage D - TreeSHAP attribution and plain-language explanations.

Only applied to processes the ML stage reports (score above the cutoff, or a
value never seen on the clean baseline).

Features that never varied on the clean baseline are named first: Isolation
Forest cannot split on them, so TreeSHAP gives them exactly 0 and they would
otherwise never appear in the sentence (evaluation section 4.5).

Uses shap.TreeExplainer on the Isolation Forest when the shap package is
available (exact per-feature attribution, proposal section III.D). When shap
is not installed it falls back to how far each feature sits above the clean
baseline mean stored on the model, so SPF still explains itself.
"""

from __future__ import annotations

import numpy as np

from spf.ml.features import FEATURE_NAMES
from spf.ml.model import SPFModel

# Plain-language phrasing per feature, used when that feature pushes the score up.
PHRASES = {
    "vma_count": "an unusually high number of memory regions",
    "anon_to_file_ratio": "an unusually high ratio of anonymous memory",
    "unbacked_exec_count": "{value:.0f} executable memory region(s) unbacked by disk files",
    "unbacked_exec_bytes": "a large amount of executable memory unbacked by disk files",
    "fd_count": "an unusual number of open file descriptors",
    "socket_count": "an unusual number of open sockets",
    "uid_differs_from_parent": "a UID different from its parent process",
    "runs_from_tmp_or_shm": "execution from /tmp or /dev/shm",
    "has_ld_preload": "LD_PRELOAD set in its environment",
}


def _contributions(model: SPFModel, x: np.ndarray) -> tuple[np.ndarray, str]:
    """Return (per-feature contribution array, method name) for one feature row x."""
    try:
        import shap

        if getattr(model, "_explainer", None) is None:
            model._explainer = shap.TreeExplainer(model.forest)
        # the forest was trained on log-scaled features, so explain that input
        vals = np.asarray(model._explainer.shap_values(model.transform(x.reshape(1, -1))))[0]
        return vals, "TreeSHAP"
    except Exception:
        base = model.feature_means if model.feature_means is not None else np.zeros_like(x)
        return x - base, "baseline-deviation"


def explain(
    model: SPFModel,
    features: dict[str, float],
    top_k: int = 3,
    novel: list[str] | None = None,
) -> tuple[dict[str, float], str]:
    """Return (per-feature contributions, plain-language sentence).

    `novel` lists features whose value never occurred on the clean baseline;
    they lead the sentence, followed by up to top_k TreeSHAP-ranked features."""
    novel = list(novel or [])
    x = np.array([features[f] for f in FEATURE_NAMES], dtype=float)
    contrib, _method = _contributions(model, x)
    contributions = {f: float(c) for f, c in zip(FEATURE_NAMES, contrib)}

    # shap's sign convention on Isolation Forest is not intuitive, so we use the
    # contribution MAGNITUDE to rank which features mattered most to this
    # prediction, then keep only the ones the process is actually elevated on
    # (above the clean baseline, or set for the binary flags). Every phrase
    # describes an elevated/present condition, so this keeps them truthful.
    means = model.feature_means
    mean_by = {f: (float(means[i]) if means is not None else 0.0) for i, f in enumerate(FEATURE_NAMES)}
    BINARY = {"runs_from_tmp_or_shm", "has_ld_preload", "uid_differs_from_parent"}

    def elevated(f: str) -> bool:
        if f in BINARY:
            return features[f] >= 1.0
        return features[f] > mean_by[f]

    parts = []
    if novel:
        n = getattr(model, "n_train", 0)
        where = f"any of the {n} clean baseline processes" if n else "the clean baseline"
        unseen = [PHRASES[f].format(value=features.get(f, 0.0)) for f in novel]
        parts.append("; ".join(unseen) + f" (never seen in {where})")

    ranked = sorted(FEATURE_NAMES, key=lambda f: abs(contributions[f]), reverse=True)
    extra = 0
    for f in ranked:
        if extra >= top_k:
            break
        if f not in novel and elevated(f) and contributions[f] != 0.0:
            parts.append(PHRASES[f].format(value=features.get(f, 0.0)))
            extra += 1

    if parts:
        sentence = "Flagged due to " + "; ".join(parts) + "."
    else:
        sentence = "Flagged as an outlier against the clean baseline."
    return contributions, sentence
