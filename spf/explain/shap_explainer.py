"""Stage D - TreeSHAP attribution and plain-language explanations.

Only applied to processes whose score exceeds the baseline threshold.
"""

from __future__ import annotations

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


def explain(model: SPFModel, features: dict[str, float], top_k: int = 3) -> tuple[dict[str, float], str]:
    """Return (per-feature SHAP contributions, plain-language sentence)."""
    raise NotImplementedError("TODO: shap.TreeExplainer(model.forest) and build the sentence from PHRASES")
