"""Stage C - Isolation Forest trained only on clean baseline processes.

Reports the native anomaly score next to a cutoff taken from the baseline
distribution (e.g. 99th percentile of clean processes). No confidence percentages.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from .features import FEATURE_NAMES


class SPFModel:
    def __init__(self, percentile: float = 99.0, random_state: int = 42):
        self.percentile = percentile
        self.forest = IsolationForest(random_state=random_state)
        self.threshold: float | None = None

    @staticmethod
    def to_matrix(rows: list[dict[str, float]]) -> np.ndarray:
        return np.array([[r[f] for f in FEATURE_NAMES] for r in rows], dtype=float)

    def score(self, rows: list[dict[str, float]]) -> np.ndarray:
        """Anomaly score from Liu et al.: near 1 = strong outlier, well below 0.5 = normal."""
        return -self.forest.score_samples(self.to_matrix(rows))

    def fit(self, clean_rows: list[dict[str, float]]) -> "SPFModel":
        self.forest.fit(self.to_matrix(clean_rows))
        self.threshold = float(np.percentile(self.score(clean_rows), self.percentile))
        return self

    def save(self, path: str | Path) -> None:
        joblib.dump(self, path)

    @staticmethod
    def load(path: str | Path) -> "SPFModel":
        return joblib.load(path)
