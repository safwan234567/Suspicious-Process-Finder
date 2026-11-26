"""Stage C - Isolation Forest trained only on clean baseline processes.

Reports the native anomaly score next to a cutoff taken from the baseline
distribution. No confidence percentages.

Three design points, each fixing a failure seen on the real Kali images
(docs/final_evaluation_evidence.md, sections 4.5-4.7):

1. Log scaling. Count and size features (VMA count, fds, sockets, bytes) are
   heavy-tailed: a desktop daemon such as wireplumber has 800+ VMAs and 96
   sockets. Isolation Forest picks split values uniformly between a feature's
   min and max, so on raw values almost every split lands in the empty tail and
   those daemons dominate the score. log1p() spreads the splits over the range
   where most processes actually sit.

2. Baseline-invariant features. Isolation Forest cannot split on a feature that
   is constant in the training data (min == max), so a feature that was always
   0 on the clean baseline (LD_PRELOAD, running from /dev/shm, unbacked
   executable memory) contributes nothing to the score, whatever its value at
   analysis time. That is why the /dev/shm + LD_PRELOAD agent (PID 5717) scored
   0.47. The model now records which features were invariant on the clean
   baseline and flags any process whose value differs from it: a value that
   never occurred in the clean data is, by definition, unseen behaviour. This
   is still learned from clean data only; nothing is a malware signature.

3. Cutoff. The 99th-percentile cutoff flags 1% of clean processes by
   construction, which is the 3-4 false positives per image seen in the
   evaluation. Because the baseline is known to be clean, the default cutoff is
   now the highest score any clean process received (percentile=100): nothing
   in the clean baseline would be flagged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from .features import FEATURE_NAMES

MODEL_VERSION = 2


@dataclass
class Detection:
    """One process the ML stage decided to report."""

    index: int                                   # position in the rows passed to detect()
    score: float
    novel_features: list[str] = field(default_factory=list)

    @property
    def reason(self) -> str:
        return "novelty" if self.novel_features else "score"


class SPFModel:
    def __init__(self, percentile: float = 100.0, random_state: int = 42, n_estimators: int = 200):
        self.version = MODEL_VERSION
        self.percentile = percentile
        self.forest = IsolationForest(n_estimators=n_estimators, random_state=random_state)
        self.threshold: float | None = None
        self.feature_means: np.ndarray | None = None   # clean-baseline means (raw scale), for explanations
        self.invariant: dict[str, float] = {}          # feature -> the single value it took on the baseline
        self.n_train: int = 0
        self._explainer = None                         # cached shap.TreeExplainer, not saved

    # ---- feature matrix -------------------------------------------------

    @staticmethod
    def to_matrix(rows: list[dict[str, float]]) -> np.ndarray:
        return np.array([[r[f] for f in FEATURE_NAMES] for r in rows], dtype=float)

    @staticmethod
    def transform(X: np.ndarray) -> np.ndarray:
        """log1p on every feature. All features are non-negative counts, sizes,
        ratios or 0/1 flags; log1p keeps 0 at 0 and preserves order."""
        return np.log1p(np.clip(X, 0.0, None))

    # ---- training -------------------------------------------------------

    def fit(self, clean_rows: list[dict[str, float]]) -> "SPFModel":
        X = self.to_matrix(clean_rows)
        if len(X) == 0:
            raise ValueError("cannot train on an empty baseline")
        self.forest.fit(self.transform(X))
        self.feature_means = X.mean(axis=0)
        self.n_train = len(X)
        self.invariant = {
            f: float(X[0, i])
            for i, f in enumerate(FEATURE_NAMES)
            if np.all(X[:, i] == X[0, i])
        }
        self.threshold = float(np.percentile(self.score(clean_rows), self.percentile))
        return self

    # ---- scoring --------------------------------------------------------

    def score(self, rows: list[dict[str, float]]) -> np.ndarray:
        """Anomaly score from Liu et al.: near 1 = strong outlier, well below 0.5 = normal."""
        return -self.forest.score_samples(self.transform(self.to_matrix(rows)))

    def novel_features(self, row: dict[str, float]) -> list[str]:
        """Features that never varied on the clean baseline but differ here."""
        return [f for f, v in self.invariant.items() if row[f] != v]

    def detect(self, rows: list[dict[str, float]]) -> list[Detection]:
        """Processes to report: score strictly above the cutoff, or a value never
        seen on the clean baseline for a feature the forest cannot split on."""
        if not rows:
            return []
        scores = self.score(rows)
        out = []
        for i, (row, s) in enumerate(zip(rows, scores)):
            novel = self.novel_features(row)
            if novel or s > self.threshold:
                out.append(Detection(index=i, score=float(s), novel_features=novel))
        return out

    # ---- persistence ----------------------------------------------------

    def __getstate__(self):
        state = self.__dict__.copy()
        state["_explainer"] = None
        return state

    def save(self, path: str | Path) -> None:
        joblib.dump(self, path)

    @staticmethod
    def load(path: str | Path) -> "SPFModel":
        model = joblib.load(path)
        if getattr(model, "version", 1) < MODEL_VERSION:
            raise SystemExit(
                f"{path} was trained by an older SPF (no log scaling / invariant features). "
                "Retrain it with `spf train`."
            )
        return model
