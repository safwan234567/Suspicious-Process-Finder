"""Glue for stage C + D: score every process, keep the ones the model reports,
and explain them. Shared by the CLI, the demo and the evaluation script so all
three use exactly the same detection logic."""

from __future__ import annotations

from spf.explain.shap_explainer import explain
from spf.ml.features import features_for_processes
from spf.ml.model import SPFModel
from spf.models import AnomalyFinding, Process


def find_anomalies(processes: list[Process], model: SPFModel) -> list[AnomalyFinding]:
    pid_features = features_for_processes(processes)
    rows = [f for _pid, f in pid_features]
    findings = []
    for d in model.detect(rows):
        pid, feats = pid_features[d.index]
        contributions, sentence = explain(model, feats, novel=d.novel_features)
        findings.append(AnomalyFinding(
            pid=pid, score=d.score, threshold=float(model.threshold),
            features=feats, contributions=contributions, explanation=sentence,
            novel_features=d.novel_features, reason=d.reason,
        ))
    return findings
