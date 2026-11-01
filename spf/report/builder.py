"""Stage D - unified report.

Rule findings (certain) and anomaly findings (scored) are kept in separate
sections. Related findings are grouped under the process tree, with memory
offsets and open connections.
"""

from __future__ import annotations

from spf.models import AnomalyFinding, MemoryEvidence, RuleFinding


def build_report(
    ev: MemoryEvidence,
    rule_findings: list[RuleFinding],
    anomaly_findings: list[AnomalyFinding],
) -> dict:
    raise NotImplementedError("TODO: group findings by process tree and render the report")
