"""Evaluation: rules only vs ML only vs both, against ground-truth images.

Metrics: detection rate, false-positive rate, run time.
Ground truth for each infected image is recorded in eval/ground_truth.yaml.
"""

from __future__ import annotations

CONFIGURATIONS = ["rules", "ml", "both"]


def main() -> None:
    raise NotImplementedError("TODO: run spf on every image in each configuration and score against ground_truth.yaml")


if __name__ == "__main__":
    main()
