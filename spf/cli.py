"""Command-line entry point.

  spf train   --images baseline/images --symbols symbols --out baseline/models/spf.joblib
  spf analyse --image eval/images/infected/x.lime --symbols symbols --model baseline/models/spf.joblib --mode both
"""

from __future__ import annotations

import argparse


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="spf", description="Suspicious Process Finder")
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("train", help="Train the Isolation Forest on clean baseline images")
    t.add_argument("--images", required=True)
    t.add_argument("--symbols", required=True)
    t.add_argument("--out", required=True)
    t.add_argument("--percentile", type=float, default=99.0)

    a = sub.add_parser("analyse", help="Analyse one memory image")
    a.add_argument("--image", required=True)
    a.add_argument("--symbols", required=True)
    a.add_argument("--model")
    a.add_argument("--mode", choices=["rules", "ml", "both"], default="both")
    a.add_argument("--out", default="report.json")

    args = p.parse_args(argv)
    raise NotImplementedError(f"TODO: wire up '{args.cmd}'")


if __name__ == "__main__":
    main()
