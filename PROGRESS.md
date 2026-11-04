# SPF progress note

Summary of what moved from stub to working. The pipeline now runs end to end
(rules + Isolation Forest + TreeSHAP + report) on synthetic evidence with no
memory image, and the CLI/extraction are fully wired for real images.

## Status

| Module | Before | Now |
|---|---|---|
| `spf/models.py` | done | unchanged |
| `spf/rules/checks.py` | done | unchanged |
| `spf/ml/features.py` | done | added `features_for_processes()` helper (resolves each process's parent UID) |
| `spf/ml/model.py` | done | stores clean-baseline feature means (used by explanations); unchanged otherwise |
| `spf/explain/shap_explainer.py` | stub | **implemented**: TreeSHAP ranking + plain-language sentence, with a baseline-deviation fallback when shap is absent |
| `spf/report/builder.py` | stub | **implemented**: `build_report()` returns the JSON dict; added `render_html()` (standard library only, no new dependency) |
| `spf/cli.py` | stub | **implemented**: `train` and `analyse` fully wired, writes report.json + report.html |
| `spf/extraction/volatility.py` | stub | **implemented**: full Volatility 3 API call filling `MemoryEvidence`. Needs a real image to validate (column names marked for confirmation) |
| `eval/run_experiments.py` | stub | **implemented**: rules vs ml vs both, detection rate / false positives / runtime vs `ground_truth.yaml` |

## Tests

`pytest` -> 8 passing (the original 7 plus `tests/test_pipeline.py`, a full
rules + ml + explain + report run on synthetic evidence).

## See it work now (no image needed)

```
pip install -e ".[dev]"
python examples/demo_report.py        # writes examples/out/report.{json,html}
```

The demo trains on 400 synthetic clean processes, then flags a DKOM-hidden
process, a hidden Diamorphine module and a hooked getdents64 syscall (rule
stage) plus two injected processes (ML stage), each with an explanation.

## What still needs real data (not code)

1. Validate `extraction.py` against one clean `.lime` + its ISF. The plugin
   names are right; confirm the column names with `python -m volatility3.cli
   -f IMAGE <plugin>` where marked TODO, and check `kernel_text` resolves
   (needed by the syscall-hook rule).
2. Capture the clean and infected images (Diamorphine, Reptile, injection
   script), run `spf train` on the clean ones, and fill `eval/ground_truth.yaml`.
3. Run `eval/run_experiments.py` for the three-configuration comparison.

## How to run the real path once images exist

```
python -m spf.cli train   --images baseline/images --symbols symbols --out baseline/models/spf.joblib
python -m spf.cli analyse --image eval/images/infected/x.lime --symbols symbols --model baseline/models/spf.joblib --mode both
```
