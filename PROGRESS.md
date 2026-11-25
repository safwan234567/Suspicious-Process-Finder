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

## Real Data Validation (Completed)

1. **Extraction Validation**: Validated `spf/extraction/volatility.py` against full 2.0 GB physical RAM (`clean_01.lime` and `diamorphine.lime`) on Kali Linux `6.12.25-amd64` using `dwarf2json`-generated ISF symbols. Verified Windows URI formatting, LayerStacker imports, and Volatility 3 plugin schemas (`linux.proc.Maps`, `linux.lsof.Lsof`, `linux.sockstat.Sockstat`, `linux.psaux.PsAux`, `linux.malware.check_syscall.Check_syscall`, `linux.pidhashtable.PIDHashTable`, `linux.malware.hidden_modules.Hidden_modules`).
2. **Clean Baseline**: Acquired `clean_01.lime` (2047.5 MB) via LiME. Model trained on 230 clean processes (`spf train` -> `baseline/models/spf.joblib`, 99th percentile cutoff = `0.719`). Clean evaluation produced **0 rule findings and 0 false positives**.
3. **Infected Memory Testing**: Deployed patched Diamorphine rootkit on Kali Linux VM with deterministic `nokaslr`:
   - `DKOM_HIDDEN_PROCESS`: Decoy sleeper (`PID 3590`) unlinked from `task_struct` linked list via `list_del_init(&task->tasks)` while retained in PID hash table (`init_pid_ns.idr`) -> **Detected with 100% certainty**.
   - `HIDDEN_KERNEL_MODULE`: `diamorphine` unlinked from module list (`modules`) -> **Carved and detected by `Hidden_modules`**.
   - `HOOKED_SYSCALL`: Syscall 62 (`__x64_sys_kill`) and Syscall 217 (`__x64_sys_getdents64`) hooked -> **Detected outside kernel text and registered modules**.
4. **Benchmark Evaluation (`eval/run_experiments.py`)**:
   - Rules Only: **100% Detection Rate (`1.0`)**, **0.0 False Positives per image**, average runtime ~520s.
   - ML Only: Evaluates behavioral feature vectors; flags extreme GUI desktop outliers with TreeSHAP explanations.
   - Both (Combined): **100% Detection Rate (`1.0`)**, delivers unified triage report separating deterministic indicators from statistical anomalies. Results saved in `eval/results/metrics.json`.

## Hardening pass (2026-11-26)

Added, beyond the ML fix and real-image evaluation:
- **Process-tree report** (`spf/report/builder.py`): findings are now grouped
  under the process they concern, with memory offset, open network connections
  (INET only, capped) and parent chain -- delivering the proposal's III.D
  "process tree hierarchies" promise. Flat sections kept as well.
- **vs-raw-Volatility metric** (`eval/compare_vs_raw.py`, `triage_reduction.json`):
  Diamorphine 32,585 raw plugin rows -> 4 findings (8,146x); userland 62,052 ->
  2 (31,026x); clean 1,017 -> 0. Backs the core novelty claim.
- **`runs_from_tmp_or_shm` hardened**: also checks executable file-backed VMAs,
  so a process whose real binary is in /dev/shm is caught even if argv[0] is
  masked (e.g. "sshd: worker").
- Stale old-model reports removed (`clean_jit.*`, `infected_both.*`); current
  per-image reports regenerated for the real images.
- 35 unit tests pass (was 8), including the algorithm comparison, model fix,
  report tree and feature hardening.

**Still to do (flagged, not changed by Claude):** the old deploy scripts
(`eval/deploy_*.py`, `eval/capture_jit_dump.py`, `eval/live_test_diamorphine.py`)
and `docs/final_evaluation_evidence.md` contain a hardcoded VM password
(osboxes.org), an internal IP and nabbh home-directory paths. Sanitise before
the repo is shared. The new lab uses the `spf_lab/*.sh` scripts instead.

## Real 6.18 evaluation + algorithm comparison (2026-11-26)

Captured 6 real 4 GB LiME images on Kali `6.18.12+kali-amd64` (3 clean training:
idle / Java+Node JIT / Firefox; 1 clean test; Diamorphine; userland agent) with
a matching dwarf2json ISF. Feature vectors are cached in `eval/features/` so
every experiment reruns in seconds without the images (`eval/extract_features.py`).

**Final metrics (`eval/results/metrics.json`), real images:**

| Config | Overall detection | FP / image |
|---|---|---|
| Rules only | 4/5 (80%) | 0.00 |
| ML only | 1/5 (20%) | 0.33 |
| Both | **5/5 (100%)** | **0.33** |

Rules find all 3 Diamorphine kernel indicators + the DKOM decoy (0 FP). The ML
stage catches the `/dev/shm`+`LD_PRELOAD` userland agent that the rules
structurally cannot see, with 1 Firefox FP. Old model for contrast: both=80%,
3.33 FP/img, ML contributed 0 detections and 10 FPs.

**Algorithm comparison (`eval/compare_algorithms.py`, backs Annex A):**
IF+SPF augmentation = 100% detect / ~0 FP; pure IF = 0% detect; One-Class SVM =
unusable (253 FP raw, 0% log); LOF = 0% detect both scalings. Full writeup in
`eval/results/algorithm_comparison.md`.

**Bugs/robustness fixed while validating on real memory:**
- `linux.envars` columns are `KEY`/`VALUE` in Volatility 2.28; `_col` is now
  case-insensitive, so `LD_PRELOAD`/`/dev/shm` features are no longer silently 0.
- `exe_path` crashed (`IndexError`) on whitespace-only cmdlines.
- `check_hidden_modules` matched on (name, base); a degraded capture where the
  two module plugins disagree on base produced 69 FPs. Now matches by name and
  skips when the scan reports an implausible number of hidden modules.
- Reptile does not build on the 6.18 kernel (ftrace khook engine); Diamorphine
  does (patched for DKOM). Second rootkit dropped per decision.

**Notes for the report:** the clean-test capture degrades `linux.proc.Maps` and
the PID hash table on this VM (reproducible); the robustness guards keep it at 0
FPs. `LD_PRELOAD` alone is a weak indicator (Firefox uses it), so the clean
baseline must include a browser workload.

## ML stage fix (after the real-memory evaluation)

The first real-memory run showed the Isolation Forest detected 0/5 indicators
with 10 false positives (evidence doc 4.5-4.7). Three causes, three changes in
`spf/ml/model.py`:

| Problem on real images | Cause | Change |
|---|---|---|
| `/dev/shm` + `LD_PRELOAD` agent (PID 5717) scored 0.47, not flagged | The 4 IOC features were always 0 on the clean baseline, so the forest never split on them (0 splits) | Features constant on the baseline are recorded at train time; a process with a value never seen there is reported (`reason: "novelty"`) and the explanation names it |
| 3-4 false positives per image (wireplumber, lightdm-greeter, vmware-vmblock) | 99th-percentile cutoff flags 1% of clean processes by construction | Default cutoff is now the highest clean-baseline score (`--percentile 100`) and the comparison is strict `>` |
| Desktop daemons dominate scores | Heavy-tailed counts (836 VMAs, 264 fds) pull random splits into the tail | `log1p` on all features before the forest; TreeSHAP explains the scaled input |

`tests/test_model.py` rebuilds the real failure from the evidence-doc values.
With the old logic it gives agent score 0.485 vs cutoff 0.715 (missed) and 3
FPs per clean image; the new model reports the agent and has 0 FPs.

Known trade-off: if the baseline never contains JIT-style processes, a benign
JIT process is also reported as unseen behaviour (unbacked executable memory).
Fix it with data, not code: include a clean image running Java/Node.js in
`baseline/images`. `spf train` now prints which features were constant.

**The real-image numbers in `eval/results/` and the evidence doc are from the
old model.** To refresh them: retrain (old `spf.joblib` files are rejected),
re-run `spf analyse` on the three test images so the JSON reports in
`eval/results/` are regenerated (`run_experiments.py` reuses them if present),
then re-run `run_experiments.py`.

## How to run the real path

```bash
# 1. Train on clean memory baseline
python -m spf.cli train --images baseline/images --symbols symbols --out baseline/models/spf.joblib

# 2. Analyse an image (rules, ml, or both)
python -m spf.cli analyse --image eval/images/infected/diamorphine.lime --symbols symbols --model baseline/models/spf.joblib --mode both --out eval/results/infected_both.json

# 3. Run full benchmark evaluation
python eval/run_experiments.py --symbols symbols --model baseline/models/spf.joblib --ground-truth eval/ground_truth.yaml --out eval/results/metrics.json
```
