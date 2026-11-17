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
2. **Clean Baseline**: Acquired `clean_01.lime` (2047.5 MB) via LiME. Model trained on 230 clean processes (`spf train` -> `baseline/models/spf.joblib`, 99th percentile cutoff = `0.719`). On the unseen clean image (`clean_jit.lime`) the rule stage produced **0 findings**; the ML stage flagged **3 benign desktop processes** (false positives, see below).
3. **Infected Memory Testing**: Deployed patched Diamorphine rootkit on Kali Linux VM with deterministic `nokaslr`:
   - `DKOM_HIDDEN_PROCESS`: Decoy sleeper (`PID 3590`) unlinked from `task_struct` linked list via `list_del_init(&task->tasks)` while retained in PID hash table (`init_pid_ns.idr`) -> **Detected** (reported as a definitive rule finding).
   - `HIDDEN_KERNEL_MODULE`: `diamorphine` unlinked from module list (`modules`) -> **Carved and detected by `Hidden_modules`**.
   - `HOOKED_SYSCALL`: Syscall 62 (`__x64_sys_kill`) and Syscall 217 (`__x64_sys_getdents64`) hooked -> **Detected outside kernel text and registered modules**.
4. **Benchmark Evaluation (`eval/run_experiments.py`)**:
   Three test images: `clean_jit.lime`, `diamorphine.lime`, `userland_malware.lime`. 5 malicious indicators in total (2 malicious PIDs, 1 hidden module, 2 hooked syscalls).
   - Rules Only: **80% overall detection (4/5)**, 0 false positives. 100% (3/3) at kernel level, 50% (1/2) at process level: the userland malware (PID 5717) is not detected because it does not touch kernel structures. Average runtime ~521s per image.
   - ML Only: **0% detection (0/5)**, **10 false positives** (3.33 per image), all benign desktop/VM processes (`wireplumber`, `lightdm-gtk-greeter`, `vmware-vmblock-fuse`). The userland malware scored 0.4719, below the 0.7187 cutoff. Main cause: in the single clean training image, `unbacked_exec_count`, `unbacked_exec_bytes`, `runs_from_tmp_or_shm` and `has_ld_preload` are always 0, so the Isolation Forest never splits on them.
   - Both (Combined): **80% overall detection (4/5)**, 10 false positives. The ML stage added no detections beyond the rules. Results saved in `eval/results/metrics.json`.

## How to run the real path

```bash
# 1. Train on clean memory baseline
python -m spf.cli train --images baseline/images --symbols symbols --out baseline/models/spf.joblib

# 2. Analyse an image (rules, ml, or both)
python -m spf.cli analyse --image eval/images/infected/diamorphine.lime --symbols symbols --model baseline/models/spf.joblib --mode both --out eval/results/infected_both.json

# 3. Run full benchmark evaluation
python eval/run_experiments.py --symbols symbols --model baseline/models/spf.joblib --ground-truth eval/ground_truth.yaml --out eval/results/metrics.json
```
