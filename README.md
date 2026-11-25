# SPF: Suspicious Process Finder

An unsupervised anomaly detector for Linux memory forensics (ICT3215 PA, Group 13).

SPF is an offline triage tool for acquired Linux memory images (`.raw` or `.lime`). It sits on top of Volatility 3 and runs four stages:

| Stage | Module | What it does |
|---|---|---|
| A. Extraction | `spf/extraction` | Calls the Volatility 3 API to collect the task list, PID hash table, VMAs and permissions, file descriptors, sockets, modules, command lines and environment. |
| B. Rules | `spf/rules` | Three definitive checks: DKOM-hidden processes, hidden kernel modules, hooked syscalls. Reported with certainty. |
| C. Machine learning | `spf/ml` | Isolation Forest trained only on clean baseline processes. Reports the raw score next to a baseline percentile cutoff. |
| D. Explain and report | `spf/explain`, `spf/report` | TreeSHAP attribution turned into plain-language reasons, plus one unified report grouped by process tree. |

## Repository layout

```
spf/            source code, one sub-package per stage
baseline/       clean images (not committed) and trained models
eval/           ground-truth images (not committed), experiment script, results
symbols/        Volatility 3 kernel symbol tables (ISF .json.xz from dwarf2json)
tests/          unit tests
docs/           proposal and reports
```

Memory images are large and are excluded by `.gitignore`. Share them outside git.

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows; use `source .venv/bin/activate` on Linux
pip install -e ".[dev]"
```

Full instructions, including capturing an image and building the Volatility
symbol table, are in [docs/USER_MANUAL.md](docs/USER_MANUAL.md).

## Usage

```bash
# see every stage with no memory image
python examples/demo_report.py          # -> examples/out/report.html

# train the model on clean baseline images
spf train   --images baseline/images --symbols symbols --out baseline/models/spf.joblib

# analyse an image (rules, ml, or both)
spf analyse --image eval/images/infected/diamorphine.lime --symbols symbols \
            --model baseline/models/spf.joblib --mode both --out report.json
```

`--mode` selects `rules`, `ml` or `both`. The report lists each flagged process
with its findings, memory offset and connections; see the manual for how to read
it.

## Evaluation

Evaluated on real memory images captured from Kali `6.18.12+kali-amd64` (idle,
Java/Node JIT and Firefox clean baselines; Diamorphine rootkit; a `/dev/shm` +
`LD_PRELOAD` userland agent). Per-process feature vectors are cached in
`eval/features/`, so the experiments reproduce in seconds without the images:

```bash
python eval/run_experiments.py    --features eval/features --model baseline/models/spf.joblib
python eval/compare_algorithms.py --features eval/features     # IF vs One-Class SVM vs LOF
python eval/compare_vs_raw.py     --features eval/features --model baseline/models/spf.joblib
```

Headline results (full detail in `eval/results/` and `PROGRESS.md`):

- Combined rules + ML: **5/5 ground-truth indicators, 0.33 false positives/image**.
- The rule stage finds all three Diamorphine indicators with zero false
  positives; the ML stage catches the userland agent the rules cannot see.
- Algorithm comparison confirms the design choice: Isolation Forest (with SPF's
  augmentation) detects with ~0 false positives, while One-Class SVM and LOF do
  not — backing the proposal's Annex A with evidence.
- SPF reduces tens of thousands of raw Volatility plugin rows to a handful of
  ranked, explained findings (8,000–31,000x fewer items to review).

## Team

Muhammad Irfan Bin Shah Jahan, Mohaamad Nabbhil Bin Mohamed Rafi, Safwan Bin Shahjehan, Adil Amr Bin Qamaruzzaman
