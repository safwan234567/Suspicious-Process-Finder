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

## Usage (planned)

```bash
spf train   --images baseline/images --symbols symbols --out baseline/models/spf.joblib
spf analyse --image eval/images/infected/sample.lime --symbols symbols --model baseline/models/spf.joblib --mode both
```

`--mode` selects the three evaluation setups: `rules`, `ml` or `both`.

## Evaluation plan

- Clean images: Linux VMs running typical server workloads, including JIT processes (Java, Node.js, a web browser).
- Infected images: the same VMs infected with Diamorphine, Reptile and memory-injection scripts, with every malicious artefact recorded in `eval/ground_truth.yaml`.
- Metrics: detection rate, false-positive rate and run time for rules only, ML only, and both combined.

## Team

Muhammad Irfan Bin Shah Jahan, Mohaamad Nabbhil Bin Mohamed Rafi, Safwan Bin Shahjehan, Adil Amr Bin Qamaruzzaman
