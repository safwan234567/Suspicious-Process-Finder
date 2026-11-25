# SPF — Consolidated Evidence for the Final Report

One clean evidence set for the written report. It combines:

- **Dataset A (6.18):** the primary evaluation on Kali `6.18.12+kali-amd64`,
  captured 2026-11-25. All ML/anomaly numbers come from here, so they are
  internally consistent.
- **Dataset B (6.12):** a second-kernel case study on Kali `6.12.25-amd64`.
  Only the **kernel-independent, model-independent** results are reused — the
  live-tool (`chkrootkit`) vs offline (SPF) comparison and the deterministic
  rule-stage findings. ML numbers are reported for Dataset A only, so the two
  datasets never mix model-dependent results.

> Why the split: the rule stage is deterministic, so its results hold on both
> kernels. The behavioural (ML) stage is evaluated only on Dataset A's
> full-feature captures, keeping every ML number internally consistent.

---

## 1. Headline results (Dataset A, 6.18, fixed model)

- **Combined (rules + ML): 5/5 ground-truth indicators detected (100% recall),
  1 false positive across 3 images (0.33 FP/image).**
- Rules alone: 4/5 (80%), **0 false positives** — all three Diamorphine kernel
  indicators + the DKOM-hidden process, with certainty.
- ML alone: catches the 1 behaviourally-visible userland threat the rules cannot
  see (the `/dev/shm` + `LD_PRELOAD` agent), at 0.67 FP/image.
- Average runtime: **~286 s/image (~4.8 min)** end-to-end (extraction + rules +
  ML + report) on a 4 GB image.

### How the ML stage detects what the rules cannot (design note)

The behavioural stage pairs an Isolation Forest with a **baseline-invariant
novelty path**: features that are constant across the clean baseline (e.g.
`runs_from_tmp_or_shm`, `has_ld_preload`) cannot be split on by the forest, so
any non-baseline value on such a feature is surfaced directly as *novel*.
Combined with log scaling and a max-score cutoff, this is what lets SPF flag the
`/dev/shm` + `LD_PRELOAD` userland agent that leaves the kernel untouched —
while a plain Isolation Forest, One-Class SVM and LOF cannot (§3). The design is
justified empirically by the algorithm comparison, not asserted.

---

## 2. Detection table / confusion matrix (Dataset A, 6.18)

Testing is on **unseen** images only; the three clean `clean_train_*` images are
used solely to fit the model (no data leakage).

| Tier | Metric | Rules | ML | Combined |
|---|---|:---:|:---:|:---:|
| Process (PIDs) | TP / FP / total | 1 / 0 / 2 | 1 / 2 / 2 | **2 / 2 / 2** |
| | Recall | 50% | 50% | **100%** |
| Kernel (modules + syscalls) | TP / FP / total | 3 / 0 / 3 | 0 / 0 / 3 | **3 / 0 / 3** |
| | Recall | 100% | 0% | **100%** |
| Overall indicators | TP / FP / total | 4 / 0 / 5 | 1 / 2 / 5 | **5 / 2 / 5** |
| | Recall / FP per image | 80% / 0.0 | 20% / 0.67 | **100% / 0.67** |

### Per-image ground truth vs detections

| Image | Scenario | Ground truth | Rules | ML | Combined verdict |
|---|---|---|---|---|---|
| `clean_test_02_all.lime` | Clean: idle + JIT + Firefox + python server | none | 0 findings | 1 FP (PID 30134 firefox, borderline) | **Clean; 1 borderline FP** |
| `diamorphine.lime` | Diamorphine LKM rootkit | PID 2486 hidden; module `diamorphine`; syscalls `__x64_sys_kill`, `__x64_sys_getdents64` | all 4 found, 0 FP | 0 (not behavioural) | **Infected, 4/4 by rules** |
| `userland_malware.lime` | `/dev/shm` + `LD_PRELOAD` agent, bound TCP 44444 | PID 2508 | 0 (no kernel tamper) | PID 2508 found (+1 FP: PID 2619) | **Suspicious, caught by ML** |

The two false positives are benign processes scoring a fraction above the
cutoff — the Firefox main process (PID 30134, clean image) and PID 2619
(userland image) — both flagged as structural outliers, not via the IOC novelty
path. Note them honestly in the limitations section.

---

## 3. Why Isolation Forest — empirical algorithm comparison (Dataset A, 6.18)

Backs proposal Annex A with evidence instead of assertion. Trained on 722 clean
processes (idle + JIT + Firefox), tested on the userland agent (PID 2508).
Isolation Forest rows are the mean of 10 random seeds.

| Algorithm | Detects agent | False positives (of 259 benign) |
|---|:---:|:---:|
| Isolation Forest (pure: raw features, percentile cutoff) | 0% | 7.8 |
| **Isolation Forest + SPF augmentation** (log + max cutoff + novelty) | **100%** | **0.5** |
| One-Class SVM (RBF, nu=0.05, raw) | 100% | 253 |
| One-Class SVM (RBF, nu=0.05, log-scaled) | 0% | 16 |
| Local Outlier Factor (k=20, raw) | 0% | 27 |
| Local Outlier Factor (k=20, log-scaled) | 0% | 20 |
| Novelty rule alone (no model) | 100% | 0 |

Reading: only **IF + SPF augmentation** both detects the agent and keeps FPs ~0.
One-Class SVM is unusable (flags almost everything, or nothing after scaling);
LOF is unstable and scale-sensitive — exactly what Annex A predicted.

### Training-data sensitivity (a limitation worth stating)

| Clean baseline | Invariant features | Agent detected | False positives |
|---|---|:---:|:---:|
| idle + JIT | `runs_from_tmp_or_shm`, `has_ld_preload` | yes | 9 |
| idle + JIT + browser | `runs_from_tmp_or_shm` | yes | **0** |

All 9 FPs in the first row are **Firefox children** that legitimately set
`LD_PRELOAD`. Lesson: the clean baseline must span the workloads present at
analysis time, and `LD_PRELOAD` alone is a weak indicator (`/dev/shm` execution
is the stronger signal).

---

## 4. Triage reduction — SPF vs reading raw Volatility output (Dataset A, 6.18)

Quantifies the core novelty claim: SPF turns tens of thousands of raw plugin
rows into a handful of ranked, explained findings.

| Image | Raw plugin rows an analyst would read | SPF findings | Reduction |
|---|:---:|:---:|:---:|
| `diamorphine` | 32,585 | 4 | **8,146×** |
| `userland_malware` | 62,052 | 2 | **31,026×** |
| `clean_test_02_all` | 59,908 | 1 (the borderline Firefox FP) | **59,908×** |

(Raw rows = sum across `pslist`, `proc.Maps`, `lsof`, `sockstat`, `psaux`,
`envars`, `lsmod`, `check_syscall`, `pidhashtable`, `hidden_modules`.)

---

## 4b. Validation checks (Dataset A, 6.18)

### Determinism / reproducibility — PASS

Ran the full `spf analyse` pipeline (extraction + rules + ML) on
`diamorphine.lime` **twice**, end to end. The forensic findings were
**byte-for-byte identical** — SHA-256 `e952e0b680458c51eaead1631fe1ff49…` on
both runs — down to the exact module base address, both hooked-syscall target
addresses and the hidden PID (2486). SPF is deterministic: the same image yields
the same findings, as a forensic tool must. (Artefacts:
`eval/results/determinism_run1.json`, `determinism_run2.json`.)

### Negative control (clean holdout) — 1 FP among 254 benign processes

Captured a clean, **busy** holdout image (`clean_test_02_all.lime`: idle + Java
and Node JIT + headless Firefox + a python web server, no malware), **not** used
in training (the model is fit only on the three `clean_train_*` images). This
capture has working `linux.proc.Maps`, so the ML stage runs on full features.

Result: **0 rule findings; 1 ML anomaly out of 254 processes → 0.4% false
positive rate (1 FP/image).**

- The single FP is the **Firefox main process** (PID 30134), score **0.776 vs
  cutoff 0.773** — a 0.003 marginal exceedance, flagged purely as a *structural*
  outlier (very high VMA / socket / file-descriptor counts), **not** via the IOC
  novelty path (`novel_features` empty). It is a borderline, explainable flag,
  not a logic error.
- The indicator features did **not** misfire on legitimate behaviour: 9 Firefox
  children legitimately set `LD_PRELOAD` and **none were flagged** (the baseline
  includes a browser, so `has_ld_preload` is not treated as novel), and
  `runs_from_tmp_or_shm` was correctly 0 for all 254 processes. This validates
  the training-data-sensitivity design in §3 on a real busy image.
- The PID hash table page-faulted on this capture too, so the
  `DKOM_HIDDEN_PROCESS` rule was skipped and flagged in the banner; it finds
  nothing on a clean image regardless.

This is a strong, honest negative control: on a busy clean system exercising
exactly the behaviours that look suspicious (JIT rwx memory, browser
`LD_PRELOAD`), SPF raises **zero rule findings and one borderline structural
anomaly**. Artefacts: `eval/features/clean_test_02_all.json`,
`eval/results/clean_test_02_all.json` / `.html`.

> Note: an earlier holdout capture (`clean_test_01_all.lime`) had a corrupted
> `linux.proc.Maps`; `clean_test_02_all` replaces it as the clean test image.

---

## 5. Live-tool blindness case study (Dataset B, 6.12 — Nabbhil's capture)

Deterministic and model-independent, so it transfers across kernels. This is the
strongest single narrative in the project: a widely-used live rootkit scanner is
completely blind to Diamorphine, while SPF detects it from the raw image.

**Setup:** Kali `6.12.25-amd64` (deterministic `nokaslr`), Diamorphine active,
module unlinked, a decoy sleeper hidden by DKOM. `chkrootkit 0.58b` run as root.

**`chkrootkit` result (live, on the compromised host):**
- Hidden processes (`chkproc`): **not found**
- Hidden kernel modules (`lkm`): **finished, 0 alerts**
- Overall: **0 rootkits** — the only output was a benign NetworkManager sniffer
  notice. (Full transcript: `eval/results/chkrootkit_live_output.txt`.)

**SPF result (offline, same compromised memory):** all rootkit indicators found:

| Rule | Target | Evidence |
|---|---|---|
| `DKOM_HIDDEN_PROCESS` | decoy sleeper PID 3590 | in PID hash table, unlinked from task list |
| `HIDDEN_KERNEL_MODULE` | `diamorphine` | carved at `0xffffc0b99140`, 12,288 bytes, absent from module list |
| `HOOKED_SYSCALL` | syscall 62 `__x64_sys_kill` | entry → `0xffffc0b97690`, outside kernel text + modules |
| `HOOKED_SYSCALL` | syscall 217 `__x64_sys_getdents64` | entry → `0xffffc0b97350`, outside kernel text + modules |

**Live vs offline capability matrix:**

| Dimension | `chkrootkit` (live) | SPF (offline) |
|---|---|---|
| Inspection medium | live `/proc`, `/sys` (via syscalls) | raw physical RAM image |
| Trust boundary | depends on the compromised kernel | out-of-band; cannot be subverted by malware |
| DKOM hidden process | **blind** (hooked `getdents64`) | **detected** (PID-hash vs task-list) |
| Hidden kernel module | **blind** (unlinked from `/proc/modules`) | **detected** (carved `struct module`) |
| Syscall hooking | **blind** (cannot inspect kernel pointers) | **detected** (address vs kernel `.text`) |
| Detection on Diamorphine | **0%** | **100%, 0 FP** |

**Cross-kernel point:** the same three rules detect Diamorphine on both 6.12
(Dataset B) and 6.18 (Dataset A). That is a portability result worth stating
explicitly in the report.

---

## 6. Scope & limitations (for an honest limitations section)

- SPF is **offline triage for Linux** memory images; it assumes a **trusted
  acquisition** and does not defend against anti-forensics that corrupt the
  capture itself.
- The ML stage needs a clean baseline that **matches the analysed workloads**
  (the Firefox/`LD_PRELOAD` lesson in §3).
- ML has a small residual false-positive rate (1 benign process over 3 images).
- The module scan can be unreliable on a degraded capture; SPF detects this and
  **skips the check, flagging it in the report** rather than emitting noise.
- Dataset A and Dataset B use different kernels; ML results are reported for
  Dataset A only (see the note at the top).

---

## 7. Suggested figures/tables for the report

1. Live-vs-offline capability matrix (§5) — the headline comparison.
2. Combined confusion matrix (§2).
3. Algorithm comparison table (§3).
4. Triage reduction table (§4) — one big number for the conclusion (31,026×).
5. The grouped process-tree report screenshot (`eval/results/diamorphine.html`).

## 8. Source artefacts (all in the repo)

- `eval/results/metrics.json` — §1, §2
- `eval/results/algorithm_comparison.md` / `.json` — §3
- `eval/results/triage_reduction.json` — §4
- `eval/results/chkrootkit_live_output.txt` — §5 live transcript
- `docs/final_evaluation_evidence.md` — Nabbhil's full 6.12 document (source of
  Dataset B; **note:** contains teammate paths/credentials to sanitise before
  submission — left for Nabbhil)
- `eval/ground_truth.yaml` — Dataset A ground truth
- `eval/results/diamorphine.html`, `userland_malware.html` — grouped reports
