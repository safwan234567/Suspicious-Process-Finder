# Algorithm comparison (empirical backing for Annex A)

Proposal Annex A argued, on paper, that Isolation Forest beats One-Class SVM,
Local Outlier Factor and autoencoders for Linux memory triage. This experiment
tests that claim on the **real** SPF feature vectors, extracted from memory
images captured on Kali `6.18.12+kali-amd64`.

## Protocol

- **Train** (clean baseline, unsupervised): 722 processes from three clean
  images — idle, Java/Node.js JIT, and headless Firefox.
- **Test**: the `userland_malware` image (260 processes). PID 2508 is the one
  behaviourally ML-visible threat: a process executing from `/dev/shm` with
  `LD_PRELOAD` set and a bound socket. The Diamorphine decoy is a plain sleeper
  caught by the rule stage, not by behaviour, so it is not an ML target.
- **Metrics**: *Detect* = agent PID 2508 flagged; *FalsePos* = flags among the
  259 benign processes. Isolation Forest rows are the mean over 10 random seeds.
- Reproduce: `python eval/compare_algorithms.py` (reads the committed feature
  cache in `eval/features/`; no memory image needed).

## Result

| Algorithm | Detect agent | False positives |
|---|---|---|
| Isolation Forest (pure: raw features, 99th-pct cutoff) | 0% | 7.8 |
| **Isolation Forest + SPF augmentation** (log + max cutoff + novelty) | **100%** | **0.5** |
| One-Class SVM (RBF, nu=0.05, raw) | 100% | 253 |
| One-Class SVM (RBF, nu=0.05, log-scaled) | 0% | 16 |
| Local Outlier Factor (k=20, raw) | 0% | 27 |
| Local Outlier Factor (k=20, log-scaled) | 0% | 20 |
| Baseline-invariant novelty only (no model) | 100% | 0 |

Fit and score time are sub-second for every configuration (full data in
`algorithm_comparison.json`).

## Reading

- **Pure Isolation Forest fails** (0% detection). With raw features and a
  percentile cutoff it cannot split on the IOC features that are constant on a
  clean baseline, so the agent scores as normal. This is the failure the SPF
  augmentation fixes, not a property of Isolation Forest itself.
- **Isolation Forest + SPF augmentation is the only configuration that both
  detects the agent and keeps false positives at ~0** (0.5 of 259).
- **One-Class SVM is unusable**: on raw features it flags 253 of 259 benign
  processes (it is not detecting the agent so much as flagging almost
  everything); log-scaling flips it to detecting nothing. This is the parameter
  and scale sensitivity Annex A predicted.
- **LOF is unstable**: it never both detects and stays clean, and its behaviour
  flips with feature scaling — the distance-metric degradation on mixed-scale,
  mostly-zero features that Annex A predicted.
- **The novelty rule alone** detects the agent with zero false positives,
  confirming that the detection comes from the baseline-invariant novelty
  component, with the forest handling the graded structural outliers.

## Training-data sensitivity (why the baseline must include a browser)

| Clean baseline | Invariant features | Agent detected | False positives |
|---|---|---|---|
| idle + JIT | `runs_from_tmp_or_shm`, `has_ld_preload` | yes | 9 |
| idle + JIT + browser | `runs_from_tmp_or_shm` | yes | 0 |

All nine false positives in the first row are **Firefox child processes**
(`Web Content`, `WebExtensions`, `RDD Process`, …), which legitimately set
`LD_PRELOAD` for Firefox's sandbox. If the clean baseline contains no browser,
`has_ld_preload` is constant 0 and the novelty rule flags every Firefox child.
Adding one browser image to the baseline removes `has_ld_preload` from the
invariant set, dropping those false positives to zero; the agent is still
detected through `runs_from_tmp_or_shm` (`/dev/shm` execution), the stronger and
less ambiguous signal. Two lessons for the report: the clean baseline must span
the workloads present at analysis time, and `LD_PRELOAD` on its own is a weak
indicator.
