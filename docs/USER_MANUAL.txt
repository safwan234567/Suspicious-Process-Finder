# SPF User Manual

SPF (Suspicious Process Finder) is an offline triage tool for Linux memory
images. It runs on top of Volatility 3 and reports suspicious processes in two
ways: definitive **rule** findings (reported with certainty) and behavioural
**anomaly** findings from an Isolation Forest trained only on clean systems.
Every finding is explained and grouped under the process it concerns.

---

## 1. Requirements

- Python 3.9+ (developed on 3.12).
- The Python packages in `pyproject.toml` (installed below): Volatility 3,
  scikit-learn, shap, numpy, pandas, joblib, pyyaml.
- For **capturing** images and **building symbols** you also need a Linux
  machine or VM with the kernel headers and debug symbols (Section 7).

## 2. Install

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows
# source .venv/bin/activate       # Linux/macOS
pip install -e ".[dev]"
```

Verify:

```bash
spf --help
pytest -q                          # unit tests should pass
```

## 3. Try it with no memory image

To see every stage (rules, Isolation Forest, explanations, report) on synthetic
evidence:

```bash
python examples/demo_report.py
# writes examples/out/report.json and report.html
```

Open `examples/out/report.html` in a browser.

## 4. Analysing a real image

You need three things: the memory image (`.raw` or `.lime`), a matching
Volatility **symbol table** (ISF, Section 7), and a trained **model**
(`baseline/models/spf.joblib`, Section 6).

```bash
spf analyse --image path/to/image.lime \
            --symbols symbols \
            --model baseline/models/spf.joblib \
            --mode both \
            --out report.json
```

- `--symbols` is the directory holding the ISF (`symbols/linux/<kernel>.json.xz`).
- `--mode` is `rules`, `ml`, or `both` (default `both`).
- Output: `report.json` and `report.html` next to it.

If the symbol table does not match the image's kernel, extraction fails or
returns nothing. The ISF kernel version must match the captured kernel exactly.

## 5. Reading the report

The HTML report has three parts:

1. **Flagged processes (grouped)** — the main view. Each process that raised any
   finding, with its memory offset, open network connections, parent chain, and
   its rule and/or anomaly findings in one place.
2. **Definitive indicators (rule stage)** — the three certain checks:
   - `DKOM_HIDDEN_PROCESS`: a PID in the PID hash table but unlinked from the
     task list (a hidden process).
   - `HIDDEN_KERNEL_MODULE`: a module in memory whose name is absent from the
     registered module list (a hidden rootkit module).
   - `HOOKED_SYSCALL`: a syscall-table entry pointing outside the kernel and
     every registered module (a hooked syscall).
3. **Behavioural anomalies (Isolation Forest)** — processes that scored above the
   clean-baseline cutoff, or that showed a value never seen on the clean
   baseline (marked *unseen on baseline*), each with a plain-language reason.

A yellow banner lists any checks that could not run fully on the image (for
example when a plugin failed), so a clean result is never mistaken for a
verified one.

## 6. Training the model (clean baseline)

The Isolation Forest must be trained on **clean** images that resemble the
systems you will analyse — including the same kinds of workload (for example a
browser or a JIT runtime), or you will get false positives (see the note below).

```bash
spf train --images baseline/images \
          --symbols symbols \
          --out baseline/models/spf.joblib
```

`--images` is a directory; every `.raw`/`.lime` under it is used. The command
prints the cutoff and lists any feature that was constant across the baseline
(a process whose value differs from such a feature at analysis time is reported
as "unseen behaviour").

> **Note.** The clean baseline must cover the workloads present at analysis time.
> For example, Firefox legitimately sets `LD_PRELOAD`; if no clean training image
> ran a browser, every browser child is flagged. Including one browser image in
> the baseline fixes this. See `eval/results/algorithm_comparison.md`.

Training can also be done from the cached feature vectors without re-reading the
images (see Section 9).

## 7. Capturing an image and building symbols

On the Linux machine/VM you want to image (example: Kali 6.18):

**a. Capture memory with LiME**

```bash
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src && make
sudo insmod ./lime-$(uname -r).ko "path=/path/out.lime" format=lime
sudo rmmod lime
```

The LiME output path must not contain spaces.

**b. Build the Volatility symbol table (ISF)**

You need the kernel's debug symbols (`vmlinux` with DWARF) and `System.map`:

```bash
# install the matching debug + header packages for your kernel, then:
dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) \
                 --system-map /boot/System.map-$(uname -r) \
                 > kernel.json
xz kernel.json
mkdir -p symbols/linux && mv kernel.json.xz symbols/linux/
```

`dwarf2json` is from the Volatility Foundation
(https://github.com/volatilityfoundation/dwarf2json). The ISF must be generated
from the **same** kernel build as the captured image.

The `spf_lab/` helper scripts used for this project's evaluation automate steps
a–b and the infection scenarios; see `eval/` and the lab notes.

## 8. Evaluation

Reproduce the project's experiments (reads the committed feature cache in
`eval/features/`, so no 4 GB images are needed):

```bash
python eval/run_experiments.py   --features eval/features --model baseline/models/spf.joblib --out eval/results/metrics.json
python eval/compare_algorithms.py --features eval/features --out eval/results/algorithm_comparison.json
python eval/compare_vs_raw.py     --features eval/features --model baseline/models/spf.joblib
```

## 9. Working from the feature cache

`eval/extract_features.py` runs the slow Volatility extraction once and caches
each process's feature vector to `eval/features/<image>.json`. All experiments
above read that cache, so they run in seconds and are reproducible without the
images. To (re)build a cache entry, and optionally a full report, for one image:

```bash
python eval/extract_features.py --image path/to/image.lime --symbols symbols \
       --out eval/features/image.json --model baseline/models/spf.joblib
```

## 10. Troubleshooting

- **"was trained by an older SPF"** on `analyse`: retrain the model with
  `spf train` (the model format changed).
- **Extraction returns 0 processes / plugin errors**: the ISF does not match the
  image's kernel, or the image is truncated. Confirm the kernel version and
  rebuild the ISF.
- **Many `HIDDEN_KERNEL_MODULE` findings on a clean image**: the module scan was
  unreliable on that capture; SPF skips the check and says so in the report's
  yellow banner. Re-capture the image.
- **Launching extraction as a detached background process hangs**: run it in the
  foreground, or train/evaluate from the feature cache.
