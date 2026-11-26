"""End-to-end proof of life with NO memory image.

Builds a synthetic clean baseline, trains the Isolation Forest, then analyses a
synthetic "suspect" MemoryEvidence that contains planted anomalies plus a
DKOM-hidden process, a hidden kernel module and a hooked syscall. Writes
report.json and report.html so every stage except real extraction is provable
today.

  python examples/demo_report.py          # -> examples/out/report.{json,html}
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # run without pip install

import numpy as np

from spf.models import VMA, Process, KernelModule, SyscallEntry, MemoryEvidence
from spf.ml.features import features_for_processes
from spf.ml.model import SPFModel
from spf.rules.checks import run_rules
from spf.pipeline import find_anomalies
from spf.report.builder import build_report, render_html

RNG = np.random.default_rng(42)
KERNEL = (0xFFFFFFFF81000000, 0xFFFFFFFF81E00000)


def clean_process(pid: int) -> Process:
    """A normal server process: mostly file-backed code, a little anon heap/stack."""
    n_file = int(RNG.integers(25, 45))
    vmas = []
    addr = 0x400000
    for _ in range(n_file):
        size = int(RNG.integers(0x1000, 0x20000))
        vmas.append(VMA(addr, addr + size, "r-x" if RNG.random() < 0.3 else "r--", "/usr/lib/x.so"))
        addr += size + 0x1000
    for _ in range(int(RNG.integers(3, 8))):           # heap / stack, anon rw-
        size = int(RNG.integers(0x10000, 0x200000))
        vmas.append(VMA(addr, addr + size, "rw-", None))
        addr += size + 0x1000
    return Process(
        pid=pid, ppid=1, uid=int(RNG.choice([0, 1000])), comm=str(RNG.choice(
            ["sshd", "bash", "nginx", "cron", "systemd", "mysqld"])),
        task_offset=0xFFFF000000 + pid, exe_path="/usr/sbin/app",
        fd_count=int(RNG.integers(6, 20)),
        sockets=[{} for _ in range(int(RNG.integers(0, 3)))], vmas=vmas,
    )


def suspect_evidence() -> MemoryEvidence:
    visible = [clean_process(900 + i) for i in range(30)]

    # planted anomaly 1: injected code, runs from /tmp, LD_PRELOAD, uid != parent
    inj = Process(
        pid=1337, ppid=1000, uid=0, comm="kworker/x", task_offset=0xFFFF00dead,
        exe_path="/tmp/.x/kworker", cmdline="/tmp/.x/kworker --quiet",
        envars={"LD_PRELOAD": "/tmp/.x/evil.so"},
        fd_count=48, sockets=[{}, {}, {}, {}, {}, {}, {}, {}, {}],
        vmas=[VMA(0x400000, 0x401000, "r-x", "/tmp/.x/kworker")]
             + [VMA(0x500000 + i * 0x100000, 0x500000 + i * 0x100000 + 0x80000, "rwx", None) for i in range(4)]
             + [VMA(0x900000, 0x4900000, "rw-", None)],   # huge anon
    )
    # planted anomaly 2: unusual socket/fd + uid change, subtler
    beacon = Process(
        pid=1500, ppid=1200, uid=0, comm="updater", task_offset=0xFFFF00beef,
        exe_path="/usr/bin/updater", fd_count=60,
        sockets=[{} for _ in range(12)],
        vmas=[VMA(0x400000, 0x420000, "r-x", "/usr/bin/updater"),
              VMA(0x500000, 0x900000, "rwx", None)],       # one unbacked exec region
    )
    visible += [inj, beacon]

    good = KernelModule("ext4", 0xFFFFFFFFA0000000, 0x40000)
    rootkit = KernelModule("diamorphine", 0xFFFFFFFFA1000000, 0x8000)

    return MemoryEvidence(
        image_path="demo_synthetic.lime",
        tasks_list=visible,
        pid_hash_pids={p.pid for p in visible} | {4242},    # 4242 hidden from the task list (DKOM)
        registered_modules=[good],
        memory_modules=[good, rootkit],                     # rootkit present but unregistered
        syscall_table=[
            SyscallEntry(0, KERNEL[0] + 0x100, "sys_read"),
            SyscallEntry(217, 0xFFFFFFFFA1000400, None),    # getdents64 hooked into diamorphine
        ],
        kernel_text=KERNEL,
    )


def main(out_dir: str = "examples/out") -> dict:
    # 1. train on a clean baseline
    clean = [clean_process(100 + i) for i in range(400)]
    clean_rows = [f for _pid, f in features_for_processes(clean)]
    model = SPFModel().fit(clean_rows)

    # 2. analyse the suspect image
    ev = suspect_evidence()
    rule_findings = run_rules(ev)

    anomaly_findings = find_anomalies(ev.tasks_list, model)

    report = build_report(ev, rule_findings, anomaly_findings)
    outd = Path(out_dir)
    outd.mkdir(parents=True, exist_ok=True)
    (outd / "report.json").write_text(json.dumps(report, indent=2, default=str))
    render_html(report, outd / "report.html")
    print(f"[+] cutoff={model.threshold:.3f}  rules={len(rule_findings)}  "
          f"anomalies={len(anomaly_findings)}  -> {outd}/report.json, report.html")
    return report


if __name__ == "__main__":
    main()
