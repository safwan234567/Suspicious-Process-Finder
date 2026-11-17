"""Stage B - Rule stage: definitive indicators of compromise.

Exactly the three rules defined in the proposal. Results are reported with
certainty and kept separate from anomaly scores.
"""

from __future__ import annotations

import sys

from spf.models import MemoryEvidence, RuleFinding

# Volatility plugins each rule depends on.
PIDHASH_PLUGIN = "linux.pidhashtable.PIDHashTable"
HIDDEN_MODULES_PLUGIN = "linux.malware.hidden_modules.Hidden_modules"
SYSCALL_PLUGIN = "linux.malware.check_syscall.Check_syscall"
LSMOD_PLUGIN = "linux.lsmod.Lsmod"


def check_dkom_hidden_processes(ev: MemoryEvidence) -> list[RuleFinding]:
    """Process present in the PID hash table but missing from the tasks linked list.

    Skipped (returns no findings) when the PID hash table is unavailable."""
    if ev.pid_hash_pids is None:
        sys.stderr.write("[spf.rules] WARNING: PID hash table unavailable; DKOM_HIDDEN_PROCESS check skipped.\n")
        return []
    listed = {p.pid for p in ev.tasks_list}
    return [
        RuleFinding(
            rule="DKOM_HIDDEN_PROCESS",
            description=f"PID {pid} is in the PID hash table but unlinked from the task list",
            pid=pid,
        )
        for pid in sorted(ev.pid_hash_pids - listed)
    ]


def check_hidden_modules(ev: MemoryEvidence) -> list[RuleFinding]:
    """Kernel module present in memory but omitted from the registered module list."""
    registered = {(m.name, m.base) for m in ev.registered_modules}
    return [
        RuleFinding(
            rule="HIDDEN_KERNEL_MODULE",
            description=f"Module '{m.name}' at {m.base:#x} is in memory but not in the module list",
            evidence={"name": m.name, "base": m.base, "size": m.size},
        )
        for m in ev.memory_modules
        if (m.name, m.base) not in registered
    ]


def check_syscall_hooks(ev: MemoryEvidence) -> list[RuleFinding]:
    """Syscall table entry pointing outside kernel code and every registered module.

    Skipped (returns no findings) when the kernel code range is unknown or
    invalid: without it every syscall would look hooked."""
    if ev.kernel_text is None or ev.kernel_text[1] <= ev.kernel_text[0]:
        sys.stderr.write(
            "[spf.rules] WARNING: kernel code range unknown; HOOKED_SYSCALL check skipped.\n"
        )
        return []
    k_start, k_end = ev.kernel_text
    ranges = [(m.base, m.base + m.size) for m in ev.registered_modules]

    def is_legit(e: SyscallEntry) -> bool:
        if k_start <= e.address < k_end:
            return True
        return e.symbol is not None and any(lo <= e.address < hi for lo, hi in ranges)

    return [
        RuleFinding(
            rule="HOOKED_SYSCALL",
            description=f"Syscall {e.index} points to {e.address:#x}, outside the kernel and registered modules",
            evidence={"index": e.index, "address": e.address, "symbol": e.symbol},
        )
        for e in ev.syscall_table
        if not is_legit(e)
    ]


def skipped_checks(ev: MemoryEvidence) -> list[str]:
    """Plain-language list of checks that could not run fully on this image,
    so a clean result is not mistaken for a verified one."""
    failed = set(ev.unavailable_plugins)
    notes = []
    if ev.pid_hash_pids is None or PIDHASH_PLUGIN in failed:
        notes.append("DKOM_HIDDEN_PROCESS skipped: the PID hash table could not be read.")
    if HIDDEN_MODULES_PLUGIN in failed:
        notes.append("HIDDEN_KERNEL_MODULE skipped: the hidden-module scan failed.")
    if LSMOD_PLUGIN in failed:
        notes.append("HIDDEN_KERNEL_MODULE and HOOKED_SYSCALL unreliable: the registered module list could not be read.")
    if SYSCALL_PLUGIN in failed:
        notes.append("HOOKED_SYSCALL skipped: the syscall table could not be read.")
    if ev.kernel_text is None or ev.kernel_text[1] <= ev.kernel_text[0]:
        notes.append("HOOKED_SYSCALL skipped: the kernel code range could not be resolved.")
    ml_inputs = sorted(failed - {PIDHASH_PLUGIN, HIDDEN_MODULES_PLUGIN, SYSCALL_PLUGIN, LSMOD_PLUGIN})
    if ml_inputs:
        notes.append("ML features incomplete (affected values read as 0): " + ", ".join(ml_inputs) + " failed.")
    return notes


def run_rules(ev: MemoryEvidence) -> list[RuleFinding]:
    return check_dkom_hidden_processes(ev) + check_hidden_modules(ev) + check_syscall_hooks(ev)
