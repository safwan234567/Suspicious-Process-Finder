"""Stage B - Rule stage: definitive indicators of compromise.

Exactly the three rules defined in the proposal. Results are reported with
certainty and kept separate from anomaly scores.
"""

from __future__ import annotations

from spf.models import MemoryEvidence, RuleFinding


def check_dkom_hidden_processes(ev: MemoryEvidence) -> list[RuleFinding]:
    """Process present in the PID hash table but missing from the tasks linked list."""
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
    """Syscall table entry pointing outside kernel code and every registered module."""
    k_start, k_end = ev.kernel_text
    ranges = [(m.base, m.base + m.size) for m in ev.registered_modules]

    def is_legit(addr: int) -> bool:
        if k_start <= addr < k_end:
            return True
        return any(lo <= addr < hi for lo, hi in ranges)

    return [
        RuleFinding(
            rule="HOOKED_SYSCALL",
            description=f"Syscall {e.index} points to {e.address:#x}, outside the kernel and registered modules",
            evidence={"index": e.index, "address": e.address, "symbol": e.symbol},
        )
        for e in ev.syscall_table
        if not is_legit(e.address)
    ]


def run_rules(ev: MemoryEvidence) -> list[RuleFinding]:
    return check_dkom_hidden_processes(ev) + check_hidden_modules(ev) + check_syscall_hooks(ev)
