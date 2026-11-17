"""Shared data structures passed between the four stages."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class VMA:
    start: int
    end: int
    flags: str              # e.g. "rwx", "r-x"
    file_path: str | None   # None = anonymous (not backed by a disk file)

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def is_executable(self) -> bool:
        return "x" in self.flags


@dataclass
class Process:
    pid: int
    ppid: int
    uid: int
    comm: str
    task_offset: int
    exe_path: str | None = None
    cmdline: str = ""
    envars: dict[str, str] = field(default_factory=dict)
    vmas: list[VMA] = field(default_factory=list)
    fd_count: int = 0
    sockets: list[dict] = field(default_factory=list)


@dataclass
class KernelModule:
    name: str
    base: int
    size: int


@dataclass
class SyscallEntry:
    index: int
    address: int
    symbol: str | None  # resolved symbol/module, None if it points nowhere known


@dataclass
class MemoryEvidence:
    """Everything the extraction stage pulls from one image."""

    image_path: str
    tasks_list: list[Process]                 # processes from the tasks linked list
    pid_hash_pids: set[int]                   # PIDs found in the PID hash table
    registered_modules: list[KernelModule]    # modules in the registered module list
    memory_modules: list[KernelModule]        # modules found in memory
    syscall_table: list[SyscallEntry]
    kernel_text: tuple[int, int] | None = None  # (start, end) of kernel code; None = unknown


@dataclass
class RuleFinding:
    """A definitive indicator of compromise. Reported with certainty, never scored."""

    rule: str
    description: str
    pid: int | None = None
    evidence: dict = field(default_factory=dict)


@dataclass
class AnomalyFinding:
    """A statistical anomaly from the Isolation Forest stage."""

    pid: int
    score: float
    threshold: float
    features: dict[str, float]
    contributions: dict[str, float] = field(default_factory=dict)  # TreeSHAP values
    explanation: str = ""
