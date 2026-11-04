"""Stage C - per-process feature vector (exactly the features listed in the proposal)."""

from __future__ import annotations

from spf.models import Process

FEATURE_NAMES = [
    "vma_count",                 # total count of VMAs
    "anon_to_file_ratio",        # anonymous memory / file-backed memory
    "unbacked_exec_count",       # executable regions not backed by a disk binary
    "unbacked_exec_bytes",       # total size of those regions
    "fd_count",                  # open file descriptors
    "socket_count",              # open sockets
    "uid_differs_from_parent",   # process UID relative to parent UID
    "runs_from_tmp_or_shm",      # executed from /tmp or /dev/shm
    "has_ld_preload",            # LD_PRELOAD present in environment
]

SUSPICIOUS_DIRS = ("/tmp/", "/dev/shm/")


def build_features(proc: Process, parent_uid: int | None) -> dict[str, float]:
    anon = sum(v.size for v in proc.vmas if v.file_path is None)
    file_backed = sum(v.size for v in proc.vmas if v.file_path is not None)
    unbacked_exec = [v for v in proc.vmas if v.is_executable and v.file_path is None]
    exe = proc.exe_path or ""

    return {
        "vma_count": float(len(proc.vmas)),
        "anon_to_file_ratio": anon / file_backed if file_backed else float(anon > 0),
        "unbacked_exec_count": float(len(unbacked_exec)),
        "unbacked_exec_bytes": float(sum(v.size for v in unbacked_exec)),
        "fd_count": float(proc.fd_count),
        "socket_count": float(len(proc.sockets)),
        "uid_differs_from_parent": float(parent_uid is not None and proc.uid != parent_uid),
        "runs_from_tmp_or_shm": float(exe.startswith(SUSPICIOUS_DIRS)),
        "has_ld_preload": float("LD_PRELOAD" in proc.envars),
    }


def features_for_processes(procs: list[Process]) -> list[tuple[int, dict[str, float]]]:
    """Build the feature vector for every process, resolving each one's parent UID
    from the process list. Returns a list of (pid, features) pairs."""
    uid_by_pid = {p.pid: p.uid for p in procs}
    return [(p.pid, build_features(p, uid_by_pid.get(p.ppid))) for p in procs]
