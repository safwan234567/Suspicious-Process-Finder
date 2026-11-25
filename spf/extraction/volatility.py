"""Stage A - Extraction.

Calls the Volatility 3 API (not the CLI) to collect raw evidence from a .raw or
.lime image and return a MemoryEvidence. This stage never decides whether
anything is malicious.

Volatility 3 Linux plugins used:
  tasks list          linux.pslist.PsList
  PID hash table      linux.pidhashtable.PIDHashTable
  VMAs + permissions  linux.proc.Maps
  file descriptors    linux.lsof.Lsof
  sockets             linux.sockstat.Sockstat
  registered modules  linux.lsmod.Lsmod
  hidden modules      linux.hidden_modules.Hidden_modules
  syscall table       linux.check_syscall.Check_syscall
  command lines       linux.psaux.PsAux
  environment vars    linux.envars.Envars

The module imports volatility3 lazily so the rest of SPF (rules, ml, explain,
report) runs without Volatility installed.

VALIDATION NOTE: plugin NAMES are correct, but the exact COLUMN names a plugin
emits vary slightly between Volatility versions. Every column lookup below goes
through _col(), which tries several spellings; confirm them once against your
build with  `python -m volatility3.cli -f IMAGE <plugin>`  and read the header.
"""

from __future__ import annotations

import sys
from pathlib import Path

from spf.models import (
    KernelModule,
    MemoryEvidence,
    Process,
    SyscallEntry,
    VMA,
)

from spf.rules.checks import HIDDEN_MODULES_PLUGIN, PIDHASH_PLUGIN, SYSCALL_PLUGIN

SUPPORTED_FORMATS = {".raw", ".lime"}


def _col(row: dict, *names, default=None):
    """Return the first present column from several candidate spellings.

    Matching is case-insensitive: Volatility renames columns between releases
    (e.g. linux.envars.Envars uses KEY/VALUE in 2.28), and a silent miss here
    turns a feature such as has_ld_preload into a constant 0."""
    lower = {k.lower(): k for k in row}
    for n in names:
        k = n if n in row else lower.get(n.lower())
        if k is not None and row[k] not in (None, "-"):
            return row[k]
    return default


def _int(v, default=0):
    try:
        return int(str(v), 0) if isinstance(v, str) else int(v)
    except (TypeError, ValueError):
        return default


def build_context(image_path: str, symbols_dir) -> object:
    """Build one Volatility context for an image. The layers are stacked lazily
    on the first plugin run and then reused, so all plugins in extract() share
    the single expensive scan instead of repeating it."""
    try:
        import volatility3.framework.symbols.linux.extensions.network  # noqa: F401
    except ImportError:
        pass
    import volatility3.symbols
    import volatility3.framework.layers
    from volatility3 import framework, plugins
    from volatility3.framework import contexts, automagic
    from volatility3.framework.configuration import requirements

    framework.import_files(plugins, True)
    framework.import_files(volatility3.framework.layers)
    framework.import_files(automagic)
    if symbols_dir:
        sp = str(Path(symbols_dir).resolve())
        if sp not in volatility3.symbols.__path__:
            volatility3.symbols.__path__ = [sp] + list(volatility3.symbols.__path__)

    ctx = contexts.Context()
    ctx.config["automagic.LayerStacker.single_location"] = requirements.URIRequirement.location_from_file(
        str(Path(image_path).resolve())
    )
    return ctx


def run_plugin(ctx, plugin_name: str) -> list[dict]:
    """Run one plugin on a shared context; return its grid as dict rows."""
    from volatility3 import framework
    from volatility3.framework import automagic, interfaces

    available = framework.list_plugins()
    plugin_cls = available.get(plugin_name) or next(
        (c for n, c in available.items() if n.endswith(plugin_name)), None)
    if plugin_cls is None:
        raise ValueError(f"Volatility plugin not found: {plugin_name}")

    base = "plugins"
    automagics = automagic.choose_automagic(automagic.available(ctx), plugin_cls)
    errors = automagic.run(automagics, ctx, plugin_cls, base, progress_callback=None)
    if errors:
        raise RuntimeError(f"automagic errors for {plugin_name}: {errors}")
    cfg_path = interfaces.configuration.path_join(base, plugin_cls.__name__)
    constructed = plugin_cls(ctx, cfg_path, progress_callback=None)
    grid = constructed.run()

    rows: list[dict] = []

    def visitor(node, _acc):
        rows.append({col.name: node.values[i] for i, col in enumerate(grid.columns)})
        return None

    grid.populate(visitor, None)
    return rows


def _run_plugin(image_path: str, symbols_dir, plugin_name: str) -> tuple[list[dict], object]:
    """Run one plugin with its OWN fresh context.

    Each plugin must get a fresh context: Volatility's layer stacker deep-copies
    the whole context, so a context reused across plugins grows every run and the
    deepcopy eventually hangs / exhausts memory. A fresh context per plugin keeps
    every clone tiny and frees the memory between plugins."""
    ctx = build_context(image_path, symbols_dir)
    return run_plugin(ctx, plugin_name), ctx


def _safe(image_path: str, symbols_dir, plugin_name: str, failed: list[str]) -> list[dict]:
    """Run one plugin and return its rows, or [] if it fails, so one bad plugin
    does not abort the whole extraction. Failed plugins are appended to
    `failed` so the report can say which checks were affected."""
    try:
        rows, _ = _run_plugin(image_path, symbols_dir, plugin_name)
        return rows
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"[spf.extraction] {plugin_name} skipped: {exc!r}\n")
        failed.append(plugin_name)
        return []


def _kernel_text(ctx) -> tuple[int, int] | None:
    """(start, end) of the kernel code section, needed by the hooked-syscall
    rule. Tries common kernel symbols. Returns None and prints a warning if
    none resolve, so the rule is skipped instead of flagging every syscall."""
    try:
        kernel = ctx.modules[next(iter(ctx.modules))]
        for lo, hi in (("_stext", "_etext"), ("_text", "_end")):
            try:
                start = kernel.get_symbol(lo).address + kernel.offset
                end = kernel.get_symbol(hi).address + kernel.offset
                if end > start:
                    return int(start), int(end)
            except Exception:
                continue
    except Exception:
        pass
    sys.stderr.write(
        "[spf.extraction] WARNING: could not resolve the kernel code range "
        "(_stext/_etext or _text/_end). The hooked-syscall rule will be skipped "
        "for this image. Check that the symbol table matches the image's kernel.\n"
    )
    return None


def extract(image_path: str | Path, symbols_dir: str | Path) -> MemoryEvidence:
    image_path = Path(image_path)
    if image_path.suffix.lower() not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported image format {image_path.suffix}; expected .raw or .lime")

    # One fresh context per plugin (see _run_plugin docstring). Each plugin is
    # wrapped so a single failure skips that plugin instead of aborting.
    failed: list[str] = []
    pslist, ctx = _run_plugin(image_path, symbols_dir, "linux.pslist.PsList")
    maps = _safe(image_path, symbols_dir, "linux.proc.Maps", failed)
    lsof = _safe(image_path, symbols_dir, "linux.lsof.Lsof", failed)
    sockstat = _safe(image_path, symbols_dir, "linux.sockstat.Sockstat", failed)
    psaux = _safe(image_path, symbols_dir, "linux.psaux.PsAux", failed)
    envars = _safe(image_path, symbols_dir, "linux.envars.Envars", failed)
    lsmod = _safe(image_path, symbols_dir, "linux.lsmod.Lsmod", failed)
    syscalls = _safe(image_path, symbols_dir, SYSCALL_PLUGIN, failed)
    pidhash = _safe(image_path, symbols_dir, PIDHASH_PLUGIN, failed)
    hidden = _safe(image_path, symbols_dir, HIDDEN_MODULES_PLUGIN, failed)

    # Raw rows per plugin: the lines an analyst would read by hand across these
    # separate plugin tables. Used by eval/compare_vs_raw.py to quantify how much
    # manual triage SPF removes.
    raw_plugin_rows = {
        "linux.pslist.PsList": len(pslist), "linux.proc.Maps": len(maps),
        "linux.lsof.Lsof": len(lsof), "linux.sockstat.Sockstat": len(sockstat),
        "linux.psaux.PsAux": len(psaux), "linux.envars.Envars": len(envars),
        "linux.lsmod.Lsmod": len(lsmod), SYSCALL_PLUGIN: len(syscalls),
        PIDHASH_PLUGIN: len(pidhash), HIDDEN_MODULES_PLUGIN: len(hidden),
    }

    # A live kernel always has PIDs and syscall entries, so an empty result
    # means the plugin did not work even if it raised no error.
    for name, rows in ((PIDHASH_PLUGIN, pidhash), (SYSCALL_PLUGIN, syscalls)):
        if not rows and name not in failed:
            sys.stderr.write(f"[spf.extraction] {name} returned no rows; treating it as unavailable\n")
            failed.append(name)

    # --- per-pid VMAs ---
    vmas_by_pid: dict[int, list[VMA]] = {}
    for r in maps:
        pid = _int(_col(r, "PID", "Pid"))
        start = _int(_col(r, "Start", "Start Address"))
        end = _int(_col(r, "End", "End Address"))
        flags = str(_col(r, "Flags", "Protection", default=""))
        path = _col(r, "File Path", "Path", "File Output")
        file_path = None if path in (None, "", "Anonymous Mapping", "0") else str(path)
        vmas_by_pid.setdefault(pid, []).append(VMA(start, end, flags, file_path))

    fd_by_pid: dict[int, int] = {}
    for r in lsof:
        pid = _int(_col(r, "PID", "Pid"))
        fd_by_pid[pid] = fd_by_pid.get(pid, 0) + 1

    sockets_by_pid: dict[int, list[dict]] = {}
    for r in sockstat:
        pid = _int(_col(r, "PID", "Pid"))
        sockets_by_pid.setdefault(pid, []).append(dict(r))

    cmd_by_pid: dict[int, str] = {}
    exe_by_pid: dict[int, str] = {}
    for r in psaux:
        pid = _int(_col(r, "PID", "Pid"))
        args = str(_col(r, "ARGS", "Args", "COMM", "Command", default=""))
        cmd_by_pid[pid] = args
        parts = args.split()
        exe_by_pid[pid] = parts[0] if parts else ""

    env_by_pid: dict[int, dict[str, str]] = {}
    for r in envars:
        pid = _int(_col(r, "PID", "Pid"))
        key = str(_col(r, "Variable", "Key", default=""))
        val = str(_col(r, "Value", default=""))
        if key:
            env_by_pid.setdefault(pid, {})[key] = val

    # --- processes (task list) ---
    tasks: list[Process] = []
    for r in pslist:
        pid = _int(_col(r, "PID", "Pid"))
        tasks.append(Process(
            pid=pid,
            ppid=_int(_col(r, "PPID", "Ppid")),
            uid=_int(_col(r, "UID", "Uid"), default=0),
            comm=str(_col(r, "COMM", "Comm", "Process", default=str(pid))),
            task_offset=_int(_col(r, "OFFSET (V)", "Offset", "Offset (V)")),
            exe_path=exe_by_pid.get(pid),
            cmdline=cmd_by_pid.get(pid, ""),
            envars=env_by_pid.get(pid, {}),
            vmas=vmas_by_pid.get(pid, []),
            fd_count=fd_by_pid.get(pid, 0),
            sockets=sockets_by_pid.get(pid, []),
        ))

    # No fallback to the task list: comparing the task list with itself would
    # make the DKOM rule silently blind. None tells the rule to skip instead.
    pid_hash_pids = {_int(_col(r, "PID", "Pid")) for r in pidhash} if pidhash else None

    registered_modules = [
        KernelModule(
            name=str(_col(r, "Module Name", "Name", "Module", default="?")),
            base=_int(_col(r, "Offset", "Address", "Base")),
            size=_int(_col(r, "Code Size", "Size")),
        )
        for r in lsmod
    ]
    hidden_modules = [
        KernelModule(
            name=str(_col(r, "Module Name", "Name", "Module", default="?")),
            base=_int(_col(r, "Offset", "Address", "Base")),
            size=_int(_col(r, "Code Size", "Size")),
        )
        for r in hidden
    ]
    memory_modules = registered_modules + hidden_modules

    syscall_table = [
        SyscallEntry(
            index=_int(_col(r, "Index", "Position", "NR")),
            address=_int(_col(r, "Handler Address", "Address", "Handler")),
            symbol=(None if str(_col(r, "Handler Symbol", "Symbol", "Module", default="")).upper() in ("", "UNKNOWN")
                    else str(_col(r, "Handler Symbol", "Symbol", "Module"))),
        )
        for r in syscalls
    ]

    return MemoryEvidence(
        image_path=str(image_path),
        tasks_list=tasks,
        pid_hash_pids=pid_hash_pids,
        registered_modules=registered_modules,
        memory_modules=memory_modules,
        syscall_table=syscall_table,
        kernel_text=_kernel_text(ctx),
        unavailable_plugins=failed,
        raw_plugin_rows=raw_plugin_rows,
    )
