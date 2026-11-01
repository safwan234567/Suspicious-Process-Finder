"""Stage A - Extraction.

Calls the Volatility 3 API (not the CLI) to collect raw evidence from a .raw or
.lime image. This stage never decides whether anything is malicious.

Volatility 3 Linux plugins to use:
  tasks list          linux.pslist.PsList
  PID hash table      linux.pidhashtable.PIDHashTable
  VMAs + permissions  linux.proc.Maps
  file descriptors    linux.lsof.Lsof
  sockets             linux.sockstat.Sockstat
  registered modules  linux.lsmod.Lsmod
  modules in memory   linux.hidden_modules.Hidden_modules
  syscall table       linux.check_syscall.Check_syscall
  command lines       linux.psaux.PsAux
  environment vars    linux.envars.Envars
"""

from __future__ import annotations

from pathlib import Path

from spf.models import MemoryEvidence

SUPPORTED_FORMATS = {".raw", ".lime"}


def extract(image_path: str | Path, symbols_dir: str | Path) -> MemoryEvidence:
    """Run the Volatility 3 plugins on one image and return the combined evidence."""
    image_path = Path(image_path)
    if image_path.suffix.lower() not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported image format {image_path.suffix}; expected .raw or .lime")
    raise NotImplementedError("TODO: build a Volatility 3 context and run the plugins listed above")
