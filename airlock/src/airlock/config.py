"""Resource limits and policy thresholds.

These are the blast radius of a hostile file. A scanner is a parser of attacker
controlled input, so every loop in this codebase terminates against a bound
declared here rather than against the file's own claims about itself.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

#: Never read more than this from a single file, whatever it claims its size is.
MAX_FILE_BYTES = 1 << 30  # 1 GiB

#: Files larger than this are hashed and typed but not deep-parsed. Deep parsers
#: are the expensive, attack-prone code paths; huge inputs are where they hurt.
MAX_DEEP_PARSE_BYTES = 128 << 20  # 128 MiB

#: Read granularity. Bounds peak RSS regardless of file size.
CHUNK_BYTES = 1 << 20  # 1 MiB

#: Largest slice any single parser may hold in memory at once.
MAX_PARSE_WINDOW = 16 << 20  # 16 MiB

#: Regex rules only ever run against this much of a file (ReDoS blast radius).
MAX_REGEX_WINDOW = 4 << 20  # 4 MiB

#: Archive limits — the zip-bomb budget.
MAX_ARCHIVE_ENTRIES = 4096
MAX_ARCHIVE_TOTAL_UNCOMPRESSED = 1 << 30  # 1 GiB
MAX_ARCHIVE_ENTRY_UNCOMPRESSED = 256 << 20  # 256 MiB
MAX_COMPRESSION_RATIO = 200.0
#: How deep nested containers (zip in zip, base64 in script) are followed.
MAX_RECURSION_DEPTH = 4
#: Entries actually opened and re-scanned inside an archive.
MAX_NESTED_SCANS = 64
MAX_NESTED_SCAN_BYTES = 8 << 20  # 8 MiB

#: A single scan may not exceed this. On expiry the verdict fails closed.
SCAN_TIMEOUT_SECONDS = 120.0

#: PE/ELF structural bounds.
MAX_SECTIONS = 512
MAX_IMPORT_DLLS = 512
MAX_IMPORTS_PER_DLL = 8192
MAX_LOAD_COMMANDS = 512

#: Scripts: how much of a decoded layer is re-analysed.
MAX_DECODED_LAYER_BYTES = 4 << 20


def _default_home() -> Path:
    env = os.environ.get("AIRLOCK_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".airlock"


@dataclass(frozen=True)
class Paths:
    """Where Airlock keeps state. All of it is created 0700."""

    home: Path = field(default_factory=_default_home)

    @property
    def quarantine(self) -> Path:
        return self.home / "quarantine"

    @property
    def audit_log(self) -> Path:
        return self.home / "audit.log"

    @property
    def audit_key(self) -> Path:
        return self.home / "audit.key"

    @property
    def pins(self) -> Path:
        return self.home / "pins.json"


PATHS = Paths()


def package_data(*parts: str) -> Path:
    """A file shipped inside the package (rules, hash databases)."""
    return Path(__file__).resolve().parent.parent.parent / Path(*parts)
