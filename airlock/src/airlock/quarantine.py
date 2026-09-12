"""The quarantine vault -- where blocked files are held.

A quarantine is itself a risk: it is a directory full of malware on the machine
you are protecting. So the vault is built to make the held file as inert as the
filesystem allows:

* stored under a random identifier, never the attacker-chosen filename, so the
  name cannot carry a traversal, an RLO override, or a device name;
* mode 0600 inside a 0700 directory, with every execute bit cleared;
* copied from the *open descriptor* that was scanned, so what is held is what
  was analysed even if the source path was swapped mid-scan;
* stored with a ``.quarantined`` suffix so nothing on the desktop treats it as
  its original type;
* accompanied by a metadata sidecar recording why it was held.

Release requires an explicit decision and is refused outright for a file judged
MALICIOUS unless the operator forces it, which is logged.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import config
from .safeio import SafeFile, secure_mkdir, strip_execute_bits
from .verdict import Decision, Report

SUFFIX = ".quarantined"


class QuarantineError(Exception):
    pass


@dataclass
class Item:
    id: str
    original_path: str
    original_name: str
    sha256: str
    size: int
    decision: str
    score: int
    quarantined_at: str
    findings: list[dict[str, Any]]
    file_type: str = ""
    released_at: str = ""
    note: str = ""

    @property
    def blob_name(self) -> str:
        return f"{self.id}{SUFFIX}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "original_path": self.original_path,
            "original_name": self.original_name, "sha256": self.sha256,
            "size": self.size, "decision": self.decision, "score": self.score,
            "quarantined_at": self.quarantined_at, "file_type": self.file_type,
            "released_at": self.released_at, "note": self.note,
            "findings": self.findings,
        }

    @classmethod
    def from_dict(cls, blob: dict[str, Any]) -> "Item":
        return cls(
            id=blob["id"], original_path=blob.get("original_path", ""),
            original_name=blob.get("original_name", ""), sha256=blob.get("sha256", ""),
            size=int(blob.get("size", 0)), decision=blob.get("decision", "UNKNOWN"),
            score=int(blob.get("score", 0)),
            quarantined_at=blob.get("quarantined_at", ""),
            findings=blob.get("findings", []), file_type=blob.get("file_type", ""),
            released_at=blob.get("released_at", ""), note=blob.get("note", ""))


class Vault:
    def __init__(self, root: Path | None = None):
        self.root = root or config.PATHS.quarantine

    def ensure(self) -> Path:
        return secure_mkdir(self.root)

    # -- intake ------------------------------------------------------------
    def store(self, sf: SafeFile, report: Report, remove_original: bool = False) -> Item:
        """Copy the scanned descriptor into the vault."""
        self.ensure()
        item_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{secrets.token_hex(6)}"
        item = Item(
            id=item_id,
            original_path=str(sf.path),
            original_name=sf.path.name,
            sha256=report.sha256,
            size=report.size,
            decision=report.decision.label,
            score=report.score,
            quarantined_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            findings=[f.to_dict() for f in report.sorted_findings()],
            file_type=report.file_type,
        )
        blob = self.root / item.blob_name
        try:
            sf.copy_to(blob, mode=0o600)
        except FileExistsError as exc:
            raise QuarantineError(f"vault collision on {item.id}") from exc
        except OSError as exc:
            raise QuarantineError(f"could not write to the vault: {exc}") from exc
        strip_execute_bits(blob)
        self._write_meta(item)

        if remove_original:
            try:
                os.unlink(sf.path)
            except OSError as exc:
                item.note = f"original left in place: {exc}"
                self._write_meta(item)
        return item

    def _write_meta(self, item: Item) -> None:
        meta = self.root / f"{item.id}.json"
        fd = os.open(meta, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps(item.to_dict(), indent=2).encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    # -- inventory ---------------------------------------------------------
    def items(self) -> list[Item]:
        if not self.root.exists():
            return []
        out: list[Item] = []
        for meta in sorted(self.root.glob("*.json")):
            try:
                out.append(Item.from_dict(json.loads(meta.read_text())))
            except (OSError, json.JSONDecodeError, KeyError, ValueError):
                continue
        return out

    def get(self, item_id: str) -> Item:
        for item in self.items():
            if item.id == item_id or item.id.startswith(item_id):
                return item
        raise QuarantineError(f"no quarantined item matching {item_id!r}")

    # -- egress ------------------------------------------------------------
    def release(self, item_id: str, destination: Path, force: bool = False) -> Path:
        """Restore a held file. Refuses MALICIOUS without an explicit force."""
        item = self.get(item_id)
        if item.decision == Decision.MALICIOUS.label and not force:
            raise QuarantineError(
                f"{item.id} was judged MALICIOUS ({item.original_name}). Releasing it puts "
                "the file back where it can be run. Re-read 'airlock quarantine show' "
                "first; pass --force only if you are certain the verdict is wrong.")
        blob = self.root / item.blob_name
        if not blob.exists():
            raise QuarantineError(f"{item.id}: the held file is missing from the vault")

        destination = Path(destination)
        if destination.is_dir():
            destination = destination / item.original_name
        # The held name is attacker-supplied. Reduce it to a basename and strip
        # the characters that make a name lie about what it is.
        destination = destination.parent / _safe_name(destination.name)
        if destination.exists():
            raise QuarantineError(f"{destination} already exists; refusing to overwrite")

        with SafeFile(blob) as held:
            held.copy_to(destination, mode=0o600)
        item.released_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        item.note = (item.note + " " if item.note else "") + f"released to {destination}"
        self._write_meta(item)
        return destination

    def purge(self, item_id: str) -> Item:
        """Overwrite and delete a held file.

        The overwrite is a courtesy, not a guarantee: on a journalling
        filesystem, an SSD with wear levelling, or any copy-on-write volume, the
        original blocks may survive. Treat it as removal from the namespace.
        """
        item = self.get(item_id)
        blob = self.root / item.blob_name
        if blob.exists():
            try:
                size = blob.stat().st_size
                fd = os.open(blob, os.O_WRONLY)
                try:
                    written = 0
                    while written < size:
                        chunk = min(config.CHUNK_BYTES, size - written)
                        written += os.write(fd, b"\x00" * chunk)
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except OSError:
                pass
            blob.unlink(missing_ok=True)
        (self.root / f"{item.id}.json").unlink(missing_ok=True)
        return item


def _safe_name(name: str) -> str:
    """Reduce an attacker-supplied name to something safe to write to disk.

    Removes path separators, control characters, and the Unicode that makes a
    name render differently from what it is -- the file is being handed back to
    a desktop, and it should not arrive still wearing its disguise.
    """
    name = name.replace("/", "_").replace("\\", "_")
    cleaned = []
    for ch in name:
        code = ord(ch)
        if (0x202A <= code <= 0x202E          # bidi embedding and override
                or 0x2066 <= code <= 0x2069   # bidi isolates
                or 0x200B <= code <= 0x200F   # zero-width and directional marks
                or code == 0xFEFF
                or not ch.isprintable()):
            continue
        cleaned.append(ch)
    result = "".join(cleaned).strip(" .")
    return (result or "released_file")[:180]
