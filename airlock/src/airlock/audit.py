"""Tamper-evident audit log.

Every decision Airlock makes is appended to a hash chain: each record carries
the digest of the record before it, and the whole record is authenticated with
an HMAC under a key that lives only in the operator's own directory, mode 0600.

What this buys, precisely:

* Editing any past record, reordering records, or inserting one, breaks the
  chain at that point and ``airlock verify-log`` names the record.
* Recomputing the chain to hide an edit requires the HMAC key.

What it does not buy, and the docs say so plainly: an attacker who reaches the
key can rewrite the log, and *anyone* can truncate it from the end -- the last
record's digest is not witnessed anywhere else. Detecting that needs the head
digest shipped somewhere the attacker does not control. The chain makes
tampering detectable, not impossible.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from . import config
from .safeio import secure_mkdir

GENESIS = "0" * 64
KEY_BYTES = 32


class AuditError(Exception):
    """The log could not be written or read."""


def _canonical(payload: dict[str, Any]) -> bytes:
    """Byte-stable serialisation -- the chain is only meaningful if every
    verifier reproduces exactly the bytes the writer hashed."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()


@dataclass
class Entry:
    seq: int
    ts: str
    event: str
    data: dict[str, Any]
    prev: str
    digest: str

    def body(self) -> dict[str, Any]:
        return {"seq": self.seq, "ts": self.ts, "event": self.event,
                "data": self.data, "prev": self.prev}

    def to_json(self) -> str:
        payload = self.body()
        payload["digest"] = self.digest
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class AuditLog:
    def __init__(self, path: Path | None = None, key_path: Path | None = None):
        self.path = path or config.PATHS.audit_log
        self.key_path = key_path or config.PATHS.audit_key
        self._key: bytes | None = None

    # -- key management ----------------------------------------------------
    def key(self) -> bytes:
        """Load the HMAC key, creating it on first use.

        Created with ``O_EXCL`` at mode 0600 so two concurrent scans cannot race
        into different keys, and so the key is never briefly world-readable.
        """
        if self._key is not None:
            return self._key
        secure_mkdir(self.path.parent)
        try:
            fd = os.open(self.key_path, os.O_RDONLY)
        except FileNotFoundError:
            material = secrets.token_bytes(KEY_BYTES)
            try:
                fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                return self.key()  # another process won the race; read theirs
            try:
                os.write(fd, material)
                os.fsync(fd)
            finally:
                os.close(fd)
            self._key = material
            return material
        try:
            material = os.read(fd, KEY_BYTES * 4)
        finally:
            os.close(fd)
        if len(material) < KEY_BYTES:
            raise AuditError(f"{self.key_path}: audit key is truncated")
        self._key = material
        return material

    def _digest(self, body: dict[str, Any]) -> str:
        return hmac.new(self.key(), _canonical(body), hashlib.sha256).hexdigest()

    # -- writing -----------------------------------------------------------
    def append(self, event: str, data: dict[str, Any]) -> Entry:
        secure_mkdir(self.path.parent)
        last = self.last_entry()
        entry = Entry(
            seq=(last.seq + 1) if last else 1,
            ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            event=event,
            data=data,
            prev=last.digest if last else GENESIS,
            digest="",
        )
        entry.digest = self._digest(entry.body())
        line = entry.to_json() + "\n"
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            # One write() of one line: O_APPEND makes it atomic against other
            # writers, so concurrent scans cannot interleave half-records.
            os.write(fd, line.encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        return entry

    # -- reading -----------------------------------------------------------
    def entries(self) -> Iterator[Entry]:
        if not self.path.exists():
            return
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                    yield Entry(seq=payload["seq"], ts=payload["ts"],
                                event=payload["event"], data=payload["data"],
                                prev=payload["prev"], digest=payload["digest"])
                except (json.JSONDecodeError, KeyError, TypeError):
                    raise AuditError("malformed audit record encountered")

    def last_entry(self) -> Entry | None:
        last = None
        try:
            for last in self.entries():
                pass
        except AuditError:
            raise
        return last

    def verify(self) -> tuple[bool, list[str]]:
        """Walk the chain. Returns (ok, problems)."""
        problems: list[str] = []
        previous_digest = GENESIS
        expected_seq = 1
        count = 0
        try:
            for entry in self.entries():
                count += 1
                if entry.seq != expected_seq:
                    problems.append(
                        f"record {count}: sequence is {entry.seq}, expected {expected_seq} "
                        "-- a record was inserted or removed")
                if entry.prev != previous_digest:
                    problems.append(
                        f"record {entry.seq}: prev digest {entry.prev[:16]}... does not match "
                        f"the previous record's {previous_digest[:16]}... -- the chain is broken here")
                recomputed = self._digest(entry.body())
                if not hmac.compare_digest(recomputed, entry.digest):
                    problems.append(
                        f"record {entry.seq}: content does not match its authenticator "
                        "-- this record was modified after it was written")
                previous_digest = entry.digest
                expected_seq = entry.seq + 1
        except AuditError as exc:
            problems.append(str(exc))
        return (not problems, problems)

    def tail(self, count: int = 20) -> list[Entry]:
        return list(self.entries())[-count:]
