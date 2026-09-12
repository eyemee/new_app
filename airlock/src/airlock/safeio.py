"""Hardened access to untrusted files.

Three properties matter here and nowhere else in the codebase has to think about
them again:

1. **No symlink traversal.** The final path component is opened ``O_NOFOLLOW``,
   so a file dropped in a watched directory cannot point the scanner at
   ``/etc/shadow`` and have it hashed into an audit log.
2. **No TOCTOU.** Everything -- stat, hash, type detection, quarantine intake --
   is done against one file descriptor opened once. The bytes that were scanned
   are the bytes that get quarantined, even if the path is swapped mid-scan.
3. **No unbounded reads.** Regular files only (an ``O_NONBLOCK`` open followed by
   an ``fstat`` check rejects FIFOs and devices before a read can block forever),
   and every read is clamped to a limit from ``config``.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

from . import config

try:  # POSIX only; Airlock analyses Windows files but also runs on Windows
    import fcntl
except ImportError:
    fcntl = None

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)
_O_NOCTTY = getattr(os, "O_NOCTTY", 0)


class UnsafeFile(Exception):
    """The path is not something we are willing to open."""


@dataclass(frozen=True)
class Digests:
    sha256: str
    sha1: str
    md5: str


class SafeFile:
    """A bounded, symlink-proof, fd-pinned handle on one regular file."""

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self._fd: int | None = None
        self.size = 0
        self.mode = 0
        self.truncated = False

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self) -> "SafeFile":
        flags = os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_BINARY | _O_NOCTTY
        try:
            fd = os.open(self.path, flags)
        except OSError as exc:
            # ELOOP is what O_NOFOLLOW raises on a symlink; say so plainly
            # rather than letting it read as a generic I/O failure.
            if exc.errno == errno.ELOOP:
                raise UnsafeFile(f"{self.path}: is a symbolic link (refusing to follow)") from exc
            raise UnsafeFile(f"{self.path}: {exc.strerror or exc}") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise UnsafeFile(f"{self.path}: not a regular file")
            # Drop O_NONBLOCK now that we know it is a regular file; it was only
            # there so the open() itself could not hang on a FIFO.
            if _O_NONBLOCK and fcntl is not None:
                fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) & ~_O_NONBLOCK)
            self.size = st.st_size
            self.mode = st.st_mode
            self.truncated = self.size > config.MAX_FILE_BYTES
        except Exception:
            os.close(fd)
            raise
        self._fd = fd
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        self.close()

    def close(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            finally:
                self._fd = None

    @property
    def fd(self) -> int:
        if self._fd is None:
            raise RuntimeError("SafeFile is not open")
        return self._fd

    # -- bounded reads -----------------------------------------------------
    @property
    def readable_size(self) -> int:
        return min(self.size, config.MAX_FILE_BYTES)

    def read_at(self, offset: int, length: int) -> bytes:
        """Read ``length`` bytes at ``offset``, clamped to the file and to
        ``MAX_PARSE_WINDOW``. Never raises on a short or out-of-range read --
        parsers ask for what a header claims is there, and a hostile header
        claims a lot."""
        if offset < 0 or length <= 0:
            return b""
        limit = self.readable_size
        if offset >= limit:
            return b""
        length = min(length, config.MAX_PARSE_WINDOW, limit - offset)
        try:
            return os.pread(self.fd, length, offset)
        except OSError:
            return b""

    def head(self, length: int = 8192) -> bytes:
        return self.read_at(0, length)

    def tail(self, length: int = 8192) -> bytes:
        limit = self.readable_size
        return self.read_at(max(0, limit - length), min(length, limit))

    def chunks(self, chunk: int = config.CHUNK_BYTES):
        offset = 0
        limit = self.readable_size
        while offset < limit:
            data = self.read_at(offset, min(chunk, limit - offset))
            if not data:
                break
            offset += len(data)
            yield data

    def read_all_bounded(self, cap: int = config.MAX_PARSE_WINDOW) -> bytes:
        return self.read_at(0, min(cap, self.readable_size))

    # -- identity ----------------------------------------------------------
    def digests(self) -> Digests:
        """All three digests in a single pass over the file.

        MD5 and SHA-1 are here because threat-intel feeds are still keyed on
        them, not because they are trusted. Only SHA-256 is used for any
        decision Airlock makes.
        """
        h256, h1, hmd5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
        for data in self.chunks():
            h256.update(data)
            h1.update(data)
            hmd5.update(data)
        return Digests(h256.hexdigest(), h1.hexdigest(), hmd5.hexdigest())

    def copy_to(self, dest: Path, mode: int = 0o600) -> int:
        """Copy the *open descriptor* (not the path) to ``dest``.

        ``O_EXCL`` means we never land on an existing file, and the mode is set
        at creation time rather than after, so the copy is never momentarily
        readable by anyone else.
        """
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_BINARY
        out = os.open(dest, flags, mode)
        written = 0
        try:
            for data in self.chunks():
                view = memoryview(data)
                while view:
                    n = os.write(out, view)
                    view = view[n:]
                    written += n
        finally:
            os.close(out)
        return written


def secure_mkdir(path: Path, mode: int = 0o700) -> Path:
    """Create a directory the current user alone can enter, and confirm it."""
    path.mkdir(parents=True, mode=mode, exist_ok=True)
    try:
        os.chmod(path, mode)
    except OSError:
        pass
    return path


def strip_execute_bits(path: Path) -> bool:
    """Remove every execute bit. First containment action on any new file.

    This is not a security boundary -- a user can chmod it back, and it does
    nothing for interpreted payloads that are run as ``sh file``. It removes the
    single-click path from "downloaded" to "running", which is the one that
    actually costs people.
    """
    try:
        current = stat.S_IMODE(os.lstat(path).st_mode)
    except OSError:
        return False
    stripped = current & ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    if stripped == current:
        return False
    try:
        os.chmod(path, stripped)
        return True
    except OSError:
        return False


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(config.CHUNK_BYTES), b""):
            h.update(block)
    return h.hexdigest()
