"""The hardened I/O layer is the only code that touches hostile files directly.

These tests encode the properties the rest of the codebase relies on, so that a
later refactor cannot quietly remove one.
"""

from __future__ import annotations

import os
import stat

import pytest

from airlock import config
from airlock.safeio import (SafeFile, UnsafeFile, secure_mkdir, sha256_bytes,
                            strip_execute_bits)


def test_reads_regular_file(tmp_path):
    path = tmp_path / "a.bin"
    path.write_bytes(b"hello world")
    with SafeFile(path) as sf:
        assert sf.size == 11
        assert sf.head(5) == b"hello"
        assert sf.read_all_bounded() == b"hello world"


def test_refuses_to_follow_symlinks(tmp_path):
    target = tmp_path / "secret"
    target.write_bytes(b"sensitive")
    link = tmp_path / "innocent.txt"
    link.symlink_to(target)
    with pytest.raises(UnsafeFile, match="symbolic link"):
        with SafeFile(link):
            pass


def test_refuses_fifo(tmp_path):
    """A FIFO would block a naive reader forever -- a one-file denial of service."""
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(UnsafeFile, match="not a regular file"):
        with SafeFile(fifo):
            pass


def test_refuses_directory(tmp_path):
    with pytest.raises(UnsafeFile):
        with SafeFile(tmp_path):
            pass


def test_missing_file_raises_unsafe(tmp_path):
    with pytest.raises(UnsafeFile):
        with SafeFile(tmp_path / "nope"):
            pass


def test_reads_are_bounded_and_never_raise(tmp_path):
    """Parsers ask for what a header claims. A hostile header claims a lot."""
    path = tmp_path / "small.bin"
    path.write_bytes(b"abcd")
    with SafeFile(path) as sf:
        assert sf.read_at(0, 1 << 40) == b"abcd"
        assert sf.read_at(1000, 10) == b""
        assert sf.read_at(-5, 10) == b""
        assert sf.read_at(0, 0) == b""
        assert sf.read_at(2, 100) == b"cd"


def test_read_at_respects_parse_window(tmp_path, monkeypatch):
    path = tmp_path / "big.bin"
    path.write_bytes(b"x" * 10000)
    monkeypatch.setattr(config, "MAX_PARSE_WINDOW", 100)
    with SafeFile(path) as sf:
        assert len(sf.read_at(0, 10000)) == 100


def test_truncation_flag_for_oversized_files(tmp_path, monkeypatch):
    path = tmp_path / "big.bin"
    path.write_bytes(b"y" * 5000)
    monkeypatch.setattr(config, "MAX_FILE_BYTES", 1000)
    with SafeFile(path) as sf:
        assert sf.truncated
        assert sf.readable_size == 1000
        assert len(sf.read_all_bounded(10000)) == 1000


def test_digests_match_hashlib(tmp_path):
    data = os.urandom(200000)
    path = tmp_path / "r.bin"
    path.write_bytes(data)
    with SafeFile(path) as sf:
        digests = sf.digests()
    assert digests.sha256 == sha256_bytes(data)


def test_copy_to_uses_the_open_descriptor_not_the_path(tmp_path):
    """The TOCTOU property: what gets quarantined is what got scanned, even if
    the path is swapped between the scan and the copy."""
    source = tmp_path / "file.bin"
    source.write_bytes(b"ORIGINAL-CONTENT")
    destination = tmp_path / "copy.bin"
    with SafeFile(source) as sf:
        source.unlink()
        source.write_bytes(b"SWAPPED-CONTENT!")
        sf.copy_to(destination)
    assert destination.read_bytes() == b"ORIGINAL-CONTENT"


def test_copy_to_refuses_to_overwrite(tmp_path):
    source = tmp_path / "a"
    source.write_bytes(b"x")
    destination = tmp_path / "b"
    destination.write_bytes(b"existing")
    with SafeFile(source) as sf:
        with pytest.raises(FileExistsError):
            sf.copy_to(destination)


def test_copy_to_creates_private_file(tmp_path):
    source = tmp_path / "a"
    source.write_bytes(b"x")
    destination = tmp_path / "b"
    with SafeFile(source) as sf:
        sf.copy_to(destination, mode=0o600)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_strip_execute_bits(tmp_path):
    path = tmp_path / "prog"
    path.write_bytes(b"#!/bin/sh\n")
    path.chmod(0o755)
    assert strip_execute_bits(path) is True
    mode = stat.S_IMODE(path.stat().st_mode)
    assert not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    assert mode & stat.S_IRUSR
    assert strip_execute_bits(path) is False  # already stripped


def test_secure_mkdir_is_private(tmp_path):
    path = secure_mkdir(tmp_path / "vault")
    assert stat.S_IMODE(path.stat().st_mode) == 0o700


def test_chunks_cover_the_whole_file(tmp_path, monkeypatch):
    data = os.urandom(5000)
    path = tmp_path / "c.bin"
    path.write_bytes(data)
    monkeypatch.setattr(config, "CHUNK_BYTES", 512)
    with SafeFile(path) as sf:
        assert b"".join(sf.chunks()) == data


def test_fd_released_on_exit(tmp_path):
    path = tmp_path / "a"
    path.write_bytes(b"x")
    sf = SafeFile(path)
    with sf:
        fd = sf.fd
    assert sf._fd is None
    with pytest.raises(OSError):
        os.fstat(fd)
