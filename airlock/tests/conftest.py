"""Shared fixtures.

Every test runs against a temporary ``AIRLOCK_HOME`` so that running the suite
never touches a real quarantine vault, audit log or pin file.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from airlock import config, reputation, samples  # noqa: E402
from airlock.rules import load_ruleset  # noqa: E402
from airlock.scanner import Scanner  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Point every stateful path at a per-test directory."""
    home = tmp_path / "airlock-home"
    monkeypatch.setattr(config, "PATHS", config.Paths(home=home))
    monkeypatch.setenv("AIRLOCK_HOME", str(home))
    return home


@pytest.fixture(scope="session")
def ruleset():
    return load_ruleset([ROOT / "rules" / "default.rules"], ROOT / "rules" / "rules.lock")


@pytest.fixture
def scanner(ruleset):
    return Scanner(ruleset=ruleset, database=reputation.load_database())


@pytest.fixture
def corpus(tmp_path):
    """The full synthetic sample corpus, written to disk."""
    return samples.write_samples(tmp_path / "corpus")


@pytest.fixture
def write_sample(tmp_path):
    """Write arbitrary bytes under an arbitrary name, and return the path."""
    directory = tmp_path / "samples"
    directory.mkdir(exist_ok=True)
    counter = {"n": 0}

    def _write(name: str, data: bytes) -> Path:
        counter["n"] += 1
        sub = directory / str(counter["n"])
        sub.mkdir()
        path = sub / name
        path.write_bytes(data)
        return path
    return _write
