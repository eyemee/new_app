"""Digest reputation: known-bad, allowlist, and publisher pinning.

Three separate mechanisms, because they answer different questions:

* **Known-bad** -- "has this exact file already been identified as malicious?"
  A hash database is exact and cheap, and useless against anything recompiled.
  It is the first check, never the only one.
* **Allowlist** -- "has my organisation reviewed this exact file?" Suppresses
  findings on software known to be fine, and only on the digest reviewed.
* **Pinning** -- "is this the same publisher's build I trusted last time?"
  The one check here that catches something new: an installer you have taken
  before whose digest has changed is either an update or a supply-chain swap,
  and the point is that you look rather than assume.

Optional online lookup sends the SHA-256 and nothing else.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import config
from .safeio import secure_mkdir
from .verdict import Decision, Finding, Severity


@dataclass
class Database:
    known_bad: dict[str, dict] = field(default_factory=dict)
    allowlist: dict[str, dict] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict:
        return {"known_bad": len(self.known_bad), "allowlist": len(self.allowlist),
                "sources": self.sources}


def load_database(paths: list[Path] | None = None) -> Database:
    db = Database()
    candidates = paths or [config.package_data("data", "known_bad.json"),
                           config.package_data("data", "allowlist.json")]
    for path in candidates:
        if not path.exists():
            continue
        try:
            blob = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue  # a corrupt database must not take the scanner down
        entries = blob.get("entries", {})
        if not isinstance(entries, dict):
            continue
        target = db.known_bad if "known_bad" in path.name else db.allowlist
        for digest, meta in entries.items():
            if isinstance(digest, str) and len(digest) == 64 and isinstance(meta, dict):
                target[digest.lower()] = meta
        db.sources.append(path.name)
    return db


def check(sha256: str, db: Database) -> list[Finding]:
    digest = sha256.lower()
    if digest in db.known_bad:
        meta = db.known_bad[digest]
        harmless = meta.get("harmless", False)
        return [Finding(
            id="REP_KNOWN_BAD",
            title=f"Digest matches known-bad entry: {meta.get('name', 'unnamed')}",
            severity=Severity.CRITICAL,
            category="reputation",
            detail=(meta.get("source", "")
                    + (" This file is inert by design and safe to handle."
                       if harmless else
                       " Do not run this file. Handle it only in an isolated environment.")),
            evidence=[f"sha256: {digest}",
                      f"family: {meta.get('family', 'unknown')}"],
            decisive=Decision.MALICIOUS,
        )]
    if digest in db.allowlist:
        meta = db.allowlist[digest]
        return [Finding(
            id="REP_ALLOWLISTED",
            title=f"Digest is allowlisted: {meta.get('name', 'reviewed file')}",
            severity=Severity.INFO,
            category="reputation",
            detail="This exact file has been reviewed and approved. Findings below are "
                   "recorded for the audit trail but do not raise the verdict, unless "
                   "something CRITICAL turns up -- in which case the allowlist entry is "
                   "what needs revisiting.",
            evidence=[f"sha256: {digest}", f"approved by: {meta.get('approved_by', 'unknown')}"],
        )]
    return []


# --------------------------------------------------------------------------
# Publisher pinning
# --------------------------------------------------------------------------
@dataclass
class Pin:
    name: str
    sha256: str
    size: int
    first_seen: str
    source_path: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "sha256": self.sha256, "size": self.size,
                "first_seen": self.first_seen, "source_path": self.source_path}


def load_pins(path: Path | None = None) -> dict[str, Pin]:
    path = path or config.PATHS.pins
    if not path.exists():
        return {}
    try:
        blob = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    out: dict[str, Pin] = {}
    for name, meta in blob.items():
        if isinstance(meta, dict) and isinstance(meta.get("sha256"), str):
            out[name] = Pin(name=name, sha256=meta["sha256"], size=meta.get("size", 0),
                            first_seen=meta.get("first_seen", ""),
                            source_path=meta.get("source_path", ""))
    return out


def save_pins(pins: dict[str, Pin], path: Path | None = None) -> None:
    path = path or config.PATHS.pins
    secure_mkdir(path.parent)
    tmp = path.with_suffix(".json.tmp")
    payload = json.dumps({n: p.to_dict() for n, p in sorted(pins.items())}, indent=2)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload.encode() + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)  # atomic: a crash never leaves a half-written pin file


def add_pin(name: str, sha256: str, size: int, source_path: str = "",
            path: Path | None = None) -> Pin:
    pins = load_pins(path)
    pin = Pin(name=name, sha256=sha256, size=size,
              first_seen=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              source_path=source_path)
    pins[name] = pin
    save_pins(pins, path)
    return pin


def check_pin(name: str, sha256: str, pins: dict[str, Pin]) -> list[Finding]:
    """Compare a file against the pinned digest for the same publisher name."""
    pin = pins.get(name)
    if pin is None:
        return []
    if pin.sha256 == sha256.lower():
        return [Finding(
            id="REP_PIN_MATCH",
            title=f"Matches the pinned digest for {name!r}",
            severity=Severity.INFO,
            category="reputation",
            detail=f"Byte-identical to the copy pinned on {pin.first_seen}.",
            evidence=[f"sha256: {sha256}"],
        )]
    return [Finding(
        id="REP_PIN_MISMATCH",
        title=f"Digest differs from the pinned copy of {name!r}",
        severity=Severity.HIGH,
        category="reputation",
        detail=("You pinned a build of this name before and this is not it. That is either "
                "a legitimate update or a substituted download -- a compromised mirror, a "
                "hijacked update channel, a man-in-the-middle. Verify against the vendor's "
                "published checksum before running it, then re-pin."),
        evidence=[f"pinned:  {pin.sha256} ({pin.size} bytes, {pin.first_seen})",
                  f"current: {sha256.lower()}"],
        attck="T1195.002",
    )]


# --------------------------------------------------------------------------
# Optional online lookup
# --------------------------------------------------------------------------
def online_lookup(sha256: str, api_key: str, timeout: float = 8.0,
                  opener=None) -> list[Finding]:
    """Query VirusTotal for a digest verdict.

    Off unless ``--online`` is passed *and* ``VT_API_KEY`` is set. Only the
    SHA-256 leaves the machine -- never the file, its name, or its path -- so a
    lookup cannot exfiltrate the contents of what you are scanning. A failed
    lookup is reported as unknown and never lowers a verdict: the network being
    down is not evidence of innocence.
    """
    import json as _json
    import urllib.error
    import urllib.request

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    request = urllib.request.Request(url, headers={"x-apikey": api_key,
                                                   "Accept": "application/json"})
    try:
        open_url = opener or urllib.request.urlopen
        with open_url(request, timeout=timeout) as response:
            payload = _json.loads(response.read(1 << 20).decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return [Finding(
                id="REP_ONLINE_UNKNOWN", title="Not present in the online reputation service",
                severity=Severity.LOW, category="reputation",
                detail="No record of this digest. Expected for a freshly built or freshly "
                       "packed file -- which includes both your own builds and new malware.",
                evidence=[f"sha256: {sha256}"], weight=3)]
        return _lookup_error(f"HTTP {exc.code}")
    except Exception as exc:  # network, TLS, JSON, timeout
        return _lookup_error(str(exc)[:120])

    stats = (payload.get("data", {}).get("attributes", {})
             .get("last_analysis_stats", {}) or {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    total = sum(int(v or 0) for v in stats.values()) or 1
    names = (payload.get("data", {}).get("attributes", {})
             .get("popular_threat_classification", {}).get("suggested_threat_label", ""))

    if malicious >= 3:
        return [Finding(
            id="REP_ONLINE_MALICIOUS",
            title=f"{malicious} of {total} engines report this file as malicious",
            severity=Severity.CRITICAL, category="reputation",
            detail=f"Online reputation verdict{f': {names}' if names else ''}.",
            evidence=[f"sha256: {sha256}", f"malicious: {malicious}", f"suspicious: {suspicious}"],
            decisive=Decision.MALICIOUS)]
    if malicious or suspicious >= 3:
        return [Finding(
            id="REP_ONLINE_SUSPICIOUS",
            title=f"{malicious} malicious / {suspicious} suspicious of {total} engines",
            severity=Severity.HIGH, category="reputation",
            detail="A minority verdict. Often a generic or heuristic detection; sometimes "
                   "the first engine to catch something new.",
            evidence=[f"sha256: {sha256}"])]
    return [Finding(
        id="REP_ONLINE_CLEAN",
        title=f"No engine of {total} reports this file as malicious",
        severity=Severity.INFO, category="reputation",
        detail="Absence of a detection is not evidence of safety, and says nothing about "
               "the local findings below.",
        evidence=[f"sha256: {sha256}"])]


def _lookup_error(reason: str) -> list[Finding]:
    return [Finding(
        id="REP_ONLINE_ERROR", title="Online reputation lookup failed",
        severity=Severity.INFO, category="reputation",
        detail="The verdict below is based on local analysis only. A failed lookup never "
               "lowers a verdict.",
        evidence=[reason])]
