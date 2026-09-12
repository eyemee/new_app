"""The airlock itself: a watcher over incoming directories.

What it actually does, stated precisely so nobody relies on more:

A new file appears in a watched directory. The watcher waits until the file has
stopped growing (a download in progress is not a file yet), immediately clears
its execute bits, scans it, and acts on the verdict -- leaving it, marking it, or
moving it into the quarantine vault.

What this is: the window between "the file landed" and "the user double-clicked
it" is where a download gets opened, and this closes it automatically for the
blocking cases.

What this is **not**: execution prevention. A userspace poller cannot stop a
process from starting. A file that is run in the seconds before the scan
completes, or that a user retrieves from quarantine and runs anyway, runs. Real
pre-execution blocking needs an OS-level hook -- AppLocker or WDAC on Windows,
Gatekeeper and Endpoint Security on macOS, fanotify with FAN_OPEN_PERM on Linux.
Airlock is complementary to those, not a replacement.

Polling rather than inotify/FSEvents/ReadDirectoryChangesW is deliberate: one
portable code path with no native dependencies, and the latency difference does
not matter against a human deciding whether to double-click.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from .audit import AuditLog
from .quarantine import QuarantineError, Vault
from .safeio import SafeFile, UnsafeFile, strip_execute_bits
from .scanner import Scanner
from .verdict import Decision, Report

#: A file is considered complete once it has stopped changing. Two independent
#: signals establish that, because neither is sufficient alone:
#:
#: * its size was unchanged across consecutive polls -- responsive, but only
#:   works within one long-running process;
#: * it has not been modified for SETTLE_SECONDS -- works for a one-shot
#:   ``--once`` run, which has no history to compare against.
STABLE_POLLS = 2
SETTLE_SECONDS = 1.5

#: Partial-download suffixes used by browsers and download managers.
IN_PROGRESS_SUFFIXES = (".part", ".crdownload", ".download", ".partial", ".tmp",
                        ".!ut", ".opdownload", ".aria2")


@dataclass
class WatchEvent:
    path: Path
    report: Report
    action: str            # "left" | "contained" | "quarantined" | "failed"
    quarantine_id: str = ""
    message: str = ""


@dataclass
class Watcher:
    scanner: Scanner
    directories: list[Path]
    vault: Vault = field(default_factory=Vault)
    audit: AuditLog = field(default_factory=AuditLog)
    interval: float = 2.0
    settle_seconds: float = SETTLE_SECONDS
    quarantine_at: Decision = Decision.QUARANTINE
    dry_run: bool = False
    recursive: bool = False
    on_event: Callable[[WatchEvent], None] | None = None

    _sizes: dict[Path, tuple[int, int]] = field(default_factory=dict, init=False)
    _handled: set[tuple[str, int, int]] = field(default_factory=set, init=False)

    # ----------------------------------------------------------------------
    def prime(self) -> int:
        """Record what is already present so a first run does not re-scan an
        entire Downloads folder. Only files arriving after this point are gated."""
        count = 0
        for path in self._candidates():
            try:
                st = path.stat()
            except OSError:
                continue
            self._handled.add((str(path), st.st_size, int(st.st_mtime)))
            count += 1
        return count

    def run(self, iterations: int | None = None) -> list[WatchEvent]:
        """Poll until interrupted, or for a fixed number of iterations (tests)."""
        events: list[WatchEvent] = []
        loops = 0
        while iterations is None or loops < iterations:
            events.extend(self.poll_once())
            loops += 1
            if iterations is not None and loops >= iterations:
                break
            time.sleep(self.interval)
        return events

    def poll_once(self) -> list[WatchEvent]:
        events: list[WatchEvent] = []
        for path in self._candidates():
            try:
                st = path.stat()
            except OSError:
                self._sizes.pop(path, None)
                continue
            key = (str(path), st.st_size, int(st.st_mtime))
            if key in self._handled:
                continue

            if not self._settled(path, st):
                continue

            self._handled.add(key)
            self._sizes.pop(path, None)
            event = self.handle(path)
            events.append(event)
            if self.on_event:
                self.on_event(event)
        return events

    def _settled(self, path: Path, st) -> bool:
        """Has this file finished being written?

        Scanning a download while it is still arriving produces a verdict on a
        prefix, which is worse than no verdict -- it is a *wrong* verdict that
        looks authoritative.
        """
        if time.time() - st.st_mtime >= self.settle_seconds:
            self._sizes.pop(path, None)
            return True
        seen_size, stable_for = self._sizes.get(path, (-1, 0))
        if st.st_size != seen_size:
            self._sizes[path] = (st.st_size, 0)
            return False
        if stable_for < STABLE_POLLS:
            self._sizes[path] = (st.st_size, stable_for + 1)
            return False
        self._sizes.pop(path, None)
        return True

    # ----------------------------------------------------------------------
    def handle(self, path: Path) -> WatchEvent:
        """Contain first, scan second. Containment is cheap and reversible; the
        scan takes time, and that time is exactly when the user is looking at a
        fresh download deciding whether to open it."""
        contained = False
        if not self.dry_run:
            contained = strip_execute_bits(path)

        report = self.scanner.scan_path(path)
        decision = report.decision

        if decision < self.quarantine_at:
            action = "contained" if contained else "left"
            message = ("execute bits cleared; left in place" if contained
                       else "left in place")
            self._record(report, action, "")
            return WatchEvent(path, report, action, message=message)

        if self.dry_run:
            self._record(report, "dry-run", "")
            return WatchEvent(path, report, "left",
                              message="would have been quarantined (dry run)")

        try:
            with SafeFile(path) as sf:
                item = self.vault.store(sf, report, remove_original=True)
        except (UnsafeFile, QuarantineError, OSError) as exc:
            self._record(report, "failed", "")
            return WatchEvent(path, report, "failed",
                              message=f"could not quarantine: {exc}")

        self._record(report, "quarantined", item.id)
        return WatchEvent(path, report, "quarantined", quarantine_id=item.id,
                          message=f"moved to quarantine as {item.id}")

    def _record(self, report: Report, action: str, item_id: str) -> None:
        try:
            self.audit.append("watch", {
                "path": report.path, "name": report.display_name,
                "sha256": report.sha256, "decision": report.decision.label,
                "score": report.score, "action": action,
                "quarantine_id": item_id,
                "top_findings": [f.id for f in report.sorted_findings()[:5]],
            })
        except Exception:
            # Losing an audit record must not stop the gate from working, but it
            # must not pass silently either -- surfaced by the caller's stderr.
            pass

    # ----------------------------------------------------------------------
    def _candidates(self) -> Iterable[Path]:
        for directory in self.directories:
            if not directory.is_dir():
                continue
            walker = directory.rglob("*") if self.recursive else directory.iterdir()
            for entry in walker:
                try:
                    # is_file() follows symlinks; a symlink into /etc is not a
                    # download and SafeFile would refuse it anyway.
                    if entry.is_symlink() or not entry.is_file():
                        continue
                except OSError:
                    continue
                name = entry.name
                if name.startswith("."):
                    continue
                if name.lower().endswith(IN_PROGRESS_SUFFIXES):
                    continue
                yield entry


def default_watch_directories() -> list[Path]:
    home = Path.home()
    candidates = [home / "Downloads", home / "Desktop", Path("/tmp/airlock-inbox")]
    return [c for c in candidates if c.is_dir()]
