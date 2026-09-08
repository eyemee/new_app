"""Core data model.

The whole system turns on one idea: every teaching point in the master plan is a
*beat* with a stable ID, and every downstream artefact declares which beat IDs it
depends on. Reconciliation assigns a status to each beat; impact analysis then
falls out of the dependency edges automatically.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


# --- Beat status vocabulary -------------------------------------------------
# These are the only verdicts the reconciler may return for a planned beat.
TAUGHT = "TAUGHT"        # covered, in the planned position, substantially as written
MOVED = "MOVED"          # covered, but somewhere else in the running order
MODIFIED = "MODIFIED"    # covered, but the substance changed (facts, count, scope)
SKIPPED = "SKIPPED"      # never covered on camera
ADDED = "ADDED"          # taught but not in the plan at all (no planned beat exists)
MERGED = "MERGED"        # folded into another beat rather than taught standalone

PLANNED_STATUSES = (TAUGHT, MOVED, MODIFIED, SKIPPED, MERGED)


def fmt_tc(seconds: float | None) -> str:
    """Format seconds as HH:MM:SS, the form editors paste into a timeline."""
    if seconds is None:
        return "--:--:--"
    seconds = int(round(seconds))
    return f"{seconds // 3600:02d}:{(seconds % 3600) // 60:02d}:{seconds % 60:02d}"


@dataclass
class Beat:
    """One atomic teaching point from the master plan."""
    id: str
    title: str
    section_id: str
    section_title: str
    order: int                      # planned position, 0-based
    body: str = ""
    est_seconds: float | None = None
    beat_type: str = "content"
    must_cover: bool = False

    @property
    def text(self) -> str:
        return f"{self.title}. {self.body}"


@dataclass
class Segment:
    """One timecoded line of transcript."""
    index: int
    start: float
    speaker: str
    text: str
    end: float | None = None


@dataclass
class Lesson:
    lesson_id: str
    title: str
    meta: dict[str, str]
    beats: list[Beat]

    def by_id(self, beat_id: str) -> Beat | None:
        return next((b for b in self.beats if b.id == beat_id), None)


@dataclass
class Finding:
    """A specific, citable reason a beat is not simply TAUGHT."""
    kind: str                       # NUMERIC_DRIFT | ON_SCREEN_CONFLICT | REORDERED | ...
    detail: str
    evidence: str = ""
    severity: str = "high"          # high = will ship wrong; low = probably a rewording


@dataclass
class ReconciledBeat:
    """A planned beat, plus what the shoot actually did with it."""
    beat_id: str
    status: str
    planned_order: int
    actual_order: int | None = None
    start: float | None = None
    end: float | None = None
    confidence: float = 0.0
    evidence_segments: list[int] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""

    @property
    def duration(self) -> float | None:
        if self.start is None or self.end is None:
            return None
        return self.end - self.start


@dataclass
class AddedBeat:
    """Content taught on camera that no planned beat accounts for."""
    id: str
    title: str
    actual_order: int
    start: float
    end: float
    summary: str
    evidence_segments: list[int] = field(default_factory=list)
    confidence: float = 0.0

    @property
    def duration(self) -> float:
        return self.end - self.start


@dataclass
class AsTaughtRecord:
    """The post-shoot source of truth. Everything downstream binds to this, not the plan."""
    lesson_id: str
    plan_version: str
    transcript_id: str
    engine: str
    beats: list[ReconciledBeat]
    added: list[AddedBeat]
    planned_runtime: float | None = None
    actual_runtime: float | None = None
    approved_by: str | None = None

    def status_of(self, beat_id: str) -> str:
        rb = next((b for b in self.beats if b.beat_id == beat_id), None)
        return rb.status if rb else SKIPPED

    def get(self, beat_id: str) -> ReconciledBeat | None:
        return next((b for b in self.beats if b.beat_id == beat_id), None)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Asset:
    """A downstream artefact bound to one or more beats."""
    id: str
    type: str
    title: str
    owner: str
    depends_on: list[str]
    on_screen_text: list[str] = field(default_factory=list)
    # Label-type assets carry identifiers ("Dana Okafor", "Chapter: Close"), not claims
    # the instructor says aloud, so checking them against the audio is pure noise.
    verify_text: bool = True


# --- Change-order verbs -----------------------------------------------------
KEEP = "KEEP"        # still correct; only its timecode is new
RETIME = "RETIME"    # content fine, position/timecode changed
REVISE = "REVISE"    # content is now wrong or incomplete — someone must edit it
KILL = "KILL"        # the beat it depends on never happened — do not produce it
CREATE = "CREATE"    # new taught content with no asset covering it

SEVERITY = {KILL: 3, CREATE: 3, REVISE: 2, RETIME: 1, KEEP: 0}


@dataclass
class ChangeOrder:
    asset_id: str
    asset_title: str
    asset_type: str
    owner: str
    action: str
    reason: str
    beat_ids: list[str] = field(default_factory=list)
    start: float | None = None
    end: float | None = None
    conflicts: list[Finding] = field(default_factory=list)
    suggested_text: list[str] = field(default_factory=list)

    @property
    def severity(self) -> int:
        return SEVERITY.get(self.action, 0)
