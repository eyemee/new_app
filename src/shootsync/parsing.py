"""Parsers for the two human-authored inputs: the master plan and the raw transcript.

Both formats are deliberately plain so a producer can keep authoring in Google Docs
or Word and export to text. Nothing here requires a special tool.
"""
from __future__ import annotations

import re

from .models import Beat, Lesson, Segment

_META_RE = re.compile(r"^>\s*([a-z_]+)\s*:\s*(.+?)\s*$", re.I)
_SECTION_RE = re.compile(r"^##\s+(?P<id>[A-Za-z0-9_.-]+)\s*[—–-]\s*(?P<title>.+?)\s*$")
_BEAT_RE = re.compile(r"^###\s+(?P<id>[A-Za-z0-9_.-]+)\s*[—–-]\s*(?P<title>.+?)\s*$")
_ATTR_RE = re.compile(r"^(est|type|must_cover)\s*:\s*(.+?)\s*$", re.I)
_TC_RE = re.compile(
    r"^\[(?:(?P<h>\d{1,2}):)?(?P<m>\d{1,2}):(?P<s>\d{2})\]\s*"
    r"(?:(?P<speaker>[A-Z][A-Z0-9 ._-]{1,24}):\s*)?(?P<text>.*)$"
)


def parse_duration(value: str) -> float | None:
    """Accept 2:30, 0:45, 1:02:30 or a bare number of minutes."""
    value = value.strip()
    if not value:
        return None
    parts = value.split(":")
    try:
        if len(parts) == 1:
            return float(parts[0]) * 60.0
        nums = [float(p) for p in parts]
    except ValueError:
        return None
    total = 0.0
    for n in nums:
        total = total * 60.0 + n
    return total


def parse_plan(text: str) -> Lesson:
    """Parse the master lesson plan into ordered beats with stable IDs."""
    title = ""
    meta: dict[str, str] = {}
    beats: list[Beat] = []
    section_id = section_title = ""
    current: Beat | None = None
    body: list[str] = []

    def flush() -> None:
        nonlocal current, body
        if current is not None:
            current.body = " ".join(" ".join(body).split())
            beats.append(current)
        current, body = None, []

    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()

        if stripped.startswith("# ") and not title:
            title = stripped[2:].strip()
            continue

        m = _META_RE.match(stripped)
        if m and current is None:
            meta[m.group(1).lower()] = m.group(2)
            continue

        m = _SECTION_RE.match(stripped)
        if m:
            flush()
            section_id, section_title = m.group("id"), m.group("title")
            continue

        m = _BEAT_RE.match(stripped)
        if m:
            flush()
            current = Beat(
                id=m.group("id"),
                title=m.group("title"),
                section_id=section_id,
                section_title=section_title,
                order=len(beats),
            )
            continue

        if current is None:
            continue

        m = _ATTR_RE.match(stripped)
        if m and not body:  # attributes only directly under the beat heading
            key, val = m.group(1).lower(), m.group(2)
            if key == "est":
                current.est_seconds = parse_duration(val)
            elif key == "type":
                current.beat_type = val.strip()
            elif key == "must_cover":
                current.must_cover = val.strip().lower() in {"true", "yes", "y", "1"}
            continue

        if stripped:
            body.append(stripped)

    flush()
    for i, b in enumerate(beats):
        b.order = i
    return Lesson(
        lesson_id=meta.get("lesson_id", "UNKNOWN"),
        title=title,
        meta=meta,
        beats=beats,
    )


def parse_transcript(text: str) -> list[Segment]:
    """Parse a timecoded transcript. Lines without a timecode are ignored."""
    segments: list[Segment] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _TC_RE.match(line)
        if not m:
            continue
        start = (
            float(m.group("h") or 0) * 3600
            + float(m.group("m")) * 60
            + float(m.group("s"))
        )
        body = m.group("text").strip()
        if not body:
            continue
        segments.append(
            Segment(
                index=len(segments),
                start=start,
                speaker=(m.group("speaker") or "UNKNOWN").strip(),
                text=body,
            )
        )
    # Close each segment at the next one's start; give the last a nominal tail.
    for i, seg in enumerate(segments):
        seg.end = segments[i + 1].start if i + 1 < len(segments) else seg.start + 8.0
    return segments
