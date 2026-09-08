"""Impact analysis: turn the as-taught record into a change order per downstream asset.

This is the step that stops the rework. Nobody has to read a diff and work out what
it means for their graphic — the dependency edges already say which assets a given
deviation touches, and the on-screen text is checked against what was actually said.
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import (
    ADDED, CREATE, KEEP, KILL, MERGED, MODIFIED, MOVED, RETIME, REVISE, SKIPPED, TAUGHT,
    Asset, AsTaughtRecord, ChangeOrder, Finding, Lesson, Segment, fmt_tc,
)
from .text import numerals, tokenize

_ENUM_RE = __import__("re").compile(r"^\s*(?:\d+[.)]|lever\s+\d|step\s+\d)", __import__("re").I)

# Asset types whose on-screen text is a label rather than a claim about content.
LABEL_TYPES = {"lower_third", "caption", "chapter_marker", "title_card"}

# Words too common to prove that a line of on-screen text was actually spoken.
_WEAK = {
    "lesson", "step", "part", "point", "rule", "key", "tip", "note", "the", "and",
    "your", "you", "how", "why", "what", "when", "who", "new", "next", "more",
}


def load_assets(path: str | Path) -> list[Asset]:
    data = json.loads(Path(path).read_text())
    return [
        Asset(
            id=a["id"], type=a["type"], title=a["title"], owner=a.get("owner", "Unassigned"),
            depends_on=list(a.get("depends_on", [])),
            on_screen_text=list(a.get("on_screen_text", [])),
            verify_text=bool(a.get("verify_text", a["type"] not in LABEL_TYPES)),
        )
        for a in data.get("assets", [])
    ]


def _spoken_terms(atr: AsTaughtRecord, segments: list[Segment], beat_ids: list[str]) -> set[str]:
    terms: set[str] = set()
    for bid in beat_ids:
        rb = atr.get(bid)
        if rb is None:
            continue
        for i in rb.evidence_segments:
            if 0 <= i < len(segments):
                terms.update(tokenize(segments[i].text))
    return terms


def _check_on_screen_text(
    asset: Asset, atr: AsTaughtRecord, segments: list[Segment], all_terms: set[str]
) -> list[Finding]:
    """Verify every line that will appear on screen against what was actually said.

    A graphic that contradicts the audio under it is the most expensive kind of
    breakage: it survives the edit, ships, and gets caught by a student.
    """
    if not asset.verify_text:
        return []
    spoken = _spoken_terms(atr, segments, asset.depends_on)
    if not spoken:
        return []

    findings: list[Finding] = []
    for line in asset.on_screen_text:
        content = [t for t in tokenize(line) if t not in _WEAK and len(t) > 2]
        if not content:
            continue
        missing = [t for t in content if t not in spoken]
        # A term the instructor never used anywhere in the lesson is a hard conflict;
        # one they used elsewhere is probably just a wording difference.
        never = [t for t in missing if t not in all_terms]
        if never:
            # An enumerated item ("4. Patience") or a quiz answer names something the
            # lesson claims to have covered, so a missing term there is a hard error.
            # Elsewhere a single missing word is more often a rewording.
            enumerated = bool(_ENUM_RE.match(line.strip())) or asset.type == "quiz_item"
            findings.append(
                Finding(
                    "ON_SCREEN_CONFLICT",
                    f'On-screen text "{line}" refers to '
                    f'{", ".join(sorted(never))} — never said anywhere in this take.',
                    severity="high" if (enumerated or len(never) > 1) else "low",
                )
            )
        elif len(missing) == len(content):
            findings.append(
                Finding(
                    "ON_SCREEN_UNSUPPORTED",
                    f'On-screen text "{line}" is not supported by the audio under it.',
                    severity="low",
                )
            )

        claimed = {n for n in numerals(line) if "%" in n or (n.isdigit() and int(n) >= 10)}
        said = numerals(" ".join(
            segments[i].text
            for bid in asset.depends_on
            for i in (atr.get(bid).evidence_segments if atr.get(bid) else [])
            if 0 <= i < len(segments)
        ))
        wrong = claimed - said
        if wrong:
            findings.append(
                Finding(
                    "ON_SCREEN_NUMBER",
                    f'On-screen figure {", ".join(sorted(wrong))} in "{line}" '
                    f"is not the figure given on camera.",
                )
            )
    return findings


def build_change_orders(
    lesson: Lesson, atr: AsTaughtRecord, assets: list[Asset], segments: list[Segment]
) -> list[ChangeOrder]:
    all_terms = {t for s in segments for t in tokenize(s.text)}
    orders: list[ChangeOrder] = []

    for asset in assets:
        statuses = {bid: atr.status_of(bid) for bid in asset.depends_on}
        gone = [b for b, s in statuses.items() if s in (SKIPPED, MERGED)]
        modified = [b for b, s in statuses.items() if s == MODIFIED]
        moved = [b for b, s in statuses.items() if s == MOVED]
        live = [b for b, s in statuses.items() if s not in (SKIPPED, MERGED)]

        spans = [
            (atr.get(b).start, atr.get(b).end)
            for b in live
            if atr.get(b) and atr.get(b).start is not None
        ]
        start = min((s for s, _ in spans), default=None)
        end = max((e for _, e in spans), default=None)

        conflicts = _check_on_screen_text(asset, atr, segments, all_terms)

        if not live:
            action = KILL
            reason = (
                f"Every beat this depends on ({', '.join(asset.depends_on)}) was not "
                f"taught. Do not produce it."
            )
        elif gone:
            action = REVISE
            reason = (
                f"Partly orphaned — {', '.join(gone)} was not taught, so the content "
                f"this asset presents is no longer complete."
            )
        elif any(c.severity == "high" for c in conflicts):
            action = REVISE
            reason = "On-screen content contradicts what was said on camera."
        elif modified:
            action = REVISE
            reason = f"Depends on {', '.join(modified)}, whose substance changed in the take."
        elif conflicts:
            action = REVISE
            reason = "On-screen wording may no longer match the take — worth a read."
        elif moved:
            action = RETIME
            reason = (
                f"Content is unchanged but {', '.join(moved)} moved in the running "
                f"order — reposition to {fmt_tc(start)}."
            )
        else:
            action = KEEP
            reason = f"Taught as planned. Bind to {fmt_tc(start)}–{fmt_tc(end)}."

        orders.append(
            ChangeOrder(
                asset_id=asset.id, asset_title=asset.title, asset_type=asset.type,
                owner=asset.owner, action=action, reason=reason,
                beat_ids=list(asset.depends_on), start=start, end=end,
                conflicts=conflicts,
            )
        )

    # Content that was taught but has no asset covering it.
    for new in atr.added:
        orders.append(
            ChangeOrder(
                asset_id=new.id,
                asset_title=new.title,
                asset_type="unplanned_content",
                owner="Producer",
                action=CREATE,
                reason=(
                    f"{fmt_tc(new.duration)} of unplanned teaching at {fmt_tc(new.start)} "
                    f"with no graphic, chapter marker or handout coverage."
                ),
                start=new.start, end=new.end,
                suggested_text=_suggest_assets(new.title),
            )
        )

    orders.sort(key=lambda o: (-o.severity, o.asset_id))
    return orders


def _suggest_assets(title: str) -> list[str]:
    return [
        "Chapter marker for the new section",
        "Lower third or caption if it introduces a named example",
        "Handout callout so the student materials cover it",
    ]


def summarise(orders: list[ChangeOrder]) -> dict[str, int]:
    counts = {KEEP: 0, RETIME: 0, REVISE: 0, KILL: 0, CREATE: 0}
    for o in orders:
        counts[o.action] = counts.get(o.action, 0) + 1
    return counts
