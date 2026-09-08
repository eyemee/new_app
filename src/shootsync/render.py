"""Render the as-taught record and change orders into the artefacts each team consumes."""
from __future__ import annotations

import json
from pathlib import Path

from .models import (
    ADDED, CREATE, KEEP, KILL, MERGED, MODIFIED, MOVED, RETIME, REVISE, SKIPPED, TAUGHT,
    Asset, AsTaughtRecord, ChangeOrder, Lesson, Segment, fmt_tc,
)

STATUS_NOTE = {
    TAUGHT: "as planned",
    MOVED: "moved in the running order",
    MODIFIED: "substance changed",
    MERGED: "folded into another beat",
    SKIPPED: "not taught",
}


def write_atr(atr: AsTaughtRecord, path: Path) -> None:
    path.write_text(json.dumps(atr.to_dict(), indent=2) + "\n")


def render_change_orders(lesson: Lesson, atr: AsTaughtRecord, orders: list[ChangeOrder]) -> str:
    lines = [
        f"# Change orders — {lesson.lesson_id}: {lesson.title}",
        "",
        f"Plan `{atr.plan_version}` reconciled against take `{atr.transcript_id}` "
        f"by the `{atr.engine}` engine.",
        f"Planned runtime {fmt_tc(atr.planned_runtime)}, actual {fmt_tc(atr.actual_runtime)}.",
        "",
        "> Nothing here is a decision. Each line is a proposal for the owner to accept "
        "or reject in the review console before post-production picks it up.",
        "",
    ]

    counts: dict[str, int] = {}
    for o in orders:
        counts[o.action] = counts.get(o.action, 0) + 1
    lines += [
        "| Action | Count | Meaning |",
        "| --- | --- | --- |",
        f"| KILL | {counts.get(KILL, 0)} | Do not produce — the content was never taught |",
        f"| CREATE | {counts.get(CREATE, 0)} | Unplanned teaching with no asset covering it |",
        f"| REVISE | {counts.get(REVISE, 0)} | Content is now wrong or incomplete |",
        f"| RETIME | {counts.get(RETIME, 0)} | Content fine, position changed |",
        f"| KEEP | {counts.get(KEEP, 0)} | Correct as built; bind to the new timecode |",
        "",
    ]

    for owner in sorted({o.owner for o in orders}):
        owned = [o for o in orders if o.owner == owner and o.action != KEEP]
        if not owned:
            continue
        lines += [f"## {owner}", ""]
        for o in owned:
            when = f"{fmt_tc(o.start)}–{fmt_tc(o.end)}" if o.start is not None else "n/a"
            lines += [
                f"### `{o.action}` {o.asset_id} — {o.asset_title}",
                f"*{o.asset_type}* · {when} · depends on {', '.join(o.beat_ids) or '—'}",
                "",
                o.reason,
                "",
            ]
            for c in o.conflicts:
                lines.append(f"- **{c.kind}** ({c.severity}): {c.detail}")
            if o.conflicts:
                lines.append("")
            if o.suggested_text:
                lines += ["Suggested new assets:", ""]
                lines += [f"- {s}" for s in o.suggested_text] + [""]

    kept = [o for o in orders if o.action == KEEP]
    if kept:
        lines += ["## No change needed", "", "| Asset | Bind to |", "| --- | --- |"]
        lines += [f"| {o.asset_id} — {o.asset_title} | {fmt_tc(o.start)}–{fmt_tc(o.end)} |" for o in kept]
        lines.append("")
    return "\n".join(lines)


def render_edit_sheet(lesson: Lesson, atr: AsTaughtRecord, orders: list[ChangeOrder]) -> str:
    """The editor's running order — what is actually on the tape, in tape order."""
    by_asset: dict[str, list[ChangeOrder]] = {}
    for o in orders:
        for bid in o.beat_ids:
            by_asset.setdefault(bid, []).append(o)

    rows: list[tuple[float, str]] = []
    for r in atr.beats:
        if r.start is None:
            continue
        beat = lesson.by_id(r.beat_id)
        assets = [
            f"{o.asset_id} ({o.action})"
            for o in by_asset.get(r.beat_id, [])
            if o.action != KILL
        ]
        rows.append((
            r.start,
            f"| {fmt_tc(r.start)} | {fmt_tc(r.end)} | {r.beat_id} | "
            f"{beat.title if beat else ''} | {STATUS_NOTE.get(r.status, r.status)} | "
            f"{', '.join(assets) or '—'} |",
        ))
    for a in atr.added:
        rows.append((
            a.start,
            f"| {fmt_tc(a.start)} | {fmt_tc(a.end)} | **{a.id}** | "
            f"**{a.title}** | unplanned — needs assets | — |",
        ))
    rows.sort(key=lambda x: x[0])

    lines = [
        f"# Edit sheet — {lesson.lesson_id}: {lesson.title}",
        "",
        f"Take `{atr.transcript_id}`. Every timecode below is read off the transcript, "
        f"not the plan.",
        "",
        "| In | Out | Beat | Title | Status | Assets |",
        "| --- | --- | --- | --- | --- | --- |",
    ] + [r for _, r in rows] + [""]

    dropped = [r for r in atr.beats if r.start is None]
    if dropped:
        lines += [
            "## Planned but not on the tape",
            "",
            "Do not look for these in the footage — they were not shot.",
            "",
        ]
        for r in dropped:
            beat = lesson.by_id(r.beat_id)
            lines.append(f"- **{r.beat_id}** {beat.title if beat else ''} — {STATUS_NOTE.get(r.status, r.status)}")
        lines.append("")

    kills = [o for o in orders if o.action == KILL]
    if kills:
        lines += ["## Do not build", ""]
        lines += [f"- {o.asset_id} — {o.asset_title}" for o in kills] + [""]
    return "\n".join(lines)


def render_curriculum_delta(lesson: Lesson, atr: AsTaughtRecord, orders: list[ChangeOrder]) -> str:
    """What the student-facing materials must change to match the lesson as shipped."""
    lines = [
        f"# Student materials delta — {lesson.lesson_id}",
        "",
        "The lesson students will watch differs from the plan the materials were "
        "written from. These are the required edits.",
        "",
    ]
    buckets = {
        KILL: ("Remove entirely", "covers content that was never taught"),
        REVISE: ("Rewrite", "no longer matches the lesson as taught"),
        CREATE: ("Write new", "the lesson teaches this but the materials do not cover it"),
        RETIME: ("Reorder", "content is unchanged but its position moved"),
    }
    for action, (heading, why) in buckets.items():
        rows = [
            o for o in orders
            if o.action == action and o.owner in {"Curriculum", "Producer"}
        ]
        if not rows:
            continue
        lines += [f"## {heading} — {why}", ""]
        for o in rows:
            lines.append(f"- **{o.asset_id}** {o.asset_title}: {o.reason}")
            for c in o.conflicts:
                lines.append(f"  - {c.detail}")
        lines.append("")

    changed = [r for r in atr.beats if r.status in (MODIFIED, SKIPPED, MERGED)]
    if changed:
        lines += ["## Teaching-point changes behind these edits", ""]
        for r in changed:
            beat = lesson.by_id(r.beat_id)
            lines.append(f"- **{r.beat_id}** {beat.title if beat else ''} — {STATUS_NOTE.get(r.status, r.status)}")
            for f in r.findings:
                lines.append(f"  - {f.detail}")
        lines.append("")
    return "\n".join(lines)
