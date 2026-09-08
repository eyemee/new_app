"""Claude-powered reconciler.

The local engine matches on vocabulary, which is exactly why it needs a
semantic counterpart: an instructor who teaches the planned point in entirely
different words looks like a skip to a bag-of-words matcher, and a recap that
restates the mechanism looks like the mechanism. Claude reads both documents and
judges coverage the way a producer would.

The contract is identical to LocalReconciler.reconcile, so the two are
interchangeable and can be diffed against each other on the same shoot.
"""
from __future__ import annotations

import json
import os

from ..models import (
    MERGED, MODIFIED, MOVED, PLANNED_STATUSES, SKIPPED, TAUGHT,
    AddedBeat, AsTaughtRecord, Finding, Lesson, ReconciledBeat, Segment, fmt_tc,
)

MODEL = "claude-opus-5"

SYSTEM = """You reconcile a master lesson plan against the raw transcript of the \
shoot, for a course production team.

The plan is what the instructor intended to teach. The transcript is what they \
actually taught. Instructors reorder points, add examples, compress or drop \
sections, and change numbers. Your job is to say precisely what happened to each \
planned beat, and to identify teaching that was not planned at all.

Rules:
- Judge coverage by meaning, not wording. An instructor who makes the planned point \
in completely different language has taught that beat.
- A beat is SKIPPED only if its substance never appears. Being brief is not skipping.
- Use MERGED when a beat's content was folded into another beat instead of being \
taught in its own right — this matters downstream, because assets that treat it as a \
separate item will be wrong.
- Use MODIFIED when the substance changed: a different figure, a different number of \
items, a dropped sub-point, a changed instruction. Say exactly what changed.
- Flag every numeric or factual claim in the plan that the instructor did not repeat \
or contradicted. These are what break on-screen graphics.
- Timecodes must be taken from the transcript markers, never invented.
- Report ADDED content only for substantial unplanned teaching, not for asides."""

SCHEMA = {
    "type": "object",
    "properties": {
        "beats": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "beat_id": {"type": "string"},
                    "status": {"type": "string", "enum": list(PLANNED_STATUSES)},
                    "start": {"type": "string", "description": "HH:MM:SS, or empty if not taught"},
                    "end": {"type": "string", "description": "HH:MM:SS, or empty if not taught"},
                    "confidence": {"type": "number"},
                    "summary": {"type": "string", "description": "What the instructor actually did with this beat."},
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "kind": {
                                    "type": "string",
                                    "enum": [
                                        "NUMERIC_DRIFT", "COUNT_DRIFT", "OMITTED_POINT",
                                        "REORDERED", "MERGED_INTO", "ADDED_CLAIM",
                                        "CHANGED_INSTRUCTION", "NOT_TAUGHT",
                                    ],
                                },
                                "detail": {"type": "string"},
                                "evidence": {"type": "string", "description": "Short quote from the transcript."},
                            },
                            "required": ["kind", "detail", "evidence"],
                            "additionalProperties": False,
                        },
                    },
                },
                "required": ["beat_id", "status", "start", "end", "confidence", "summary", "findings"],
                "additionalProperties": False,
            },
        },
        "added": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "start": {"type": "string"},
                    "end": {"type": "string"},
                    "summary": {"type": "string"},
                    "confidence": {"type": "number"},
                },
                "required": ["title", "start", "end", "summary", "confidence"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["beats", "added"],
    "additionalProperties": False,
}


def _seconds(tc: str) -> float | None:
    tc = (tc or "").strip()
    if not tc:
        return None
    try:
        parts = [float(p) for p in tc.split(":")]
    except ValueError:
        return None
    total = 0.0
    for p in parts:
        total = total * 60.0 + p
    return total


class ClaudeReconciler:
    name = "claude"

    def __init__(self, model: str = MODEL, api_key: str | None = None, effort: str = "high"):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.effort = effort

    def reconcile(
        self, lesson: Lesson, segments: list[Segment], transcript_id: str = ""
    ) -> AsTaughtRecord:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RuntimeError(
                "The 'claude' engine needs the Anthropic SDK: pip install anthropic. "
                "Use --engine local to run without it."
            ) from exc

        client = anthropic.Anthropic(api_key=self.api_key) if self.api_key else anthropic.Anthropic()

        plan_text = "\n\n".join(
            f"[{b.id}] {b.title}\n"
            f"section: {b.section_id} — {b.section_title}\n"
            f"planned position: {b.order + 1}\n"
            f"planned duration: {fmt_tc(b.est_seconds)}\n"
            f"{b.body}"
            for b in lesson.beats
        )
        transcript_text = "\n".join(
            f"[{fmt_tc(s.start)}] {s.speaker}: {s.text}" for s in segments
        )

        prompt = (
            f"MASTER LESSON PLAN ({lesson.lesson_id} — {lesson.title})\n"
            f"=====\n{plan_text}\n\n"
            f"SHOOT TRANSCRIPT\n=====\n{transcript_text}\n\n"
            f"Reconcile them. Return a verdict for every one of the "
            f"{len(lesson.beats)} planned beats, in plan order, plus any substantial "
            f"unplanned teaching."
        )

        # Streaming because the response covers every beat in the lesson; server-side
        # fallback so a refusal on one take does not stall the whole post-production run.
        with client.beta.messages.stream(
            model=self.model,
            max_tokens=32000,
            system=SYSTEM,
            messages=[{"role": "user", "content": prompt}],
            thinking={"type": "adaptive"},
            output_config={"effort": self.effort, "format": {"type": "json_schema", "schema": SCHEMA}},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        ) as stream:
            response = stream.get_final_message()

        if response.stop_reason == "refusal":
            raise RuntimeError(
                f"Model declined to reconcile this take "
                f"({getattr(response.stop_details, 'category', 'unknown')})."
            )

        payload = json.loads(
            "".join(b.text for b in response.content if b.type == "text")
        )
        return self._to_record(lesson, segments, payload, transcript_id)

    def _to_record(
        self, lesson: Lesson, segments: list[Segment], payload: dict, transcript_id: str
    ) -> AsTaughtRecord:
        by_id = {item["beat_id"]: item for item in payload.get("beats", [])}
        results: list[ReconciledBeat] = []
        for beat in lesson.beats:
            item = by_id.get(beat.id)
            if item is None:
                results.append(
                    ReconciledBeat(
                        beat_id=beat.id, status=SKIPPED, planned_order=beat.order,
                        confidence=0.3,
                        summary="Model returned no verdict for this beat.",
                        findings=[Finding("NOT_TAUGHT", "No verdict returned; review by hand.")],
                    )
                )
                continue
            status = item["status"] if item["status"] in PLANNED_STATUSES else SKIPPED
            start, end = _seconds(item.get("start", "")), _seconds(item.get("end", ""))
            results.append(
                ReconciledBeat(
                    beat_id=beat.id, status=status, planned_order=beat.order,
                    start=start, end=end,
                    confidence=round(float(item.get("confidence", 0.5)), 2),
                    evidence_segments=[
                        s.index for s in segments
                        if start is not None and end is not None and start <= s.start <= end
                    ],
                    findings=[
                        Finding(f["kind"], f["detail"], f.get("evidence", ""))
                        for f in item.get("findings", [])
                    ],
                    summary=item.get("summary", ""),
                )
            )

        for pos, r in enumerate(
            sorted((r for r in results if r.start is not None), key=lambda r: r.start or 0.0)
        ):
            r.actual_order = pos

        added = []
        for i, item in enumerate(payload.get("added", []), start=1):
            start, end = _seconds(item.get("start", "")), _seconds(item.get("end", ""))
            if start is None or end is None:
                continue
            added.append(
                AddedBeat(
                    id=f"NEW-{i:02d}", title=item.get("title", "Unplanned content"),
                    actual_order=i, start=start, end=end,
                    summary=item.get("summary", ""),
                    evidence_segments=[s.index for s in segments if start <= s.start <= end],
                    confidence=round(float(item.get("confidence", 0.5)), 2),
                )
            )

        return AsTaughtRecord(
            lesson_id=lesson.lesson_id,
            plan_version=lesson.meta.get("plan_version", ""),
            transcript_id=transcript_id,
            engine=self.name,
            beats=results,
            added=added,
            planned_runtime=sum(b.est_seconds for b in lesson.beats if b.est_seconds) or None,
            actual_runtime=segments[-1].end if segments else None,
        )
