"""Regression tests for the reconciliation of the NEG-L03 shoot.

The expectations below are the ground truth of that take, established by reading the
transcript: the instructor swapped the opening two beats, taught the levers in a
different order, softened a cited statistic, dropped one section entirely, added a
long unplanned story, and ran a third role-play take that the plan does not contain.
"""
from shootsync.models import MODIFIED, MOVED, SKIPPED, TAUGHT


def test_every_planned_beat_gets_exactly_one_verdict(lesson, atr):
    assert [b.beat_id for b in atr.beats] == [b.id for b in lesson.beats]


def test_the_skipped_section_is_the_only_one_missing(atr):
    assert [b.beat_id for b in atr.beats if b.status == SKIPPED] == ["B12"]


def test_the_reordered_beats_are_identified(atr):
    # B02 (roadmap) was deferred until after B03; B08 (justification) was promoted
    # ahead of the two levers written before it.
    assert {b.beat_id for b in atr.beats if b.status == MOVED} == {"B02", "B08"}


def test_the_softened_statistic_is_caught(atr):
    b04 = atr.get("B04")
    assert b04.status == MODIFIED
    kinds = {f.kind for f in b04.findings}
    assert "NUMERIC_DRIFT" in kinds
    assert any("41%" in f.detail for f in b04.findings)


def test_beats_taught_as_written_are_left_alone(atr):
    assert {b.beat_id for b in atr.beats if b.status == TAUGHT} == {
        "B01", "B03", "B05", "B06", "B07", "B09", "B11", "B14"
    }


def test_unplanned_teaching_is_found_with_timecodes(atr):
    assert len(atr.added) == 2
    marcus = atr.added[0]
    assert 840 <= marcus.start <= 850          # the Marcus story opens around 00:14:06
    assert marcus.duration > 100
    assert "Marcus" in marcus.title


def test_taught_beats_carry_usable_timecodes(lesson, atr, segments):
    runtime = segments[-1].end
    for r in atr.beats:
        if r.status == SKIPPED:
            assert r.start is None
            continue
        assert r.start is not None and r.end is not None
        assert 0 <= r.start < r.end <= runtime
        assert r.evidence_segments


def test_taught_beats_do_not_claim_overlapping_footage(atr):
    spans = sorted(
        (r.start, r.end) for r in atr.beats if r.start is not None
    )
    for (_, prev_end), (next_start, _) in zip(spans, spans[1:]):
        assert next_start >= prev_end


def test_actual_order_reflects_the_tape_not_the_plan(atr):
    order = [r.beat_id for r in sorted(
        (b for b in atr.beats if b.actual_order is not None),
        key=lambda b: b.actual_order,
    )]
    assert order.index("B03") < order.index("B02")
    assert order.index("B08") < order.index("B06")


def test_runtime_overrun_is_reported(atr):
    assert atr.actual_runtime > atr.planned_runtime


def test_reconciliation_is_deterministic(lesson, segments):
    from shootsync.engines.local import LocalReconciler

    a = LocalReconciler().reconcile(lesson, segments)
    b = LocalReconciler().reconcile(lesson, segments)
    assert a.to_dict() == b.to_dict()


def test_reconciliation_is_stable_across_processes():
    """Two runs of the same take must produce the same record.

    Ranking terms by IDF pulls them out of a set, and set iteration order is salted
    per process, so a tie could otherwise flip a borderline verdict between runs.
    Post-production cannot chase a record that changes when it is regenerated.
    """
    import hashlib
    import json
    import os
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    script = (
        "import json,sys;sys.path.insert(0,'src');"
        "from shootsync.parsing import parse_plan,parse_transcript;"
        "from shootsync.engines.local import LocalReconciler;"
        "L=parse_plan(open('fixtures/NEG-L03/master-plan.md').read());"
        "S=parse_transcript(open('fixtures/NEG-L03/transcript.txt').read());"
        "print(json.dumps(LocalReconciler().reconcile(L,S).to_dict(),sort_keys=True))"
    )
    digests = set()
    for seed in ("0", "1", "424242"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        out = subprocess.run(
            [sys.executable, "-c", script], cwd=root, env=env,
            capture_output=True, text=True, check=True,
        ).stdout
        digests.add(hashlib.sha256(out.encode()).hexdigest())
    assert len(digests) == 1


def test_an_unshot_lesson_reports_everything_missing(lesson):
    from shootsync.engines.local import LocalReconciler
    from shootsync.parsing import parse_transcript

    empty = parse_transcript("[00:00:01] DANA: right, we are not rolling yet.\n")
    result = LocalReconciler().reconcile(lesson, empty)
    assert all(b.status == SKIPPED for b in result.beats)
