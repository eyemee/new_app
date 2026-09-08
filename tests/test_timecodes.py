"""Timecode accuracy against hand-annotated ground truth.

The verdict on a beat is only half the deliverable — an editor works from the
in-points. These are the true starts, read off the transcript by hand, and the
budget below is what the deterministic aligner currently achieves. It is a
regression guard: tightening the matcher should move these down, never up.
"""
import statistics

# beat id -> true start in seconds, read from the transcript
TRUE_STARTS = {
    "B01": 3, "B02": 192, "B03": 66, "B04": 248, "B05": 362, "B06": 576,
    "B07": 694, "B08": 444, "B09": 737, "B10": 1008, "B11": 1236,
    "B13": 1324, "B14": 1386,
}


def _errors(atr):
    return [abs(atr.get(bid).start - true) for bid, true in TRUE_STARTS.items()]


def test_most_beats_land_on_the_exact_segment(atr):
    errors = _errors(atr)
    assert statistics.median(errors) == 0
    assert sum(1 for e in errors if e <= 15) >= 9


def test_no_beat_is_wildly_misplaced(atr):
    # A cut point more than two minutes out would send an editor to the wrong part
    # of the tape, which is worse than no timecode at all.
    assert max(_errors(atr)) <= 120


def test_mean_error_stays_within_budget(atr):
    assert statistics.mean(_errors(atr)) <= 25


def test_unplanned_content_is_bounded_correctly(atr):
    # The Marcus story runs 00:14:06 to 00:16:22 on the tape.
    marcus = atr.added[0]
    assert abs(marcus.start - 846) <= 15
    assert abs(marcus.end - 982) <= 30
