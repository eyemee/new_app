from shootsync.parsing import parse_duration, parse_plan, parse_transcript


def test_plan_beats_are_ordered_with_stable_ids(lesson):
    assert lesson.lesson_id == "NEG-L03"
    assert [b.id for b in lesson.beats] == [f"B{i:02d}" for i in range(1, 15)]
    assert [b.order for b in lesson.beats] == list(range(14))


def test_plan_attributes_and_sections_are_read(lesson):
    b04 = lesson.by_id("B04")
    assert b04.est_seconds == 150.0
    assert b04.beat_type == "evidence"
    assert b04.must_cover is True
    assert b04.section_id == "S2"
    assert "41%" in b04.body


def test_attribute_lines_do_not_leak_into_the_talk_track(lesson):
    for beat in lesson.beats:
        assert not beat.body.startswith("est:")
        assert "must_cover:" not in beat.body


def test_transcript_segments_are_timecoded_and_closed(segments):
    assert len(segments) == 114
    assert segments[0].start == 3.0
    assert segments[0].speaker == "DANA"
    assert all(s.end > s.start for s in segments)
    assert all(
        segments[i].end == segments[i + 1].start for i in range(len(segments) - 1)
    )


def test_transcript_comments_are_ignored():
    text = "# header comment\n[00:00:01] X: hello\nnot a segment\n"
    assert [s.text for s in parse_transcript(text)] == ["hello"]


def test_parse_duration_accepts_the_forms_producers_write():
    assert parse_duration("0:45") == 45
    assert parse_duration("2:30") == 150
    assert parse_duration("1:02:30") == 3750
    assert parse_duration("") is None


def test_empty_inputs_do_not_crash():
    assert parse_plan("").beats == []
    assert parse_transcript("") == []
