"""Tests for the change orders produced from the reconciliation.

Each of these corresponds to a specific way this shoot would have broken something
downstream if the plan had stayed the source of truth.
"""
from shootsync.models import CREATE, KEEP, KILL, RETIME, REVISE


def test_every_asset_gets_a_change_order(assets, orders):
    assert {a.id for a in assets} <= {o.asset_id for o in orders}


def test_assets_for_the_skipped_section_are_killed(by_asset):
    # B12 was never taught, so its graphic, handout section and quiz question
    # are not "review these" — they must not be produced at all.
    for asset_id in ("GFX-07", "HND-4", "QUIZ-04"):
        assert by_asset[asset_id].action == KILL, asset_id


def test_a_quiz_question_on_untaught_content_is_caught(by_asset):
    quiz = by_asset["QUIZ-04"]
    assert quiz.action == KILL
    assert "B12" in quiz.reason


def test_the_stat_card_contradicting_the_audio_is_flagged(by_asset):
    gfx = by_asset["GFX-02"]
    assert gfx.action == REVISE
    assert any("41%" in c.detail for c in gfx.conflicts)
    assert any(c.severity == "high" for c in gfx.conflicts)


def test_a_lever_named_on_screen_but_never_said_is_flagged(by_asset):
    # The plan has four levers; the instructor taught three and never said
    # "patience". The list graphic and the worksheet both still name it.
    for asset_id in ("GFX-04", "HND-2", "QUIZ-03"):
        order = by_asset[asset_id]
        assert order.action == REVISE, asset_id
        assert any("patience" in c.detail.lower() for c in order.conflicts), asset_id


def test_changed_homework_is_caught_in_the_handout(by_asset):
    hnd5 = by_asset["HND-5"]
    assert hnd5.action == REVISE
    assert any("procurement" in c.detail.lower() for c in hnd5.conflicts)


def test_label_assets_are_not_checked_against_the_audio(by_asset):
    # A lower third says the instructor's name. Nobody says their own name on
    # camera, and flagging that every single shoot would train people to ignore
    # the report.
    assert by_asset["GFX-01"].action == KEEP
    assert by_asset["GFX-01"].conflicts == []


def test_moved_content_is_retimed_not_rewritten(by_asset):
    # B08 moved but its substance is intact, so the quiz on it only needs a new
    # timecode — not a curriculum rewrite.
    quiz = by_asset["QUIZ-02"]
    assert quiz.action == RETIME
    assert quiz.start == 444.0


def test_unchanged_assets_still_receive_a_timecode(by_asset):
    keep = by_asset["QUIZ-01"]
    assert keep.action == KEEP
    assert keep.start is not None and keep.end is not None


def test_unplanned_teaching_becomes_work_to_create(orders):
    created = [o for o in orders if o.action == CREATE]
    assert len(created) == 2
    assert all(o.suggested_text for o in created)
    assert all(o.start is not None for o in created)


def test_orders_are_ranked_with_the_costly_ones_first(orders):
    severities = [o.severity for o in orders]
    assert severities == sorted(severities, reverse=True)
    assert orders[0].action in (KILL, CREATE)


def test_every_order_names_an_owner_and_a_reason(orders):
    for o in orders:
        assert o.owner and o.reason
        assert o.action in (KEEP, RETIME, REVISE, KILL, CREATE)
