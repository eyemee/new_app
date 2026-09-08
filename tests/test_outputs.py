"""The generated artefacts must be usable by the people who receive them."""
import json
import sys
from pathlib import Path

from shootsync.console import render_console
from shootsync.render import (
    render_change_orders, render_curriculum_delta, render_edit_sheet,
)

ROOT = Path(__file__).resolve().parents[1]


def test_edit_sheet_is_in_tape_order_with_timecodes(lesson, atr, orders):
    sheet = render_edit_sheet(lesson, atr, orders)
    rows = [ln for ln in sheet.splitlines() if ln.startswith("| 00:")]
    times = [ln.split("|")[1].strip() for ln in rows]
    assert times == sorted(times)
    # The unplanned story sits between the beats it interrupted, not at the end.
    beats = [ln.split("|")[3].strip().strip("*") for ln in rows]
    assert beats.index("B09") < beats.index("NEW-01") < beats.index("B10")


def test_edit_sheet_tells_the_editor_what_was_never_shot(lesson, atr, orders):
    sheet = render_edit_sheet(lesson, atr, orders)
    assert "Planned but not on the tape" in sheet
    assert "**B12**" in sheet
    assert "GFX-07" in sheet.split("## Do not build")[1]


def test_change_orders_are_grouped_by_owner(lesson, atr, orders):
    doc = render_change_orders(lesson, atr, orders)
    for owner in ("Design", "Curriculum", "Edit"):
        assert f"## {owner}" in doc
    assert "`KILL` GFX-07" in doc


def test_curriculum_delta_separates_removals_from_rewrites(lesson, atr, orders):
    doc = render_curriculum_delta(lesson, atr, orders)
    remove, rewrite = doc.index("Remove entirely"), doc.index("Rewrite")
    assert "QUIZ-04" in doc[remove:rewrite]
    assert "HND-5" in doc[rewrite:]


def test_console_is_self_contained_and_themed(lesson, atr, orders, segments):
    html = render_console(lesson, atr, orders, segments)
    assert html.startswith("<!doctype html>")
    assert html.count("<script") == 1 and "cdn" not in html.lower()
    # Every palette token is defined on bare :root before any theme block overrides it.
    root = html.split(":root {")[1].split("}")[0]
    for token in ("--ground", "--surface", "--ink", "--kill", "--create"):
        assert token in root
    assert 'prefers-color-scheme: dark' in html and '[data-theme="dark"]' in html


def test_console_shows_the_expensive_findings(lesson, atr, orders, segments):
    html = render_console(lesson, atr, orders, segments)
    assert "GFX-07" in html and "QUIZ-03" in html
    assert "41%" in html and "Marcus" in html


def test_console_escapes_content(lesson, atr, orders, segments):
    html = render_console(lesson, atr, orders, segments)
    assert "<script>alert" not in html
    assert "&amp;" in html or "&#x27;" in html or "&quot;" in html


def test_cli_writes_every_artefact(tmp_path):
    from shootsync.cli import main

    out = tmp_path / "out"
    code = main(["reconcile", str(ROOT / "fixtures" / "NEG-L03"),
                 "--out", str(out), "--take", "take-02"])
    assert code == 0
    for name in ("as-taught-record.json", "change-orders.md", "edit-sheet.md",
                 "student-materials-delta.md", "review-console.html"):
        assert (out / name).stat().st_size > 500, name

    record = json.loads((out / "as-taught-record.json").read_text())
    assert record["lesson_id"] == "NEG-L03"
    assert record["engine"] == "local"
    assert len(record["beats"]) == 14


def test_strict_mode_fails_the_build_when_work_is_outstanding(tmp_path):
    from shootsync.cli import main

    assert main(["reconcile", str(ROOT / "fixtures" / "NEG-L03"),
                 "--out", str(tmp_path), "--strict"]) == 1
