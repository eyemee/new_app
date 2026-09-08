"""Command line entry point.

    shootsync reconcile fixtures/NEG-L03 --out out/
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .console import render_console
from .engines import get_engine
from .impact import build_change_orders, load_assets, summarise
from .models import CREATE, KILL, REVISE, fmt_tc
from .parsing import parse_plan, parse_transcript
from .render import (
    render_change_orders, render_curriculum_delta, render_edit_sheet, write_atr,
)


def _resolve(lesson_dir: Path) -> tuple[Path, Path, Path]:
    plan = lesson_dir / "master-plan.md"
    transcript = lesson_dir / "transcript.txt"
    assets = lesson_dir / "assets.json"
    for p in (plan, transcript, assets):
        if not p.exists():
            raise SystemExit(f"missing {p}")
    return plan, transcript, assets


def cmd_reconcile(args: argparse.Namespace) -> int:
    lesson_dir = Path(args.lesson_dir)
    plan_path, transcript_path, assets_path = _resolve(lesson_dir)

    lesson = parse_plan(plan_path.read_text())
    segments = parse_transcript(transcript_path.read_text())
    assets = load_assets(assets_path)

    engine = get_engine(args.engine)
    atr = engine.reconcile(lesson, segments, transcript_id=args.take or transcript_path.stem)
    orders = build_change_orders(lesson, atr, assets, segments)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    write_atr(atr, out / "as-taught-record.json")
    (out / "change-orders.md").write_text(render_change_orders(lesson, atr, orders))
    (out / "edit-sheet.md").write_text(render_edit_sheet(lesson, atr, orders))
    (out / "student-materials-delta.md").write_text(render_curriculum_delta(lesson, atr, orders))
    (out / "review-console.html").write_text(render_console(lesson, atr, orders, segments))

    counts = summarise(orders)
    blocking = counts.get(KILL, 0) + counts.get(CREATE, 0) + counts.get(REVISE, 0)
    print(f"{lesson.lesson_id} — {lesson.title}")
    print(f"  engine        {atr.engine}")
    print(f"  runtime       planned {fmt_tc(atr.planned_runtime)} / actual {fmt_tc(atr.actual_runtime)}")
    print(f"  beats         " + ", ".join(
        f"{s}={sum(1 for b in atr.beats if b.status == s)}"
        for s in sorted({b.status for b in atr.beats})
    ))
    print(f"  unplanned     {len(atr.added)}")
    print(f"  change orders " + ", ".join(f"{k}={v}" for k, v in counts.items() if v))
    print(f"  written to    {out}/")
    return 1 if (args.strict and blocking) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shootsync",
        description="Reconcile a master lesson plan with what was actually taught on shoot day.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    rec = sub.add_parser("reconcile", help="reconcile a lesson and emit change orders")
    rec.add_argument("lesson_dir", help="directory holding master-plan.md, transcript.txt, assets.json")
    rec.add_argument("--out", default="out", help="output directory (default: out)")
    rec.add_argument("--engine", default="local", choices=["local", "claude"],
                     help="local = deterministic, no API key; claude = semantic (default: local)")
    rec.add_argument("--take", default="", help="label for this take")
    rec.add_argument("--strict", action="store_true",
                     help="exit non-zero if anything downstream needs work (for CI)")
    rec.set_defaults(func=cmd_reconcile)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
