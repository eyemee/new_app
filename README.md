# ShootSync

Reconciles a master lesson plan with what the instructor actually taught on shoot
day, and turns the difference into per-asset work orders for design, edit and
curriculum.

The design rationale is in **[docs/DESIGN.md](docs/DESIGN.md)**. The short version:
after a shoot the plan is fiction, the footage is truth, and everything downstream is
still bound to the plan. ShootSync produces an **As-Taught Record** and rebinds
downstream work to it.

## Try it

No dependencies, no API key.

```bash
PYTHONPATH=src python3 -m shootsync.cli reconcile fixtures/NEG-L03 --out out
```

```
NEG-L03 — Lesson 3 — Anchoring and the First Offer
  engine        local
  runtime       planned 00:23:15 / actual 00:23:47
  beats         MODIFIED=3, MOVED=2, SKIPPED=1, TAUGHT=8
  unplanned     2
  change orders KEEP=4, RETIME=3, REVISE=12, KILL=3, CREATE=2
  written to    out/
```

Five artefacts land in `out/`:

| File | For | What it is |
| --- | --- | --- |
| `review-console.html` | Producer | The review and sign-off surface — open this first |
| `as-taught-record.json` | Pipeline | The machine-readable source of truth |
| `edit-sheet.md` | Edit | Running order as shot, with timecodes and what was never filmed |
| `change-orders.md` | Design | Every asset with a verb: keep, retime, revise, kill, create |
| `student-materials-delta.md` | Curriculum | Handout and quiz edits required |

## What it catches on the sample shoot

The fixture is a 24-minute negotiation lesson whose instructor departed from the
plan in the ordinary ways. ShootSync finds all of it:

- **A stat card that would have shipped wrong.** The plan cites a 41% figure; on
  camera she says "about a third". `GFX-02` is flagged before it is built.
- **A graphic naming something never taught.** The plan has four anchoring levers;
  she folds the fourth into the third and says "three levers". `GFX-04`, the
  worksheet and a quiz question all still name "Patience".
- **A quiz question on a cut section.** She runs out of time and skips "When not to
  anchor first". Its graphic, handout page and quiz item are killed rather than built.
- **Five minutes of unplanned teaching.** A long client story and an extra role-play
  take, neither in the plan, both with no graphic, chapter marker or handout coverage.
- **Reordering.** She defers the roadmap and promotes the third lever, so the
  chapter markers and one quiz item need retiming — but not rewriting.

## Inputs

A lesson is a directory of three files. All three are plain text so producers can
keep authoring in Google Docs and export.

```
fixtures/NEG-L03/
  master-plan.md   # teaching points, each with a stable beat ID
  transcript.txt   # timecoded transcript of the take
  assets.json      # downstream assets, each declaring the beats it depends on
```

**The plan** — `###` headings are beats. The ID is what everything binds to.

```markdown
### B09 — Lever 4: Patience
est: 1:30
type: framework
must_cover: true
Say the number, then stop talking. The silence after an anchor is what makes it land.
```

**The transcript** — any `[HH:MM:SS]` or `[MM:SS]` timecoded lines; speaker optional.

```
[00:12:17] DANA: When you say the range, you stop talking.
```

**The assets** — the dependency edges that make impact computable.

```json
{ "id": "GFX-04", "type": "list_build", "owner": "Design",
  "title": "The Four Anchoring Levers",
  "depends_on": ["B06", "B07", "B08", "B09"],
  "on_screen_text": ["1. Precision", "2. Range", "3. Justification", "4. Patience"] }
```

Every line of `on_screen_text` is checked against what was said underneath it. That
check needs no model and catches the most expensive class of error — a graphic that
contradicts its own audio.

## Two engines

```bash
--engine local    # default: deterministic, offline, byte-identical on re-runs
--engine claude   # semantic: judges coverage by meaning, needs ANTHROPIC_API_KEY
```

`local` aligns by vocabulary. It treats plan-to-transcript matching as an exclusive
assignment over topic blocks, with a monotonicity prior (lessons are mostly taught in
order) and a support gate (a beat is only "covered" if its own distinctive words were
actually spoken). It is strong on omissions, reordering and numeric drift.

`claude` reads both documents and judges coverage the way a producer would — an
instructor who makes the planned point in completely different words has taught that
beat, and no lexical matcher will agree. It uses `claude-opus-5` with structured
output so the two engines are interchangeable, and can be diffed against each other
to find the beats worth a human's attention.

```bash
pip install anthropic
ANTHROPIC_API_KEY=... PYTHONPATH=src python3 -m shootsync.cli \
  reconcile fixtures/NEG-L03 --engine claude --out out-claude
```

## How accurate is it

Timecodes matter as much as verdicts — an editor works from the in-points. Against
hand-annotated ground truth for the sample shoot, the deterministic engine gets every
beat verdict right, and places the in-point exactly on 9 of 13 beats (median error 0s,
mean 17s, worst 91s). The worst cases are boundaries that abut unplanned content,
where there is no second beat to slide the cut against. `tests/test_timecodes.py`
holds that as a budget so the matcher cannot regress silently.

## In CI

`--strict` exits non-zero while any asset still needs work, so a lesson cannot reach
post-production with unreviewed drift.

```bash
PYTHONPATH=src python3 -m shootsync.cli reconcile fixtures/NEG-L03 --strict
```

## Tests

```bash
pip install pytest && python3 -m pytest tests/ -q
```

41 tests. The reconciliation tests encode the ground truth of the sample shoot, so
tuning the matcher cannot quietly regress it.

## Using your own lesson

Copy the fixture layout, replace the three files, and run. To retrofit an existing
lesson: add a `### B01 — Title` heading per teaching point, export the transcript to
text, and list your graphics with the beats they cover.
