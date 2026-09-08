# Handling the gap between the plan and the shoot

## The diagnosis

The instinct is to treat instructor deviation as the problem and try to reduce it —
tighter plans, stricter scripts, a monitor calling out omissions. That is the wrong
target. Most deviation is the instructor improving the lesson live: they read the
room, find a better example, notice a section is dragging. A course where nobody
ever departs from the plan is usually a worse course.

The actual failure is narrower, and it is structural:

> **After the shoot, the plan is still the source of truth, and it is now fiction.**

Every downstream artefact — graphics, edit instructions, handouts, quiz items,
chapter markers — is built against a document that describes a lesson that no
longer exists. Nobody is doing anything wrong. Design builds the graphic the plan
specified. The instructor taught something else. Neither knows about the other
until the graphic lands under the wrong audio, and then someone redoes the work.

Three things go wrong, and they are worth separating because they cost differently:

| | What happens | What it costs |
|---|---|---|
| **Silent** | The graphic says 41%, the instructor said "about a third" | Worst. Ships, and a student catches it |
| **Orphaned** | A section is skipped; its graphic, handout page and quiz question are built anyway | Wasted production, plus a quiz on content nobody was taught |
| **Positional** | Points are reordered; every timecode-bound instruction is off | Cheap individually, endless in aggregate |

None of these is a transcription problem. They are all a *binding* problem: the
downstream work is bound to the plan, and nothing rebinds it to reality.

## The move

Stop letting the plan be the post-shoot source of truth. Introduce one new artefact
and one new rule.

**The As-Taught Record (ATR)** — a timecoded, reconciled account of what the lesson
actually became. Produced within minutes of wrap, reviewed by a producer, then
frozen.

**The rule** — nothing downstream binds to the plan. Everything binds to the ATR.

For that to work mechanically rather than by discipline, two structural changes to
how the plan is written:

**1. The plan is made of beats with stable IDs.** A beat is one teaching point.
`B07` is "Lever 2: Range" for the life of the lesson — through re-shoots, re-cuts
and version 5 of the plan. Producers keep authoring in Google Docs; the only new
requirement is that each teaching point carries an ID.

**2. Downstream artefacts declare what they depend on.** The lower third, the stat
card, handout §2, quiz item 3, the chapter marker — each names the beat IDs it
covers. This is a one-line addition to files these teams already maintain, and it
is what makes impact computable instead of a judgement call.

Once both exist, the shape of the problem changes. Reconciliation assigns a verdict
to each beat, and the consequences fall out of the dependency edges automatically:

```
Master plan (beats: B01…B14)
      │
      ├──── depends_on ───→  Asset registry (GFX-04 → B06,B07,B08,B09)
      │
Shoot ────→ Raw transcript (timecoded)
      │
      ▼
  Reconciler  ──→  As-Taught Record        ← the new source of truth
      │              per beat: TAUGHT | MOVED | MODIFIED | MERGED | SKIPPED
      │              plus: ADDED content the plan never had
      │              plus: timecodes, evidence, confidence
      ▼
  Producer review + sign-off               ← the human gate; nothing moves without it
      │
      ▼
  Change orders, one per asset
      KEEP · RETIME · REVISE · KILL · CREATE
      │
      ├──→ Design:     which graphics to bin, fix, or rebuild
      ├──→ Edit:       running order and timecodes as shot
      └──→ Curriculum: which handout and quiz items are now wrong
```

The verbs matter more than they look. "Here is a diff, work out what it means for
you" is what teams do today, in their heads, inconsistently. `KILL GFX-07 — the
content was never taught` is a decision someone can act on without rereading the
transcript.

## Where the deviation is caught

Two places, and the cheap one is optional.

**During the shoot (optional).** Whoever is monitoring taps a beat as it is covered.
Thirty seconds of effort produces a near-perfect running order and raises confidence
on everything downstream. It also allows a live prompt: *"B12 hasn't been covered and
you're four minutes from the end"* — which is the only intervention that avoids the
cost entirely rather than absorbing it.

**After the shoot (always).** The reconciler runs on the transcript. This is the
safety net, and it is deliberately the default: a process that only works when
somebody remembers to keep a log will fail on the day it matters. The live log makes
the automatic pass better; it is never a prerequisite.

## Why AI, and where it is fenced

Alignment between a plan and a transcript is a semantic judgement. An instructor who
makes the planned point in entirely different words has taught that beat; a recap
that restates the mechanism has not re-taught it. Nothing lexical settles that
reliably, which is why the Claude engine exists.

But an AI verdict must never silently drive production work, so:

- **Every verdict cites evidence** — the timecodes and the transcript lines it rests on.
- **Every verdict carries confidence**, and the console sorts the uncertain ones to
  where a human will see them.
- **A producer signs off** before any change order is actionable. The reconciler
  proposes; it does not decide.
- **A deterministic engine ships alongside**, so the pipeline runs in CI, on a
  laptop with no API key, and produces byte-identical output on a re-run. A record
  that changes when you regenerate it cannot be a source of truth.

The most valuable check is the cheapest one and needs no model at all: **compare
every word that will appear on screen against what was actually said underneath it.**
A stat card reading 41% over audio saying "about a third" is a defect the current
process cannot see and this one catches before the graphic is built.

## What changes for each team

**Producer** — reviews the ATR after wrap and signs it off. New work, roughly ten
minutes a lesson. It replaces the scattered rework it prevents.

**Instructor** — nothing changes. This is the point. They are free to teach it
better than it was written, because the system now notices.

**Design** — receives a list with verbs, not a transcript. Builds nothing that was
never taught.

**Edit** — receives the running order as shot, with real timecodes, and an explicit
list of what is not in the footage.

**Curriculum** — learns that a quiz question tests content that was cut *before*
students do.

## Adopting it

The dependency edges are the only real prerequisite, and they can be added
incrementally:

1. **Beat IDs in the plan template.** One lesson, retrofitted, to see the output.
2. **Dependencies on graphics only.** Graphics are where breakage is most visible
   and most expensive; this alone justifies the change.
3. **Handouts and quiz items.** The silent failures live here — nobody watches the
   lesson to check the quiz still matches it.
4. **The live shoot log**, once the reports are trusted enough that people want them
   sooner and sharper.

Steps 1 and 2 are a day of work on an existing lesson and produce the report in this
repository.

## What this does not do

- **It does not judge whether the deviation was good.** Change orders describe
  consequences, not quality. The instructor going off-plan is usually right.
- **It does not decide anything.** Producer sign-off is load-bearing, not ceremony.
- **It cannot see what the transcript cannot.** A misdrawn diagram or a mislabelled
  axis on a slide the instructor never reads aloud is invisible here.
- **Boundaries next to unplanned content are loose.** On the sample shoot the
  deterministic engine puts 9 of 13 in-points on the exact segment (median error 0s,
  worst 91s); the misses are all beats that border a digression, where there is no
  neighbouring beat to slide the cut against. Good enough to find the moment, not
  yet frame-accurate.
- **The deterministic engine matches on vocabulary.** It is strong on omissions,
  reordering and numeric drift, and weaker when the same point is made in entirely
  different words — precisely the case the Claude engine covers. Running both and
  diffing them is a cheap way to find the beats worth a human's attention.
