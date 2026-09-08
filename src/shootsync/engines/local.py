"""Deterministic reconciler.

No API key, no network, same answer every time — which makes it the right default
for CI, for regression tests, and for a demo that has to be reproducible.

The alignment is an exclusive assignment problem, not a nearest-neighbour lookup:
each planned beat competes for one contiguous window of transcript, and whatever no
beat claims is, by definition, unplanned content.
"""
from __future__ import annotations

from collections import Counter

from ..models import (
    MERGED, MODIFIED, MOVED, SKIPPED, TAUGHT,
    AddedBeat, AsTaughtRecord, Finding, Lesson, ReconciledBeat, Segment, fmt_tc,
)
from ..text import Tfidf, numerals, tokenize


class LocalReconciler:
    name = "local"

    def __init__(
        self,
        match_threshold: float = 0.055,
        context: int = 1,
        block_window: int = 3,
        block_sigma: float = 0.25,
        min_block: int = 3,
        absorb_ratio: float = 0.5,
        order_prior: float = 0.55,
        min_added_segments: int = 5,
        support_terms: int = 5,
        min_support: int = 2,
        coverage_floor: float = 0.34,
        merge_overlap: float = 0.5,
        max_overlap_segments: int = 1,
    ):
        self.match_threshold = match_threshold
        self.context = context
        self.block_window = block_window
        self.block_sigma = block_sigma
        self.min_block = min_block
        self.absorb_ratio = absorb_ratio
        self.order_prior = order_prior
        self.min_added_segments = min_added_segments
        self.support_terms = support_terms
        self.min_support = min_support
        self.coverage_floor = coverage_floor
        self.merge_overlap = merge_overlap
        self.max_overlap_segments = max_overlap_segments

    # -- scoring ------------------------------------------------------------
    def _similarity_matrix(self, lesson: Lesson, segments: list[Segment]):
        beat_tokens = [tokenize(b.text) for b in lesson.beats]
        seg_tokens = [tokenize(s.text) for s in segments]
        model = Tfidf(beat_tokens + seg_tokens)
        beat_vecs = [model.vector(t) for t in beat_tokens]

        # Score each segment together with its neighbours: single transcript lines
        # are too short to align reliably on their own.
        scores: list[list[float]] = []
        for i in range(len(segments)):
            lo = max(0, i - self.context)
            hi = min(len(segments), i + self.context + 1)
            ctx: list[str] = []
            for j in range(lo, hi):
                ctx.extend(seg_tokens[j])
            vec = model.vector(ctx)
            scores.append([Tfidf.cosine(vec, bv) for bv in beat_vecs])
        return scores, model, seg_tokens, beat_vecs

    # -- transcript blocking -------------------------------------------------
    def _blocks(self, seg_tokens: list[list[str]], model: Tfidf) -> list[tuple[int, int]]:
        """Split the transcript into coherent topic blocks (TextTiling-style).

        Aligning whole blocks rather than free-form windows is what keeps one beat
        from swallowing its neighbour's material.
        """
        n = len(seg_tokens)
        if n == 0:
            return []
        w = self.block_window
        gaps: list[tuple[int, float]] = []
        for i in range(1, n):
            left: list[str] = []
            right: list[str] = []
            for j in range(max(0, i - w), i):
                left.extend(seg_tokens[j])
            for j in range(i, min(n, i + w)):
                right.extend(seg_tokens[j])
            gaps.append((i, Tfidf.cosine(model.vector(left), model.vector(right))))

        if not gaps:
            return [(0, n - 1)]

        sims = [g[1] for g in gaps]
        mean = sum(sims) / len(sims)
        var = sum((s - mean) ** 2 for s in sims) / len(sims)
        cutoff = mean - self.block_sigma * (var ** 0.5)

        # Keep only local minima below the cutoff, so one dip yields one boundary.
        boundaries = []
        for k, (i, s) in enumerate(gaps):
            if s > cutoff:
                continue
            prev_s = gaps[k - 1][1] if k > 0 else 1.0
            next_s = gaps[k + 1][1] if k + 1 < len(gaps) else 1.0
            if s <= prev_s and s <= next_s:
                last = boundaries[-1] if boundaries else 0
                if i - last >= self.min_block and n - i >= self.min_block:
                    boundaries.append(i)

        edges = [0] + boundaries + [n]
        out = [(edges[k], edges[k + 1] - 1) for k in range(len(edges) - 1) if edges[k] < edges[k + 1]]
        # Fold any runt block into its neighbour; a two-line block cannot carry a topic.
        merged: list[tuple[int, int]] = []
        for lo, hi in out:
            if merged and (hi - lo + 1) < self.min_block:
                merged[-1] = (merged[-1][0], hi)
            else:
                merged.append((lo, hi))
        return merged

    # -- main ---------------------------------------------------------------
    def reconcile(
        self, lesson: Lesson, segments: list[Segment], transcript_id: str = ""
    ) -> AsTaughtRecord:
        scores, model, seg_tokens, beat_vecs = self._similarity_matrix(lesson, segments)
        blocks = self._blocks(seg_tokens, model)

        # Similarity of each whole block to each beat.
        block_sim: list[list[float]] = []
        for lo, hi in blocks:
            toks: list[str] = []
            for j in range(lo, hi + 1):
                toks.extend(seg_tokens[j])
            vec = model.vector(toks)
            block_sim.append([Tfidf.cosine(vec, bv) for bv in beat_vecs])

        # A lesson is mostly taught in the order it was written, so a beat matching a
        # block far from its planned position is discounted. The penalty is mild: a
        # local swap survives it, teaching the recap in slot two does not.
        nb, nk = len(lesson.beats), len(blocks)
        def prior(k: int, bi: int) -> float:
            if nb < 2 or nk < 2:
                return 1.0
            drift = abs(k / (nk - 1) - bi / (nb - 1))
            return max(0.15, 1.0 - self.order_prior * drift)

        scored = [[block_sim[k][bi] * prior(k, bi) for bi in range(nb)] for k in range(nk)]

        # Greedy 1:1 assignment — the strongest block/beat pairs claim each other first.
        pairs = sorted(
            ((scored[k][bi], k, bi) for k in range(nk) for bi in range(nb)),
            reverse=True,
        )
        block_of_beat: dict[int, list[int]] = {}
        beat_of_block: dict[int, int] = {}
        for sim, k, bi in pairs:
            if block_sim[k][bi] < self.match_threshold or k in beat_of_block or bi in block_of_beat:
                continue
            beat_of_block[k] = bi
            block_of_beat[bi] = [k]

        # Absorb pass: a beat taught across two blocks leaves an orphan beside it.
        # Give that orphan back to the neighbouring beat — but only if it looks like
        # more of the same beat. Judging that against the beat's own peak (rather than
        # a global threshold) is what stops a digression being absorbed into whatever
        # happened to precede it.
        peak = [max((block_sim[k][bi] for k in range(nk)), default=0.0) for bi in range(nb)]
        for k in range(nk):
            if k in beat_of_block:
                continue
            best_bi, best_sim = None, 0.0
            for neighbour in (k - 1, k + 1):
                bi = beat_of_block.get(neighbour)
                if bi is not None and block_sim[k][bi] > best_sim:
                    best_bi, best_sim = bi, block_sim[k][bi]
            if best_bi is None:
                continue
            if best_sim >= self.match_threshold and best_sim >= self.absorb_ratio * peak[best_bi]:
                beat_of_block[k] = best_bi
                block_of_beat[best_bi].append(k)
                continue
            # A block with no topical signal at all is continuation or filler, not a
            # new teaching point. Hand it to whichever beat it sits next to.
            if max(block_sim[k]) < self.match_threshold and best_bi is not None:
                beat_of_block[k] = best_bi
                block_of_beat[best_bi].append(k)

        # Support gate: a beat counts as covered only if its own distinctive vocabulary
        # turns up in the take. Shared phrasing alone ("anchor", "first") is how a
        # bag-of-words matcher talks itself into believing a skipped beat was taught.
        #
        # The vocabulary is drawn only from plan words that appear *somewhere* in the
        # transcript. A lesson plan is half content and half stage direction ("cite",
        # "emphasise", "re-run with the producer"), and stage directions are the rarest
        # words in it — nobody says them on camera — so ranking by IDF alone puts
        # exactly the useless terms on top.
        spoken_anywhere = {t for toks in seg_tokens for t in toks}
        for bi in list(block_of_beat):
            ks = sorted(block_of_beat[bi])
            lo, hi = blocks[ks[0]][0], blocks[ks[-1]][1]
            here = {t for j in range(lo, hi + 1) for t in seg_tokens[j]}
            # The term itself breaks IDF ties: sets iterate in hash order, which Python
            # randomises per process, and without a tiebreak the chosen terms — and so
            # the verdict on a borderline beat — could differ between two runs on
            # identical input.
            distinctive = sorted(
                (t for t in set(tokenize(lesson.beats[bi].text)) if t in spoken_anywhere),
                key=lambda t: (-model.idf.get(t, model.default_idf), t),
            )[: self.support_terms]
            if sum(1 for t in distinctive if t in here) < self.min_support:
                for k in ks:
                    beat_of_block.pop(k, None)
                block_of_beat.pop(bi)

        results: list[ReconciledBeat] = []
        for bi, beat in enumerate(lesson.beats):
            ks = sorted(block_of_beat.get(bi, []))
            if not ks:
                results.append(
                    ReconciledBeat(
                        beat_id=beat.id, status=SKIPPED, planned_order=beat.order,
                        confidence=self._skip_confidence(scores, bi),
                        summary="No passage in the transcript covers this beat.",
                        findings=[Finding("NOT_TAUGHT", "Planned beat never appears on camera.")],
                    )
                )
                continue
            lo, hi = blocks[ks[0]][0], blocks[ks[-1]][1]
            mean_sim = sum(block_sim[k][bi] for k in ks) / len(ks)
            window = " ".join(segments[i].text for i in range(lo, hi + 1))
            results.append(
                ReconciledBeat(
                    beat_id=beat.id, status=TAUGHT, planned_order=beat.order,
                    start=segments[lo].start, end=segments[hi].end,
                    confidence=self._confidence(mean_sim, hi - lo + 1),
                    evidence_segments=list(range(lo, hi + 1)),
                    summary=window[:400],
                )
            )

        placed = sorted(
            (r for r in results if r.start is not None), key=lambda r: r.start or 0.0
        )
        for pos, r in enumerate(placed):
            r.actual_order = pos

        spans = {
            bi: (blocks[sorted(ks)[0]][0], blocks[sorted(ks)[-1]][1])
            for bi, ks in block_of_beat.items()
        }
        self._mark_merged(lesson, results, scores, spans)
        self._mark_moved(results)
        self._mark_modified(lesson, results, segments)
        added = self._find_added(segments, scores, list(spans.values()))

        return AsTaughtRecord(
            lesson_id=lesson.lesson_id,
            plan_version=lesson.meta.get("plan_version", ""),
            transcript_id=transcript_id,
            engine=self.name,
            beats=results,
            added=added,
            planned_runtime=self._planned_runtime(lesson),
            actual_runtime=segments[-1].end if segments else None,
        )

    # -- status refinement --------------------------------------------------
    @staticmethod
    def _confidence(mean_sim: float, length: int) -> float:
        """Similarity carries most of the signal; a longer window corroborates it."""
        base = min(1.0, mean_sim / 0.16)
        support = min(1.0, length / 6.0)
        return round(min(0.97, 0.35 + 0.5 * base + 0.15 * support), 2)

    @staticmethod
    def _planned_runtime(lesson: Lesson) -> float | None:
        est = [b.est_seconds for b in lesson.beats if b.est_seconds]
        return sum(est) if est else None

    @staticmethod
    def _skip_confidence(scores: list[list[float]], bi: int) -> float:
        peak = max((row[bi] for row in scores if row), default=0.0)
        return round(max(0.4, min(0.95, 0.95 - peak * 3.0)), 2)

    def _mark_merged(
        self, lesson: Lesson, results: list[ReconciledBeat],
        scores: list[list[float]], assigned: dict[int, tuple[int, int]],
    ) -> None:
        """A skipped beat whose material sits inside another beat's window was folded in."""
        index = {b.id: i for i, b in enumerate(lesson.beats)}
        for r in results:
            if r.status != SKIPPED:
                continue
            bi = index[r.beat_id]
            col = [row[bi] if row else 0.0 for row in scores]
            best_host, best_share = None, 0.0
            for hbi, (lo, hi) in assigned.items():
                inside = sum(col[lo : hi + 1])
                total = sum(col) or 1.0
                share = inside / total
                if share > best_share:
                    best_host, best_share = hbi, share
            if best_host is not None and best_share >= self.merge_overlap:
                host = lesson.beats[best_host]
                r.status = MERGED
                r.start, r.end = None, None
                r.findings = [
                    Finding(
                        "MERGED_INTO",
                        f"Not taught as its own beat — the material appears inside "
                        f"{host.id} ({host.title}).",
                    )
                ]
                r.summary = (
                    f"Folded into {host.id}. Downstream assets that treat this as a "
                    f"separate item need rework."
                )

    @staticmethod
    def _mark_moved(results: list[ReconciledBeat]) -> None:
        """Flag genuine reordering only.

        Naive rank comparison marks the whole back half of a lesson MOVED as soon as
        one thing is inserted. Instead, find the longest run of beats that is still in
        planned order and treat everything outside it as the thing that actually moved.
        """
        placed = sorted(
            (r for r in results if r.actual_order is not None), key=lambda r: r.actual_order or 0
        )
        if not placed:
            return
        seq = [r.planned_order for r in placed]

        # Longest strictly-increasing subsequence, O(n^2) — n is a lesson, not a corpus.
        n = len(seq)
        length = [1] * n
        prev = [-1] * n
        for i in range(n):
            for j in range(i):
                if seq[j] < seq[i] and length[j] + 1 > length[i]:
                    length[i], prev[i] = length[j] + 1, j
        end = max(range(n), key=lambda i: length[i])
        keep = set()
        while end != -1:
            keep.add(end)
            end = prev[end]

        for pos, r in enumerate(placed):
            if pos in keep or r.status != TAUGHT:
                continue
            in_order = [placed[i] for i in sorted(keep)]
            after = [x.beat_id for x in in_order if (x.actual_order or 0) < (r.actual_order or 0)]
            where = f"after {after[-1]}" if after else "at the top of the lesson"
            r.status = MOVED
            r.findings.append(
                Finding(
                    "REORDERED",
                    f"Planned in position {r.planned_order + 1} of the written order; "
                    f"taught out of sequence, {where}.",
                )
            )

    def _mark_modified(
        self, lesson: Lesson, results: list[ReconciledBeat], segments: list[Segment]
    ) -> None:
        """Detect substance drift inside a beat that was otherwise covered."""
        for r in results:
            if r.start is None or not r.evidence_segments:
                continue
            beat = lesson.by_id(r.beat_id)
            if beat is None:
                continue
            spoken = " ".join(segments[i].text for i in r.evidence_segments)

            # 1. Numeric claims the plan makes that were not said on camera. These are
            #    the ones that burn a graphic: the card says 41%, the audio does not.
            missing = {n for n in numerals(beat.body) if n not in numerals(spoken)}
            missing = {n for n in missing if "%" in n or (n.isdigit() and int(n) >= 10)}
            if missing:
                r.findings.append(
                    Finding(
                        "NUMERIC_DRIFT",
                        f"Plan states {', '.join(sorted(missing))} — not said on camera.",
                        evidence=spoken[:240],
                    )
                )

            # 2. Distinctive plan vocabulary that never made it into the take.
            plan_terms = set(tokenize(beat.text))
            spoken_terms = set(tokenize(spoken))
            if plan_terms:
                coverage = len(plan_terms & spoken_terms) / len(plan_terms)
                if coverage < self.coverage_floor:
                    r.findings.append(
                        Finding(
                            "COVERAGE_LOW",
                            f"Only {coverage:.0%} of the planned language appears in the take.",
                        )
                    )

            # 3. Ran materially long or short against the estimate.
            if beat.est_seconds and r.duration:
                ratio = r.duration / beat.est_seconds
                if ratio >= 1.6 or ratio <= 0.5:
                    r.findings.append(
                        Finding(
                            "DURATION_DRIFT",
                            f"Planned {fmt_tc(beat.est_seconds)}, ran {fmt_tc(r.duration)} "
                            f"({ratio:.1f}x).",
                        )
                    )

            if any(f.kind in {"NUMERIC_DRIFT", "COVERAGE_LOW"} for f in r.findings):
                if r.status == TAUGHT:
                    r.status = MODIFIED

    def _find_added(
        self, segments: list[Segment], scores: list[list[float]],
        taken: list[tuple[int, int]],
    ) -> list[AddedBeat]:
        """Stretches of camera time that no planned beat claimed."""
        claimed = [False] * len(segments)
        for lo, hi in taken:
            for i in range(lo, hi + 1):
                claimed[i] = True

        added: list[AddedBeat] = []
        i = 0
        while i < len(segments):
            if claimed[i]:
                i += 1
                continue
            lo = i
            while i < len(segments) and not claimed[i]:
                i += 1
            hi = i - 1
            if hi - lo + 1 < self.min_added_segments:
                continue
            window = " ".join(segments[j].text for j in range(lo, hi + 1))
            peak = max((max(scores[j]) if scores[j] else 0.0) for j in range(lo, hi + 1))
            added.append(
                AddedBeat(
                    id=f"NEW-{len(added) + 1:02d}",
                    title=self._title_for(window),
                    actual_order=lo,
                    start=segments[lo].start,
                    end=segments[hi].end,
                    summary=window[:600],
                    evidence_segments=list(range(lo, hi + 1)),
                    confidence=round(max(0.4, min(0.95, 0.9 - peak * 2.0)), 2),
                )
            )
        return added

    @staticmethod
    def _title_for(window: str) -> str:
        """Label unplanned content with its opening words.

        A producer scanning an edit sheet needs to recognise the moment, and the
        instructor's own first line does that better than a bag of keywords. Any
        proper noun in the passage usually is the moment, so lead with it.
        """
        opening = " ".join(window.split())
        proper = [
            w.strip(".,;:?!\u2019'\u201d\"")
            for w in opening.split()[1:]
            if w[:1].isupper() and w.strip(".,;:?!").isalpha() and len(w) > 3
        ]
        head = opening[:64].rsplit(" ", 1)[0] if len(opening) > 64 else opening
        name = Counter(proper).most_common(1)[0][0] if proper else ""
        return f"Unplanned — {name}: \u201c{head}\u2026\u201d" if name else f"Unplanned — \u201c{head}\u2026\u201d"
