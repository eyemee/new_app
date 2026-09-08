"""Build the producer's review console.

The reconciliation is a proposal, not a decision. This is the surface where a human
accepts or rejects each proposed change before anything reaches post-production.
"""
from __future__ import annotations

import html
import json

from .models import (
    CREATE, KEEP, KILL, MERGED, MODIFIED, MOVED, RETIME, REVISE, SKIPPED, TAUGHT,
    AsTaughtRecord, ChangeOrder, Lesson, Segment, fmt_tc,
)

STATUS_LABEL = {
    TAUGHT: "as planned", MOVED: "moved", MODIFIED: "changed",
    MERGED: "folded in", SKIPPED: "not taught",
}

STYLE = """
:root {
  --ground:#eef0f4; --surface:#ffffff; --surface-2:#f6f7fa; --line:#d8dce5;
  --ink:#151922; --ink-2:#3d4655; --muted:#6b7488;
  --accent:#3c4a70; --accent-soft:#e5e9f4;
  --keep:#2f6d4f; --retime:#2f5f96; --revise:#9a6410; --kill:#a3333a; --create:#6a4a9c;
  --keep-bg:#e6f1ea; --retime-bg:#e5edf7; --revise-bg:#faf0dd; --kill-bg:#f8e5e6; --create-bg:#efe9f7;
  --shadow:0 1px 2px rgba(21,25,34,.06), 0 4px 14px rgba(21,25,34,.05);
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --ground:#12151c; --surface:#191d26; --surface-2:#20252f; --line:#2c323e;
    --ink:#eaedf3; --ink-2:#c2c8d4; --muted:#8b94a6;
    --accent:#93a6d8; --accent-soft:#232a3c;
    --keep:#6cc294; --retime:#7dabe4; --revise:#e0ad4e; --kill:#e78a90; --create:#b394e8;
    --keep-bg:#17301f; --retime-bg:#152438; --revise-bg:#33260c; --kill-bg:#361a1d; --create-bg:#241a38;
    --shadow:0 1px 2px rgba(0,0,0,.4), 0 4px 14px rgba(0,0,0,.3);
  }
}
:root[data-theme="dark"] {
  --ground:#12151c; --surface:#191d26; --surface-2:#20252f; --line:#2c323e;
  --ink:#eaedf3; --ink-2:#c2c8d4; --muted:#8b94a6;
  --accent:#93a6d8; --accent-soft:#232a3c;
  --keep:#6cc294; --retime:#7dabe4; --revise:#e0ad4e; --kill:#e78a90; --create:#b394e8;
  --keep-bg:#17301f; --retime-bg:#152438; --revise-bg:#33260c; --kill-bg:#361a1d; --create-bg:#241a38;
  --shadow:0 1px 2px rgba(0,0,0,.4), 0 4px 14px rgba(0,0,0,.3);
}
*{box-sizing:border-box}
body{margin:0;background:var(--ground);color:var(--ink);
  font-family:"IBM Plex Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased}
.wrap{max-width:1180px;margin:0 auto;padding:32px 24px 80px;display:flex;flex-direction:column;gap:28px}
h1,h2,h3{font-family:Archivo,"IBM Plex Sans",sans-serif;margin:0;text-wrap:balance;letter-spacing:-.01em}
h1{font-size:29px;font-weight:650;line-height:1.2}
h2{font-size:18px;font-weight:620}
h3{font-size:15px;font-weight:600}
.mono{font-family:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
  font-variant-numeric:tabular-nums}
.eyebrow{font-family:Archivo,sans-serif;font-size:11px;font-weight:650;letter-spacing:.1em;
  text-transform:uppercase;color:var(--muted)}

/* header */
.masthead{display:flex;flex-wrap:wrap;gap:20px 40px;align-items:flex-end;
  justify-content:space-between;padding-bottom:22px;border-bottom:2px solid var(--ink)}
.masthead p{margin:6px 0 0;color:var(--ink-2);max-width:62ch}
.facts{display:flex;flex-wrap:wrap;gap:0 28px}
.fact{display:flex;flex-direction:column;gap:2px}
.fact b{font-size:15px;font-weight:600}
.over{color:var(--revise)}

/* timeline */
.ribbon{display:flex;flex-direction:column;gap:14px;background:var(--surface);
  border:1px solid var(--line);border-radius:6px;padding:20px;box-shadow:var(--shadow)}
.track{display:flex;width:100%;height:38px;gap:2px;overflow:hidden}
.seg{display:flex;align-items:center;justify-content:center;min-width:0;border-radius:3px;
  font-size:10.5px;font-weight:600;padding:0 2px;overflow:hidden;white-space:nowrap;
  font-family:"IBM Plex Mono",monospace;cursor:default}
.seg[data-s="TAUGHT"]{background:var(--keep-bg);color:var(--keep);border:1px solid var(--keep)}
.seg[data-s="MOVED"]{background:var(--retime-bg);color:var(--retime);border:1px solid var(--retime)}
.seg[data-s="MODIFIED"]{background:var(--revise-bg);color:var(--revise);border:1px solid var(--revise)}
.seg[data-s="SKIPPED"],.seg[data-s="MERGED"]{background:var(--kill-bg);color:var(--kill);
  border:1px dashed var(--kill)}
.seg[data-s="ADDED"]{background:var(--create-bg);color:var(--create);border:1px solid var(--create)}
.tl-label{display:flex;justify-content:space-between;align-items:baseline;gap:12px}
.scale{display:flex;justify-content:space-between;color:var(--muted);font-size:11px;
  border-top:1px solid var(--line);padding-top:5px}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:12px;color:var(--ink-2)}
.legend span{display:flex;align-items:center;gap:6px}
.dot{width:9px;height:9px;border-radius:2px;flex:none}

/* triage */
.triage{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;
  background:var(--line);border:1px solid var(--line);border-radius:6px;overflow:hidden}
.tri{background:var(--surface);padding:14px 16px;display:flex;flex-direction:column;gap:3px}
.tri b{font-family:Archivo,sans-serif;font-size:26px;font-weight:650;line-height:1;
  font-variant-numeric:tabular-nums}
.tri small{color:var(--muted);font-size:12px;line-height:1.4}

/* controls */
.bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.chip{font-family:Archivo,sans-serif;font-size:12px;font-weight:600;padding:5px 11px;
  border-radius:100px;border:1px solid var(--line);background:var(--surface);color:var(--ink-2);
  cursor:pointer}
.chip[aria-pressed="true"]{background:var(--ink);color:var(--ground);border-color:var(--ink)}
.chip:focus-visible,.row summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}

/* change orders */
.orders{display:flex;flex-direction:column;gap:8px}
.row{background:var(--surface);border:1px solid var(--line);border-left-width:4px;
  border-radius:5px;box-shadow:var(--shadow)}
.row[data-a="KILL"]{border-left-color:var(--kill)}
.row[data-a="CREATE"]{border-left-color:var(--create)}
.row[data-a="REVISE"]{border-left-color:var(--revise)}
.row[data-a="RETIME"]{border-left-color:var(--retime)}
.row[data-a="KEEP"]{border-left-color:var(--keep)}
.row summary{display:grid;grid-template-columns:76px 92px 1fr auto;gap:14px;align-items:center;
  padding:11px 16px;cursor:pointer;list-style:none}
.row summary::-webkit-details-marker{display:none}
.row summary:hover{background:var(--surface-2)}
.pill{font-family:Archivo,sans-serif;font-size:10.5px;font-weight:700;letter-spacing:.07em;
  text-align:center;padding:3px 0;border-radius:3px}
.pill[data-a="KILL"]{background:var(--kill-bg);color:var(--kill)}
.pill[data-a="CREATE"]{background:var(--create-bg);color:var(--create)}
.pill[data-a="REVISE"]{background:var(--revise-bg);color:var(--revise)}
.pill[data-a="RETIME"]{background:var(--retime-bg);color:var(--retime)}
.pill[data-a="KEEP"]{background:var(--keep-bg);color:var(--keep)}
.who{font-size:11px;color:var(--muted);text-align:right;white-space:nowrap}
.body{padding:2px 16px 16px 16px;border-top:1px solid var(--line);
  display:flex;flex-direction:column;gap:10px;font-size:14px;color:var(--ink-2)}
.body p{margin:10px 0 0}
.flag{border-left:3px solid var(--kill);background:var(--kill-bg);color:var(--ink);
  padding:8px 12px;border-radius:0 4px 4px 0;font-size:13.5px}
.flag.low{border-left-color:var(--muted);background:var(--surface-2);color:var(--ink-2)}
.decide{display:flex;gap:6px;align-items:center;padding-top:4px}
.decide button{font-family:Archivo,sans-serif;font-size:12px;font-weight:600;padding:5px 12px;
  border-radius:4px;border:1px solid var(--line);background:var(--surface);color:var(--ink-2);
  cursor:pointer}
.decide button[aria-pressed="true"]{background:var(--accent);border-color:var(--accent);
  color:var(--surface)}
.state{font-size:11px;color:var(--muted);margin-left:auto}

/* beats table */
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:6px;background:var(--surface);
  box-shadow:var(--shadow)}
table{border-collapse:collapse;width:100%;font-size:13.5px;min-width:760px}
th{font-family:Archivo,sans-serif;font-size:10.5px;font-weight:650;letter-spacing:.08em;
  text-transform:uppercase;color:var(--muted);text-align:left;padding:10px 14px;
  border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:10px 14px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:none}
.tag{font-family:Archivo,sans-serif;font-size:10px;font-weight:700;letter-spacing:.06em;
  padding:2px 7px;border-radius:3px;white-space:nowrap}
.tag[data-s="TAUGHT"]{background:var(--keep-bg);color:var(--keep)}
.tag[data-s="MOVED"]{background:var(--retime-bg);color:var(--retime)}
.tag[data-s="MODIFIED"]{background:var(--revise-bg);color:var(--revise)}
.tag[data-s="SKIPPED"],.tag[data-s="MERGED"]{background:var(--kill-bg);color:var(--kill)}
.tag[data-s="ADDED"]{background:var(--create-bg);color:var(--create)}
.conf{display:flex;align-items:center;gap:7px;white-space:nowrap}
.meter{width:42px;height:4px;border-radius:2px;background:var(--line);overflow:hidden;flex:none}
.meter i{display:block;height:100%;background:var(--accent)}
.meter.low i{background:var(--revise)}
.find{color:var(--muted);font-size:12.5px;margin-top:3px}
.quote{color:var(--muted);font-size:12px;font-style:italic}
.note{color:var(--muted);font-size:13px;max-width:70ch}
footer{border-top:1px solid var(--line);padding-top:16px;color:var(--muted);font-size:12.5px}
@media (max-width:720px){
  .row summary{grid-template-columns:70px 1fr;gap:8px}
  .who{display:none}
  h1{font-size:24px}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
"""


def _esc(s: str) -> str:
    return html.escape(s or "", quote=True)


def _ribbon(lesson: Lesson, atr: AsTaughtRecord) -> str:
    """Two tracks: the lesson as written, and the lesson as it exists on tape."""
    planned = [b for b in lesson.beats]
    total_plan = sum(b.est_seconds or 60 for b in planned) or 1
    plan_cells = "".join(
        f'<div class="seg" data-s="{atr.status_of(b.id)}" '
        f'style="flex:{(b.est_seconds or 60) / total_plan}" '
        f'title="{_esc(b.id)} — {_esc(b.title)} · planned {fmt_tc(b.est_seconds)}">{_esc(b.id)}</div>'
        for b in planned
    )

    taught: list[tuple[float, float, str, str, str]] = []
    for r in atr.beats:
        if r.start is None or r.end is None:
            continue
        beat = lesson.by_id(r.beat_id)
        taught.append((r.start, r.end, r.beat_id, beat.title if beat else "", r.status))
    for a in atr.added:
        taught.append((a.start, a.end, a.id, a.title, "ADDED"))
    taught.sort(key=lambda x: x[0])
    total_actual = sum(max(e - s, 1) for s, e, _, _, _ in taught) or 1
    taught_cells = "".join(
        f'<div class="seg" data-s="{st}" style="flex:{max(e - s, 1) / total_actual}" '
        f'title="{_esc(bid)} — {_esc(title)} · {fmt_tc(s)}–{fmt_tc(e)} · '
        f'{STATUS_LABEL.get(st, st.lower())}">{_esc(bid)}</div>'
        for s, e, bid, title, st in taught
    )

    legend = "".join(
        f'<span><i class="dot" style="background:var(--{c})"></i>{lbl}</span>'
        for c, lbl in [
            ("keep", "as planned"), ("retime", "moved"), ("revise", "changed"),
            ("kill", "not taught"), ("create", "unplanned"),
        ]
    )
    return f"""<section class="ribbon">
  <div class="tl-label"><h2>Running order</h2>
    <div class="legend">{legend}</div></div>
  <div>
    <div class="eyebrow" style="margin-bottom:5px">As written &middot; plan {_esc(atr.plan_version)}</div>
    <div class="track">{plan_cells}</div>
  </div>
  <div>
    <div class="eyebrow" style="margin-bottom:5px">As taught &middot; take {_esc(atr.transcript_id)}</div>
    <div class="track">{taught_cells}</div>
    <div class="scale mono"><span>00:00:00</span><span>{fmt_tc(atr.actual_runtime)}</span></div>
  </div>
  <p class="note">Read the two rows against each other: a block that changes colour or
  position between them is work for somebody downstream. Hover any block for its timecode.</p>
</section>"""


def _orders_section(orders: list[ChangeOrder]) -> str:
    owners = sorted({o.owner for o in orders})
    chips = "".join(
        f'<button class="chip" data-filter="owner" data-value="{_esc(o)}" '
        f'aria-pressed="false">{_esc(o)}</button>'
        for o in owners
    )
    rows = []
    for o in orders:
        when = f"{fmt_tc(o.start)}" if o.start is not None else "&mdash;"
        flags = "".join(
            f'<div class="flag{" low" if c.severity == "low" else ""}">'
            f'<strong>{_esc(c.kind.replace("_", " ").title())}</strong> — {_esc(c.detail)}</div>'
            for c in o.conflicts
        )
        suggest = ""
        if o.suggested_text:
            items = "".join(f"<li>{_esc(s)}</li>" for s in o.suggested_text)
            suggest = f"<div><strong>Needs:</strong><ul>{items}</ul></div>"
        rows.append(f"""<details class="row" data-a="{o.action}" data-owner="{_esc(o.owner)}"
    data-id="{_esc(o.asset_id)}">
  <summary>
    <span class="pill" data-a="{o.action}">{o.action}</span>
    <span class="mono">{_esc(o.asset_id)}</span>
    <span>{_esc(o.asset_title)}</span>
    <span class="who">{_esc(o.owner)} &middot; <span class="mono">{when}</span></span>
  </summary>
  <div class="body">
    <p>{_esc(o.reason)}</p>
    {flags}
    {suggest}
    <div class="decide">
      <button data-decide="accept" aria-pressed="false">Accept</button>
      <button data-decide="reject" aria-pressed="false">Reject</button>
      <span class="state">undecided</span>
    </div>
  </div>
</details>""")
    return f"""<section>
  <div class="tl-label" style="margin-bottom:12px">
    <h2>Change orders</h2>
    <span class="note" id="ordercount"></span>
  </div>
  <div class="bar" style="margin-bottom:12px">
    <button class="chip" data-filter="action" data-value="blocking" aria-pressed="true">Needs work</button>
    <button class="chip" data-filter="action" data-value="all" aria-pressed="false">Everything</button>
    <span style="width:14px"></span>{chips}
  </div>
  <div class="orders">{"".join(rows)}</div>
</section>"""


def _beats_section(lesson: Lesson, atr: AsTaughtRecord, segments: list[Segment]) -> str:
    rows = []
    for r in sorted(atr.beats, key=lambda b: b.planned_order):
        beat = lesson.by_id(r.beat_id)
        when = (
            f"{fmt_tc(r.start)}–{fmt_tc(r.end)}" if r.start is not None else "&mdash;"
        )
        findings = "".join(
            f'<div class="find">{_esc(f.detail)}</div>' for f in r.findings
        )
        quote = ""
        if r.evidence_segments:
            first = segments[r.evidence_segments[0]].text
            quote = f'<div class="quote">&ldquo;{_esc(first[:130])}&hellip;&rdquo;</div>'
        low = " low" if r.confidence < 0.7 else ""
        rows.append(f"""<tr>
  <td class="mono">{_esc(r.beat_id)}</td>
  <td>{_esc(beat.title if beat else "")}{findings}{quote}</td>
  <td><span class="tag" data-s="{r.status}">{STATUS_LABEL.get(r.status, r.status)}</span></td>
  <td class="mono">{when}</td>
  <td><div class="conf"><span class="meter{low}"><i style="width:{int(r.confidence * 100)}%"></i></span>
    <span class="mono">{r.confidence:.2f}</span></div></td>
</tr>""")
    for a in atr.added:
        rows.append(f"""<tr>
  <td class="mono">{_esc(a.id)}</td>
  <td><strong>Unplanned teaching</strong>
    <div class="quote">&ldquo;{_esc(a.summary[:160])}&hellip;&rdquo;</div></td>
  <td><span class="tag" data-s="ADDED">unplanned</span></td>
  <td class="mono">{fmt_tc(a.start)}–{fmt_tc(a.end)}</td>
  <td><div class="conf"><span class="meter{' low' if a.confidence < 0.7 else ''}">
    <i style="width:{int(a.confidence * 100)}%"></i></span>
    <span class="mono">{a.confidence:.2f}</span></div></td>
</tr>""")
    return f"""<section>
  <h2 style="margin-bottom:12px">Beat-by-beat reconciliation</h2>
  <div class="tablewrap"><table>
    <thead><tr><th>Beat</th><th>Planned teaching point</th><th>Verdict</th>
      <th>On tape</th><th>Confidence</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table></div>
  <p class="note" style="margin-top:10px">Confidence is the reconciler's, not a
  guarantee. Anything under 0.70 is where a human should look first.</p>
</section>"""


SCRIPT = """
(function () {
  var root = document.querySelector('.wrap');
  var KEY = 'shootsync:' + ((root && root.dataset.lesson) || 'lesson');
  var saved = {};
  try { saved = JSON.parse(localStorage.getItem(KEY) || '{}'); } catch (e) { saved = {}; }

  var rows = Array.prototype.slice.call(document.querySelectorAll('.row'));
  var filters = { action: 'blocking', owner: null };

  function paint(row) {
    var id = row.dataset.id, v = saved[id] || null;
    row.querySelectorAll('[data-decide]').forEach(function (b) {
      b.setAttribute('aria-pressed', String(b.dataset.decide === v));
    });
    var state = row.querySelector('.state');
    if (state) state.textContent = v ? v + 'ed' : 'undecided';
  }

  function apply() {
    var shown = 0;
    rows.forEach(function (row) {
      var okAction = filters.action === 'all' || row.dataset.a !== 'KEEP';
      var okOwner = !filters.owner || row.dataset.owner === filters.owner;
      var show = okAction && okOwner;
      row.hidden = !show;
      if (show) shown++;
    });
    var undecided = rows.filter(function (r) { return !r.hidden && !saved[r.dataset.id]; }).length;
    var el = document.getElementById('ordercount');
    if (el) el.textContent = shown + ' shown · ' + undecided + ' still to decide';
  }

  document.querySelectorAll('.chip').forEach(function (chip) {
    chip.addEventListener('click', function () {
      var kind = chip.dataset.filter, val = chip.dataset.value;
      if (kind === 'action') {
        filters.action = val;
      } else {
        filters.owner = (filters.owner === val) ? null : val;
      }
      document.querySelectorAll('.chip').forEach(function (c) {
        var on = c.dataset.filter === 'action'
          ? c.dataset.value === filters.action
          : c.dataset.value === filters.owner;
        c.setAttribute('aria-pressed', String(!!on));
      });
      apply();
    });
  });

  rows.forEach(function (row) {
    paint(row);
    row.querySelectorAll('[data-decide]').forEach(function (btn) {
      btn.addEventListener('click', function (ev) {
        ev.preventDefault();
        var id = row.dataset.id, v = btn.dataset.decide;
        saved[id] = (saved[id] === v) ? null : v;
        if (!saved[id]) delete saved[id];
        try { localStorage.setItem(KEY, JSON.stringify(saved)); } catch (e) {}
        paint(row);
        apply();
      });
    });
  });

  apply();
})();
"""


def render_console(
    lesson: Lesson, atr: AsTaughtRecord, orders: list[ChangeOrder],
    segments: list[Segment], standalone: bool = True,
) -> str:
    counts: dict[str, int] = {}
    for o in orders:
        counts[o.action] = counts.get(o.action, 0) + 1

    over = (atr.actual_runtime or 0) - (atr.planned_runtime or 0)
    over_cls = ' class="over"' if over > 60 else ""
    changed = sum(1 for b in atr.beats if b.status != TAUGHT)

    tri = "".join(
        f'<div class="tri"><b style="color:var(--{c})">{counts.get(a, 0)}</b>'
        f"<small>{d}</small></div>"
        for a, c, d in [
            (KILL, "kill", "assets to bin &mdash; the content was never taught"),
            (CREATE, "create", "unplanned segments with no asset covering them"),
            (REVISE, "revise", "assets whose content no longer matches the take"),
            (RETIME, "retime", "correct, but the position moved"),
            (KEEP, "keep", "ship as built, on the new timecode"),
        ]
    )

    title = f"{lesson.lesson_id} Shoot Reconciliation"
    head = f"""<title>{_esc(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;600;650;700&family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap">
<style>{STYLE}</style>"""

    body = f"""<div class="wrap" data-lesson="{_esc(lesson.lesson_id)}">
  <header class="masthead">
    <div>
      <div class="eyebrow">As-taught record &middot; awaiting sign-off</div>
      <h1>{_esc(lesson.lesson_id)} &mdash; {_esc(lesson.title)}</h1>
      <p>The plan is no longer what this lesson is. Everything below is bound to the
      footage, not to <span class="mono">{_esc(atr.plan_version)}</span>.</p>
    </div>
    <div class="facts">
      <div class="fact"><span class="eyebrow">Take</span>
        <b class="mono">{_esc(atr.transcript_id)}</b></div>
      <div class="fact"><span class="eyebrow">Reconciler</span>
        <b class="mono">{_esc(atr.engine)}</b></div>
      <div class="fact"><span class="eyebrow">Planned</span>
        <b class="mono">{fmt_tc(atr.planned_runtime)}</b></div>
      <div class="fact"><span class="eyebrow">Actual</span>
        <b class="mono"{over_cls}>{fmt_tc(atr.actual_runtime)}</b></div>
      <div class="fact"><span class="eyebrow">Beats off-plan</span>
        <b class="mono">{changed} of {len(atr.beats)}</b></div>
    </div>
  </header>

  {_ribbon(lesson, atr)}

  <section>
    <h2 style="margin-bottom:12px">What this take costs downstream</h2>
    <div class="triage">{tri}</div>
  </section>

  {_orders_section(orders)}
  {_beats_section(lesson, atr, segments)}

  <footer>
    Generated by ShootSync from <span class="mono">{_esc(atr.transcript_id)}</span>
    against plan <span class="mono">{_esc(atr.plan_version)}</span>.
    Decisions are held in this browser only &mdash; in production they belong in the
    pipeline, alongside the as-taught record.
  </footer>
</div>
<script>{SCRIPT}</script>"""

    if not standalone:
        return head + "\n" + body
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        f'{head}\n</head>\n<body data-lesson="{_esc(lesson.lesson_id)}">\n{body}\n</body>\n</html>\n'
    )
