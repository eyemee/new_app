"""Rendering scan results for people and for pipelines.

The terminal output is the product surface: it has to say what was found, why it
matters, and what to do, without the reader opening a file. So findings lead with
severity, carry their evidence inline, and the verdict comes with a
recommendation rather than a number to interpret.
"""

from __future__ import annotations

import html
import json
import os
import shutil
import sys
from pathlib import Path

from .verdict import Decision, Finding, Report, Severity

_COLOURS = {
    Severity.CRITICAL: "\033[1;31m", Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m", Severity.LOW: "\033[36m", Severity.INFO: "\033[90m",
}
_DECISION_COLOURS = {
    Decision.ALLOW: "\033[1;32m", Decision.WARN: "\033[1;33m",
    Decision.QUARANTINE: "\033[1;31m", Decision.MALICIOUS: "\033[1;37;41m",
}
_RESET = "\033[0m"

RECOMMENDATION = {
    Decision.ALLOW: "No blocking findings. Ordinary caution still applies.",
    Decision.WARN: "Review the findings below before opening or running this.",
    Decision.QUARANTINE: "Do not open this. Held for review -- release it only if you can "
                         "explain every finding below.",
    Decision.MALICIOUS: "Do not open or run this under any circumstances. Delete it, and "
                        "if it arrived by email or link, report it.",
}


def use_colour(stream=None) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("AIRLOCK_FORCE_COLOR"):
        return True
    stream = stream or sys.stdout
    return hasattr(stream, "isatty") and stream.isatty()


def render_text(report: Report, verbose: bool = False, colour: bool | None = None) -> str:
    colour = use_colour() if colour is None else colour
    width = min(shutil.get_terminal_size((100, 24)).columns, 100)

    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if colour else text

    decision = report.decision
    lines: list[str] = []
    lines.append(paint(f" {decision.label} ", _DECISION_COLOURS[decision])
                 + f"  {report.display_name or report.path}")
    lines.append(f"  {report.type_description}  ·  {_human(report.size)}  ·  "
                 f"score {report.score}  ·  {report.duration_ms} ms")
    lines.append(f"  sha256  {report.sha256}")
    lines.append("")
    lines.append(_wrap(RECOMMENDATION[decision], width, "  "))

    if report.errors:
        lines.append("")
        lines.append(paint("  Scan did not complete:", _COLOURS[Severity.HIGH]))
        for err in report.errors:
            lines.append(_wrap(err, width, "    · "))
        lines.append(_wrap("A file that could not be fully examined is treated as blocked, "
                           "not as clean.", width, "    "))

    shown = [f for f in report.sorted_findings()
             if verbose or f.severity >= Severity.LOW]
    hidden = len(report.findings) - len(shown)

    if shown:
        lines.append("")
        lines.append(f"  Findings ({len(report.findings)}):")
        for finding in shown:
            lines.append("")
            tag = paint(f"{finding.severity.name:>8}", _COLOURS[finding.severity])
            layer = f"  [{finding.layer}]" if finding.layer else ""
            lines.append(f"  {tag}  {finding.title}{layer}")
            if finding.detail:
                lines.append(_wrap(finding.detail, width, "            "))
            for item in finding.evidence[:6]:
                lines.append(_truncate(f"            · {item}", width))
            if len(finding.evidence) > 6:
                lines.append(f"            · ... and {len(finding.evidence) - 6} more")
            meta = []
            if finding.attck:
                meta.append(f"ATT&CK {finding.attck}")
            meta.append(f"{finding.id} (+{finding.score})")
            lines.append(paint(f"            {' · '.join(meta)}", _COLOURS[Severity.INFO]))
    if hidden and not verbose:
        lines.append("")
        lines.append(f"  {hidden} informational finding(s) hidden; pass -v to show them.")
    return "\n".join(lines) + "\n"


def render_summary_line(report: Report, colour: bool | None = None) -> str:
    colour = use_colour() if colour is None else colour
    decision = report.decision
    label = decision.label
    if colour:
        label = f"{_DECISION_COLOURS[decision]} {label} {_RESET}"
    else:
        label = f"[{label}]"
    top = ""
    blocking = [f for f in report.sorted_findings() if f.severity >= Severity.HIGH]
    if blocking:
        top = f"  — {blocking[0].title}"
    return f"{label:<12} {report.display_name or report.path}  ({report.score}){top}"


def render_json(reports: list[Report]) -> str:
    return json.dumps(
        {"airlock": [r.to_dict() for r in reports]}, indent=2, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------
def render_html(reports: list[Report], title: str = "Airlock scan report") -> str:
    """A self-contained report. No external requests: a page about hostile files
    should not make any."""
    counts = {d: sum(1 for r in reports if r.decision is d) for d in Decision}
    rows = "\n".join(_html_report(r, i) for i, r in enumerate(reports))
    tiles = "\n".join(
        f'<div class="tile {d.label.lower()}"><span class="n">{counts[d]}</span>'
        f'<span class="l">{d.label}</span></div>'
        for d in (Decision.MALICIOUS, Decision.QUARANTINE, Decision.WARN, Decision.ALLOW))
    generated = reports[0].scanned_at if reports else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root {{
  --bg:#f7f7f5; --fg:#1a1a19; --muted:#6b6b66; --card:#fff; --line:#e2e2dd;
  --critical:#b4232a; --high:#c8641c; --medium:#a8830f; --low:#2b6ca3; --info:#6b6b66;
  --allow:#2f7d44;
}}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg:#161614; --fg:#eceae5; --muted:#9a978f; --card:#201e1c; --line:#332f2c;
    --critical:#f2726f; --high:#e89452; --medium:#d9b64a; --low:#6fb3e0; --info:#9a978f;
    --allow:#6cc08a; }}
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--fg); padding:2rem 1rem;
  font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }}
.wrap {{ max-width:60rem; margin:0 auto; }}
h1 {{ font-size:1.4rem; margin:0 0 .2rem; letter-spacing:-.01em; }}
.sub {{ color:var(--muted); font-size:.85rem; margin-bottom:1.5rem; }}
.tiles {{ display:flex; gap:.6rem; flex-wrap:wrap; margin-bottom:1.5rem; }}
.tile {{ background:var(--card); border:1px solid var(--line); border-radius:9px;
  padding:.7rem 1rem; min-width:7rem; }}
.tile .n {{ display:block; font-size:1.6rem; font-weight:650; line-height:1.1; }}
.tile .l {{ display:block; font-size:.7rem; letter-spacing:.09em; color:var(--muted); }}
.tile.malicious .n {{ color:var(--critical); }} .tile.quarantine .n {{ color:var(--high); }}
.tile.warn .n {{ color:var(--medium); }} .tile.allow .n {{ color:var(--allow); }}
.file {{ background:var(--card); border:1px solid var(--line); border-radius:11px;
  margin-bottom:.9rem; overflow:hidden; }}
.file > summary {{ cursor:pointer; padding:.85rem 1.1rem; display:flex; gap:.7rem;
  align-items:baseline; flex-wrap:wrap; }}
.file > summary::-webkit-details-marker {{ display:none; }}
.badge {{ font-size:.66rem; font-weight:700; letter-spacing:.08em; padding:.22rem .5rem;
  border-radius:5px; color:#fff; white-space:nowrap; }}
.badge.malicious {{ background:var(--critical); }} .badge.quarantine {{ background:var(--high); }}
.badge.warn {{ background:var(--medium); }} .badge.allow {{ background:var(--allow); }}
.name {{ font-weight:600; word-break:break-all; }}
.meta {{ color:var(--muted); font-size:.78rem; margin-left:auto; }}
.body {{ padding:0 1.1rem 1rem; border-top:1px solid var(--line); }}
.rec {{ margin:.9rem 0; padding:.6rem .8rem; background:var(--bg); border-radius:7px;
  border-left:3px solid var(--line); font-size:.88rem; }}
dl.facts {{ display:grid; grid-template-columns:max-content 1fr; gap:.2rem .9rem;
  font-size:.8rem; margin:.6rem 0 1rem; }}
dl.facts dt {{ color:var(--muted); }}
dl.facts dd {{ margin:0; font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  word-break:break-all; }}
.finding {{ border-top:1px solid var(--line); padding:.75rem 0; }}
.finding h3 {{ margin:0 0 .3rem; font-size:.92rem; font-weight:600;
  display:flex; gap:.55rem; align-items:baseline; flex-wrap:wrap; }}
.sev {{ font-size:.62rem; font-weight:700; letter-spacing:.08em; padding:.15rem .42rem;
  border-radius:4px; border:1px solid currentColor; white-space:nowrap; }}
.sev.critical {{ color:var(--critical); }} .sev.high {{ color:var(--high); }}
.sev.medium {{ color:var(--medium); }} .sev.low {{ color:var(--low); }}
.sev.info {{ color:var(--info); }}
.finding p {{ margin:.3rem 0; font-size:.85rem; color:var(--fg); }}
.finding ul {{ margin:.35rem 0; padding-left:1.1rem; font-size:.78rem;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace; color:var(--muted);
  overflow-x:auto; }}
.finding ul li {{ word-break:break-all; }}
.tags {{ font-size:.7rem; color:var(--muted); margin-top:.35rem; }}
.layer {{ font-size:.66rem; background:var(--bg); border:1px solid var(--line);
  padding:.1rem .35rem; border-radius:4px; color:var(--muted); }}
footer {{ color:var(--muted); font-size:.75rem; margin-top:2rem; }}
@media (max-width:480px) {{ body {{ padding:1rem .75rem; }} .meta {{ margin-left:0; }} }}
</style></head><body><div class="wrap">
<h1>{html.escape(title)}</h1>
<div class="sub">{len(reports)} file(s) · generated {html.escape(generated)} ·
airlock {html.escape(reports[0].engine_version if reports else '')}</div>
<div class="tiles">{tiles}</div>
{rows}
<footer>Static analysis only. Nothing in these files was executed. A clean verdict
means nothing matched, not that the file is safe.</footer>
</div></body></html>
"""


def _html_report(report: Report, index: int) -> str:
    d = report.decision
    findings = "\n".join(_html_finding(f) for f in report.sorted_findings())
    open_attr = " open" if d.blocks or index == 0 else ""
    errors = ""
    if report.errors:
        errors = ("<div class='rec'><strong>Scan did not complete.</strong> "
                  + html.escape("; ".join(report.errors))
                  + " A file that could not be fully examined is treated as blocked.</div>")
    return f"""<details class="file"{open_attr}>
<summary><span class="badge {d.label.lower()}">{d.label}</span>
<span class="name">{html.escape(report.display_name or report.path)}</span>
<span class="meta">{html.escape(report.type_description)} · {_human(report.size)} ·
score {report.score}</span></summary>
<div class="body">
<div class="rec">{html.escape(RECOMMENDATION[d])}</div>
{errors}
<dl class="facts">
<dt>path</dt><dd>{html.escape(report.path)}</dd>
<dt>sha256</dt><dd>{report.sha256}</dd>
<dt>sha1</dt><dd>{report.sha1}</dd>
<dt>md5</dt><dd>{report.md5}</dd>
<dt>type</dt><dd>{html.escape(report.file_type)}</dd>
<dt>scanned</dt><dd>{html.escape(report.scanned_at)} ({report.duration_ms} ms)</dd>
</dl>
{findings or '<p style="font-size:.85rem;color:var(--muted)">No findings.</p>'}
</div></details>"""


def _html_finding(f: Finding) -> str:
    sev = f.severity.name.lower()
    evidence = ""
    if f.evidence:
        items = "".join(f"<li>{html.escape(str(e))}</li>" for e in f.evidence[:12])
        evidence = f"<ul>{items}</ul>"
    tags = [f.id, f"+{f.score}"]
    if f.attck:
        tags.append(f"ATT&amp;CK {html.escape(f.attck)}")
    layer = f'<span class="layer">{html.escape(f.layer)}</span>' if f.layer else ""
    detail = f"<p>{html.escape(f.detail)}</p>" if f.detail else ""
    return f"""<div class="finding">
<h3><span class="sev {sev}">{f.severity.name}</span>{html.escape(f.title)}{layer}</h3>
{detail}{evidence}
<div class="tags">{' · '.join(tags)}</div></div>"""


# --------------------------------------------------------------------------
def _human(n: int) -> str:
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{n} B"


def _wrap(text: str, width: int, indent: str) -> str:
    import textwrap
    return "\n".join(textwrap.wrap(text, width=max(width - len(indent), 30),
                                   initial_indent=indent, subsequent_indent=indent)) or indent


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[:width - 1] + "…"


def write_html(reports: list[Report], path: Path, title: str = "Airlock scan report") -> Path:
    path.write_text(render_html(reports, title), encoding="utf-8")
    return path
