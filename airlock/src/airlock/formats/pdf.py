"""PDF analysis.

A PDF is a container with a scripting engine, an auto-run hook and an embedded
file system. The checks here look for those three, and for the name-obfuscation
that is used to hide them: PDF names may encode any character as ``#xx``, so
``/JavaScript`` and ``/#4A#61vaScript`` are the same token to a reader and
different strings to a naive scanner. Names are normalised before matching.
"""

from __future__ import annotations

import re

from .. import config
from ..safeio import SafeFile
from ..strings import extract_iocs
from ..verdict import Finding, Severity

_HEX_NAME = re.compile(rb"#([0-9A-Fa-f]{2})")

#: (normalised token, id, title, severity, ATT&CK, detail)
MARKERS: list[tuple[bytes, str, str, Severity, str, str]] = [
    (b"/javascript", "PDF_JAVASCRIPT", "Contains JavaScript", Severity.HIGH, "T1059.007",
     "PDF JavaScript has been the delivery vehicle for most reader exploits. A "
     "document that only needs to be read does not need a scripting engine."),
    (b"/js", "PDF_JS_ABBREV", "Contains a /JS action", Severity.HIGH, "T1059.007",
     "The abbreviated form of a JavaScript action."),
    (b"/openaction", "PDF_OPENACTION", "Runs an action when opened", Severity.HIGH, "T1203",
     "An OpenAction fires on open, with no click and no prompt."),
    (b"/aa", "PDF_ADDITIONAL_ACTIONS", "Has additional (event-triggered) actions",
     Severity.MEDIUM, "T1203", "Actions bound to page or field events."),
    (b"/launch", "PDF_LAUNCH_ACTION", "Contains a /Launch action", Severity.CRITICAL, "T1204.002",
     "A Launch action asks the reader to run an external program. There is no "
     "legitimate use of this in a document sent to you."),
    (b"/embeddedfile", "PDF_EMBEDDED_FILE", "Carries an embedded file", Severity.HIGH, "T1027.009",
     "An embedded file rides inside the document and is extracted on click, past "
     "any gateway that inspected only the outer type."),
    (b"/richmedia", "PDF_RICHMEDIA", "Contains RichMedia (Flash/3D) content",
     Severity.HIGH, "T1203", "RichMedia annotations embed a player with its own "
     "exploit history."),
    (b"/xfa", "PDF_XFA_FORM", "Contains an XFA form", Severity.MEDIUM, "T1203",
     "XFA is a second, scriptable document format inside the PDF."),
    (b"/submitform", "PDF_SUBMITFORM", "Submits form data to a remote endpoint",
     Severity.MEDIUM, "T1041", "Form submission exfiltrates whatever the user types."),
    (b"/gotoe", "PDF_GOTOE", "Contains a GoToE (embedded-file jump) action",
     Severity.HIGH, "T1204.002", "Navigates into an embedded file, a known reader-sandbox bypass."),
    (b"/objstm", "PDF_OBJECT_STREAMS", "Uses object streams", Severity.LOW, "T1027",
     "Object streams compress objects out of plain sight; legitimate, but they are "
     "also how markers are hidden from simple scanners."),
    (b"/encrypt", "PDF_ENCRYPTED", "Document is encrypted", Severity.MEDIUM, "T1027.013",
     "Encrypted contents cannot be inspected. Treat as unvetted."),
]


def _normalise(data: bytes) -> bytes:
    """Resolve ``#xx`` escapes and lowercase, so evasive spellings collapse."""
    def sub(match: re.Match[bytes]) -> bytes:
        try:
            return bytes([int(match.group(1), 16)])
        except ValueError:
            return match.group(0)
    return _HEX_NAME.sub(sub, data).lower()


def analyse(sf: SafeFile, name: str) -> list[Finding]:
    raw = sf.read_at(0, min(sf.readable_size, config.MAX_REGEX_WINDOW))
    data = _normalise(raw)
    findings: list[Finding] = []

    evasive = raw.count(b"#") > 0 and _HEX_NAME.search(raw) is not None
    hits: list[str] = []
    for token, fid, title, severity, attck, detail in MARKERS:
        if token not in data:
            continue
        # /js matches inside /javascript; only report it standing alone.
        if token == b"/js" and b"/javascript" in data:
            continue
        hits.append(fid)
        findings.append(Finding(
            id=fid, title=title, severity=severity, category="document",
            detail=detail, attck=attck,
            evidence=[f"marker: {token.decode()}", f"occurrences: {data.count(token)}"],
        ))

    if evasive and any(h in hits for h in ("PDF_JAVASCRIPT", "PDF_JS_ABBREV", "PDF_OPENACTION",
                                           "PDF_LAUNCH_ACTION")):
        findings.append(Finding(
            id="PDF_NAME_OBFUSCATION",
            title="Action names are hex-escaped to evade string matching",
            severity=Severity.HIGH,
            category="obfuscation",
            detail="PDF name objects may encode characters as #xx. Writing /JavaScript as "
                   "/#4Aavascript changes nothing for the reader and everything for a "
                   "scanner matching on literals. Doing this to an action name is not an "
                   "accident of a generator.",
            evidence=[m.group(0).decode("latin-1") for m in _HEX_NAME.finditer(raw)][:8],
            attck="T1027",
        ))

    # Auto-running script is the combination that matters, not either alone.
    if ("PDF_OPENACTION" in hits or "PDF_ADDITIONAL_ACTIONS" in hits) and \
            ("PDF_JAVASCRIPT" in hits or "PDF_JS_ABBREV" in hits):
        findings.append(Finding(
            id="PDF_AUTORUN_SCRIPT",
            title="JavaScript runs automatically when the document opens",
            severity=Severity.CRITICAL,
            category="document",
            detail="Script plus an open-trigger means code executes on preview, before the "
                   "reader has decided to trust the document.",
            evidence=["/OpenAction or /AA combined with /JavaScript"],
            attck="T1203",
        ))

    if b"%pdf" in data[:1024] and b"mz" in data[:2048][:2]:
        findings.append(Finding(
            id="PDF_POLYGLOT", title="File is valid as both a PDF and an executable",
            severity=Severity.CRITICAL, category="masquerade",
            detail="Polyglot files are interpreted differently by the gateway that scanned "
                   "them and the program that opens them.",
            evidence=["header carries both signatures"], attck="T1027.009"))

    iocs = extract_iocs(raw)
    if iocs["urls"]:
        findings.append(Finding(
            id="PDF_EXTERNAL_URLS",
            title=f"References {len(iocs['urls'])} external URL(s)",
            severity=Severity.INFO if len(iocs["urls"]) <= 3 else Severity.LOW,
            category="network", evidence=iocs["urls"][:10],
            detail="Links and remote resources referenced by the document."))
    return findings
