"""Archive inspection: ZIP, OOXML and tar.

Archives are the standard delivery wrapper, for three reasons that each need a
different check. They hide the payload's real type behind an innocuous outer
extension; they carry entry *paths* that the extractor obeys, so the archive can
choose where its contents land; and they expand, so a small file can exhaust a
disk. Nothing here is ever extracted -- entries are read through bounded
in-memory streams and discarded.
"""

from __future__ import annotations

import io
import posixpath
import tarfile
import zipfile

from .. import config
from ..entropy import shannon
from ..identify import (analyse_name, compare_type_and_name, detect_type,
                        final_extension)
from ..safeio import SafeFile
from ..verdict import Decision, Finding, Severity

#: Relationship types that make a document fetch and act on something remote.
REMOTE_RELATIONSHIPS = {
    "attachedTemplate": ("remote template injection", Severity.CRITICAL, "T1221"),
    "oleObject": ("remote OLE object", Severity.HIGH, "T1221"),
    "frame": ("remote frame", Severity.HIGH, "T1221"),
    "hyperlink": ("external hyperlink", Severity.INFO, ""),
    "image": ("external image (tracking pixel)", Severity.LOW, ""),
    "subDocument": ("remote subdocument", Severity.HIGH, "T1221"),
    "externalLink": ("external workbook link", Severity.MEDIUM, "T1221"),
}

MACRO_PARTS = ("vbaproject.bin", "vbadata.xml", "_vba_project")
_SAFE_SCHEMES = ("http://", "https://", "ftp://", "file://", "\\\\", "smb://", "mhtml:")


class ArchiveError(Exception):
    """Container could not be read. Fails the scan closed."""


def is_zip(head: bytes) -> bool:
    return head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def analyse_zip(sf: SafeFile, name: str, depth: int = 0, ruleset=None) -> list[Finding]:
    data = sf.read_all_bounded(min(config.MAX_PARSE_WINDOW, sf.readable_size))
    if len(data) < sf.readable_size:
        # zipfile needs the central directory at the end; a truncated read
        # cannot be parsed, and guessing is worse than saying so.
        return [Finding(
            id="ZIP_TOO_LARGE",
            title="Archive exceeds the deep-inspection limit",
            severity=Severity.LOW,
            category="coverage",
            detail=f"Only the first {len(data)} of {sf.readable_size} bytes were read, so "
                   "entry-level checks did not run. Treat the contents as unvetted.",
        )]
    return _analyse_zip_bytes(data, name, depth, ruleset)


def _analyse_zip_bytes(data: bytes, name: str, depth: int, ruleset=None) -> list[Finding]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        raise ArchiveError(f"unreadable ZIP container: {exc}") from exc

    findings: list[Finding] = []
    with zf:
        try:
            infos = zf.infolist()
        except Exception as exc:
            raise ArchiveError(f"unreadable central directory: {exc}") from exc

        if len(infos) > config.MAX_ARCHIVE_ENTRIES:
            findings.append(Finding(
                id="ZIP_ENTRY_FLOOD",
                title=f"Archive declares {len(infos)} entries",
                severity=Severity.MEDIUM,
                category="resource",
                detail=f"Above the {config.MAX_ARCHIVE_ENTRIES}-entry inspection limit; "
                       "only the first were examined.",
            ))
            infos = infos[:config.MAX_ARCHIVE_ENTRIES]

        names = [i.filename for i in infos]
        findings.extend(_check_entry_paths(infos))
        findings.extend(_check_compression_ratio(infos, len(data)))
        findings.extend(_check_encryption(infos, name))
        findings.extend(_check_entry_contents(zf, infos, depth, ruleset))
        if _is_ooxml(names):
            findings.extend(_analyse_ooxml(zf, infos, name))
    return findings


def _check_entry_paths(infos: list[zipfile.ZipInfo]) -> list[Finding]:
    """Zip-slip: an entry path that escapes the directory it extracts into."""
    escaping: list[str] = []
    absolute: list[str] = []
    for info in infos:
        raw = info.filename
        normalised = raw.replace("\\", "/")
        if normalised.startswith("/") or (len(raw) > 1 and raw[1] == ":"):
            absolute.append(raw)
            continue
        parts = [p for p in normalised.split("/") if p not in ("", ".")]
        depth = 0
        for part in parts:
            depth += -1 if part == ".." else 1
            if depth < 0:
                escaping.append(raw)
                break

    out: list[Finding] = []
    if escaping or absolute:
        out.append(Finding(
            id="ZIP_PATH_TRAVERSAL",
            title="Archive entries write outside the extraction directory",
            severity=Severity.CRITICAL,
            category="container",
            detail=("Entry paths containing '..' or an absolute root let the archive choose "
                    "where its contents land -- a startup folder, a cron directory, an "
                    "existing binary. Extractors that join paths naively obey it."),
            evidence=(escaping + absolute)[:10],
            attck="T1574",
            decisive=Decision.QUARANTINE,
        ))

    # Names inside the archive get the same masquerade analysis as the outer file.
    for info in infos[:256]:
        base = posixpath.basename(info.filename.replace("\\", "/"))
        if not base:
            continue
        for finding in analyse_name(base):
            if finding.id in ("NAME_BIDI_OVERRIDE", "NAME_INVISIBLE_CHARS",
                              "NAME_DOUBLE_EXTENSION", "NAME_MIXED_SCRIPT"):
                out.append(Finding(
                    id=f"ZIP_ENTRY_{finding.id}",
                    title=f"Archived entry: {finding.title.lower()}",
                    severity=finding.severity,
                    category="container",
                    detail=finding.detail,
                    evidence=[f"entry: {base}"] + finding.evidence,
                    attck=finding.attck,
                    decisive=finding.decisive,
                    layer=f"zip!{info.filename}",
                ))
    return out


def _check_compression_ratio(infos: list[zipfile.ZipInfo], container_size: int) -> list[Finding]:
    total_in = sum(max(i.compress_size, 0) for i in infos)
    total_out = sum(max(i.file_size, 0) for i in infos)
    if total_out == 0:
        return []
    ratio = total_out / max(total_in, 1)
    worst = max(infos, key=lambda i: i.file_size / max(i.compress_size, 1))
    worst_ratio = worst.file_size / max(worst.compress_size, 1)

    if (ratio > config.MAX_COMPRESSION_RATIO
            or total_out > config.MAX_ARCHIVE_TOTAL_UNCOMPRESSED
            or worst_ratio > config.MAX_COMPRESSION_RATIO * 5):
        return [Finding(
            id="ZIP_DECOMPRESSION_BOMB",
            title=f"Archive expands {ratio:.0f}x to {_human(total_out)}",
            severity=Severity.HIGH,
            category="resource",
            detail=("A compression ratio this high does not occur in archives of real "
                    "content. Extracting it fills the disk, which is either the point or "
                    "a way to knock out logging and scanning before the real payload runs."),
            evidence=[f"container: {_human(container_size)}",
                      f"expands to: {_human(total_out)}",
                      f"overall ratio: {ratio:.0f}:1",
                      f"worst entry: {worst.filename} at {worst_ratio:.0f}:1"],
            attck="T1499.003",
            decisive=Decision.QUARANTINE,
        )]
    return []


def _check_encryption(infos: list[zipfile.ZipInfo], name: str) -> list[Finding]:
    encrypted = [i.filename for i in infos if i.flag_bits & 0x1]
    if not encrypted:
        return []
    return [Finding(
        id="ZIP_ENCRYPTED_ENTRIES",
        title=f"{len(encrypted)} of {len(infos)} entries are password-protected",
        severity=Severity.HIGH,
        category="container",
        detail=("Encrypted entries cannot be inspected by anything -- this scanner, the "
                "mail gateway, or the endpoint agent. A password in the covering email "
                "is the standard way to deliver a payload through a filtering pipeline, "
                "and is the reason to treat the contents as unknown rather than clean."),
        evidence=encrypted[:10],
        attck="T1027.013",
    )]


def _check_entry_contents(zf: zipfile.ZipFile, infos: list[zipfile.ZipInfo],
                          depth: int, ruleset=None) -> list[Finding]:
    """Type each entry from its first bytes. Names inside archives lie as freely
    as names outside them."""
    findings: list[Finding] = []
    executables: list[str] = []
    scripts: list[str] = []
    nested: list[str] = []
    scanned = 0

    for info in infos:
        if info.is_dir() or scanned >= config.MAX_NESTED_SCANS:
            continue
        if info.file_size <= 0 or info.file_size > config.MAX_ARCHIVE_ENTRY_UNCOMPRESSED:
            continue
        if info.flag_bits & 0x1:
            continue  # encrypted; already reported
        want = min(config.MAX_NESTED_SCAN_BYTES, max(8192, info.file_size))
        try:
            with zf.open(info) as fh:
                head = fh.read(want)
        except (RuntimeError, zipfile.BadZipFile, OSError, ValueError, NotImplementedError):
            continue
        scanned += 1
        ft = detect_type(head, size=info.file_size)

        # Signature rules see inside the container too. An archive is the most
        # common way a payload reaches a machine without its bytes ever being
        # examined; decompressing each entry into memory is the point.
        if ruleset is not None:
            for hit in ruleset.scan(head, layer=f"zip!{info.filename}", kind=ft.kind):
                findings.append(Finding(
                    id=hit.id, title=f"{hit.title} (in {info.filename})",
                    severity=hit.severity, category=hit.category, detail=hit.detail,
                    evidence=[f"entry: {info.filename}"] + hit.evidence,
                    attck=hit.attck, decisive=hit.decisive, layer=f"zip!{info.filename}"))
        base = posixpath.basename(info.filename.replace("\\", "/"))

        if ft.is_executable:
            executables.append(f"{info.filename} ({ft.description})")
        elif ft.is_script:
            scripts.append(f"{info.filename} ({ft.description})")
        elif ft.kind in ("zip", "rar", "7z", "gzip", "bzip2", "xz", "tar"):
            nested.append(f"{info.filename} ({ft.description})")

        for mismatch in compare_type_and_name(ft, base):
            findings.append(Finding(
                id=f"ZIP_ENTRY_{mismatch.id}",
                title=f"Archived entry: {mismatch.title.lower()}",
                severity=mismatch.severity,
                category="container",
                detail=mismatch.detail,
                evidence=[f"entry: {info.filename}"] + mismatch.evidence,
                attck=mismatch.attck,
                decisive=mismatch.decisive,
                layer=f"zip!{info.filename}",
            ))

    if executables:
        hidden = [e for e in executables if "/." in e or e.startswith(".")]
        findings.append(Finding(
            id="ZIP_CONTAINS_EXECUTABLE",
            title=f"Archive contains {len(executables)} executable file(s)",
            severity=Severity.HIGH if hidden else Severity.MEDIUM,
            category="container",
            detail=("An executable inside an archive is how a payload crosses a boundary "
                    "that blocks executables directly. It also loses the mark-of-the-web "
                    "on extraction, so the operating system stops warning about it.")
                   + (" One or more are in hidden directories." if hidden else ""),
            evidence=executables[:10],
            attck="T1027.002" if hidden else "",
        ))
    if scripts:
        findings.append(Finding(
            id="ZIP_CONTAINS_SCRIPT",
            title=f"Archive contains {len(scripts)} script file(s)",
            severity=Severity.MEDIUM,
            category="container",
            evidence=scripts[:10],
            detail="Scripts execute through an interpreter that is already installed.",
        ))
    if nested and depth >= config.MAX_RECURSION_DEPTH - 1:
        findings.append(Finding(
            id="ZIP_NESTED_UNINSPECTED",
            title=f"{len(nested)} nested archive(s) beyond the recursion limit",
            severity=Severity.MEDIUM,
            category="coverage",
            detail="Nesting archives past the inspection depth is a deliberate way to "
                   "outlast a scanner. The contents were not examined.",
            evidence=nested[:10],
            attck="T1027.013",
        ))
    elif nested:
        findings.append(Finding(
            id="ZIP_NESTED_ARCHIVE",
            title=f"Archive contains {len(nested)} nested archive(s)",
            severity=Severity.LOW,
            category="container",
            evidence=nested[:10],
            detail="Layered containers; each layer sheds one round of inspection.",
        ))
    return findings


# --------------------------------------------------------------------------
# OOXML (docx / xlsx / pptx)
# --------------------------------------------------------------------------
def _is_ooxml(names: list[str]) -> bool:
    return "[Content_Types].xml" in names


def _analyse_ooxml(zf: zipfile.ZipFile, infos: list[zipfile.ZipInfo], name: str) -> list[Finding]:
    findings: list[Finding] = []
    names = [i.filename for i in infos]
    lowered = [n.lower() for n in names]
    ext = final_extension(name)

    # --- macros ------------------------------------------------------------
    macro_parts = [n for n, low in zip(names, lowered)
                   if any(part in low for part in MACRO_PARTS)]
    if macro_parts:
        # A .docx cannot legally hold a VBA project -- Word would refuse to open
        # it. The extension is therefore a lie about what the file is.
        misdeclared = ext in ("docx", "xlsx", "pptx", "dotx", "xltx", "potx")
        findings.append(Finding(
            id="OOXML_MACROS",
            title="Document contains a VBA macro project"
                  + (f" despite its .{ext} extension" if misdeclared else ""),
            severity=Severity.CRITICAL if misdeclared else Severity.HIGH,
            category="document",
            detail=("Macros are code that runs when the document is opened and the user "
                    "clicks Enable Content. ")
                   + ("A macro-free extension carrying a VBA project is a deliberate "
                      "mismatch: the extension is chosen to pass filters that block .docm."
                      if misdeclared else
                      "The extension correctly declares this, which is the honest case; "
                      "the risk is the user, not the naming."),
            evidence=macro_parts[:6],
            attck="T1566.001",
            decisive=Decision.QUARANTINE if misdeclared else None,
        ))

    # --- external relationships --------------------------------------------
    external: list[tuple[str, str, str]] = []
    for info in infos:
        if not info.filename.lower().endswith(".rels") or info.file_size > 1 << 20:
            continue
        try:
            with zf.open(info) as fh:
                blob = fh.read(1 << 20).decode("utf-8", "replace")
        except Exception:
            continue
        for chunk in blob.split("<Relationship")[1:]:
            if 'targetmode="external"' not in chunk.lower():
                continue
            rel_type = _attr(chunk, "Type").rsplit("/", 1)[-1]
            target = _attr(chunk, "Target")
            if target:
                external.append((rel_type, target, info.filename))

    grouped: dict[str, list[tuple[str, str]]] = {}
    for rel_type, target, source in external:
        grouped.setdefault(rel_type, []).append((target, source))

    for rel_type, entries in grouped.items():
        description, severity, attck = REMOTE_RELATIONSHIPS.get(
            rel_type, (f"external {rel_type} relationship", Severity.MEDIUM, "T1221"))
        remote = [t for t, _s in entries if t.lower().startswith(_SAFE_SCHEMES)]
        if not remote:
            continue
        if severity is Severity.INFO:
            continue
        findings.append(Finding(
            id=f"OOXML_EXTERNAL_{rel_type.upper()}",
            title=f"Document fetches a {description} on open",
            severity=severity,
            category="document",
            detail=("The payload is not in this file. Opening it makes Word or Excel "
                    "retrieve the target and act on it, which is how a document with no "
                    "macros and nothing detectable inside still runs code -- and how a "
                    "document harvests NTLM credentials from a UNC path."),
            evidence=[f"{rel_type} -> {t}" for t in remote[:6]],
            attck=attck,
            decisive=Decision.QUARANTINE if severity >= Severity.HIGH else None,
        ))

    # --- DDE and legacy execution vectors ----------------------------------
    for info in infos:
        low = info.filename.lower()
        if not (low.endswith("document.xml") or low.endswith("workbook.xml")) or info.file_size > 8 << 20:
            continue
        try:
            with zf.open(info) as fh:
                blob = fh.read(8 << 20).lower()
        except Exception:
            continue
        if b"ddeauto" in blob or (b"<w:fldsimple" in blob and b"dde" in blob):
            findings.append(Finding(
                id="OOXML_DDE_FIELD",
                title="Document contains a DDE field",
                severity=Severity.CRITICAL,
                category="document",
                detail="Dynamic Data Exchange fields execute a command without any macro "
                       "and without the macro warning.",
                evidence=[info.filename],
                attck="T1559.002",
                decisive=Decision.QUARANTINE,
            ))

    if any("xl/macrosheets/" in low or "macrosheet" in low for low in lowered):
        findings.append(Finding(
            id="OOXML_EXCEL4_MACROS",
            title="Workbook contains an Excel 4.0 macro sheet",
            severity=Severity.CRITICAL,
            category="document",
            detail="XLM (Excel 4.0) macros predate VBA, run with the same privileges, and "
                   "are handled by fewer defences.",
            evidence=[n for n, low in zip(names, lowered) if "macrosheet" in low][:5],
            attck="T1059.005",
            decisive=Decision.QUARANTINE,
        ))

    activex = [n for n, low in zip(names, lowered) if "activex" in low]
    if activex:
        findings.append(Finding(
            id="OOXML_ACTIVEX",
            title=f"Document embeds {len(activex)} ActiveX control(s)",
            severity=Severity.HIGH,
            category="document",
            detail="ActiveX controls instantiate COM objects on open.",
            evidence=activex[:6],
            attck="T1203",
        ))

    embedded = [n for n, low in zip(names, lowered)
                if "/embeddings/" in low or (low.endswith(".bin") and "vba" not in low)]
    if embedded:
        findings.append(Finding(
            id="OOXML_EMBEDDED_OBJECTS",
            title=f"Document embeds {len(embedded)} OLE object(s)",
            severity=Severity.MEDIUM,
            category="document",
            evidence=embedded[:6],
            detail="Embedded objects can be executables a user double-clicks inside the page.",
            attck="T1204.002",
        ))
    return findings


def _attr(chunk: str, key: str) -> str:
    marker = f'{key}="'
    idx = chunk.find(marker)
    if idx < 0:
        marker = f"{key}='"
        idx = chunk.find(marker)
        if idx < 0:
            return ""
        end = chunk.find("'", idx + len(marker))
    else:
        end = chunk.find('"', idx + len(marker))
    return chunk[idx + len(marker):end] if end > 0 else ""


# --------------------------------------------------------------------------
# tar
# --------------------------------------------------------------------------
def analyse_tar(sf: SafeFile, name: str) -> list[Finding]:
    data = sf.read_all_bounded(min(config.MAX_PARSE_WINDOW, sf.readable_size))
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ArchiveError(f"unreadable tar container: {exc}") from exc

    findings: list[Finding] = []
    escaping: list[str] = []
    links: list[str] = []
    specials: list[str] = []
    setuid: list[str] = []
    total = 0
    with tf:
        for i, member in enumerate(tf):
            if i >= config.MAX_ARCHIVE_ENTRIES:
                break
            total += max(member.size, 0)
            path = member.name.replace("\\", "/")
            if path.startswith("/") or any(p == ".." for p in path.split("/")):
                escaping.append(member.name)
            if member.issym() or member.islnk():
                target = member.linkname.replace("\\", "/")
                if target.startswith("/") or ".." in target.split("/"):
                    links.append(f"{member.name} -> {member.linkname}")
            if member.isdev() or member.ischr() or member.isblk() or member.isfifo():
                specials.append(member.name)
            if member.mode & 0o6000:
                setuid.append(f"{member.name} (mode {member.mode:o})")

    if escaping:
        findings.append(Finding(
            id="TAR_PATH_TRAVERSAL",
            title="Tar entries write outside the extraction directory",
            severity=Severity.CRITICAL, category="container",
            detail="Absolute or parent-relative member paths let the archive choose its "
                   "own destination.",
            evidence=escaping[:10], attck="T1574", decisive=Decision.QUARANTINE))
    if links:
        findings.append(Finding(
            id="TAR_ESCAPING_LINK",
            title="Tar contains links pointing outside the archive",
            severity=Severity.HIGH, category="container",
            detail="A symlink extracted first, then written through, is the standard way "
                   "to turn an unpack into an arbitrary file write.",
            evidence=links[:10], attck="T1574"))
    if setuid:
        findings.append(Finding(
            id="TAR_SETUID_MEMBER",
            title=f"Tar contains {len(setuid)} setuid/setgid file(s)",
            severity=Severity.HIGH, category="container",
            detail="Extracted as root, these become privilege-escalation primitives.",
            evidence=setuid[:10], attck="T1548.001"))
    if specials:
        findings.append(Finding(
            id="TAR_DEVICE_NODE",
            title=f"Tar contains {len(specials)} device or FIFO node(s)",
            severity=Severity.MEDIUM, category="container",
            detail="Device nodes in a distributed archive have no legitimate purpose.",
            evidence=specials[:10]))
    if total and total / max(sf.size, 1) > config.MAX_COMPRESSION_RATIO:
        findings.append(Finding(
            id="TAR_DECOMPRESSION_BOMB",
            title=f"Tar expands to {_human(total)}",
            severity=Severity.HIGH, category="resource",
            detail="Expansion ratio beyond anything real content produces.",
            evidence=[f"container: {_human(sf.size)}", f"expands to: {_human(total)}"],
            attck="T1499.003", decisive=Decision.QUARANTINE))
    return findings


def analyse_compressed_stream(sf: SafeFile, kind: str) -> list[Finding]:
    """gzip/bzip2/xz single streams: check the expansion ratio only."""
    head = sf.head(4096)
    entropy = shannon(head)
    if kind == "gzip" and len(head) > 10:
        # A gzip stream wrapping a tar is the common case; note it and move on.
        return [Finding(
            id="GZIP_STREAM", title="gzip-compressed stream", severity=Severity.INFO,
            category="container", detail=f"entropy {entropy:.2f} bits/byte; "
            "contents are inspected only if the stream is also a tar archive.")]
    return []


def _human(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n}"
