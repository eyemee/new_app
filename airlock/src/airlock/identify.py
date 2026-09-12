"""What a file actually is, versus what its name claims it is.

This module carries most of Airlock's value. The dominant way malware reaches a
desktop is not a novel exploit -- it is a file whose name says "invoice.pdf" and
whose first two bytes say ``MZ``. Content type is derived from magic bytes only;
the extension is treated as an untrusted assertion by whoever sent the file, and
the gap between the two is a finding.
"""

from __future__ import annotations

import posixpath
import re
import unicodedata
from dataclasses import dataclass, field

from .entropy import looks_textual
from .verdict import Decision, Finding, Severity

# --------------------------------------------------------------------------
# Content classes
# --------------------------------------------------------------------------
#: Types that can execute directly, given only a double click.
EXECUTABLE_TYPES = {
    "pe", "pe-dll", "elf", "macho", "macho-fat", "java-class", "dex",
    "lnk", "msi", "cab-installer", "dos-mz",
}
#: Types that execute through an interpreter.
SCRIPT_TYPES = {"script", "powershell", "vbscript", "jscript", "batch", "shell",
                "python", "perl", "ruby", "php", "hta", "wsf"}
#: Types a user reasonably believes are inert content.
DOCUMENT_TYPES = {"pdf", "ooxml", "ole2", "rtf", "text", "html", "xml", "json",
                  "image", "audio", "video", "csv"}
ARCHIVE_TYPES = {"zip", "tar", "gzip", "bzip2", "xz", "rar", "7z", "cab", "iso",
                 "ooxml", "jar", "apk"}

#: Extensions Windows, macOS or a desktop environment will execute or interpret.
DANGEROUS_EXTENSIONS = {
    # Windows native
    "exe", "com", "scr", "pif", "cpl", "msi", "msp", "msc", "dll", "sys", "drv",
    "ocx", "efi", "scf", "lnk", "url", "inf", "reg", "job", "appref-ms", "appx",
    "msix", "gadget", "library-ms", "diagcab", "settingcontent-ms",
    # Script hosts
    "bat", "cmd", "ps1", "ps1xml", "psm1", "psd1", "vb", "vbs", "vbe", "js",
    "jse", "wsf", "wsh", "wsc", "hta", "chm", "jar", "class", "py", "pyw",
    "pyc", "rb", "pl", "php", "sh", "bash", "zsh", "csh", "ksh", "run",
    # Mac / Linux packages
    "app", "dmg", "pkg", "command", "workflow", "action", "deb", "rpm",
    "appimage", "snap", "flatpakref", "desktop",
    # Macro-enabled Office
    "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm",
    # Disk images that mount and autorun
    "iso", "img", "vhd", "vhdx", "udf",
    # Android
    "apk", "dex",
}

#: Extensions a user reads as "safe to open".
BENIGN_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp",
    "txt", "rtf", "csv", "md", "log", "json", "xml", "yaml", "yml",
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "svg", "ico", "tif", "tiff",
    "mp3", "mp4", "wav", "avi", "mov", "mkv", "flac", "m4a", "webm",
    "htm", "html", "eml", "msg", "ics", "vcf",
}

#: Unicode that rewrites how a filename renders without changing what it is.
BIDI_CONTROLS = {
    "‪": "LEFT-TO-RIGHT EMBEDDING",
    "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‬": "POP DIRECTIONAL FORMATTING",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE",
    "⁨": "FIRST STRONG ISOLATE",
    "⁩": "POP DIRECTIONAL ISOLATE",
    "؜": "ARABIC LETTER MARK",
    "‎": "LEFT-TO-RIGHT MARK",
    "‏": "RIGHT-TO-LEFT MARK",
}
INVISIBLE_CHARS = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE",
    "­": "SOFT HYPHEN",
    "ㅤ": "HANGUL FILLER",
}

WINDOWS_RESERVED = {"con", "prn", "aux", "nul", "clock$"} | {
    f"{stem}{n}" for stem in ("com", "lpt") for n in range(1, 10)
}


@dataclass
class FileType:
    kind: str = "unknown"
    description: str = "unrecognised"
    extensions: tuple[str, ...] = ()
    confidence: str = "low"
    details: dict[str, object] = field(default_factory=dict)

    @property
    def is_executable(self) -> bool:
        return self.kind in EXECUTABLE_TYPES

    @property
    def is_script(self) -> bool:
        return self.kind in SCRIPT_TYPES


# --------------------------------------------------------------------------
# Magic byte table
# --------------------------------------------------------------------------
# (offset, signature, kind, description, plausible extensions)
_MAGIC: list[tuple[int, bytes, str, str, tuple[str, ...]]] = [
    (0, b"\x7fELF", "elf", "ELF executable / shared object", ("", "so", "elf", "bin", "o", "ko", "run", "appimage")),
    (0, b"\xca\xfe\xba\xbe", "macho-fat", "Mach-O universal binary", ("", "dylib", "bundle", "o")),
    (0, b"\xcf\xfa\xed\xfe", "macho", "Mach-O 64-bit executable", ("", "dylib", "bundle", "o")),
    (0, b"\xce\xfa\xed\xfe", "macho", "Mach-O 32-bit executable", ("", "dylib", "bundle", "o")),
    (0, b"\xfe\xed\xfa\xcf", "macho", "Mach-O 64-bit executable (big endian)", ("", "dylib", "bundle")),
    (0, b"\xfe\xed\xfa\xce", "macho", "Mach-O 32-bit executable (big endian)", ("", "dylib", "bundle")),
    (0, b"dex\n", "dex", "Android DEX bytecode", ("dex",)),
    (0, b"PK\x03\x04", "zip", "ZIP archive", ("zip", "docx", "xlsx", "pptx", "jar", "apk", "odt", "ods", "epub", "ipa", "whl", "xpi", "vsix", "nupkg")),
    (0, b"PK\x05\x06", "zip", "ZIP archive (empty)", ("zip",)),
    (0, b"PK\x07\x08", "zip", "ZIP archive (spanned)", ("zip",)),
    (0, b"Rar!\x1a\x07", "rar", "RAR archive", ("rar",)),
    (0, b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive", ("7z",)),
    (0, b"\x1f\x8b", "gzip", "gzip stream", ("gz", "tgz", "gzip", "svgz")),
    (0, b"BZh", "bzip2", "bzip2 stream", ("bz2", "tbz2")),
    (0, b"\xfd7zXZ\x00", "xz", "XZ stream", ("xz", "txz")),
    (0, b"\x04\x22\x4d\x18", "lz4", "LZ4 stream", ("lz4",)),
    (0, b"\x28\xb5\x2f\xfd", "zstd", "Zstandard stream", ("zst",)),
    (0, b"MSCF", "cab", "Microsoft Cabinet", ("cab",)),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2", "OLE2 compound document", ("doc", "xls", "ppt", "msi", "msg", "vsd", "db")),
    (0, b"%PDF", "pdf", "PDF document", ("pdf",)),
    (0, b"{\\rtf", "rtf", "Rich Text Format", ("rtf", "doc")),
    (0, b"\x4c\x00\x00\x00\x01\x14\x02\x00", "lnk", "Windows shortcut (.lnk)", ("lnk",)),
    (0, b"\xca\xfe\xba\xbe\x00\x00\x00", "java-class", "Java class file", ("class",)),
    (0, b"\x89PNG\r\n\x1a\n", "image", "PNG image", ("png",)),
    (0, b"\xff\xd8\xff", "image", "JPEG image", ("jpg", "jpeg", "jpe")),
    (0, b"GIF87a", "image", "GIF image", ("gif",)),
    (0, b"GIF89a", "image", "GIF image", ("gif",)),
    (0, b"BM", "image", "BMP image", ("bmp", "dib")),
    (0, b"\x00\x00\x01\x00", "image", "Windows icon", ("ico", "cur")),
    (0, b"II*\x00", "image", "TIFF image", ("tif", "tiff")),
    (0, b"MM\x00*", "image", "TIFF image", ("tif", "tiff")),
    (0, b"ID3", "audio", "MP3 audio", ("mp3",)),
    (0, b"OggS", "audio", "Ogg container", ("ogg", "oga", "ogv", "opus")),
    (0, b"fLaC", "audio", "FLAC audio", ("flac",)),
    (0, b"ITSF", "chm", "Compiled HTML Help", ("chm",)),
    (0, b"!<arch>", "ar", "ar archive", ("a", "deb", "lib")),
    (0, b"\xed\xab\xee\xdb", "rpm", "RPM package", ("rpm",)),
    (0, b"SQLite format 3\x00", "sqlite", "SQLite database", ("db", "sqlite", "sqlite3")),
    (0, b"\x25\x21\x50\x53", "postscript", "PostScript", ("ps", "eps")),
    (0, b"\x38\x42\x50\x53", "image", "Photoshop document", ("psd",)),
    (0, b"wOFF", "font", "WOFF font", ("woff",)),
    (0, b"\x00\x01\x00\x00\x00", "font", "TrueType font", ("ttf",)),
    (0, b"OTTO", "font", "OpenType font", ("otf",)),
    (4, b"ftyp", "video", "ISO base media (MP4/MOV)", ("mp4", "m4a", "m4v", "mov", "3gp", "heic")),
    (8, b"WAVE", "audio", "WAV audio", ("wav",)),
    (8, b"AVI ", "video", "AVI video", ("avi",)),
    (257, b"ustar", "tar", "tar archive", ("tar", "tgz")),
    (0, b"\x1aE\xdf\xa3", "video", "Matroska / WebM", ("mkv", "webm", "mka")),
    (32769, b"CD001", "iso", "ISO 9660 disk image", ("iso",)),
]

#: Shebangs mapped to the interpreter that would run the file.
_SHEBANGS: list[tuple[re.Pattern[bytes], str, str]] = [
    (re.compile(rb"^#!.*\b(?:ba|z|k|a|c)?sh\b"), "shell", "shell script"),
    (re.compile(rb"^#!.*\bpython[\d.]*\b"), "python", "Python script"),
    (re.compile(rb"^#!.*\bperl\b"), "perl", "Perl script"),
    (re.compile(rb"^#!.*\bruby\b"), "ruby", "Ruby script"),
    (re.compile(rb"^#!.*\bnode\b"), "script", "Node.js script"),
    (re.compile(rb"^#!.*\bphp\b"), "php", "PHP script"),
    (re.compile(rb"^#!.*\bpwsh\b"), "powershell", "PowerShell script"),
    (re.compile(rb"^#!"), "script", "script with shebang"),
]

#: Textual formats with no magic number, recognised by leading content.
_TEXT_HINTS: list[tuple[re.Pattern[bytes], str, str, tuple[str, ...]]] = [
    (re.compile(rb"^\s*<\?xml", re.I), "xml", "XML document", ("xml", "svg", "xsl", "rels", "plist")),
    (re.compile(rb"^\s*<(?:!doctype\s+html|html|head|body)\b", re.I), "html", "HTML document", ("htm", "html", "hta", "xhtml")),
    (re.compile(rb"^\s*<svg\b", re.I), "xml", "SVG image", ("svg",)),
    (re.compile(rb"^\s*[{\[]"), "json", "JSON / JSON-like text", ("json", "jsonl", "geojson", "webmanifest", "map")),
    (re.compile(rb"^\s*(?:@echo\s+off|rem\s)", re.I), "batch", "Windows batch script", ("bat", "cmd")),
    (re.compile(rb"^MIME-Version:|^Received:|^From:\s", re.I), "email", "RFC 822 message", ("eml", "mbox")),
    (re.compile(rb"^-----BEGIN [A-Z ]+-----"), "pem", "PEM encoded data", ("pem", "crt", "key", "csr")),
]

#: Content-level hints for interpreted languages with no shebang.
_SCRIPT_HINTS: list[tuple[re.Pattern[bytes], str, str, tuple[str, ...]]] = [
    (re.compile(rb"(?:^|\n)\s*(?:function\s+[\w-]+\s*\{|param\s*\(|\$\w+\s*=\s*|Write-Host|Import-Module)", re.I),
     "powershell", "PowerShell script", ("ps1", "psm1", "psd1")),
    (re.compile(rb"(?:^|\n)\s*(?:Set\s+\w+\s*=\s*CreateObject|WScript\.|Dim\s+\w+|Sub\s+\w+\s*\(\))", re.I),
     "vbscript", "VBScript", ("vbs", "vbe", "vb")),
    (re.compile(rb"(?:^|\n)\s*(?:var\s+\w+\s*=|function\s*\w*\s*\(|new\s+ActiveXObject)", ),
     "jscript", "JScript / JavaScript", ("js", "jse", "mjs")),
]


def _ext_chain(name: str) -> list[str]:
    """Every extension in a name, outermost last: a.tar.gz -> ['tar','gz']."""
    base = posixpath.basename(name.replace("\\", "/"))
    # A leading dot is a hidden-file marker, not an extension.
    parts = base.lstrip(".").split(".")
    return [p.lower() for p in parts[1:] if p] if len(parts) > 1 else []


def final_extension(name: str) -> str:
    chain = _ext_chain(name)
    return chain[-1] if chain else ""


def detect_type(head: bytes, tail: bytes = b"", size: int = 0,
                probe_at: "callable | None" = None) -> FileType:
    """Identify content from bytes alone. The filename is never consulted."""
    for offset, sig, kind, desc, exts in _MAGIC:
        if offset == 0:
            window = head
        elif offset + len(sig) <= len(head):
            window = head
        elif probe_at is not None:
            window = b"\x00" * offset + probe_at(offset, len(sig))
        else:
            continue
        if len(window) >= offset + len(sig) and window[offset:offset + len(sig)] == sig:
            if kind == "zip":
                return FileType(kind, desc, exts, "high")
            return FileType(kind, desc, exts, "high")

    # MZ needs more than the two magic bytes: a real PE has a valid e_lfanew
    # pointing at a "PE\0\0" signature. DOS-era .com droppers and corrupt files
    # have the MZ without the rest, which is itself worth knowing.
    if head[:2] == b"MZ":
        e_lfanew = int.from_bytes(head[0x3C:0x40], "little") if len(head) >= 0x40 else 0
        pe_sig = b""
        if 0 < e_lfanew and e_lfanew + 4 <= len(head):
            pe_sig = head[e_lfanew:e_lfanew + 4]
        elif probe_at is not None and 0 < e_lfanew < size:
            pe_sig = probe_at(e_lfanew, 4)
        if pe_sig == b"PE\x00\x00":
            return FileType("pe", "Windows PE executable",
                            ("exe", "dll", "sys", "scr", "cpl", "ocx", "efi", "mui", "node"), "high")
        return FileType("dos-mz", "DOS MZ executable (no PE header)", ("exe", "com"), "medium")

    for pattern, kind, desc in _SHEBANGS:
        if pattern.search(head[:256]):
            return FileType(kind, desc, ("sh", "bash", "py", "pl", "rb", "js", ""), "high")

    if not head:
        return FileType("empty", "empty file", (), "high")

    if looks_textual(head):
        stripped = head.lstrip()
        for pattern, kind, desc, exts in _TEXT_HINTS:
            if pattern.search(stripped[:512]):
                return FileType(kind, desc, exts, "medium")
        for pattern, kind, desc, exts in _SCRIPT_HINTS:
            if pattern.search(head[:4096]):
                return FileType(kind, desc, exts, "low")
        return FileType("text", "plain text", ("txt", "md", "log", "csv", "ini", "cfg", "conf"), "low")

    return FileType("unknown", "unrecognised binary data", (), "low")


# --------------------------------------------------------------------------
# Filename analysis
# --------------------------------------------------------------------------
def _script_set(char: str) -> str:
    """Coarse script name for a letter, used for confusable detection."""
    try:
        name = unicodedata.name(char)
    except ValueError:
        return "OTHER"
    for script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC",
                   "CHEROKEE", "HAN", "HIRAGANA", "KATAKANA", "HANGUL"):
        if name.startswith(script):
            return script
    return "OTHER"


def analyse_name(name: str) -> list[Finding]:
    """Findings derived from the filename alone.

    Everything here is about the gap between what a name *renders as* and what
    the operating system *does with it*.
    """
    findings: list[Finding] = []
    base = posixpath.basename(name.replace("\\", "/"))
    chain = _ext_chain(base)
    final = chain[-1] if chain else ""

    # --- bidirectional override -------------------------------------------
    present = {ch: desc for ch, desc in BIDI_CONTROLS.items() if ch in base}
    if present:
        # RLO is the classic: "annexe‮gnp.exe" renders as "annexeexe.png".
        rendered = _render_bidi(base)
        findings.append(Finding(
            id="NAME_BIDI_OVERRIDE",
            title="Filename contains a bidirectional text override",
            severity=Severity.CRITICAL,
            category="masquerade",
            detail=("The name contains Unicode direction controls, which reverse how part "
                    "of it is drawn. The operating system uses the real byte order, so the "
                    "extension that runs is not the extension you see."),
            evidence=[f"{desc} (U+{ord(ch):04X})" for ch, desc in present.items()]
                     + [f"renders as: {rendered}", f"actually is: {_escape_controls(base)}"],
            attck="T1036.002",
            decisive=Decision.QUARANTINE,
        ))

    # --- invisible characters ---------------------------------------------
    invisible = {ch: desc for ch, desc in INVISIBLE_CHARS.items() if ch in base}
    if invisible:
        findings.append(Finding(
            id="NAME_INVISIBLE_CHARS",
            title="Filename contains zero-width or invisible characters",
            severity=Severity.HIGH,
            category="masquerade",
            detail="Invisible code points let two different files render identically.",
            evidence=[f"{desc} (U+{ord(ch):04X})" for ch, desc in invisible.items()],
            attck="T1036",
        ))

    # --- mixed scripts (homoglyphs) ---------------------------------------
    # Compared per word, not across the whole name. A Russian document called
    # "отчет.pdf" mixes Cyrillic and Latin at whole-name level and is completely
    # ordinary; a homoglyph attack substitutes one letter *inside* a word, so
    # "Аdobe" is Cyrillic-plus-Latin in a single token and "отчет" is not.
    for token in re.split(r"[^\w]+", base, flags=re.UNICODE):
        letters = [c for c in token if c.isalpha()]
        scripts = {s for s in (_script_set(c) for c in letters) if s != "OTHER"}
        if len(scripts) <= 1 or "LATIN" not in scripts:
            continue
        confusables = [f"U+{ord(c):04X} {c!r}" for c in letters
                       if _script_set(c) not in ("LATIN", "OTHER")]
        findings.append(Finding(
            id="NAME_MIXED_SCRIPT",
            title="Filename mixes writing systems within one word (homoglyph spoofing)",
            severity=Severity.HIGH,
            category="masquerade",
            detail=(f"The word {token!r} draws on {', '.join(sorted(scripts))}. Non-Latin "
                    "letters that render identically to Latin ones are how a fake 'Аdobe' "
                    "passes for 'Adobe'."),
            evidence=[f"word: {token}"] + confusables[:12],
            attck="T1036.003",
        ))
        break

    # --- double extension --------------------------------------------------
    if len(chain) >= 2 and final in DANGEROUS_EXTENSIONS:
        inner = chain[-2]
        if inner in BENIGN_EXTENSIONS:
            findings.append(Finding(
                id="NAME_DOUBLE_EXTENSION",
                title=f"Double extension: .{inner} inside a .{final}",
                severity=Severity.HIGH,
                category="masquerade",
                detail=("The name is built to read as a document while ending in an "
                        "executable extension. Windows hides known extensions by default, "
                        "so this commonly renders with the real one removed."),
                evidence=[f"name: {_escape_controls(base)}",
                          f"renders on Windows as: {base[:base.rfind('.')] if '.' in base else base}"],
                attck="T1036.007",
            ))

    # --- trailing dots and spaces -----------------------------------------
    if base != base.rstrip(" .") and base.rstrip(" ."):
        findings.append(Finding(
            id="NAME_TRAILING_PADDING",
            title="Filename ends in spaces or dots",
            severity=Severity.MEDIUM,
            category="masquerade",
            detail="Windows silently strips trailing spaces and dots, so the stored name "
                   "differs from the one shown and from the one a policy check matched on.",
            evidence=[repr(base)],
            attck="T1036",
        ))

    # --- long name padding -------------------------------------------------
    if len(base) > 120:
        findings.append(Finding(
            id="NAME_EXCESSIVE_LENGTH",
            title=f"Filename is {len(base)} characters long",
            severity=Severity.MEDIUM if final in DANGEROUS_EXTENSIONS else Severity.LOW,
            category="masquerade",
            detail="Overlong names push the real extension past the edge of the column in "
                   "file managers and mail clients.",
            evidence=[_escape_controls(base[:80]) + "..."],
        ))

    # --- reserved device names --------------------------------------------
    stem = base.split(".")[0].strip().lower()
    if stem in WINDOWS_RESERVED:
        findings.append(Finding(
            id="NAME_RESERVED_DEVICE",
            title=f"Filename uses the reserved Windows device name {stem.upper()}",
            severity=Severity.MEDIUM,
            category="masquerade",
            detail="Reserved device names behave unpredictably and are used to break "
                   "naive extraction and cleanup tooling.",
            evidence=[base],
        ))

    # --- path traversal in the supplied name -------------------------------
    if ".." in base or "/" in name or "\\" in name:
        if ".." in name.replace("\\", "/").split("/"):
            findings.append(Finding(
                id="NAME_PATH_TRAVERSAL",
                title="Name contains a parent-directory reference",
                severity=Severity.HIGH,
                category="masquerade",
                detail="A name carrying '..' escapes the directory it was meant to land in.",
                evidence=[name],
                attck="T1574",
            ))
    return findings


def compare_type_and_name(ft: FileType, name: str) -> list[Finding]:
    """The core masquerade check: does the content match the claimed extension?"""
    findings: list[Finding] = []
    final = final_extension(name)
    if not final:
        return findings
    if not ft.extensions or ft.confidence == "low":
        return findings
    if final in ft.extensions:
        return findings

    dangerous_content = ft.is_executable or ft.is_script
    benign_claim = final in BENIGN_EXTENSIONS

    if dangerous_content and benign_claim:
        findings.append(Finding(
            id="TYPE_EXECUTABLE_MASQUERADE",
            title=f"Executable content named as a .{final} file",
            severity=Severity.CRITICAL,
            category="masquerade",
            detail=(f"The bytes are {ft.description}, but the name claims .{final}, which "
                    "a user opens without thinking. This mismatch has no innocent cause."),
            evidence=[f"claimed: .{final}", f"actual: {ft.description}",
                      f"plausible extensions: {', '.join(e for e in ft.extensions if e) or 'none'}"],
            attck="T1036.008",
            decisive=Decision.QUARANTINE,
        ))
    elif dangerous_content:
        findings.append(Finding(
            id="TYPE_EXTENSION_MISMATCH",
            title=f"Executable content with an unexpected .{final} extension",
            severity=Severity.MEDIUM,
            category="masquerade",
            detail=f"Content is {ft.description}; .{final} is not an extension it normally carries.",
            evidence=[f"claimed: .{final}", f"actual: {ft.description}"],
        ))
    elif final in DANGEROUS_EXTENSIONS and ft.kind in DOCUMENT_TYPES:
        findings.append(Finding(
            id="TYPE_INERT_WITH_DANGEROUS_EXTENSION",
            title=f"Inert content carrying the executable extension .{final}",
            severity=Severity.LOW,
            category="anomaly",
            detail=f"Content looks like {ft.description} but the name would have the system "
                   "try to run it.",
            evidence=[f"claimed: .{final}", f"actual: {ft.description}"],
        ))
    return findings


def dangerous_extension_finding(name: str, ft: FileType) -> Finding | None:
    """Note that a file is directly runnable. Context, not an accusation."""
    final = final_extension(name)
    if final not in DANGEROUS_EXTENSIONS and not (ft.is_executable or ft.is_script):
        return None
    return Finding(
        id="TYPE_DIRECTLY_EXECUTABLE",
        title="File can execute code when opened",
        severity=Severity.LOW,
        category="capability",
        detail=f"{ft.description}"
               + (f" with a .{final} extension" if final else "")
               + ". Treat as software, not as content.",
        evidence=[f"type: {ft.kind}"] + ([f"extension: .{final}"] if final else []),
        weight=3,
    )


def _render_bidi(name: str) -> str:
    """Approximate how a bidi-override name draws, so the report can show both."""
    out: list[str] = []
    buffer: list[str] = []
    reversing = False
    for ch in name:
        if ch in ("‮", "‫", "⁧"):
            reversing = True
            continue
        if ch in ("‬", "⁩", "‭", "‪", "⁦"):
            if reversing:
                out.append("".join(reversed(buffer)))
                buffer = []
                reversing = False
            continue
        (buffer if reversing else out).append(ch)
    if buffer:
        out.append("".join(reversed(buffer)))
    return "".join(out)


def _escape_controls(text: str) -> str:
    return "".join(
        ch if ch.isprintable() and ch not in BIDI_CONTROLS and ch not in INVISIBLE_CHARS
        else f"\\u{ord(ch):04x}"
        for ch in text
    )
