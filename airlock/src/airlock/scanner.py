"""The scan orchestrator.

Order matters and is deliberate:

1. Open the file safely and pin the descriptor. Everything after this works on
   that one descriptor, so the file cannot change under the scan.
2. Hash it. Identity first, because reputation is the cheapest decisive answer.
3. Identify the content from bytes, then compare that against the name. The
   masquerade check needs both and is the highest-yield check in the tool.
4. Run the format analyser for whatever it actually is -- not for what it claims.
5. Run signature rules over the raw bytes.
6. Apply the policy profile, which can escalate but never silently downgrade.

Every stage is wrapped: a parser that raises records an error finding and the
verdict fails closed to QUARANTINE, because a file we could not finish reading
is not a file we can vouch for.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from . import __version__, config, reputation
from .formats import archive, elf, pdf, script
from .formats import pe as pe_mod
from .identify import (compare_type_and_name, dangerous_extension_finding,
                       detect_type, analyse_name)
from .rules import RuleSet
from .safeio import SafeFile, UnsafeFile
from .verdict import Decision, Finding, Report, Severity


class ScanTimeout(Exception):
    pass


@dataclass
class Policy:
    """How strict the gate is. Profiles escalate; they never hide a finding."""

    name: str = "standard"
    #: Severity at or above which a single finding forces a block.
    block_at: Severity = Severity.CRITICAL
    #: Extra score added for any directly-executable file.
    executable_surcharge: int = 0
    #: Treat macro documents and unsigned executables as blocking.
    block_macros: bool = False
    block_unsigned_executables: bool = False
    #: Block anything whose contents could not be fully inspected.
    block_uninspectable: bool = False

    @classmethod
    def named(cls, name: str) -> "Policy":
        name = (name or "standard").lower()
        if name == "permissive":
            return cls(name="permissive", block_at=Severity.CRITICAL)
        if name == "strict":
            return cls(name="strict", block_at=Severity.HIGH,
                       executable_surcharge=10, block_macros=True,
                       block_uninspectable=True)
        if name == "paranoid":
            return cls(name="paranoid", block_at=Severity.HIGH,
                       executable_surcharge=25, block_macros=True,
                       block_unsigned_executables=True, block_uninspectable=True)
        if name != "standard":
            raise ValueError(f"unknown policy profile {name!r} "
                             "(permissive, standard, strict, paranoid)")
        return cls()


PROFILES = ("permissive", "standard", "strict", "paranoid")

#: Findings that mean "we could not see inside this".
UNINSPECTABLE = {"ZIP_ENCRYPTED_ENTRIES", "ZIP_TOO_LARGE", "PDF_ENCRYPTED",
                 "ZIP_NESTED_UNINSPECTED", "SCAN_TRUNCATED"}


class Scanner:
    def __init__(self, ruleset: RuleSet | None = None,
                 database: reputation.Database | None = None,
                 pins: dict | None = None,
                 policy: Policy | None = None,
                 online_key: str = "",
                 timeout: float = config.SCAN_TIMEOUT_SECONDS):
        self.ruleset = ruleset or RuleSet()
        self.database = database if database is not None else reputation.Database()
        self.pins = pins if pins is not None else {}
        self.policy = policy or Policy()
        self.online_key = online_key
        self.timeout = timeout

    # ----------------------------------------------------------------------
    def scan_path(self, path: str | Path, display_name: str | None = None) -> Report:
        path = Path(path)
        name = display_name or path.name
        started = time.monotonic()
        report = Report(path=str(path), display_name=name,
                        scanned_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        engine_version=__version__,
                        ruleset=self.ruleset.summary)
        try:
            with SafeFile(path) as sf:
                self._scan_open(sf, name, report, started)
        except UnsafeFile as exc:
            report.errors.append(str(exc))
        except ScanTimeout:
            report.errors.append(
                f"scan exceeded {self.timeout:.0f}s and was stopped; verdict fails closed")
        except Exception as exc:  # a parser bug must not become a silent ALLOW
            report.errors.append(f"unhandled error during scan: {type(exc).__name__}: {exc}")
        report.duration_ms = int((time.monotonic() - started) * 1000)
        return report

    # ----------------------------------------------------------------------
    def _scan_open(self, sf: SafeFile, name: str, report: Report, started: float) -> None:
        def check_clock() -> None:
            if time.monotonic() - started > self.timeout:
                raise ScanTimeout()

        report.size = sf.size
        if sf.truncated:
            report.truncated = True
            report.add(Finding(
                id="SCAN_TRUNCATED",
                title=f"File is larger than the {config.MAX_FILE_BYTES // (1 << 20)} MiB scan limit",
                severity=Severity.MEDIUM, category="coverage",
                detail="Only the first portion was examined. The remainder is unvetted.",
                evidence=[f"size: {sf.size} bytes"]))

        # 1. identity
        digests = sf.digests()
        report.sha256, report.sha1, report.md5 = digests.sha256, digests.sha1, digests.md5
        check_clock()

        # 2. reputation -- may be decisive on its own
        report.extend(reputation.check(report.sha256, self.database))
        report.extend(reputation.check_pin(name, report.sha256, self.pins))
        if self.online_key:
            report.extend(reputation.online_lookup(report.sha256, self.online_key))
        check_clock()

        # 3. what it is, versus what it says it is
        head = sf.head(min(65536, max(sf.readable_size, 1)))
        ft = detect_type(head, tail=sf.tail(4096), size=sf.size, probe_at=sf.read_at)
        report.file_type = ft.kind
        report.type_description = ft.description
        report.extend(analyse_name(name))
        report.extend(compare_type_and_name(ft, name))
        report.add(dangerous_extension_finding(name, ft))
        check_clock()

        # 4. format-specific analysis, dispatched on real content
        self._dispatch(sf, ft, name, report)
        check_clock()

        # 5. signature rules over raw bytes
        if self.ruleset.rules:
            try:
                window = sf.read_at(0, min(sf.readable_size, config.MAX_REGEX_WINDOW))
                report.extend(self.ruleset.scan(window, kind=ft.kind))
            except Exception as exc:
                report.errors.append(f"rule evaluation failed: {exc}")

        # 6. policy
        self._apply_policy(report, ft)

    # ----------------------------------------------------------------------
    def _dispatch(self, sf: SafeFile, ft, name: str, report: Report) -> None:
        kind = ft.kind
        if sf.size > config.MAX_DEEP_PARSE_BYTES:
            report.add(Finding(
                id="SCAN_DEEP_PARSE_SKIPPED",
                title="File too large for structural analysis",
                severity=Severity.LOW, category="coverage",
                detail=f"Above the {config.MAX_DEEP_PARSE_BYTES // (1 << 20)} MiB deep-parse "
                       "limit. Hashing, typing and signature rules still ran.",
                evidence=[f"size: {sf.size} bytes"]))
            return

        try:
            if kind in ("pe", "dos-mz"):
                report.extend(pe_mod.analyse(sf))
            elif kind == "elf":
                report.extend(elf.analyse_elf(sf, name))
            elif kind in ("macho", "macho-fat"):
                report.extend(elf.analyse_macho(sf, name, fat=kind == "macho-fat"))
            elif kind == "zip":
                report.extend(archive.analyse_zip(sf, name, ruleset=self.ruleset))
            elif kind == "tar":
                report.extend(archive.analyse_tar(sf, name))
            elif kind == "pdf":
                report.extend(pdf.analyse(sf, name))
            elif kind in ("script", "powershell", "vbscript", "jscript", "batch",
                          "shell", "python", "perl", "ruby", "php", "hta", "html",
                          "text", "xml"):
                report.extend(script.analyse(sf, kind, name, ruleset=self.ruleset))
            elif kind in ("gzip", "bzip2", "xz"):
                report.extend(archive.analyse_compressed_stream(sf, kind))
            elif kind == "ole2":
                report.extend(_analyse_ole(sf, name))
        except (pe_mod.PEError, elf.ELFError, archive.ArchiveError) as exc:
            # A file that announces a format and then fails to be one is itself
            # a finding, not a reason to stay quiet.
            report.add(Finding(
                id="SCAN_MALFORMED_STRUCTURE",
                title=f"Declares {ft.description} but does not parse as one",
                severity=Severity.MEDIUM, category="anomaly",
                detail="Malformed headers break analysis tools while still loading in the "
                       "target application, which is the point of making them malformed.",
                evidence=[str(exc)]))
        except Exception as exc:
            report.errors.append(
                f"{kind} analyser failed: {type(exc).__name__}: {exc}")

    # ----------------------------------------------------------------------
    def _apply_policy(self, report: Report, ft) -> None:
        policy = self.policy
        if policy.name == "standard":
            return
        notes: list[str] = []

        top = report.top_severity
        if top >= policy.block_at and not report.decision.blocks:
            notes.append(f"a {top.name} finding blocks under this profile")

        if policy.executable_surcharge and (ft.is_executable or ft.is_script):
            report.add(Finding(
                id="POLICY_EXECUTABLE_SURCHARGE",
                title=f"Executable content under the {policy.name} profile",
                severity=Severity.LOW, category="policy",
                detail="This profile treats anything runnable as suspect by default.",
                evidence=[f"type: {ft.description}"],
                weight=policy.executable_surcharge))

        if policy.block_macros and any(f.id == "OOXML_MACROS" for f in report.findings):
            notes.append("macro-bearing documents are blocked under this profile")
        if policy.block_unsigned_executables and any(f.id == "PE_UNSIGNED" for f in report.findings):
            notes.append("unsigned executables are blocked under this profile")
        if policy.block_uninspectable and any(f.id in UNINSPECTABLE for f in report.findings):
            notes.append("contents that could not be fully inspected are blocked under this profile")

        if notes:
            report.add(Finding(
                id="POLICY_BLOCK",
                title=f"Blocked by the {policy.name} policy profile",
                severity=Severity.HIGH, category="policy",
                detail="Under the default (standard) profile this file would not have been "
                       "blocked on these grounds alone. The profile, not the file, is the "
                       "reason -- review the findings and decide.",
                evidence=notes,
                decisive=Decision.QUARANTINE))


def _analyse_ole(sf: SafeFile, name: str) -> list[Finding]:
    """Legacy OLE2 compound documents (.doc/.xls/.ppt/.msi).

    A byte-level heuristic rather than a full compound-file parse: stream names
    are stored as UTF-16LE inside the directory, so searching for the names that
    matter finds them without walking the FAT. Stated plainly because it is a
    heuristic -- it can be defeated by a file that fragments its directory, and
    it will not tell you what the macro does.
    """
    data = sf.read_at(0, min(sf.readable_size, config.MAX_REGEX_WINDOW))
    out: list[Finding] = []

    def wide(text: str) -> bytes:
        return text.encode("utf-16-le")

    macro_markers = [m for m in ("VBA", "_VBA_PROJECT", "Macros", "PROJECTwm")
                     if wide(m) in data]
    if macro_markers:
        out.append(Finding(
            id="OLE_MACROS", title="Legacy Office document contains a VBA project",
            severity=Severity.HIGH, category="document",
            detail="Macros execute when the document is opened and the user enables "
                   "content. Detected by stream name; the macro body is not decompiled.",
            evidence=macro_markers, attck="T1566.001"))

    if wide("Equation Native") in data:
        out.append(Finding(
            id="OLE_EQUATION_EDITOR",
            title="Embeds an Equation Editor object",
            severity=Severity.CRITICAL, category="document",
            detail="The Equation Editor object is the carrier for a family of memory-"
                   "corruption exploits (CVE-2017-11882 and relatives) that need no macro "
                   "and no user interaction beyond opening the file. A modern document has "
                   "no reason to contain one.",
            evidence=["stream: Equation Native"], attck="T1203",
            decisive=Decision.QUARANTINE))

    for marker, fid, title, severity in (
            ("oleObject", "OLE_EMBEDDED_OBJECT", "Embeds an OLE object", Severity.MEDIUM),
            ("Package", "OLE_PACKAGER", "Embeds a packaged file (Packager object)", Severity.HIGH)):
        if wide(marker) in data:
            out.append(Finding(
                id=fid, title=title, severity=severity, category="document",
                detail="Packaged objects carry an arbitrary file that runs on double-click.",
                evidence=[f"stream: {marker}"], attck="T1204.002"))
    return out
