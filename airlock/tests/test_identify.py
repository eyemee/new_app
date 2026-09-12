"""Content typing and the masquerade checks.

The name-versus-content gap is the single highest-yield signal Airlock has, so
these tests cover each spoofing technique individually.
"""

from __future__ import annotations

import pytest

from airlock import samples
from airlock.identify import (analyse_name, compare_type_and_name, detect_type,
                              final_extension)
from airlock.verdict import Decision, Severity


def ids(findings):
    return {f.id for f in findings}


# -- content typing --------------------------------------------------------
@pytest.mark.parametrize("data,expected", [
    (b"%PDF-1.7\n", "pdf"),
    (b"PK\x03\x04\x14\x00", "zip"),
    (b"\x7fELF\x02\x01\x01", "elf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2"),
    (b"#!/bin/bash\necho hi", "shell"),
    (b"#!/usr/bin/env python3\n", "python"),
    (b"\x89PNG\r\n\x1a\n", "image"),
    (b"Rar!\x1a\x07\x00", "rar"),
    (b"{\\rtf1\\ansi", "rtf"),
    (b"\x4c\x00\x00\x00\x01\x14\x02\x00", "lnk"),
    (b"plain english text here", "text"),
    (b"<?xml version='1.0'?><a/>", "xml"),
    (b"", "empty"),
])
def test_magic_detection(data, expected):
    assert detect_type(data, size=len(data)).kind == expected


def test_pe_requires_a_real_pe_header():
    """MZ alone is not a PE -- the e_lfanew pointer has to resolve."""
    assert detect_type(samples.benign_pe(), size=4096).kind == "pe"
    assert detect_type(b"MZ" + b"\x00" * 200, size=202).kind == "dos-mz"


def test_magic_at_offset_uses_the_probe_callback():
    """tar's signature lives at byte 257, past a short head read."""
    blob = b"\x00" * 257 + b"ustar\x00"
    ft = detect_type(blob[:64], size=len(blob),
                     probe_at=lambda off, n: blob[off:off + n])
    assert ft.kind == "tar"


def test_final_extension():
    assert final_extension("a.tar.gz") == "gz"
    assert final_extension("Invoice.pdf.exe") == "exe"
    assert final_extension("noext") == ""
    assert final_extension(".bashrc") == ""


# -- masquerade ------------------------------------------------------------
def test_right_to_left_override_is_critical_and_decisive():
    findings = analyse_name("annexe‮gnp.exe")
    assert "NAME_BIDI_OVERRIDE" in ids(findings)
    finding = next(f for f in findings if f.id == "NAME_BIDI_OVERRIDE")
    assert finding.severity is Severity.CRITICAL
    assert finding.decisive is Decision.QUARANTINE
    # The report must show the reader both the rendered and the real name.
    assert any("annexeexe.png" in e for e in finding.evidence)


def test_double_extension():
    findings = analyse_name("Invoice_2024.pdf.exe")
    assert "NAME_DOUBLE_EXTENSION" in ids(findings)


def test_double_extension_not_flagged_for_ordinary_compound_names():
    assert "NAME_DOUBLE_EXTENSION" not in ids(analyse_name("archive.tar.gz"))
    assert "NAME_DOUBLE_EXTENSION" not in ids(analyse_name("report.final.pdf"))


def test_homoglyph_mixed_script():
    findings = analyse_name("Аdobe_Reader.exe")  # Cyrillic capital A
    assert "NAME_MIXED_SCRIPT" in ids(findings)


def test_pure_non_latin_name_is_not_flagged():
    """A legitimately Russian filename is not a homoglyph attack."""
    assert "NAME_MIXED_SCRIPT" not in ids(analyse_name("отчет.pdf"))


def test_zero_width_characters():
    assert "NAME_INVISIBLE_CHARS" in ids(analyse_name("setup​.exe"))


def test_trailing_padding_and_reserved_names():
    assert "NAME_TRAILING_PADDING" in ids(analyse_name("report.pdf   "))
    assert "NAME_RESERVED_DEVICE" in ids(analyse_name("CON.txt"))


def test_overlong_name():
    assert "NAME_EXCESSIVE_LENGTH" in ids(analyse_name("a" * 200 + ".exe"))


def test_clean_name_produces_nothing():
    assert analyse_name("quarterly-report-2024.pdf") == []


# -- content versus name ---------------------------------------------------
def test_executable_claiming_to_be_a_document_is_decisive():
    ft = detect_type(samples.benign_pe(), size=4096)
    findings = compare_type_and_name(ft, "Q3_results.pdf")
    finding = next(f for f in findings if f.id == "TYPE_EXECUTABLE_MASQUERADE")
    assert finding.severity is Severity.CRITICAL
    assert finding.decisive is Decision.QUARANTINE


def test_executable_with_its_own_extension_is_clean():
    ft = detect_type(samples.benign_pe(), size=4096)
    assert compare_type_and_name(ft, "setup.exe") == []
    assert compare_type_and_name(ft, "library.dll") == []


def test_docx_is_not_flagged_as_a_zip_mismatch():
    """OOXML files really are ZIPs. Reporting that would be noise on every
    Office document that ever arrives."""
    ft = detect_type(samples.macro_document(), size=4096)
    assert ft.kind == "zip"
    assert compare_type_and_name(ft, "timesheet.docx") == []


def test_script_named_as_a_document():
    ft = detect_type(b"#!/bin/bash\nrm -rf /\n")
    findings = compare_type_and_name(ft, "readme.txt")
    assert "TYPE_EXECUTABLE_MASQUERADE" in ids(findings)
