"""Format analysers: PE, archives, OOXML, PDF, scripts, ELF."""

from __future__ import annotations

import io
import zipfile

import pytest

from airlock import samples
from airlock.formats import archive, elf, pdf, script
from airlock.formats import pe as pe_mod
from airlock.safeio import SafeFile
from airlock.verdict import Severity


def ids(findings):
    return {f.id for f in findings}


def analyse(path, fn, *args, **kwargs):
    with SafeFile(path) as sf:
        return fn(sf, *args, **kwargs)


# ==========================================================================
# PE
# ==========================================================================
def test_pe_parses_structure(write_sample):
    path = write_sample("a.exe", samples.benign_pe())
    with SafeFile(path) as sf:
        pe = pe_mod.PEFile(sf)
        assert pe.bits == 64
        assert [s.name for s in pe.sections] == [".text", ".rdata"]
        imports = pe.imports()
        assert "KERNEL32.dll" in imports
        assert "WriteFile" in imports["KERNEL32.dll"]
        assert "printf" in imports["msvcrt.dll"]


def test_pe_rejects_non_pe(write_sample):
    path = write_sample("a.exe", b"not a pe at all, just text")
    with SafeFile(path) as sf:
        with pytest.raises(pe_mod.PEError):
            pe_mod.PEFile(sf)


def test_pe_rejects_out_of_range_e_lfanew(write_sample):
    """A hostile e_lfanew must not send the parser off the end of the file."""
    blob = bytearray(samples.benign_pe())
    blob[0x3C:0x40] = (0x7FFFFFFF).to_bytes(4, "little")
    path = write_sample("bad.exe", bytes(blob))
    with SafeFile(path) as sf:
        with pytest.raises(pe_mod.PEError):
            pe_mod.PEFile(sf)


def test_pe_clamps_absurd_section_count(write_sample):
    blob = bytearray(samples.benign_pe())
    e_lfanew = int.from_bytes(blob[0x3C:0x40], "little")
    blob[e_lfanew + 6:e_lfanew + 8] = (0xFFFF).to_bytes(2, "little")
    path = write_sample("bad.exe", bytes(blob))
    with SafeFile(path) as sf:
        with pytest.raises(pe_mod.PEError, match="absurd section count"):
            pe_mod.PEFile(sf)


def test_pe_detects_injection_cluster(write_sample):
    path = write_sample("x.exe", samples.injector_pe())
    found = ids(analyse(path, pe_mod.analyse))
    assert "PE_API_PROCESS_INJECTION" in found
    assert "PE_API_ANTI_ANALYSIS" in found
    assert "PE_API_PERSISTENCE" in found
    assert "PE_CAPABILITY_STACK" in found
    assert "PE_WRITABLE_EXECUTABLE_SECTION" in found


def test_pe_capability_stack_needs_multiple_independent_capabilities(write_sample):
    """One capability is explainable. The stack finding must not fire on it."""
    path = write_sample("x.exe", samples.benign_pe())
    assert "PE_CAPABILITY_STACK" not in ids(analyse(path, pe_mod.analyse))


def test_pe_detects_packer_and_entropy(write_sample):
    path = write_sample("p.exe", samples.packed_pe())
    found = ids(analyse(path, pe_mod.analyse))
    assert "PE_PACKER_SECTION" in found
    assert "PE_HIGH_ENTROPY_SECTION" in found
    assert "PE_SPARSE_IMPORTS" in found


def test_pe_detects_ransomware_indicators(write_sample):
    path = write_sample("r.exe", samples.ransomware_like_pe())
    found = ids(analyse(path, pe_mod.analyse))
    assert "PE_API_ENCRYPTION" in found
    assert "PE_DESTRUCTIVE_COMMANDS" in found
    assert "PE_TOR_ADDRESS" in found


def test_pe_detects_appended_overlay(write_sample):
    path = write_sample("poly.exe", samples.pe_with_appended_zip())
    findings = analyse(path, pe_mod.analyse)
    overlay = next(f for f in findings if f.id == "PE_OVERLAY")
    assert any("ZIP header" in e for e in overlay.evidence)


def test_pe_reports_missing_mitigations(write_sample):
    path = write_sample("x.exe", samples.injector_pe())
    finding = next(f for f in analyse(path, pe_mod.analyse)
                   if f.id == "PE_MISSING_MITIGATIONS")
    assert "ASLR (DYNAMIC_BASE)" in finding.evidence
    assert "DEP (NX_COMPAT)" in finding.evidence


def test_benign_pe_stays_low(write_sample):
    path = write_sample("ok.exe", samples.benign_pe())
    findings = analyse(path, pe_mod.analyse)
    assert not [f for f in findings if f.severity >= Severity.HIGH]


# ==========================================================================
# Archives
# ==========================================================================
def test_zip_slip(write_sample):
    path = write_sample("a.zip", samples.zip_slip())
    finding = next(f for f in analyse(path, archive.analyse_zip, "a.zip")
                   if f.id == "ZIP_PATH_TRAVERSAL")
    assert finding.severity is Severity.CRITICAL
    assert any(".." in e for e in finding.evidence)


def test_zip_slip_ignores_internal_dot_dot(write_sample):
    """'a/../b.txt' stays inside the extraction root and is not an escape."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a/../b.txt", b"fine")
        zf.writestr("./c.txt", b"fine")
    path = write_sample("ok.zip", buf.getvalue())
    assert "ZIP_PATH_TRAVERSAL" not in ids(analyse(path, archive.analyse_zip, "ok.zip"))


def test_zip_bomb(write_sample):
    path = write_sample("b.zip", samples.zip_bomb())
    assert "ZIP_DECOMPRESSION_BOMB" in ids(analyse(path, archive.analyse_zip, "b.zip"))


def test_ordinary_zip_is_not_a_bomb(write_sample):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("notes.txt", b"the quick brown fox " * 50)
    path = write_sample("ok.zip", buf.getvalue())
    assert "ZIP_DECOMPRESSION_BOMB" not in ids(analyse(path, archive.analyse_zip, "ok.zip"))


def test_zip_finds_hidden_executables_and_spoofed_names(write_sample):
    path = write_sample("i.zip", samples.archive_with_hidden_executable())
    found = ids(analyse(path, archive.analyse_zip, "i.zip"))
    assert "ZIP_CONTAINS_EXECUTABLE" in found
    assert "ZIP_ENTRY_NAME_BIDI_OVERRIDE" in found


def test_zip_encrypted_entries(write_sample):
    """Encrypted entries are opaque to every scanner in the chain, which is the
    point of shipping a payload with the password in the covering email."""
    path = write_sample("e.zip", samples.password_protected_archive())
    finding = next(f for f in analyse(path, archive.analyse_zip, "e.zip")
                   if f.id == "ZIP_ENCRYPTED_ENTRIES")
    assert finding.severity is Severity.HIGH
    assert "invoice.exe" in finding.evidence


def test_corrupt_zip_raises_rather_than_passing(write_sample):
    path = write_sample("bad.zip", b"PK\x03\x04" + b"\xff" * 200)
    with pytest.raises(archive.ArchiveError):
        analyse(path, archive.analyse_zip, "bad.zip")


# ==========================================================================
# OOXML
# ==========================================================================
def test_ooxml_macro_in_honest_docm(write_sample):
    path = write_sample("a.docm", samples.macro_document())
    finding = next(f for f in analyse(path, archive.analyse_zip, "a.docm")
                   if f.id == "OOXML_MACROS")
    # Honestly named: high, but not decisive.
    assert finding.severity is Severity.HIGH
    assert finding.decisive is None


def test_ooxml_macro_in_mislabelled_docx_is_decisive(write_sample):
    path = write_sample("a.docx", samples.macro_document())
    finding = next(f for f in analyse(path, archive.analyse_zip, "a.docx")
                   if f.id == "OOXML_MACROS")
    assert finding.severity is Severity.CRITICAL
    assert finding.decisive is not None


def test_ooxml_remote_template_injection(write_sample):
    path = write_sample("c.docx", samples.template_injection_docx())
    finding = next(f for f in analyse(path, archive.analyse_zip, "c.docx")
                   if f.id == "OOXML_EXTERNAL_ATTACHEDTEMPLATE")
    assert finding.severity is Severity.CRITICAL
    assert any("example.invalid" in e for e in finding.evidence)


def test_ooxml_without_macros_or_remote_refs_is_clean(write_sample):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:document/>")
    path = write_sample("plain.docx", buf.getvalue())
    found = ids(analyse(path, archive.analyse_zip, "plain.docx"))
    assert not {f for f in found if f.startswith("OOXML_")}


# ==========================================================================
# Tar
# ==========================================================================
def _tar_with(members):
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for info, data in members:
            tf.addfile(info, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def test_tar_path_traversal(write_sample):
    import tarfile
    info = tarfile.TarInfo("../../etc/passwd")
    info.size = 4
    path = write_sample("a.tar", _tar_with([(info, b"root")]))
    assert "TAR_PATH_TRAVERSAL" in ids(analyse(path, archive.analyse_tar, "a.tar"))


def test_tar_setuid_and_escaping_link(write_sample):
    import tarfile
    setuid = tarfile.TarInfo("bin/su")
    setuid.size, setuid.mode = 0, 0o4755
    link = tarfile.TarInfo("link")
    link.type, link.linkname = tarfile.SYMTYPE, "/etc/shadow"
    path = write_sample("a.tar", _tar_with([(setuid, b""), (link, None)]))
    found = ids(analyse(path, archive.analyse_tar, "a.tar"))
    assert "TAR_SETUID_MEMBER" in found
    assert "TAR_ESCAPING_LINK" in found


# ==========================================================================
# PDF
# ==========================================================================
def test_pdf_autorun_javascript(write_sample):
    path = write_sample("a.pdf", samples.pdf_with_javascript())
    found = ids(analyse(path, pdf.analyse, "a.pdf"))
    assert "PDF_JAVASCRIPT" in found
    assert "PDF_OPENACTION" in found
    assert "PDF_AUTORUN_SCRIPT" in found
    assert "PDF_EMBEDDED_FILE" in found


def test_pdf_hex_escaped_names_are_normalised(write_sample):
    """/#4Aavascript is /Javascript. A scanner matching literals sees neither."""
    blob = b"%PDF-1.5\n1 0 obj<</OpenAction<</S/#4A#61vaScript/JS(x)>>>>endobj\n"
    path = write_sample("e.pdf", blob)
    found = ids(analyse(path, pdf.analyse, "e.pdf"))
    assert "PDF_JAVASCRIPT" in found
    assert "PDF_NAME_OBFUSCATION" in found


def test_benign_pdf_is_clean(write_sample):
    path = write_sample("b.pdf", samples.benign_pdf())
    assert not [f for f in analyse(path, pdf.analyse, "b.pdf")
                if f.severity >= Severity.MEDIUM]


def test_pdf_launch_action_is_critical(write_sample):
    path = write_sample("l.pdf", b"%PDF-1.4\n1 0 obj<</S/Launch/F(cmd.exe)>>endobj\n")
    finding = next(f for f in analyse(path, pdf.analyse, "l.pdf")
                   if f.id == "PDF_LAUNCH_ACTION")
    assert finding.severity is Severity.CRITICAL


# ==========================================================================
# Scripts
# ==========================================================================
def test_powershell_encoded_layer_is_decoded_and_analysed(write_sample):
    path = write_sample("a.ps1", samples.obfuscated_powershell())
    findings = analyse(path, script.analyse, "powershell", "a.ps1")
    found = ids(findings)
    assert "PS_ENCODED_COMMAND" in found
    assert "SCRIPT_ENCODED_LAYER" in found
    # The payload indicators must come from *inside* the decoded layer.
    inner = [f for f in findings if f.layer.startswith("base64")]
    assert {"PS_IEX", "PS_DOWNLOADER"} <= {f.id for f in inner}


def test_shell_reverse_shell_and_persistence(write_sample):
    path = write_sample("a.sh", samples.reverse_shell_script())
    found = ids(analyse(path, script.analyse, "shell", "a.sh"))
    assert "SH_REVERSE_SHELL" in found
    assert "SH_CURL_PIPE_SHELL" in found
    assert "SH_PERSISTENCE" in found
    assert "SH_ANTI_FORENSICS" in found


def test_ordinary_script_is_clean(write_sample):
    path = write_sample("build.sh", b"#!/bin/bash\nset -e\nmake all\nmake test\n")
    assert not [f for f in analyse(path, script.analyse, "shell", "build.sh")
                if f.severity >= Severity.MEDIUM]


def test_decoding_stops_at_the_recursion_limit(write_sample):
    """Nesting encodings must terminate, not recurse until the stack gives out."""
    import base64
    payload = b"Write-Output 'innermost'"
    for _ in range(12):
        payload = base64.b64encode(payload)
    path = write_sample("nested.ps1", b"$x = '" + payload + b"'")
    findings = analyse(path, script.analyse, "powershell", "nested.ps1")
    depths = [f.layer.count("base64") for f in findings if f.layer]
    from airlock import config
    assert max(depths, default=0) <= config.MAX_RECURSION_DEPTH


def test_base64_of_binary_is_not_reported_as_a_script_layer(write_sample):
    """A base64 blob that decodes to binary is not a hidden script."""
    import base64
    blob = base64.b64encode(bytes(range(256)) * 4)
    path = write_sample("data.txt", b"data = " + blob)
    assert "SCRIPT_ENCODED_LAYER" not in ids(
        analyse(path, script.analyse, "text", "data.txt"))


# ==========================================================================
# ELF
# ==========================================================================
def test_elf_rejects_garbage(write_sample):
    path = write_sample("a.bin", b"\x7fELF" + b"\xff" * 8)
    with pytest.raises(elf.ELFError):
        analyse(path, elf.analyse_elf, "a.bin")


def test_real_system_binary_is_clean(write_sample):
    """The false-positive test that matters most: a real, signed-by-nobody,
    dynamically linked system binary must not be flagged."""
    import shutil
    source = shutil.which("ls") or shutil.which("sh")
    if source is None:
        pytest.skip("no system binary available")
    path = write_sample("ls", open(source, "rb").read())
    findings = analyse(path, elf.analyse_elf, "ls")
    assert not [f for f in findings if f.severity >= Severity.HIGH]


# ==========================================================================
# False positives on real software
# ==========================================================================
@pytest.mark.parametrize("binary", ["bash", "git", "ls", "tar", "python3", "grep"])
def test_real_system_binaries_are_not_flagged(binary, write_sample):
    """Regression: bash embeds "/dev/tcp/" because bash is the program that
    *implements* /dev/tcp, and git embeds "crontab -" from its scheduler.
    Matching those fragments without asking what kind of file they were found
    in flagged the operating system's own tooling as a reverse shell.
    """
    import shutil
    source = shutil.which(binary)
    if source is None:
        pytest.skip(f"{binary} not installed")
    path = write_sample(binary, open(source, "rb").read())
    findings = analyse(path, elf.analyse_elf, binary)
    offenders = [f for f in findings if f.severity >= Severity.MEDIUM]
    assert not offenders, f"{binary} flagged by {[f.id for f in offenders]}"


def test_script_idioms_still_fire_in_scripts(write_sample):
    """The other half of the same fix: the context filter must not blunt
    detection where these idioms genuinely mean something."""
    path = write_sample("x.sh", samples.reverse_shell_script())
    found = ids(analyse(path, script.analyse, "shell", "x.sh"))
    assert "SH_REVERSE_SHELL" in found
    assert "SCRIPT_DESTRUCTIVE_COMMANDS" in found


def test_ransomware_commands_still_fire_in_binaries(write_sample):
    path = write_sample("r.exe", samples.ransomware_like_pe())
    finding = next(f for f in analyse(path, pe_mod.analyse)
                   if f.id == "PE_DESTRUCTIVE_COMMANDS")
    assert finding.severity is Severity.CRITICAL
    assert any("vssadmin" in e for e in finding.evidence)
