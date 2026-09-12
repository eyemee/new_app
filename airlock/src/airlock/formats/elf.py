"""ELF and Mach-O analysis.

Lighter than the PE path by design: the Linux and macOS threat surface reaching a
desktop through downloads is dominated by scripts and installer packages rather
than by raw binaries, so this covers structure, packing and dynamic-linking
anomalies rather than a full symbol-level capability model.
"""

from __future__ import annotations

import struct

from .. import config
from ..entropy import is_packed, shannon
from ..safeio import SafeFile
from ..strings import (extract_iocs, find_destructive_commands, find_lolbins)
from ..verdict import Finding, Severity

ET_TYPE = {0: "none", 1: "relocatable", 2: "executable", 3: "shared object", 4: "core dump"}
EM_MACHINE = {3: "x86", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V", 21: "PowerPC64"}
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE, PT_GNU_STACK = 1, 2, 3, 4, 0x6474E551

PACKER_MARKERS = [
    (b"UPX!", "UPX"), (b"$Info: This file is packed with the UPX", "UPX"),
    (b"Packed by Themida", "Themida"), (b"midgetpack", "midgetpack"),
    (b".upxstub", "UPX"),
]


class ELFError(Exception):
    """Not a parseable ELF."""


def analyse_elf(sf: SafeFile, name: str) -> list[Finding]:
    head = sf.read_at(0, 64)
    if len(head) < 52 or head[:4] != b"\x7fELF":
        raise ELFError("not an ELF header")
    ei_class, ei_data = head[4], head[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        raise ELFError(f"invalid EI_CLASS/EI_DATA ({ei_class}/{ei_data})")
    bits = 32 if ei_class == 1 else 64
    endian = "<" if ei_data == 1 else ">"

    e_type, e_machine = struct.unpack_from(f"{endian}HH", head, 16)
    if bits == 64:
        e_phoff = struct.unpack_from(f"{endian}Q", head, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from(f"{endian}HH", head, 54)
        e_shoff = struct.unpack_from(f"{endian}Q", head, 40)[0]
        e_shnum = struct.unpack_from(f"{endian}H", head, 60)[0]
    else:
        e_phoff = struct.unpack_from(f"{endian}I", head, 28)[0]
        e_phentsize, e_phnum = struct.unpack_from(f"{endian}HH", head, 42)
        e_shoff = struct.unpack_from(f"{endian}I", head, 32)[0]
        e_shnum = struct.unpack_from(f"{endian}H", head, 48)[0]

    e_phnum = min(e_phnum, config.MAX_SECTIONS)
    findings: list[Finding] = []
    findings.append(Finding(
        id="ELF_SUMMARY",
        title=f"ELF {bits}-bit {ET_TYPE.get(e_type, e_type)} for "
              f"{EM_MACHINE.get(e_machine, f'machine {e_machine}')}",
        severity=Severity.INFO, category="structure",
        detail=f"{e_phnum} program headers, {e_shnum} section headers",
    ))

    # -- program headers ---------------------------------------------------
    rwx: list[str] = []
    interp = ""
    exec_stack = False
    gnu_stack_seen = False
    if e_phoff and e_phentsize >= 32:
        table = sf.read_at(e_phoff, min(e_phnum * e_phentsize, config.MAX_PARSE_WINDOW))
        for i in range(e_phnum):
            base = i * e_phentsize
            if base + e_phentsize > len(table):
                break
            p_type = struct.unpack_from(f"{endian}I", table, base)[0]
            if bits == 64:
                p_flags = struct.unpack_from(f"{endian}I", table, base + 4)[0]
                p_offset = struct.unpack_from(f"{endian}Q", table, base + 8)[0]
                p_filesz = struct.unpack_from(f"{endian}Q", table, base + 32)[0]
            else:
                p_offset = struct.unpack_from(f"{endian}I", table, base + 4)[0]
                p_filesz = struct.unpack_from(f"{endian}I", table, base + 16)[0]
                p_flags = struct.unpack_from(f"{endian}I", table, base + 24)[0]
            if p_type == PT_LOAD and (p_flags & 0x1) and (p_flags & 0x2):
                rwx.append(f"segment {i}: RWX, {p_filesz} bytes at 0x{p_offset:x}")
            if p_type == PT_INTERP and p_filesz < 256:
                interp = sf.read_at(p_offset, p_filesz).split(b"\x00", 1)[0].decode("latin-1", "replace")
            if p_type == PT_GNU_STACK:
                gnu_stack_seen = True
                exec_stack = bool(p_flags & 0x1)

    if rwx:
        findings.append(Finding(
            id="ELF_RWX_SEGMENT", title="Loadable segment is writable and executable",
            severity=Severity.HIGH, category="obfuscation",
            detail="An RWX segment lets the process rewrite its own code. Normal toolchains "
                   "do not produce this; runtime unpackers require it.",
            evidence=rwx[:4], attck="T1027.002"))
    if exec_stack:
        findings.append(Finding(
            id="ELF_EXECUTABLE_STACK", title="Executable stack requested",
            severity=Severity.MEDIUM, category="hardening",
            detail="PT_GNU_STACK marked executable disables a baseline exploit mitigation.",
            evidence=["PT_GNU_STACK has PF_X"]))
    elif not gnu_stack_seen:
        findings.append(Finding(
            id="ELF_NO_GNU_STACK", title="No PT_GNU_STACK header",
            severity=Severity.LOW, category="hardening",
            detail="Without this header the kernel may default the stack to executable.",
            evidence=["PT_GNU_STACK absent"]))

    if e_shnum == 0 or e_shoff == 0:
        findings.append(Finding(
            id="ELF_NO_SECTION_HEADERS", title="Section header table has been removed",
            severity=Severity.HIGH, category="obfuscation",
            detail="Sections are not needed to run, only to analyse. Stripping the table "
                   "entirely is a deliberate obstacle to disassembly, and is what packers "
                   "leave behind.",
            evidence=[f"e_shoff={e_shoff}, e_shnum={e_shnum}"], attck="T1027.002"))

    if interp:
        findings.append(Finding(
            id="ELF_INTERPRETER", title=f"Dynamic loader: {interp}",
            severity=Severity.INFO, category="structure", detail=""))

    findings.extend(_binary_content_checks(sf, prefix="ELF"))
    return findings


def analyse_macho(sf: SafeFile, name: str, fat: bool) -> list[Finding]:
    head = sf.read_at(0, 32)
    findings: list[Finding] = []
    if fat:
        if len(head) >= 8:
            count = min(struct.unpack_from(">I", head, 4)[0], 64)
            findings.append(Finding(
                id="MACHO_FAT", title=f"Universal binary with {count} architecture slice(s)",
                severity=Severity.INFO, category="structure",
                detail="Each slice is a separate image; Airlock inspects the container only."))
    else:
        if len(head) >= 16:
            filetype, ncmds = struct.unpack_from("<II", head, 12)
            names = {2: "executable", 6: "dylib", 8: "bundle", 10: "dSYM", 11: "kext"}
            findings.append(Finding(
                id="MACHO_SUMMARY",
                title=f"Mach-O {names.get(filetype, f'type {filetype}')} "
                      f"with {min(ncmds, config.MAX_LOAD_COMMANDS)} load commands",
                severity=Severity.INFO, category="structure", detail=""))
    findings.extend(_binary_content_checks(sf, prefix="MACHO"))
    return findings


def _binary_content_checks(sf: SafeFile, prefix: str) -> list[Finding]:
    """Packing markers, destructive commands and network indicators."""
    data = sf.read_at(0, min(sf.readable_size, config.MAX_REGEX_WINDOW))
    out: list[Finding] = []

    packers = sorted({label for marker, label in PACKER_MARKERS if marker in data})
    if packers:
        out.append(Finding(
            id=f"{prefix}_PACKED", title=f"Packed with {', '.join(packers)}",
            severity=Severity.MEDIUM, category="obfuscation",
            detail="Packer signature present; the real code is compressed and not visible "
                   "to static analysis.",
            evidence=packers, attck="T1027.002"))

    ent = shannon(data[:1 << 20])
    if is_packed(ent, len(data), min_size=1 << 16):
        out.append(Finding(
            id=f"{prefix}_HIGH_ENTROPY", title=f"Whole-file entropy {ent:.2f} bits/byte",
            severity=Severity.MEDIUM, category="obfuscation",
            detail="The image as a whole is indistinguishable from compressed data, which "
                   "for a binary means its contents are packed or encrypted.",
            evidence=[f"{ent:.2f} bits/byte over {len(data)} bytes"], attck="T1027.002"))

    destructive = find_destructive_commands(data)
    if destructive:
        out.append(Finding(
            id=f"{prefix}_DESTRUCTIVE_COMMANDS",
            title=f"Embeds {len(destructive)} destructive or defence-disabling command(s)",
            severity=Severity.HIGH, category="capability",
            evidence=[f"{c} -- {d}" for c, d, _ in destructive[:8]],
            detail="Command strings compiled into the binary.", attck=destructive[0][2]))

    lolbins = find_lolbins(data)
    if lolbins:
        out.append(Finding(
            id=f"{prefix}_LOLBIN_USAGE", title="References living-off-the-land techniques",
            severity=Severity.HIGH, category="capability",
            evidence=[f"{c} -- {d}" for c, d, _ in lolbins[:8]],
            detail="Trusted system binaries invoked as execution proxies.", attck=lolbins[0][2]))

    iocs = extract_iocs(data)
    net = iocs["urls"] + iocs["onion"]
    if iocs["onion"]:
        out.append(Finding(
            id=f"{prefix}_TOR_ADDRESS", title="Embeds a Tor hidden-service address",
            severity=Severity.HIGH, category="network", evidence=iocs["onion"][:5],
            detail="A .onion endpoint compiled into a binary.", attck="T1090.003"))
    if net:
        out.append(Finding(
            id=f"{prefix}_NETWORK_INDICATORS",
            title=f"Embeds {len(net)} hard-coded network indicator(s)",
            severity=Severity.INFO if len(net) <= 3 else Severity.LOW,
            category="network", evidence=net[:12],
            detail="Addresses compiled into the binary."))
    return out
