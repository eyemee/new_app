"""Windows PE (Portable Executable) static analysis.

The parser is written against the PE/COFF specification but trusts none of it:
every offset the file supplies is range-checked against the real file size
before use, every count is clamped, and a malformed structure ends that branch
of parsing instead of the scan.

What it reports on: imported API surface (mapped to ATT&CK), packing and
section anomalies, exploit mitigations the binary opted out of, Authenticode
presence, and appended overlay data.
"""

from __future__ import annotations

import datetime as dt
import struct

from .. import config
from ..entropy import PACKED_THRESHOLD, is_packed, shannon
from ..safeio import SafeFile
from ..strings import (extract_iocs, find_destructive_commands, find_lolbins,
                       find_persistence_keys)
from ..verdict import Finding, Severity

# -- constants from the PE/COFF specification ------------------------------
MACHINE = {
    0x014C: "x86", 0x8664: "x86-64", 0x01C0: "ARM", 0xAA64: "ARM64",
    0x01C4: "ARMv7", 0x0200: "Itanium", 0x0EBC: "EFI bytecode", 0x5032: "RISC-V 32",
    0x5064: "RISC-V 64", 0x6264: "LoongArch64",
}
SUBSYSTEM = {
    1: "native (driver)", 2: "Windows GUI", 3: "Windows console", 5: "OS/2",
    7: "POSIX", 9: "Windows CE", 10: "EFI application", 11: "EFI boot driver",
    12: "EFI runtime driver", 13: "EFI ROM", 14: "Xbox", 16: "boot application",
}

SCN_CNT_CODE = 0x00000020
SCN_MEM_DISCARDABLE = 0x02000000
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000

DLLCHAR = {
    0x0020: "HIGH_ENTROPY_VA", 0x0040: "DYNAMIC_BASE", 0x0080: "FORCE_INTEGRITY",
    0x0100: "NX_COMPAT", 0x0200: "NO_ISOLATION", 0x0400: "NO_SEH",
    0x0800: "NO_BIND", 0x1000: "APPCONTAINER", 0x2000: "WDM_DRIVER",
    0x4000: "GUARD_CF", 0x8000: "TERMINAL_SERVER_AWARE",
}
IMAGE_FILE_DLL = 0x2000

DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_SECURITY = 0, 1, 2, 4
DIR_TLS, DIR_LOADCONFIG, DIR_DELAY_IMPORT, DIR_CLR = 9, 10, 13, 14

#: Section names written by known packers and protectors.
PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", "upx!": "UPX", ".upx": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack", "aspack": "ASPack",
    ".nsp0": "NsPack", ".nsp1": "NsPack", ".nsp2": "NsPack",
    ".petite": "Petite", "petite": "Petite", "pec2": "PECompact",
    ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".themida": "Themida", "winlicen": "WinLicense", ".winlice": "WinLicense",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".enigma1": "Enigma", ".enigma2": "Enigma",
    "fsg!": "FSG", ".packed": "generic packer", ".rlpack": "RLPack",
    ".neolite": "NeoLite", ".perplex": "Perplex", "dastub": "DAStub",
    ".boom": "Boomerang", "kkrunchy": "kkrunchy", ".taz": "PESpin",
    "bitarts": "BitArts", ".shrink": "Shrinker", "molebox": "MoleBox",
    ".pklstb": "PKLite", "!epack": "EPack", ".y0da": "yoda", ".ccg": "CCG",
}

#: Imported APIs grouped by what an attacker uses them for. The grouping is the
#: point -- one of these on its own is unremarkable, a cluster is a capability.
API_GROUPS: dict[str, dict] = {
    "process_injection": {
        "title": "process injection",
        "severity": Severity.HIGH,
        "attck": "T1055",
        "min_hits": 2,
        "apis": {
            "virtualallocex", "writeprocessmemory", "createremotethread",
            "createremotethreadex", "ntcreatethreadex", "rtlcreateuserthread",
            "queueuserapc", "ntqueueapcthread", "setthreadcontext",
            "getthreadcontext", "ntunmapviewofsection", "ntmapviewofsection",
            "zwunmapviewofsection", "virtualprotectex", "ntwritevirtualmemory",
            "ntallocatevirtualmemory", "openprocess", "resumethread",
            "suspendthread", "ntresumethread",
        },
    },
    "dynamic_api_resolution": {
        "title": "runtime API resolution and RWX memory",
        "severity": Severity.MEDIUM,
        "attck": "T1027",
        "min_hits": 3,
        "apis": {
            "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw",
            "getprocaddress", "virtualalloc", "virtualprotect", "ldrloaddll",
            "ldrgetprocedureaddress", "getmodulehandlea", "getmodulehandlew",
            "heapcreate", "ntprotectvirtualmemory",
        },
    },
    "persistence": {
        "title": "persistence installation",
        "severity": Severity.HIGH,
        "attck": "T1547",
        "min_hits": 2,
        "apis": {
            "regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw",
            "createservicea", "createservicew", "openscmanagera", "openscmanagerw",
            "startservicea", "startservicew", "changeserviceconfiga",
            "changeserviceconfigw", "shgetfolderpatha", "shgetfolderpathw",
            "regdeletevaluea", "regdeletekeya", "netscheduleJobAdd",
        },
    },
    "anti_analysis": {
        "title": "debugger and sandbox evasion",
        "severity": Severity.HIGH,
        "attck": "T1622",
        "min_hits": 2,
        "apis": {
            "isdebuggerpresent", "checkremotedebuggerpresent",
            "ntqueryinformationprocess", "outputdebugstringa", "outputdebugstringw",
            "ntsetinformationthread", "queryperformancecounter", "gettickcount",
            "gettickcount64", "findwindowa", "findwindoww", "getsystemmetrics",
            "blockinput", "ntclose", "zwqueryinformationprocess",
            "isprocessorfeaturepresent", "rdtsc", "ntquerysystemtime",
        },
    },
    "credential_access": {
        "title": "credential theft",
        "severity": Severity.CRITICAL,
        "attck": "T1003",
        "min_hits": 1,
        "apis": {
            "credenumeratea", "credenumeratew", "credreada", "credreadw",
            "cryptunprotectdata", "lsaopenpolicy", "lsaretrieveprivatedata",
            "samconnect", "samienumeratealiasesindomain", "minidumpwritedump",
            "netusergetinfo", "wnetenumresourcea",
        },
    },
    "surveillance": {
        "title": "keylogging and screen capture",
        "severity": Severity.HIGH,
        "attck": "T1056.001",
        "min_hits": 2,
        "apis": {
            "setwindowshookexa", "setwindowshookexw", "getasynckeystate",
            "getkeystate", "getkeyboardstate", "getforegroundwindow",
            "getwindowtexta", "getwindowtextw", "bitblt", "getdc", "createdc",
            "createcompatiblebitmap", "registerrawinputdevices", "mapvirtualkeya",
            "waveinopen", "capcreatecapturewindowa",
        },
    },
    "network": {
        "title": "network communication",
        "severity": Severity.LOW,
        "attck": "T1071",
        "min_hits": 2,
        "apis": {
            "internetopena", "internetopenw", "internetopenurla", "internetopenurlw",
            "internetreadfile", "httpsendrequesta", "httpsendrequestw",
            "httpopenrequesta", "urldownloadtofilea", "urldownloadtofilew",
            "winhttpopen", "winhttpsendrequest", "winhttpconnect",
            "socket", "connect", "send", "recv", "wsastartup", "gethostbyname",
            "dnsquery_a", "dnsquery_w", "ftpputfile", "inet_addr", "bind", "listen",
        },
    },
    "encryption": {
        "title": "bulk file encryption",
        "severity": Severity.HIGH,
        "attck": "T1486",
        "min_hits": 2,
        "apis": {
            "cryptencrypt", "cryptdecrypt", "cryptgenkey", "cryptacquirecontexta",
            "cryptacquirecontextw", "cryptderivekey", "cryptimportkey",
            "bcryptencrypt", "bcryptgeneratesymmetrickey", "cryptgenrandom",
            "cryptdestroykey", "bcryptopenalgorithmprovider",
        },
    },
    "discovery": {
        "title": "host and process discovery",
        "severity": Severity.LOW,
        "attck": "T1057",
        "min_hits": 3,
        "apis": {
            "getcomputernamea", "getcomputernamew", "getusernamea", "getusernamew",
            "getsysteminfo", "getnativesysteminfo", "getvolumeinformationa",
            "enumprocesses", "createtoolhelp32snapshot", "process32first",
            "process32next", "module32first", "netuserenum", "getadaptersinfo",
            "getlogicaldrives", "getdrivetypea", "netwkstagetinfo",
        },
    },
    "privilege": {
        "title": "privilege and token manipulation",
        "severity": Severity.HIGH,
        "attck": "T1134",
        "min_hits": 2,
        "apis": {
            "adjusttokenprivileges", "openprocesstoken", "openthreadtoken",
            "lookupprivilegevaluea", "lookupprivilegevaluew", "duplicatetokenex",
            "impersonateloggedonuser", "setthreadtoken", "createprocessasusera",
            "createprocesswithtokenw", "logonusera",
        },
    },
    "execution": {
        "title": "child process creation",
        "severity": Severity.LOW,
        "attck": "T1059",
        "min_hits": 1,
        "apis": {
            "createprocessa", "createprocessw", "shellexecutea", "shellexecutew",
            "shellexecuteexa", "winexec", "system", "_wsystem", "_popen",
        },
    },
}


class PEError(Exception):
    """The file is not a PE we can parse. Callers turn this into an error
    finding -- never into silence."""


class Section:
    __slots__ = ("name", "vsize", "vaddr", "rawsize", "rawptr", "flags", "entropy")

    def __init__(self, name, vsize, vaddr, rawsize, rawptr, flags):
        self.name = name
        self.vsize = vsize
        self.vaddr = vaddr
        self.rawsize = rawsize
        self.rawptr = rawptr
        self.flags = flags
        self.entropy = 0.0

    @property
    def executable(self) -> bool:
        return bool(self.flags & SCN_MEM_EXECUTE)

    @property
    def writable(self) -> bool:
        return bool(self.flags & SCN_MEM_WRITE)

    @property
    def perms(self) -> str:
        return ("R" if self.flags & SCN_MEM_READ else "-") + \
               ("W" if self.writable else "-") + \
               ("X" if self.executable else "-")


class PEFile:
    """A bounds-checked view over a PE image."""

    def __init__(self, sf: SafeFile):
        self.sf = sf
        self.size = sf.readable_size
        head = sf.read_at(0, 4096)
        if head[:2] != b"MZ":
            raise PEError("no MZ signature")
        if len(head) < 0x40:
            raise PEError("truncated DOS header")
        self.e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
        if not (0 < self.e_lfanew < self.size - 24):
            raise PEError(f"e_lfanew {self.e_lfanew} outside file")
        coff = sf.read_at(self.e_lfanew, 24)
        if len(coff) < 24 or coff[:4] != b"PE\x00\x00":
            raise PEError("no PE signature at e_lfanew")
        (self.machine, self.num_sections, self.timestamp, _symptr, _numsym,
         self.size_opt_header, self.characteristics) = struct.unpack_from("<HHIIIHH", coff, 4)

        if self.num_sections > config.MAX_SECTIONS:
            raise PEError(f"absurd section count {self.num_sections}")

        opt_off = self.e_lfanew + 24
        opt = sf.read_at(opt_off, min(max(self.size_opt_header, 96), 4096))
        if len(opt) < 2:
            raise PEError("no optional header")
        self.opt_magic = struct.unpack_from("<H", opt, 0)[0]
        if self.opt_magic == 0x10B:
            self.bits, dd_off, self.thunk_size = 32, 96, 4
        elif self.opt_magic == 0x20B:
            self.bits, dd_off, self.thunk_size = 64, 112, 8
        elif self.opt_magic == 0x107:
            raise PEError("ROM image, not analysed")
        else:
            raise PEError(f"unknown optional header magic 0x{self.opt_magic:x}")

        self.entry_rva = struct.unpack_from("<I", opt, 16)[0] if len(opt) >= 20 else 0
        self.section_alignment = struct.unpack_from("<I", opt, 32)[0] if len(opt) >= 36 else 0
        self.file_alignment = struct.unpack_from("<I", opt, 36)[0] if len(opt) >= 40 else 0
        self.size_of_image = struct.unpack_from("<I", opt, 56)[0] if len(opt) >= 60 else 0
        self.size_of_headers = struct.unpack_from("<I", opt, 60)[0] if len(opt) >= 64 else 0
        self.subsystem = struct.unpack_from("<H", opt, 68)[0] if len(opt) >= 70 else 0
        self.dll_characteristics = struct.unpack_from("<H", opt, 70)[0] if len(opt) >= 72 else 0
        self.num_dirs = struct.unpack_from("<I", opt, dd_off - 4)[0] if len(opt) >= dd_off else 0
        self.num_dirs = min(self.num_dirs, 16)

        self.directories: list[tuple[int, int]] = []
        for i in range(self.num_dirs):
            off = dd_off + i * 8
            if off + 8 > len(opt):
                break
            self.directories.append(struct.unpack_from("<II", opt, off))

        self.sections = self._read_sections(opt_off + self.size_opt_header)
        self.is_dll = bool(self.characteristics & IMAGE_FILE_DLL)

    # -- structure ---------------------------------------------------------
    def _read_sections(self, table_off: int) -> list[Section]:
        raw = self.sf.read_at(table_off, self.num_sections * 40)
        out: list[Section] = []
        for i in range(self.num_sections):
            base = i * 40
            if base + 40 > len(raw):
                break
            name = raw[base:base + 8].rstrip(b"\x00").decode("latin-1", "replace")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", raw, base + 8)
            flags = struct.unpack_from("<I", raw, base + 36)[0]
            # Clamp what the header claims against what the file actually holds.
            if rawptr > self.size:
                rawsize = 0
            else:
                rawsize = min(rawsize, self.size - rawptr)
            out.append(Section(name, vsize, vaddr, rawsize, rawptr, flags))
        return out

    def directory(self, index: int) -> tuple[int, int]:
        if 0 <= index < len(self.directories):
            return self.directories[index]
        return (0, 0)

    def rva_to_offset(self, rva: int) -> int | None:
        if rva < 0:
            return None
        if self.size_of_headers and rva < self.size_of_headers:
            return rva if rva < self.size else None
        for s in self.sections:
            span = max(s.vsize, s.rawsize)
            if span and s.vaddr <= rva < s.vaddr + span:
                offset = s.rawptr + (rva - s.vaddr)
                return offset if 0 <= offset < self.size else None
        return None

    def read_rva(self, rva: int, length: int) -> bytes:
        off = self.rva_to_offset(rva)
        return self.sf.read_at(off, length) if off is not None else b""

    def cstring_at_rva(self, rva: int, cap: int = 256) -> str:
        raw = self.read_rva(rva, cap)
        return raw.split(b"\x00", 1)[0].decode("latin-1", "replace")

    # -- derived facts -----------------------------------------------------
    def compute_entropy(self) -> None:
        for s in self.sections:
            if s.rawsize:
                s.entropy = shannon(self.sf.read_at(s.rawptr, min(s.rawsize, config.MAX_PARSE_WINDOW)))

    def imports(self) -> dict[str, list[str]]:
        """Parse the import directory. Returns {dll: [function, ...]}.

        A packed binary usually has an almost-empty table here, which is itself
        one of the strongest signals in the file.
        """
        rva, _size = self.directory(DIR_IMPORT)
        if not rva:
            return {}
        out: dict[str, list[str]] = {}
        for i in range(config.MAX_IMPORT_DLLS):
            desc = self.read_rva(rva + i * 20, 20)
            if len(desc) < 20:
                break
            orig_thunk, _ts, _fwd, name_rva, first_thunk = struct.unpack("<IIIII", desc)
            if not any((orig_thunk, name_rva, first_thunk)):
                break  # terminating null descriptor
            dll = self.cstring_at_rva(name_rva, 128) or f"<unnamed#{i}>"
            out.setdefault(dll, [])
            thunk_rva = orig_thunk or first_thunk
            if not thunk_rva:
                continue
            out[dll].extend(self._read_thunks(thunk_rva))
            if len(out) >= config.MAX_IMPORT_DLLS:
                break
        return out

    def _read_thunks(self, thunk_rva: int) -> list[str]:
        names: list[str] = []
        high_bit = 1 << (self.bits - 1)
        fmt = "<I" if self.thunk_size == 4 else "<Q"
        # Read the thunk array in one bounded slice rather than per-entry.
        blob = self.read_rva(thunk_rva, config.MAX_IMPORTS_PER_DLL * self.thunk_size)
        for i in range(0, len(blob) - self.thunk_size + 1, self.thunk_size):
            value = struct.unpack_from(fmt, blob, i)[0]
            if value == 0:
                break
            if value & high_bit:
                names.append(f"#{value & 0xFFFF}")  # imported by ordinal
            else:
                name = self.cstring_at_rva((value & 0x7FFFFFFF) + 2, 128)
                if name:
                    names.append(name)
            if len(names) >= config.MAX_IMPORTS_PER_DLL:
                break
        return names

    def delay_imports(self) -> list[str]:
        rva, _ = self.directory(DIR_DELAY_IMPORT)
        if not rva:
            return []
        out = []
        for i in range(64):
            desc = self.read_rva(rva + i * 32, 32)
            if len(desc) < 32:
                break
            name_rva = struct.unpack_from("<I", desc, 4)[0]
            if not name_rva:
                break
            name = self.cstring_at_rva(name_rva, 128)
            if name:
                out.append(name)
        return out

    @property
    def has_authenticode(self) -> bool:
        rva, size = self.directory(DIR_SECURITY)
        # The security directory is a file offset, not an RVA, and a non-zero
        # size is what actually indicates an embedded signature.
        return bool(rva and size and rva + size <= self.size + 4096)

    @property
    def is_dotnet(self) -> bool:
        return bool(self.directory(DIR_CLR)[0])

    @property
    def has_tls_callbacks(self) -> bool:
        rva, size = self.directory(DIR_TLS)
        if not rva or size < 24:
            return False
        blob = self.read_rva(rva, 40)
        if len(blob) < (24 if self.bits == 32 else 40):
            return False
        # AddressOfCallBacks is the 4th pointer-sized field in the TLS directory.
        if self.bits == 32:
            cb_va = struct.unpack_from("<I", blob, 12)[0]
        else:
            cb_va = struct.unpack_from("<Q", blob, 24)[0]
        return bool(cb_va)

    @property
    def overlay_offset(self) -> int:
        end = max((s.rawptr + s.rawsize for s in self.sections if s.rawsize), default=0)
        return end

    @property
    def overlay_size(self) -> int:
        return max(0, self.size - self.overlay_offset)


# --------------------------------------------------------------------------
def analyse(sf: SafeFile) -> list[Finding]:
    """Full PE analysis. Raises ``PEError`` if the file is not parseable."""
    pe = PEFile(sf)
    pe.compute_entropy()
    findings: list[Finding] = []
    arch = MACHINE.get(pe.machine, f"0x{pe.machine:04x}")
    subsystem = SUBSYSTEM.get(pe.subsystem, str(pe.subsystem))

    findings.append(Finding(
        id="PE_SUMMARY",
        title=f"PE {pe.bits}-bit {'DLL' if pe.is_dll else 'executable'} for {arch}",
        severity=Severity.INFO,
        category="structure",
        detail=f"subsystem: {subsystem}"
               + (", .NET assembly" if pe.is_dotnet else "")
               + f", {len(pe.sections)} sections",
        evidence=[f"{s.name or '<unnamed>'}  {s.perms}  raw={s.rawsize}  entropy={s.entropy:.2f}"
                  for s in pe.sections[:16]],
    ))

    findings.extend(_check_sections(pe))
    findings.extend(_check_mitigations(pe))
    findings.extend(_check_signature(pe))
    findings.extend(_check_timestamp(pe))
    findings.extend(_check_imports(pe))
    findings.extend(_check_overlay(pe))
    findings.extend(_check_content_indicators(pe, sf))
    return findings


def _check_sections(pe: PEFile) -> list[Finding]:
    out: list[Finding] = []
    packers = {PACKER_SECTIONS[s.name.lower()] for s in pe.sections
               if s.name.lower() in PACKER_SECTIONS}
    if packers:
        out.append(Finding(
            id="PE_PACKER_SECTION",
            title=f"Packed or protected with {', '.join(sorted(packers))}",
            severity=Severity.MEDIUM,
            category="obfuscation",
            detail="Section names match a known packer. Packing is legitimate for "
                   "commercial software and near-universal in malware; it means the "
                   "real code is not visible to static analysis.",
            evidence=[s.name for s in pe.sections if s.name.lower() in PACKER_SECTIONS],
            attck="T1027.002",
        ))

    high = [s for s in pe.sections if is_packed(s.entropy, s.rawsize)]
    if high:
        total_high = sum(s.rawsize for s in high)
        ratio = total_high / max(pe.size, 1)
        out.append(Finding(
            id="PE_HIGH_ENTROPY_SECTION",
            title=f"{len(high)} section(s) at compression-grade entropy",
            severity=Severity.MEDIUM if ratio > 0.3 else Severity.LOW,
            category="obfuscation",
            detail=f"{ratio:.0%} of the file is statistically indistinguishable from "
                   f"compressed or encrypted data (threshold {PACKED_THRESHOLD} bits/byte).",
            evidence=[f"{s.name or '<unnamed>'}: {s.entropy:.2f} bits/byte over {s.rawsize} bytes"
                      for s in high[:8]],
            attck="T1027.002",
        ))

    wx = [s for s in pe.sections if s.writable and s.executable]
    if wx:
        out.append(Finding(
            id="PE_WRITABLE_EXECUTABLE_SECTION",
            title="Section is both writable and executable",
            severity=Severity.HIGH,
            category="obfuscation",
            detail="A W+X section lets the image rewrite its own code at runtime. "
                   "Compilers do not emit this; unpackers and self-modifying code do.",
            evidence=[f"{s.name or '<unnamed>'} ({s.perms})" for s in wx],
            attck="T1027.002",
        ))

    # Entry point should land in a section marked executable.
    if pe.entry_rva:
        host = None
        for s in pe.sections:
            span = max(s.vsize, s.rawsize)
            if span and s.vaddr <= pe.entry_rva < s.vaddr + span:
                host = s
                break
        if host is None:
            out.append(Finding(
                id="PE_ENTRY_OUTSIDE_SECTIONS",
                title="Entry point is outside every declared section",
                severity=Severity.HIGH,
                category="anomaly",
                detail=f"AddressOfEntryPoint RVA 0x{pe.entry_rva:x} maps into no section. "
                       "Loaders tolerate this; it defeats naive disassembly.",
                evidence=[f"entry RVA: 0x{pe.entry_rva:x}"],
            ))
        elif not host.executable:
            out.append(Finding(
                id="PE_ENTRY_IN_NONEXEC_SECTION",
                title=f"Entry point is in non-executable section {host.name!r}",
                severity=Severity.HIGH,
                category="anomaly",
                detail="Execution starts in a section not marked executable, which implies "
                       "the section flags are rewritten at load time.",
                evidence=[f"entry RVA 0x{pe.entry_rva:x} in {host.name} ({host.perms})"],
            ))
        elif host is not pe.sections[0] and host.name.lower() not in (".text", "code", ".itext", ".textbss"):
            out.append(Finding(
                id="PE_ENTRY_UNUSUAL_SECTION",
                title=f"Entry point is in section {host.name!r}, not .text",
                severity=Severity.LOW,
                category="anomaly",
                detail="Common in packed binaries, where the entry point is the unpacking stub.",
                evidence=[f"entry RVA 0x{pe.entry_rva:x} in {host.name}"],
            ))

    # A raw size far below the virtual size means the section is allocated but
    # unpopulated on disk -- filled in at runtime by an unpacker.
    for s in pe.sections:
        if s.vsize > 0x1000 and s.rawsize == 0 and s.executable:
            out.append(Finding(
                id="PE_EMPTY_EXECUTABLE_SECTION",
                title=f"Executable section {s.name!r} has no data on disk",
                severity=Severity.MEDIUM,
                category="obfuscation",
                detail=f"{s.vsize} bytes are allocated at runtime with nothing backing them "
                       "in the file -- the classic shape of an unpacking target.",
                evidence=[f"{s.name}: virtual={s.vsize}, raw=0, {s.perms}"],
                attck="T1027.002",
            ))
            break
    return out


def _check_mitigations(pe: PEFile) -> list[Finding]:
    flags = pe.dll_characteristics
    missing = []
    if not flags & 0x0040:
        missing.append("ASLR (DYNAMIC_BASE)")
    if not flags & 0x0100:
        missing.append("DEP (NX_COMPAT)")
    if not flags & 0x4000:
        missing.append("Control Flow Guard (GUARD_CF)")
    if not missing:
        return []
    # Missing mitigations are a software-quality signal, not a malware signal.
    return [Finding(
        id="PE_MISSING_MITIGATIONS",
        title=f"Built without {len(missing)} standard exploit mitigation(s)",
        severity=Severity.LOW if len(missing) < 3 else Severity.MEDIUM,
        category="hardening",
        detail="These are opt-in linker flags present in essentially all modern "
               "legitimate software. Their absence means the binary is either very "
               "old, built by a non-standard toolchain, or deliberately made easier "
               "to exploit.",
        evidence=missing + [f"DllCharacteristics: 0x{flags:04x} ("
                            + ", ".join(n for bit, n in DLLCHAR.items() if flags & bit) + ")"],
        weight=4 * len(missing),
    )]


def _check_signature(pe: PEFile) -> list[Finding]:
    if pe.has_authenticode:
        _rva, size = pe.directory(DIR_SECURITY)
        return [Finding(
            id="PE_SIGNED",
            title="Carries an embedded Authenticode signature",
            severity=Severity.INFO,
            category="provenance",
            detail="A signature block is present. Airlock does not validate the "
                   "certificate chain or timestamp -- presence is not validity, and a "
                   "stolen or self-signed certificate produces exactly this result.",
            evidence=[f"certificate table: {size} bytes"],
        )]
    return [Finding(
        id="PE_UNSIGNED",
        title="Unsigned executable",
        severity=Severity.MEDIUM,
        category="provenance",
        detail="No Authenticode signature. Reputable Windows software is signed; an "
               "unsigned installer arriving from outside is the common case for both "
               "hobbyist tools and commodity malware.",
        evidence=["certificate table: empty"],
        weight=15,
    )]


def _check_timestamp(pe: PEFile) -> list[Finding]:
    out = []
    ts = pe.timestamp
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    if ts == 0:
        out.append(Finding(
            id="PE_ZERO_TIMESTAMP",
            title="Compilation timestamp is zeroed",
            severity=Severity.LOW,
            category="anomaly",
            detail="Either a reproducible build (legitimate and increasingly common) or "
                   "deliberate removal of build provenance.",
            evidence=["TimeDateStamp: 0"],
        ))
    elif ts > now + 86400:
        when = dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat()
        out.append(Finding(
            id="PE_FUTURE_TIMESTAMP",
            title="Compilation timestamp is in the future",
            severity=Severity.MEDIUM,
            category="anomaly",
            detail="A forged header field. Used to confuse timeline analysis during "
                   "incident response.",
            evidence=[f"TimeDateStamp: {when}"],
            attck="T1070.006",
        ))
    return out


def _check_imports(pe: PEFile) -> list[Finding]:
    out: list[Finding] = []
    imports = pe.imports()
    all_funcs = [f.lower() for funcs in imports.values() for f in funcs]
    total = len(all_funcs)

    if not imports or total == 0:
        if not pe.is_dotnet:
            out.append(Finding(
                id="PE_NO_IMPORTS",
                title="Import table is empty",
                severity=Severity.HIGH,
                category="obfuscation",
                detail="A PE that imports nothing cannot call the operating system through "
                       "normal means, so it resolves its APIs itself at runtime. This is "
                       "standard packer and shellcode-loader behaviour.",
                evidence=[f"DLLs: {len(imports)}", "functions: 0"],
                attck="T1027.002",
            ))
    elif total < 10:
        out.append(Finding(
            id="PE_SPARSE_IMPORTS",
            title=f"Only {total} imported function(s) across {len(imports)} DLL(s)",
            severity=Severity.MEDIUM,
            category="obfuscation",
            detail="Too small an import table to account for any real program. The rest "
                   "of the API surface is resolved at runtime.",
            evidence=[f"{dll}: {', '.join(fns[:6]) or '(none)'}" for dll, fns in list(imports.items())[:6]],
            attck="T1027.002",
        ))

    lookup = set(all_funcs)
    for group_id, group in API_GROUPS.items():
        hits = sorted(lookup & group["apis"])
        if len(hits) < group["min_hits"]:
            continue
        # Scale severity with how much of the cluster is present.
        severity = group["severity"]
        if len(hits) >= group["min_hits"] * 3 and severity < Severity.CRITICAL:
            severity = Severity(min(int(severity) + 1, int(Severity.CRITICAL)))
        out.append(Finding(
            id=f"PE_API_{group_id.upper()}",
            title=f"Imports an API cluster for {group['title']}",
            severity=severity,
            category="capability",
            detail=f"{len(hits)} of {len(group['apis'])} APIs associated with "
                   f"{group['title']} are imported.",
            evidence=hits[:16],
            attck=group["attck"],
        ))

    # Cross-group amplification: capability groups are individually explainable,
    # but injection plus evasion plus persistence in one binary is not.
    fired = {f.id for f in out if f.id.startswith("PE_API_")}
    heavy = {"PE_API_PROCESS_INJECTION", "PE_API_ANTI_ANALYSIS", "PE_API_PERSISTENCE",
             "PE_API_CREDENTIAL_ACCESS", "PE_API_SURVEILLANCE", "PE_API_ENCRYPTION"}
    overlap = fired & heavy
    if len(overlap) >= 3:
        out.append(Finding(
            id="PE_CAPABILITY_STACK",
            title=f"{len(overlap)} independent offensive capabilities in one binary",
            severity=Severity.CRITICAL,
            category="capability",
            detail="Each capability has legitimate uses in isolation. Combined in a "
                   "single image they describe a tool built to run without the user's "
                   "knowledge and stay running.",
            evidence=sorted(i.replace("PE_API_", "").lower() for i in overlap),
            attck="T1055",
        ))
    return out


def _check_overlay(pe: PEFile) -> list[Finding]:
    size = pe.overlay_size
    if size < 4096:
        return []
    ratio = size / max(pe.size, 1)
    data = pe.sf.read_at(pe.overlay_offset, min(size, 1 << 20))
    ent = shannon(data)
    # Authenticode signatures live in the overlay, so account for the certificate
    # table before calling appended data suspicious.
    _cert_off, cert_size = pe.directory(DIR_SECURITY)
    unexplained = size - (cert_size if pe.has_authenticode else 0)
    if unexplained < 4096:
        return []
    severity = Severity.LOW
    detail = ("Data appended after the last section. Installers legitimately store "
              "payloads here.")
    if ent >= PACKED_THRESHOLD and ratio > 0.25:
        severity = Severity.MEDIUM
        detail = ("A large, high-entropy blob appended after the last section: an "
                  "encrypted or compressed second stage carried inside the file.")
    embedded = []
    if data[:2] == b"MZ":
        embedded.append("overlay begins with an MZ header (embedded PE)")
        severity = Severity.HIGH
    if data[:4] == b"PK\x03\x04":
        embedded.append("overlay begins with a ZIP header (embedded archive)")
        severity = max(severity, Severity.MEDIUM)
    return [Finding(
        id="PE_OVERLAY",
        title=f"{unexplained} bytes of appended overlay data ({ratio:.0%} of file)",
        severity=severity,
        category="structure",
        detail=detail,
        evidence=[f"offset: 0x{pe.overlay_offset:x}", f"entropy: {ent:.2f} bits/byte"] + embedded,
        attck="T1027.009" if embedded else "",
    )]


def _check_content_indicators(pe: PEFile, sf: SafeFile) -> list[Finding]:
    """Strings-level indicators. Only meaningful on unpacked binaries -- a packed
    image hides these, which is why packing is itself reported."""
    out: list[Finding] = []
    data = sf.read_at(0, min(sf.readable_size, config.MAX_REGEX_WINDOW))

    destructive = find_destructive_commands(data, context="binary")
    if destructive:
        ransom = [d for d in destructive if d[2] in ("T1490", "T1485")]
        out.append(Finding(
            id="PE_DESTRUCTIVE_COMMANDS",
            title=f"Embeds {len(destructive)} destructive or defence-disabling command(s)",
            severity=Severity.CRITICAL if ransom else Severity.HIGH,
            category="capability",
            detail="Command strings compiled into the binary. Shadow-copy deletion and "
                   "recovery tampering are the defining behaviour of ransomware."
                   if ransom else "Command strings that disable defences or cover tracks.",
            evidence=[f"{cmd} -- {desc}" for cmd, desc, _ in destructive[:10]],
            attck=destructive[0][2],
        ))

    lolbins = find_lolbins(data)
    if lolbins:
        out.append(Finding(
            id="PE_LOLBIN_USAGE",
            title=f"References {len(lolbins)} living-off-the-land execution technique(s)",
            severity=Severity.HIGH,
            category="capability",
            detail="Signed Microsoft binaries invoked with the arguments that turn them "
                   "into downloaders or script hosts, which is how execution is laundered "
                   "past allowlisting.",
            evidence=[f"{cmd} -- {desc}" for cmd, desc, _ in lolbins[:10]],
            attck=lolbins[0][2],
        ))

    persistence = find_persistence_keys(data)
    if persistence:
        out.append(Finding(
            id="PE_PERSISTENCE_KEYS",
            title="Embeds registry paths that survive a reboot",
            severity=Severity.MEDIUM if len(persistence) < 3 else Severity.HIGH,
            category="capability",
            evidence=persistence[:10],
            detail="Autostart locations written into the binary.",
            attck="T1547.001",
        ))

    iocs = extract_iocs(data)
    net = iocs["urls"] + iocs["ips"] + iocs["onion"] + iocs["unc_paths"]
    if iocs["onion"]:
        out.append(Finding(
            id="PE_TOR_ADDRESS",
            title="Embeds a Tor hidden-service address",
            severity=Severity.HIGH,
            category="network",
            detail="Legitimate desktop software almost never ships a .onion address; "
                   "ransomware payment portals and C2 channels do.",
            evidence=iocs["onion"][:5],
            attck="T1090.003",
        ))
    if net:
        out.append(Finding(
            id="PE_NETWORK_INDICATORS",
            title=f"Embeds {len(net)} hard-coded network indicator(s)",
            severity=Severity.INFO if len(net) <= 3 else Severity.LOW,
            category="network",
            detail="Addresses compiled into the binary. Review them before allowing it to run.",
            evidence=net[:15],
        ))
    return out
