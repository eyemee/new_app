"""String and indicator extraction from binary content.

Everything here runs over attacker-controlled bytes, so extraction is bounded by
byte budget rather than by anything the file claims about itself.
"""

from __future__ import annotations

import re

from . import config

_ASCII_RUN = re.compile(rb"[\x20-\x7e]{5,}")
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")

URL_RE = re.compile(rb"(?:https?|ftp|file|smb)://[\w\-.~:/?#\[\]@!$&'()*+,;=%]{4,256}", re.I)
UNC_RE = re.compile(rb"\\\\[\w.\-]{2,64}\\[\w.$\-]{1,64}")
IPV4_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
ONION_RE = re.compile(rb"\b[a-z2-7]{16,56}\.onion\b", re.I)
REGISTRY_RE = re.compile(
    rb"(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU)"
    rb"[\\/][\w\\/ .\-]{4,160}", re.I)

#: Registry locations that give code persistence across a reboot.
PERSISTENCE_KEYS = (
    b"currentversion\\run", b"currentversion\\runonce", b"currentversion\\runservices",
    b"winlogon\\shell", b"winlogon\\userinit", b"currentversion\\explorer\\shell folders",
    b"image file execution options", b"currentversion\\policies\\explorer\\run",
    b"\\environment\\userinitmprlogonscript", b"currentversion\\windows\\load",
    b"currentversion\\app paths", b"\\services\\", b"appinit_dlls",
)

#: Commands whose presence is evidence of intent rather than of capability.
#:
#: The third field is the *context* the indicator is meaningful in, and it is
#: the difference between a useful finding and noise. ``/dev/tcp/`` inside a
#: shell script is a reverse shell; inside a compiled binary it is almost
#: certainly bash, which is the program that implements the feature. The same
#: goes for ``crontab -`` and git. Matching a fragment without asking where it
#: was found flags the operating system's own tooling.
SCRIPT, BINARY, ANYWHERE = ("script",), ("binary",), ("script", "binary")

DESTRUCTIVE_COMMANDS = (
    (b"vssadmin delete shadows", "deletes Volume Shadow Copies", "T1490", ANYWHERE),
    (b"wmic shadowcopy delete", "deletes Volume Shadow Copies via WMI", "T1490", ANYWHERE),
    (b"bcdedit /set", "alters boot configuration (recovery tampering)", "T1490", ANYWHERE),
    (b"recoveryenabled no", "disables Windows recovery", "T1490", ANYWHERE),
    (b"wbadmin delete catalog", "deletes the backup catalogue", "T1490", ANYWHERE),
    (b"cipher /w", "wipes free space", "T1485", ANYWHERE),
    (b"schtasks /create", "creates a scheduled task", "T1053.005", ANYWHERE),
    (b"netsh advfirewall", "reconfigures the Windows firewall", "T1562.004", ANYWHERE),
    (b"set-mppreference", "alters Microsoft Defender settings", "T1562.001", ANYWHERE),
    (b"add-mppreference -exclusionpath", "adds a Defender exclusion", "T1562.001", ANYWHERE),
    (b"wevtutil cl", "clears an event log", "T1070.001", ANYWHERE),
    (b"clear-eventlog", "clears an event log", "T1070.001", ANYWHERE),
    (b"taskkill /f /im", "force-kills a named process", "T1562", ANYWHERE),
    (b"attrib +h +s", "hides a file as a system file", "T1564.001", ANYWHERE),
    (b"csrutil disable", "disables macOS System Integrity Protection", "T1562.001", ANYWHERE),
    # Script idioms. In a compiled binary these are the interpreter or the
    # tooling that implements them -- bash ships "/dev/tcp/", git ships
    # "crontab -" -- so matching them there flags the system's own software.
    (b"/dev/tcp/", "opens a raw TCP socket from the shell (reverse shell)", "T1059.004", SCRIPT),
    (b"history -c", "clears shell history", "T1070.003", SCRIPT),
    (b"crontab -", "installs a cron job from stdin", "T1053.003", SCRIPT),
    (b"chattr +i", "makes a file immutable", "T1222.002", SCRIPT),
    (b"launchctl load", "loads a macOS launch agent", "T1543.001", SCRIPT),
    (b"reg add", "writes to the registry from the shell", "T1112", SCRIPT),
    (b"icacls", "rewrites file ACLs", "T1222.001", SCRIPT),
)

#: Living-off-the-land binaries: signed, trusted, and abusable for execution.
LOLBINS = (
    (b"certutil", b"-urlcache", "certutil used to download", "T1105"),
    (b"certutil", b"-decode", "certutil used to decode a payload", "T1140"),
    (b"bitsadmin", b"/transfer", "bitsadmin used to download", "T1197"),
    (b"mshta", b"http", "mshta executing remote script", "T1218.005"),
    (b"regsvr32", b"scrobj.dll", "regsvr32 scriptlet execution (squiblydoo)", "T1218.010"),
    (b"rundll32", b"javascript:", "rundll32 executing inline JavaScript", "T1218.011"),
    (b"wmic", b"process call create", "WMI process creation", "T1047"),
    (b"msbuild", b"</Task>", "MSBuild inline task execution", "T1127.001"),
    (b"installutil", b"/logfile", "InstallUtil execution proxy", "T1218.004"),
    (b"cmstp", b".inf", "CMSTP execution proxy", "T1218.003"),
    (b"odbcconf", b"/a", "odbcconf DLL execution", "T1218.008"),
    (b"forfiles", b"/c", "forfiles used as an execution proxy", "T1202"),
    (b"pcalua", b"-a", "pcalua execution proxy", "T1202"),
)


def ascii_strings(data: bytes, min_len: int = 5, limit: int = 20000) -> list[bytes]:
    return [m.group() for m in _ASCII_RUN.finditer(data[:config.MAX_REGEX_WINDOW])][:limit]


def utf16_strings(data: bytes, limit: int = 20000) -> list[bytes]:
    out = []
    for m in _UTF16_RUN.finditer(data[:config.MAX_REGEX_WINDOW]):
        out.append(m.group().replace(b"\x00", b""))
        if len(out) >= limit:
            break
    return out


def all_strings(data: bytes) -> list[bytes]:
    """ASCII and UTF-16LE runs together. Windows malware stores half its
    indicators as wide strings, so looking only at ASCII misses them."""
    return ascii_strings(data) + utf16_strings(data)


def extract_iocs(data: bytes) -> dict[str, list[str]]:
    """Network and host indicators, deduplicated and capped."""
    window = data[:config.MAX_REGEX_WINDOW]
    flat = window + b"\n" + b"\n".join(utf16_strings(window)[:5000])

    def grab(pattern: re.Pattern[bytes], cap: int = 64) -> list[str]:
        seen: dict[str, None] = {}
        for m in pattern.finditer(flat):
            try:
                text = m.group().decode("utf-8", "replace")
            except Exception:
                continue
            seen.setdefault(text, None)
            if len(seen) >= cap:
                break
        return list(seen)

    urls = grab(URL_RE)
    ips = [ip for ip in grab(IPV4_RE) if not _is_uninteresting_ip(ip)]
    return {
        "urls": urls,
        "ips": ips,
        "unc_paths": grab(UNC_RE, 32),
        "onion": grab(ONION_RE, 16),
        "registry": grab(REGISTRY_RE, 48),
    }


def _is_uninteresting_ip(ip: str) -> bool:
    """Version numbers and loopback produce most IPv4 false positives."""
    if ip in ("0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8"):
        return True
    parts = ip.split(".")
    # 1.2.3.4-style version strings: every octet small and single-digit.
    return all(len(p) == 1 for p in parts)


def find_persistence_keys(data: bytes) -> list[str]:
    lowered = data[:config.MAX_REGEX_WINDOW].lower()
    wide = b"\n".join(utf16_strings(data[:config.MAX_REGEX_WINDOW])).lower()
    hits = []
    for key in PERSISTENCE_KEYS:
        if key in lowered or key in wide:
            hits.append(key.decode())
    return hits


def find_destructive_commands(data: bytes, context: str = "script") -> list[tuple[str, str, str]]:
    """Destructive commands meaningful in ``context`` ("script" or "binary")."""
    lowered = data[:config.MAX_REGEX_WINDOW].lower()
    wide = b"\n".join(utf16_strings(data[:config.MAX_REGEX_WINDOW])).lower()
    out = []
    for needle, description, attck, contexts in DESTRUCTIVE_COMMANDS:
        if context not in contexts:
            continue
        if needle in lowered or needle in wide:
            out.append((needle.decode(), description, attck))
    return out


def find_lolbins(data: bytes) -> list[tuple[str, str, str]]:
    """A LOLBin name alone is noise; the name plus its abuse argument is signal."""
    lowered = data[:config.MAX_REGEX_WINDOW].lower()
    wide = b"\n".join(utf16_strings(data[:config.MAX_REGEX_WINDOW])).lower()
    out = []
    for binary, argument, description, attck in LOLBINS:
        for haystack in (lowered, wide):
            if binary in haystack and argument.lower() in haystack:
                out.append((f"{binary.decode()} {argument.decode()}", description, attck))
                break
    return out
