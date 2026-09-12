"""Script analysis with recursive layer decoding.

A malicious script is almost never malicious on its surface. It is a loader: one
line of base64, hex or string arithmetic whose only job is to produce the real
script and hand it to an interpreter. Reading only the outer layer is how a
scanner sees ``powershell -enc <blob>`` and reports nothing.

So this analyser peels. Each layer it decodes is analysed with the same rules as
the outer file, and every finding records which layer it came from. Decoding is
bounded by ``MAX_RECURSION_DEPTH`` and by a byte budget -- a script that nests
deeper than the budget is reported as such rather than followed.
"""

from __future__ import annotations

import base64
import binascii
import re
import statistics

from .. import config
from ..entropy import shannon
from ..safeio import SafeFile
from ..strings import extract_iocs, find_destructive_commands, find_lolbins
from ..verdict import Finding, Severity

# --------------------------------------------------------------------------
# Indicator tables. (pattern, id, title, severity, ATT&CK)
# --------------------------------------------------------------------------
POWERSHELL_INDICATORS: list[tuple[re.Pattern[str], str, str, Severity, str]] = [
    (re.compile(r"-e(?:nc|ncoded|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}", re.I),
     "PS_ENCODED_COMMAND", "Base64 -EncodedCommand payload", Severity.HIGH, "T1027"),
    (re.compile(r"\b(?:iex|invoke-expression)\b", re.I),
     "PS_IEX", "Invoke-Expression on constructed data", Severity.HIGH, "T1059.001"),
    (re.compile(r"frombase64string", re.I),
     "PS_FROMBASE64", "Runtime base64 decoding", Severity.MEDIUM, "T1140"),
    (re.compile(r"downloadstring|downloadfile|downloaddata|invoke-webrequest|invoke-restmethod|\bwget\b|\bcurl\b", re.I),
     "PS_DOWNLOADER", "Downloads content at runtime", Severity.HIGH, "T1105"),
    (re.compile(r"-w(?:indowstyle)?\s+hidden|-nop\b|-noprofile|-noninteractive|-executionpolicy\s+bypass|-ep\s+bypass", re.I),
     "PS_HIDDEN_EXECUTION", "Launches hidden and without profile or policy", Severity.HIGH, "T1564.003"),
    (re.compile(r"\[reflection\.assembly\]::load|\[appdomain\]|assembly\.load", re.I),
     "PS_REFLECTIVE_LOAD", "Loads a .NET assembly from memory", Severity.HIGH, "T1620"),
    (re.compile(r"add-type\s+.*(?:-memberdefinition|dllimport)", re.I | re.S),
     "PS_PINVOKE", "Declares native Win32 calls via P/Invoke", Severity.HIGH, "T1106"),
    (re.compile(r"virtualalloc|writeprocessmemory|createremotethread|memcpy", re.I),
     "PS_INJECTION_API", "Calls process-injection APIs from script", Severity.CRITICAL, "T1055"),
    (re.compile(r"set-mppreference|add-mppreference|-disablerealtimemonitoring|-exclusionpath", re.I),
     "PS_DEFENDER_TAMPER", "Disables or excludes paths from Microsoft Defender", Severity.CRITICAL, "T1562.001"),
    (re.compile(r"new-object\s+system\.net\.sockets\.tcpclient|net\.sockets", re.I),
     "PS_RAW_SOCKET", "Opens a raw TCP socket", Severity.HIGH, "T1071"),
    (re.compile(r"start-process\s+.*-verb\s+runas", re.I),
     "PS_ELEVATION", "Requests elevation", Severity.MEDIUM, "T1548.002"),
    (re.compile(r"new-itemproperty.*currentversion\\\\?run|schtasks\s+/create|register-scheduledtask|new-service", re.I),
     "PS_PERSISTENCE", "Installs an autostart entry", Severity.HIGH, "T1547.001"),
    (re.compile(r"bypass\s+-c|hidden\s+-c|\|\s*iex", re.I),
     "PS_ONELINER", "Download-and-execute one-liner", Severity.HIGH, "T1059.001"),
    (re.compile(r"get-wmiobject|get-ciminstance|win32_", re.I),
     "PS_WMI", "WMI queries", Severity.LOW, "T1047"),
    (re.compile(r"convertto-securestring|get-credential|\$cred\b", re.I),
     "PS_CREDENTIALS", "Handles credentials", Severity.MEDIUM, "T1555"),
]

SHELL_INDICATORS: list[tuple[re.Pattern[str], str, str, Severity, str]] = [
    (re.compile(r"(?:curl|wget)[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b", re.I),
     "SH_CURL_PIPE_SHELL", "Pipes a downloaded script straight into a shell", Severity.HIGH, "T1059.004"),
    (re.compile(r"/dev/tcp/|/dev/udp/"),
     "SH_REVERSE_SHELL", "Opens a raw socket through /dev/tcp (reverse shell)", Severity.CRITICAL, "T1059.004"),
    (re.compile(r"\bnc\b[^\n]{0,60}\s-[a-z]*e[a-z]*\s|\bncat\b[^\n]{0,60}--exec"),
     "SH_NETCAT_EXEC", "netcat with command execution", Severity.CRITICAL, "T1059.004"),
    (re.compile(r"base64\s+(?:-d|--decode)[^\n]{0,60}\|\s*(?:ba)?sh|openssl\s+enc\s+-d[^\n]*\|\s*sh"),
     "SH_DECODE_EXEC", "Decodes and executes in one pipeline", Severity.HIGH, "T1140"),
    (re.compile(r"crontab\s+-|/etc/cron\.|systemctl\s+enable|/etc/systemd/system/|launchctl\s+load|~/Library/LaunchAgents"),
     "SH_PERSISTENCE", "Installs a persistent job or service", Severity.HIGH, "T1053.003"),
    (re.compile(r"history\s+-c|unset\s+HISTFILE|export\s+HISTSIZE=0|rm\s+[^\n]*\.bash_history|shred\s"),
     "SH_ANTI_FORENSICS", "Clears shell history or shreds evidence", Severity.HIGH, "T1070.003"),
    (re.compile(r"chattr\s+\+i|setenforce\s+0|systemctl\s+stop\s+(?:firewalld|auditd|apparmor)|ufw\s+disable|csrutil\s+disable"),
     "SH_DEFENCE_EVASION", "Disables a security control", Severity.CRITICAL, "T1562.001"),
    (re.compile(r"\brm\s+-rf\s+(?:/|/\*|~|\$HOME)(?:\s|$)"),
     "SH_DESTRUCTIVE_DELETE", "Recursive delete of a filesystem root or home directory", Severity.CRITICAL, "T1485"),
    (re.compile(r"chmod\s+[+0-7]*[0-7]?777|chmod\s+\+s|chown\s+root"),
     "SH_PERMISSION_CHANGE", "Broad permission or ownership change", Severity.MEDIUM, "T1222.002"),
    (re.compile(r"\bsudo\s+-S\b|echo\s+[^\n|]*\|\s*sudo\s+-S"),
     "SH_PASSWORD_PIPE", "Feeds a password into sudo on stdin", Severity.HIGH, "T1078"),
    (re.compile(r"~/\.ssh/authorized_keys|\.ssh/id_rsa|/etc/shadow|/etc/passwd\b"),
     "SH_CREDENTIAL_PATH", "Touches SSH keys or the local credential store", Severity.HIGH, "T1552.004"),
    (re.compile(r"\bnohup\b[^\n]*&|\bdisown\b|setsid\s"),
     "SH_BACKGROUND_DETACH", "Detaches a process from the session", Severity.LOW, "T1564"),
]

WSH_INDICATORS: list[tuple[re.Pattern[str], str, str, Severity, str]] = [
    (re.compile(r"new\s+activexobject|createobject\s*\(", re.I),
     "WSH_ACTIVEX", "Instantiates a COM/ActiveX object", Severity.HIGH, "T1059.005"),
    (re.compile(r"wscript\.shell|shell\.application|\.run\s*\(|\.exec\s*\(", re.I),
     "WSH_SHELL_EXEC", "Runs a shell command", Severity.HIGH, "T1059.005"),
    (re.compile(r"\beval\s*\(|\bunescape\s*\(|\bfunction\s*\(\s*\)\s*\{\s*return\s+eval", re.I),
     "WSH_EVAL", "Evaluates constructed code", Severity.HIGH, "T1059.007"),
    (re.compile(r"msxml2\.xmlhttp|winhttp\.winhttprequest|adodb\.stream", re.I),
     "WSH_DOWNLOADER", "HTTP download plus stream-to-disk", Severity.HIGH, "T1105"),
    (re.compile(r"document\.write\s*\(\s*unescape|String\.fromCharCode\s*\(", re.I),
     "WSH_CHARCODE_OBFUSCATION", "Builds code from character codes", Severity.MEDIUM, "T1027"),
    (re.compile(r"powershell(?:\.exe)?\s+-", re.I),
     "WSH_SPAWNS_POWERSHELL", "Spawns PowerShell", Severity.HIGH, "T1059.001"),
]

PYTHON_INDICATORS: list[tuple[re.Pattern[str], str, str, Severity, str]] = [
    (re.compile(r"\bexec\s*\(\s*(?:base64|codecs|zlib|marshal|__import__)", re.I),
     "PY_EXEC_DECODED", "Executes decoded or decompressed data", Severity.CRITICAL, "T1027"),
    (re.compile(r"\bos\.system\s*\(|subprocess\.(?:call|run|Popen|check_output)"),
     "PY_SHELL_EXEC", "Runs a shell command", Severity.LOW, "T1059.006"),
    (re.compile(r"socket\.socket[^\n]{0,200}(?:connect|SOCK_STREAM)[^\n]{0,400}(?:dup2|subprocess)", re.S),
     "PY_REVERSE_SHELL", "Socket wired to a subprocess (reverse shell)", Severity.CRITICAL, "T1059.006"),
    (re.compile(r"pickle\.loads?\s*\(|marshal\.loads?\s*\("),
     "PY_UNSAFE_DESERIALISE", "Deserialises untrusted data (arbitrary code execution)", Severity.HIGH, "T1059.006"),
    (re.compile(r"ctypes\.(?:windll|CDLL|cdll)|ctypes\.memmove|VirtualAlloc"),
     "PY_NATIVE_CALLS", "Calls native APIs through ctypes", Severity.MEDIUM, "T1106"),
    (re.compile(r"urllib[^\n]{0,80}urlopen|requests\.get[^\n]{0,200}(?:exec|eval|write)", re.S),
     "PY_DOWNLOADER", "Fetches remote content and acts on it", Severity.MEDIUM, "T1105"),
]

BATCH_INDICATORS: list[tuple[re.Pattern[str], str, str, Severity, str]] = [
    (re.compile(r"powershell[^\n]{0,80}-(?:enc|e)\s+[A-Za-z0-9+/=]{40,}", re.I),
     "BAT_ENCODED_POWERSHELL", "Launches an encoded PowerShell payload", Severity.CRITICAL, "T1059.001"),
    (re.compile(r"\bstart\s+/min|\bstart\s+\"\"\s+/b", re.I),
     "BAT_HIDDEN_START", "Starts a process minimised or detached", Severity.MEDIUM, "T1564.003"),
    (re.compile(r"reg\s+add[^\n]{0,120}(?:\\Run|\\RunOnce)", re.I),
     "BAT_PERSISTENCE", "Writes a Run key", Severity.HIGH, "T1547.001"),
    (re.compile(r"vssadmin[^\n]{0,40}delete|wbadmin[^\n]{0,40}delete|bcdedit[^\n]{0,60}recoveryenabled", re.I),
     "BAT_DESTROYS_RECOVERY", "Destroys backups or recovery configuration", Severity.CRITICAL, "T1490"),
]

LANGUAGE_TABLES = {
    "powershell": POWERSHELL_INDICATORS,
    "shell": SHELL_INDICATORS,
    "jscript": WSH_INDICATORS,
    "vbscript": WSH_INDICATORS,
    "hta": WSH_INDICATORS,
    "html": WSH_INDICATORS,
    "python": PYTHON_INDICATORS,
    "batch": BATCH_INDICATORS,
}

_B64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_RUN = re.compile(r"(?:0x)?[0-9a-fA-F]{60,}")
_PS_ESCAPE = re.compile(r"`[a-z]", re.I)
_CHAR_BUILD = re.compile(r"\[char\]\s*\d+|chr\s*\(\s*\d+\s*\)|String\.fromCharCode", re.I)
_CONCAT_BUILD = re.compile(r"['\"][^'\"\n]{0,4}['\"]\s*\+\s*['\"][^'\"\n]{0,4}['\"]")
_FORMAT_BUILD = re.compile(r"\{\d\}[^\n]{0,40}-f\s+['\"]", re.I)


def analyse(sf: SafeFile, kind: str, name: str, ruleset=None) -> list[Finding]:
    raw = sf.read_at(0, min(sf.readable_size, config.MAX_DECODED_LAYER_BYTES))
    text = raw.decode("utf-8", "replace")
    return analyse_text(text, kind, name, depth=0, layer="", ruleset=ruleset)


def analyse_text(text: str, kind: str, name: str, depth: int, layer: str,
                 ruleset=None) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_match_indicators(text, kind, layer))
    findings.extend(_check_obfuscation(text, kind, layer))
    findings.extend(_check_shared_indicators(text, layer))
    # Signature rules run against every decoded layer, not just the outer text.
    # The outer layer of a loader is, by construction, the part with nothing in
    # it worth matching.
    if ruleset is not None and layer:
        findings.extend(ruleset.scan(text.encode("utf-8", "replace"), layer=layer, kind=kind))
    if depth < config.MAX_RECURSION_DEPTH:
        findings.extend(_decode_layers(text, kind, name, depth, layer, ruleset))
    return findings


def _match_indicators(text: str, kind: str, layer: str) -> list[Finding]:
    tables = LANGUAGE_TABLES.get(kind)
    if tables is None:
        # An unrecognised script language still gets every table: a .txt file
        # full of PowerShell is still PowerShell to whoever renames it.
        tables = [row for table in (POWERSHELL_INDICATORS, SHELL_INDICATORS,
                                    WSH_INDICATORS, BATCH_INDICATORS) for row in table]
    window = text[:config.MAX_REGEX_WINDOW]
    out: list[Finding] = []
    for pattern, fid, title, severity, attck in tables:
        match = pattern.search(window)
        if not match:
            continue
        out.append(Finding(
            id=fid,
            title=title + (f" (layer {layer})" if layer else ""),
            severity=severity,
            category="script",
            detail=_INDICATOR_DETAIL.get(fid, ""),
            evidence=[_excerpt(window, match.start(), match.end())],
            attck=attck,
            layer=layer,
        ))
    return out


def _check_obfuscation(text: str, kind: str, layer: str) -> list[Finding]:
    """Measure how hard the script is working to be unreadable."""
    out: list[Finding] = []
    window = text[:config.MAX_REGEX_WINDOW]
    if len(window) < 40:
        return out

    signals: list[str] = []
    score = 0

    escapes = len(_PS_ESCAPE.findall(window))
    if escapes >= 8:
        signals.append(f"{escapes} backtick escapes inside identifiers")
        score += 2
    chars = len(_CHAR_BUILD.findall(window))
    if chars >= 5:
        signals.append(f"{chars} characters assembled from numeric codes")
        score += 2
    concat = len(_CONCAT_BUILD.findall(window))
    if concat >= 5:
        signals.append(f"{concat} split-string concatenations")
        score += 2
    if _FORMAT_BUILD.search(window):
        signals.append("format-operator string reassembly")
        score += 2

    lines = [ln for ln in window.splitlines() if ln.strip()]
    if lines:
        longest = max(len(ln) for ln in lines)
        median = statistics.median(len(ln) for ln in lines)
        if longest > 2000 and median < 100:
            signals.append(f"one line of {longest} characters among otherwise short lines")
            score += 2
    ent = shannon(window.encode("utf-8", "replace")[:1 << 20])
    if ent > 5.4 and len(window) > 512:
        signals.append(f"character entropy {ent:.2f} bits/byte (plain source sits near 4.5)")
        score += 1

    if score >= 4:
        out.append(Finding(
            id="SCRIPT_OBFUSCATED",
            title="Script is deliberately obfuscated",
            severity=Severity.HIGH if score >= 6 else Severity.MEDIUM,
            category="obfuscation",
            detail=("Obfuscation in a script that arrived from outside has one purpose: to "
                    "stop a reviewer and a scanner from reading what it does. Legitimate "
                    "minification does not use these constructions."),
            evidence=signals,
            attck="T1027.010",
            layer=layer,
        ))
    return out


def _check_shared_indicators(text: str, layer: str) -> list[Finding]:
    """LOLBins, destructive commands and network IOCs, shared with the PE path."""
    data = text.encode("utf-8", "replace")[:config.MAX_REGEX_WINDOW]
    out: list[Finding] = []

    destructive = find_destructive_commands(data)
    if destructive:
        ransom = [d for d in destructive if d[2] in ("T1490", "T1485")]
        out.append(Finding(
            id="SCRIPT_DESTRUCTIVE_COMMANDS",
            title=f"Runs {len(destructive)} destructive or defence-disabling command(s)",
            severity=Severity.CRITICAL if ransom else Severity.HIGH,
            category="capability",
            evidence=[f"{cmd} -- {desc}" for cmd, desc, _ in destructive[:10]],
            detail="Commands that remove recovery options or disable security controls.",
            attck=destructive[0][2],
            layer=layer,
        ))
    lolbins = find_lolbins(data)
    if lolbins:
        out.append(Finding(
            id="SCRIPT_LOLBIN_USAGE",
            title=f"Invokes {len(lolbins)} living-off-the-land technique(s)",
            severity=Severity.HIGH,
            category="capability",
            evidence=[f"{cmd} -- {desc}" for cmd, desc, _ in lolbins[:10]],
            detail="Trusted system binaries used as downloaders or script hosts.",
            attck=lolbins[0][2],
            layer=layer,
        ))
    iocs = extract_iocs(data)
    net = iocs["urls"] + iocs["onion"] + iocs["unc_paths"]
    if iocs["onion"]:
        out.append(Finding(
            id="SCRIPT_TOR_ADDRESS", title="References a Tor hidden service",
            severity=Severity.HIGH, category="network", evidence=iocs["onion"][:5],
            detail="A .onion endpoint in a script is a C2 or payment channel.",
            attck="T1090.003", layer=layer))
    if net:
        out.append(Finding(
            id="SCRIPT_NETWORK_INDICATORS",
            title=f"Contacts {len(net)} hard-coded address(es)",
            severity=Severity.LOW if len(net) <= 2 else Severity.MEDIUM,
            category="network", evidence=net[:12],
            detail="Review every destination before running this.", layer=layer))
    return out


def _decode_layers(text: str, kind: str, name: str, depth: int, layer: str,
                   ruleset=None) -> list[Finding]:
    """Decode embedded base64/hex blobs and re-analyse what comes out."""
    out: list[Finding] = []
    budget = config.MAX_DECODED_LAYER_BYTES
    seen: set[str] = set()

    for index, match in enumerate(_B64_RUN.finditer(text[:config.MAX_REGEX_WINDOW])):
        if index >= 8 or budget <= 0:
            break
        blob = match.group()
        decoded = _try_base64(blob)
        if decoded is None:
            continue
        rendered = _render(decoded)
        if rendered is None or len(rendered) < 16:
            continue
        digest = rendered[:200]
        if digest in seen:
            continue
        seen.add(digest)
        budget -= len(rendered)
        child_layer = f"{layer}/base64[{index}]" if layer else f"base64[{index}]"

        out.append(Finding(
            id="SCRIPT_ENCODED_LAYER",
            title=f"Contains a {len(blob)}-character base64 layer that decodes to script",
            severity=Severity.HIGH,
            category="obfuscation",
            detail=("The real instruction set is not in the visible text. Decoded and "
                    "analysed below; findings from it are tagged with their layer."),
            evidence=[f"encoded: {blob[:60]}...",
                      f"decodes to: {rendered[:160].strip()}"],
            attck="T1027",
            layer=child_layer,
        ))
        out.extend(analyse_text(rendered, _guess_kind(rendered, kind), name,
                                depth + 1, child_layer, ruleset))

    # Long hex runs that decode to text are the other common wrapper.
    for index, match in enumerate(_HEX_RUN.finditer(text[:config.MAX_REGEX_WINDOW])):
        if index >= 4 or budget <= 0:
            break
        blob = match.group().removeprefix("0x")
        if len(blob) % 2:
            blob = blob[:-1]
        try:
            decoded = binascii.unhexlify(blob)
        except (binascii.Error, ValueError):
            continue
        rendered = _render(decoded)
        if rendered is None or len(rendered) < 16:
            continue
        budget -= len(rendered)
        child_layer = f"{layer}/hex[{index}]" if layer else f"hex[{index}]"
        out.append(Finding(
            id="SCRIPT_HEX_LAYER",
            title=f"Contains a {len(blob)}-character hex layer that decodes to text",
            severity=Severity.MEDIUM,
            category="obfuscation",
            evidence=[f"decodes to: {rendered[:160].strip()}"],
            detail="Hex encoding of an embedded stage.",
            attck="T1027",
            layer=child_layer,
        ))
        out.extend(analyse_text(rendered, _guess_kind(rendered, kind), name,
                                depth + 1, child_layer, ruleset))
    return out


def _try_base64(blob: str) -> bytes | None:
    padded = blob + "=" * (-len(blob) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None


def _render(decoded: bytes) -> str | None:
    """Turn decoded bytes into text if they are text.

    PowerShell's ``-EncodedCommand`` is UTF-16LE, so a successful decode that
    looks like NUL-interleaved ASCII is decoded as wide text rather than
    discarded as binary -- missing this is the single most common way a scanner
    fails to see an encoded payload.
    """
    if not decoded:
        return None
    sample = decoded[:512]
    nul_ratio = sample.count(0) / len(sample)
    if 0.3 < nul_ratio < 0.7 and len(decoded) % 2 == 0:
        try:
            text = decoded.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
    else:
        try:
            text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            return None
    printable = sum(1 for c in text[:2048] if c.isprintable() or c in "\r\n\t")
    if not text or printable / min(len(text), 2048) < 0.85:
        return None
    return text


def _guess_kind(text: str, fallback: str) -> str:
    lowered = text[:2048].lower()
    if any(t in lowered for t in ("$", "new-object", "invoke-", "write-host", "-encodedcommand")):
        return "powershell"
    if any(t in lowered for t in ("#!/bin/", "curl ", "wget ", "/dev/tcp")):
        return "shell"
    if any(t in lowered for t in ("activexobject", "wscript.", "createobject")):
        return "jscript"
    if "import " in lowered and "def " in lowered:
        return "python"
    return fallback


def _excerpt(text: str, start: int, end: int, pad: int = 40) -> str:
    snippet = text[max(0, start - pad):min(len(text), end + pad)]
    snippet = " ".join(snippet.split())
    return (snippet[:200] + "...") if len(snippet) > 200 else snippet


_INDICATOR_DETAIL = {
    "PS_ENCODED_COMMAND": "A base64 blob passed to -EncodedCommand hides the payload from "
                          "logs, from the user, and from anything reading only the command line.",
    "PS_IEX": "Invoke-Expression runs text as code. Combined with a downloader it is the "
              "fileless execution pattern -- nothing is ever written to disk to be scanned.",
    "PS_DEFENDER_TAMPER": "Turning off real-time protection or excluding a path is a "
                          "precondition to running something the scanner would catch.",
    "PS_INJECTION_API": "Injection APIs reached from a script mean shellcode, not administration.",
    "SH_REVERSE_SHELL": "Bash's /dev/tcp needs no tooling on the host and leaves no binary behind.",
    "SH_CURL_PIPE_SHELL": "The fetched script is executed unread. Whatever the server returns "
                          "at that moment runs with your privileges.",
    "SH_DEFENCE_EVASION": "Disabling a security control is never a side effect.",
    "PY_EXEC_DECODED": "exec() over decoded data means the visible source is not the program.",
}
