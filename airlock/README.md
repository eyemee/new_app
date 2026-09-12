# Airlock

A pre-execution gate for files arriving on a machine. It inspects a download
**before** you open it, tells you what the file actually is rather than what its
name claims, and holds the ones that should not be opened.

Static analysis only. Nothing Airlock examines is ever executed, interpreted, or
extracted to disk.

```bash
PYTHONPATH=src python3 -m airlock.cli selftest
```

```
sample                         type        score  verdict     expected
----------------------------------------------------------------------------------
notes.txt                      text            0  ALLOW       ALLOW
hello-cli.exe                  pe             22  WARN        WARN
Invoice_4471.pdf.exe           pe             72  QUARANTINE  QUARANTINE
quarterly-results.pdf          pe            428  MALICIOUS   MALICIOUS
contract.docx                  zip           140  MALICIOUS   MALICIOUS
update.ps1                     text          125  MALICIOUS   MALICIOUS
...
all 18 samples produced the expected verdict
```

No dependencies. Python 3.11+, standard library only.

## What it is for

The way malware reaches a desktop is not usually a novel exploit. It is a file
whose name says `Invoice.pdf` and whose first two bytes say `MZ`, or a document
with no macros that fetches its payload from a URL on open, or a one-line
PowerShell command whose real instructions are inside a base64 blob.

All three are visible without running anything. Airlock's job is to look, in the
window between the file landing and somebody double-clicking it.

## Start here

```bash
# Is this safe to open?
PYTHONPATH=src python3 -m airlock.cli scan ~/Downloads/invoice.pdf

# Gate a whole folder, blocked files into quarantine
PYTHONPATH=src python3 -m airlock.cli scan ~/Downloads -r --quarantine

# Watch a folder: contain, scan and hold new arrivals automatically
PYTHONPATH=src python3 -m airlock.cli watch ~/Downloads
```

`scan` exits **0** allowed · **1** warnings · **2** blocked · **3** error, so it
composes:

```bash
airlock gate ./installer.run && ./installer.run
```

## What it finds

### The name is not the file

Content type comes from magic bytes. The extension is treated as an untrusted
claim by whoever sent the file, and the gap between the two is the finding.

| Technique | What Airlock shows you |
| --- | --- |
| **Right-to-left override** | `annexe‮gnp.exe` — *renders as* `annexeexe.png`, *actually is* `annexe‮gnp.exe` |
| **Double extension** | `Invoice_2024.pdf.exe`, and how it renders once Windows hides the real extension |
| **Homoglyphs** | `Аdobe_Reader.exe` — the `А` is Cyrillic U+0410 |
| **Type mismatch** | "the bytes are a Windows PE executable, the name claims `.pdf`" |
| Zero-width characters, trailing dots and spaces, reserved device names, overlong names | |

Homoglyph detection compares scripts **within a single word**, so `отчет.pdf`
and `日本語資料.pdf` are clean while `Аdobe` is not.

### Executables

The PE parser reads the import table and reports *capabilities*, not API names:

```
  CRITICAL  Imports an API cluster for process injection
            9 of 20 APIs associated with process injection are imported.
            · createremotethread
            · ntqueueapcthread
            · ntunmapviewofsection
            · openprocess
            · resumethread
            · ... and 4 more
            ATT&CK T1055 · PE_API_PROCESS_INJECTION (+70)

  CRITICAL  3 independent offensive capabilities in one binary
            Each capability has legitimate uses in isolation. Combined in a single image
            they describe a tool built to run without the user's knowledge and stay
            running.
            · anti_analysis
            · persistence
            · process_injection
            ATT&CK T1055 · PE_CAPABILITY_STACK (+70)
```

Also: packer and section-entropy analysis, W+X sections, entry points outside
`.text`, missing ASLR/DEP/CFG, Authenticode presence, appended overlay data,
and embedded commands (`vssadmin delete shadows`, `certutil -urlcache`,
`.onion` addresses). ELF and Mach-O get structure, packing and RWX-segment
checks.

### Documents

- **Remote template injection** — a `.docx` with no macros that pulls
  `attachedTemplate` from `http://…` on open. This is the shape that passes
  "does it have macros?"
- **Macros**, with the distinction that matters: a `.docm` carrying a VBA project
  is HIGH (the extension is honest); a `.docx` carrying one is CRITICAL and
  blocking (the extension was chosen to pass filters).
- **DDE fields**, Excel 4.0 macro sheets, ActiveX, embedded OLE objects.
- **PDF**: `/OpenAction` + `/JavaScript` together, `/Launch`, embedded files,
  and hex-escaped name evasion — `/#4A#61vaScript` is normalised before matching.
- **Legacy OLE2**: VBA streams and the Equation Editor object (CVE-2017-11882).

### Archives

Zip-slip (`../../etc/cron.d/x`), decompression bombs, password-protected entries
that nothing in the chain can inspect, executables hidden in dot-directories,
tar members with setuid bits or symlinks pointing outside the archive. Signature
rules run against entries too, so a payload does not escape inspection by being
compressed.

### Scripts, layer by layer

A malicious script is a loader. Airlock decodes and re-analyses each layer, and
tags every finding with where it came from:

```
HIGH  Contains a 340-character base64 layer that decodes to script  [base64[0]]
HIGH  Invoke-Expression on constructed data                         [base64[0]]
HIGH  Downloads content at runtime                                  [base64[0]]
      $c = New-Object Net.WebClient; $d = $c.DownloadString('http://…'); IEX $d
```

`-EncodedCommand` payloads are UTF-16LE; decoding them as UTF-8 and giving up is
the most common way a scanner misses this entirely.

## Verdicts

`ALLOW` → `WARN` → `QUARANTINE` → `MALICIOUS`.

The gap between the last two is deliberate. QUARANTINE says *blocked, go and
look*; one CRITICAL finding earns that. MALICIOUS says *this is malware, delete
it* — a much stronger claim, needing a decisive finding (a known-bad digest, an
executable wearing a document's name) or several independent strong signals.

**Weak signals do not stack into strong ones.** Within a category, each
successive finding contributes less. A legitimately UPX-packed unsigned
installer produces six MEDIUM findings — packed, high entropy, few imports,
unusual entry point, unsigned, no CFG — which are one observation seen six ways,
not six reasons. Summing them would call it malware. It scores QUARANTINE, and
the reasons are on screen.

```
                        raw    damped   verdict
clean unsigned binary    22        22   WARN
UPX-packed installer    117        88   QUARANTINE
process injector        420       358   MALICIOUS
```

### Policy profiles

```bash
airlock scan file --profile strict
```

| | `permissive` | `standard` | `strict` | `paranoid` |
| --- | --- | --- | --- | --- |
| Honest `.docm` with macros | WARN | WARN | **QUARANTINE** | **QUARANTINE** |
| Clean unsigned executable | WARN | WARN | WARN | **QUARANTINE** |
| Contents that could not be inspected | — | — | block | block |

Profiles only ever escalate. None of them hides a finding.

## Security properties

Airlock parses attacker-controlled input for a living, so it is built to be a
poor target.

**Nothing is executed.** No `eval`, no subprocess, no extraction to disk. Rules
are data, parsed by recursive descent into tuples and walked — a rule file
cannot execute anything.

**No symlink traversal, no TOCTOU.** Files are opened `O_NOFOLLOW`, checked with
`fstat` to be regular files, and *everything* — hashing, parsing, quarantine
intake — works on that one descriptor. What gets quarantined is what got
scanned, even if the path is swapped mid-scan.

**Everything is bounded.** File size, parse windows, archive entry counts,
expansion ratios, recursion depth, regex scan windows, wall-clock timeout. No
loop terminates against a number the file supplied.

**It fails closed.** A parser that raises, a timeout, a symlink, a file that
could not be fully read — all produce `QUARANTINE`, never `ALLOW`. A file we
could not finish looking at is not a file we can vouch for.

**Rules are integrity-checked.** Rule files are content-addressed in
`rules/rules.lock`. A modified or unpinned ruleset raises and refuses to scan,
because scanning with silently tampered rules is worse than not scanning — the
operator believes they are covered. Rule regexes are length-capped and rejected
for nested quantifiers (ReDoS).

**The audit log is tamper-evident.** Each record chains to the previous digest
and is authenticated with an HMAC under a key stored 0600:

```bash
$ airlock log verify
audit chain intact: 21 record(s) verified
```

Edit a record and it names it:

```
AUDIT CHAIN BROKEN (3 problem(s)):
  · record 2: sequence is 3, expected 2 -- a record was inserted or removed
  · record 3: prev digest d1fd43bd... does not match the previous record's 4bcd5268...
  · record 3: content does not match its authenticator -- this record was modified
```

**The vault is inert.** Held files are stored under a random identifier (never
the attacker-chosen name), mode 0600 in a 0700 directory, execute bits cleared,
suffixed `.quarantined`. Releasing a MALICIOUS file requires `--force` and is
logged. Released names are stripped of separators, control characters and bidi
overrides — a file handed back to a desktop should not still be wearing its
disguise.

## Publisher pinning

The one check here that catches something genuinely new:

```bash
airlock pin add ~/Downloads/vendor-tool-3.2.0.exe
# ... a month later, having downloaded it again ...
```

```
HIGH  Digest differs from the pinned copy of 'vendor-tool-3.2.0.exe'
      You pinned a build of this name before and this is not it. That is either
      a legitimate update or a substituted download -- a compromised mirror, a
      hijacked update channel, a man-in-the-middle. Verify against the vendor's
      published checksum before running it, then re-pin.
      pinned:  9f2b... (4531200 bytes, 2026-08-14T09:12:03Z)
      current: 71ae...
      ATT&CK T1195.002
```

Reported, never auto-blocked — an update is a mismatch too.

## Optional online reputation

Off by default.

```bash
VT_API_KEY=… airlock scan file.exe --online
```

Only the SHA-256 leaves the machine — never the file, its name, or its path. A
failed lookup is recorded as unknown and never lowers a verdict.

## Signature rules

A small data-only format. `2 of them`, `all of them`, `$a and not $b`,
parenthesised groups; text, `{ 4D 5A ?? 00 }` hex with wildcards, and regex.

```
rule Remote_Template_Injection : document {
    meta:
        severity = "critical"
        attck = "T1221"
        description = "Office relationship pointing at a remote template"
    strings:
        $rel  = "attachedTemplate"
        $ext  = "TargetMode=\"External\""
        $http = "Target=\"http"
        $unc  = "Target=\"\\\\"
    condition:
        $rel and $ext and 1 of ($http, $unc)
}
```

`applies_to` and `excludes` gate a rule by file type, so "an MZ header inside
this file" fires on a document without firing on every executable ever scanned.

```bash
airlock rules list        # what is loaded
airlock rules verify      # digests match the lockfile
airlock rules pin         # approve the current rule files
```

## The watcher

```bash
airlock watch ~/Downloads
```

```
14:22:07  [ALLOW]      notes.txt  (0)
            left in place
14:22:09  [MALICIOUS]  report.docx  (140)  — Document fetches a remote template injection on open
            moved to quarantine as 20260912T142209Z-16c18271d3c7
```

It waits for a file to stop changing — scanning a half-downloaded file gives a
confident *wrong* answer — then clears its execute bits **before** scanning,
because the scan takes time and that time is exactly when a fresh download gets
double-clicked.

## What this is not

Worth being exact about, because security tools are easy to over-claim.

**It is not execution prevention.** A userspace poller cannot stop a process
from starting. Real pre-execution blocking needs an OS hook: AppLocker or WDAC
on Windows, Gatekeeper and Endpoint Security on macOS, fanotify with
`FAN_OPEN_PERM` on Linux. Airlock is complementary to those.

**It is not an antivirus.** There is no commercial signature feed, no behavioural
sandbox, no kernel driver, no cloud telemetry, no memory scanning. It will not
catch a compiled payload with no notable imports, a clean-looking dropper whose
logic is in a remote second stage, or anything already running.

**A clean verdict means nothing matched.** It does not mean the file is safe.

**Detection is heuristic and static.** Packed binaries hide their contents by
design — that is reported, but the contents stay hidden. Legitimate software
gets flagged (installers pack themselves; admin tools call admin APIs). The
findings are written to be read, so you can disagree with one.

## Tests

```bash
pip install pytest && python3 -m pytest tests/ -q
```

203 tests. The sample corpus is ground truth: each of the 18 synthetic samples
asserts its verdict, so a heuristic change cannot quietly reclassify something.
Included among them are the false-positive tests that matter most — a real
system binary, an ordinary shell script, a plain `.docx`, a Russian filename.

Every sample is **generated inert**. The "suspicious" PE imports dangerous APIs
and its code section is breakpoint padding; the obfuscated PowerShell decodes to
an echo. The EICAR test string is assembled at runtime rather than committed, so
checking out this repository does not trip your own antivirus.

## Layout

```
src/airlock/
  safeio.py      O_NOFOLLOW, fd-pinned, bounded reads — the only code that touches hostile files
  identify.py    magic-byte typing, and the name-versus-content checks
  verdict.py     findings, severities, damped scoring, fail-closed decisions
  scanner.py     orchestration, policy profiles, timeout
  rules.py       data-only signature engine with integrity pinning
  reputation.py  known-bad, allowlist, publisher pinning, optional online lookup
  quarantine.py  the vault
  audit.py       HMAC hash-chained log
  watch.py       the folder gate
  formats/       pe · elf · archive (+ooxml) · pdf · script
  samples.py     synthetic corpus generator
```

Design rationale is in [docs/DESIGN.md](docs/DESIGN.md); the threat model,
including what an attacker who reads this code can do about it, is in
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
