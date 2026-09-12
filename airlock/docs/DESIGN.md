# Why Airlock is built this way

## The diagnosis

The instinct when asked for "something that stops malware getting in" is to
build a scanner that recognises malware. That is the wrong target for anything
built from scratch, for a reason worth stating plainly:

> **Recognition-based detection is a data problem, not a code problem.**

An antivirus engine is not valuable because of its matching algorithm. It is
valuable because of a signature feed maintained by a team watching live
campaigns, a cloud reputation graph covering billions of files, and a
behavioural sandbox. None of that can be written; it has to be *operated*, at
scale, continuously. A from-scratch tool with a hash list is a worse antivirus
than the free one already on the machine.

So the question is not "how do I recognise malware?" It is: **what is knowable
about a file, from the file alone, that the user cannot see and an attacker
cannot cheaply remove?**

There are three such things, and they are what Airlock is built on.

## 1. What a file *is* versus what it *says* it is

A file has two identities. Its content type is a fact about its bytes. Its
extension is a claim made by whoever sent it. Users act on the second; the
operating system acts on the first.

That gap is the delivery mechanism for most desktop compromise, and it is
completely visible statically:

| Trick | Renders as | Actually is |
| --- | --- | --- |
| `annexe‮gnp.exe` | `annexeexe.png` | a PE executable |
| `Invoice_2024.pdf.exe` | `Invoice_2024.pdf` (Windows hides known extensions) | a PE executable |
| `Аdobe_Reader.exe` | `Adobe_Reader.exe` | whatever it likes; the `А` is Cyrillic |

An attacker cannot remove this signal without giving up the deception, because
the deception *is* the signal. That is what makes it the highest-yield check in
the tool, and why `identify.py` carries more care than the format parsers.

It also has to be precise to be usable. Comparing scripts across a whole
filename flags every non-English document ever downloaded — `отчет.pdf` mixes
Cyrillic and Latin, and is completely ordinary. A homoglyph attack substitutes a
letter *inside* a word. So the comparison is per-token, and `отчет.pdf` is clean
while `Аdobe` is not. A check that fires on every Russian filename would be
turned off within a day, and then it protects nobody.

## 2. Capability, not identity

Signatures ask "is this the malware I have seen?" Static structure answers a
different and more durable question: **what can this file do?**

A PE's import table is a declaration of intent that survives recompilation,
repacking and renaming, because the program still needs the operating system to
do the work. So `pe.py` reports *clusters*:

```
VirtualAllocEx + WriteProcessMemory + CreateRemoteThread + SetThreadContext
```

That is process injection. Not "a known injector" — process injection, the
capability, mapped to ATT&CK T1055.

The subtlety is that every cluster has legitimate members. Debuggers call
`OpenProcess`. Installers write `Run` keys. Backup software encrypts files. So
one cluster is an observation, not an accusation. What has no benign
explanation is the *stack*: injection **and** anti-debugging **and** persistence
**and** credential access in one binary describes a tool built to run without
the user's knowledge and keep running. Hence `PE_CAPABILITY_STACK`, which fires
only on three or more independent offensive capabilities and is the finding that
actually earns a CRITICAL.

The same logic drives the document checks. A `.docm` with macros is a legitimate
file format that businesses use. A `.docx` with macros is a mismatch chosen to
pass filters that block `.docm` — same payload, different claim, different
verdict.

## 3. Obfuscation is itself the evidence

A malicious script is almost never malicious on its surface. It is a loader:
one line whose job is to produce the real script and hand it to an interpreter.

```powershell
powershell -w hidden -ep bypass -EncodedCommand JABjACAAPQAgAE4AZQB3AC0A...
```

Reading only the outer layer finds nothing, because there is nothing there. So
`script.py` peels: decode each layer, re-analyse it with the same rules, tag
every finding with which layer produced it. The rule engine runs on decoded
layers and on archive entries too, so compression and encoding do not buy an
attacker an exemption from inspection.

One detail matters disproportionately: `-EncodedCommand` payloads are UTF-16LE.
Decoding them as UTF-8, getting mojibake, and discarding the result is the most
common way a scanner misses this class entirely. `_render()` checks the NUL
interleaving ratio and decodes accordingly.

And the wrapper is itself a finding. Nobody base64-encodes a legitimate
deployment script, obfuscates identifiers with backticks, and passes
`-WindowStyle Hidden`. The effort spent on unreadability is evidence of intent,
independent of what the payload turns out to be.

---

# The scoring problem

Getting the detections right is the easy half. The hard half is the verdict,
and there is one failure mode that destroys a security tool faster than any
missed detection: **crying wolf**.

## Why summing scores does not work

The obvious model is: each finding has a weight, add them up, threshold. It
fails immediately on real software.

A legitimately UPX-packed unsigned installer produces:

```
MEDIUM  Packed or protected with UPX                        15
MEDIUM  1 section at compression-grade entropy              15
MEDIUM  Only 3 imported functions across 1 DLL              15
HIGH    Section is both writable and executable             35
MEDIUM  Runtime API resolution and RWX memory               15
MEDIUM  Unsigned executable                                 15
LOW     Built without 1 exploit mitigation                   4
LOW     File can execute code when opened                    3
                                                    total  117  -> MALICIOUS
```

Every finding is true. The verdict is wrong. Those are not seven independent
reasons to distrust the file — they are **one fact, observed seven ways**. It is
packed. Packed binaries have high entropy, few imports, an unusual entry point
and a writable code section, *because that is what packing is*.

## Damping

So findings are grouped by category, and within a category each successive
finding contributes less: `1.0, 0.6, 0.35, 0.2, 0.12, …`. Corroboration is worth
something; the fourth restatement of the same observation is worth almost
nothing.

```
                        raw    damped   verdict
clean unsigned binary    22        22   WARN
UPX-packed installer    117        88   QUARANTINE
process injector        420       358   MALICIOUS
```

The packed installer lands on QUARANTINE — blocked, explained, releasable — and
the injector is still unambiguous. Findings in genuinely different categories
(`obfuscation`, `capability`, `network`, `provenance`) do not damp each other,
because those *are* independent signals.

CRITICAL and decisive findings are exempt. "This digest is known malware" and
"this executable is wearing a document's name" do not get quieter by being
repeated.

## QUARANTINE and MALICIOUS are different claims

Two blocking verdicts exist because the tool should be careful about what it
asserts:

- **QUARANTINE** — *blocked, go and look.* One CRITICAL finding earns this.
- **MALICIOUS** — *this is malware, delete it.* Needs a decisive finding (a
  known-bad digest) or several independent strong signals.

Over-claiming in the confident direction is how a scanner loses the user. Once
someone has clicked through three wrong MALICIOUS verdicts, the fourth one —
the real one — gets clicked through too.

## Policy belongs to the operator

Whether an honestly-named `.docm` should be blocked is not a technical question.
It depends on whether the organisation uses Excel macros. So that decision lives
in a profile, not in a heuristic, and profiles only ever *escalate* — no profile
hides a finding, it only changes what blocks.

---

# Building a scanner that is not itself a liability

A scanner is a parser of hostile input, running on the machine it protects, with
a privileged view of every file arriving. That is an attractive target. Three
design commitments follow.

## Fail closed, always

Every uncertainty resolves toward blocking. A parser raises, a timeout expires,
a file is a symlink, a read comes up short — `QUARANTINE`, never `ALLOW`.

```python
if self.errors:
    base = Decision.QUARANTINE
```

The reasoning: a file we could not finish examining is not a file we can vouch
for. The alternative — a crash producing an empty finding list and therefore a
clean verdict — turns *any* parser bug into a bypass. An attacker who finds a
malformed header that crashes `pe.py` gets a blocked file and a visible error,
not a pass.

`test_analyser_crash_fails_closed` injects a parser bug and asserts this, so a
future refactor cannot lose it.

## One descriptor, opened safely, for everything

`safeio.py` is the only module that touches a hostile file, and it holds three
properties so nothing else has to:

- **`O_NOFOLLOW`** — a file dropped in a watched directory cannot point the
  scanner at `/etc/shadow` and have it hashed into an audit log.
- **`O_NONBLOCK` + `fstat` regular-file check** — a FIFO would block a reader
  forever. A one-file denial of service.
- **fd pinning** — stat, hash, parse and quarantine intake all use the same
  descriptor. What gets held is what got scanned, even if the path is swapped
  mid-scan. This is a real race: the window between "verdict: block" and "copy
  to vault" is attacker-observable.

## Bound everything, trust no declared length

Every loop in the codebase terminates against a limit in `config.py`, never
against a number the file supplied. Section counts, import counts, archive
entries, expansion ratios, recursion depth, regex windows, wall-clock time.

The rule engine gets particular care because rules contain regexes and Python's
`re` has no match timeout. Three layers: nested-quantifier patterns are rejected
at parse time, regex length is capped, and matching only ever runs over
`MAX_REGEX_WINDOW` bytes. Plus the ruleset integrity check below, which means
untrusted regexes cannot be introduced without an explicit operator decision.

## Integrity where the trust actually sits

Two mechanisms, both about the same thing: *an attacker who can write files
should not be able to silently blind or rewrite the tool.*

**Rules are content-addressed.** `rules/rules.lock` pins the SHA-256 of every
rule file. A modified or unpinned ruleset raises and refuses to scan. This is
deliberately stricter than a warning, because a warning gets ignored and the
operator carries on believing they are covered. Editing a rule file is a normal
thing to do — it just requires `airlock rules pin`, an explicit approval.

**The audit log is a hash chain under an HMAC.** Each record carries the
previous record's digest; the whole record is authenticated with a key stored
0600. Editing, reordering or inserting a record breaks the chain and
`verify` names the record.

What it does *not* buy is stated in the code and in `log verify`'s own output:
anyone can truncate the log from the end, and an attacker who reaches the key
can rewrite it wholesale. Detecting truncation needs the head digest witnessed
somewhere the attacker does not control. The chain makes tampering **detectable,
not impossible** — and saying which is which is the difference between a
security property and a security claim.

---

# Testing a detector

Two things make this test suite different from an ordinary one.

**The corpus is ground truth, and it is generated.** Eighteen synthetic samples,
each asserting its verdict. A heuristic change that reclassifies one fails the
build. Every sample is built from scratch and is inert — the injector imports
dangerous APIs and its code section is `int3` padding; the obfuscated PowerShell
decodes to an echo. A security tool that ships real malware to test itself is a
liability, and committing EICAR would trip the reader's own antivirus on
checkout, so it is assembled at runtime instead.

**The false-positive tests matter more than the detection tests.** A missed
detection costs one incident. A false-positive rate that makes people ignore the
tool costs every future incident. So the suite asserts that a real system
binary, an ordinary build script, a plain `.docx`, a normal compressed archive,
and filenames in Russian, Japanese and French all come back clean — and two of
those tests were written because the implementation failed them.
