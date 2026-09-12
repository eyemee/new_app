# Threat model

Written for someone deciding whether to rely on this, and for an attacker
reading the source. Both should come away with the same understanding.

## What Airlock defends

A single workstation, against files arriving from outside it — downloads, email
attachments, USB media, shared folders. The protected asset is the user's
decision to open a file.

## Where it sits

```
   internet ──> browser / mail client ──> filesystem ──> [ AIRLOCK ] ──> user double-clicks
                                                              │
                                                              └──> quarantine vault
```

Airlock acts **after** the file is written and **before** the user opens it.
That is the whole of its coverage, and both boundaries matter.

## Threats it addresses

| Threat | Mechanism | Residual risk |
| --- | --- | --- |
| Executable disguised as a document | Content typed from magic bytes; decisive mismatch finding | None for the disguise itself |
| Filename spoofing (RLO, homoglyph, double extension) | Unicode and extension-chain analysis | Techniques not in the table |
| Malicious Office document | Macro, remote-template, DDE, XLM, ActiveX detection | An obfuscated macro's *behaviour* is not analysed |
| Malicious PDF | Auto-run actions, `/Launch`, embedded files, name-obfuscation normalisation | Exploits in the renderer's parser, not in document structure |
| Obfuscated script loader | Recursive layer decoding, per-language indicators | Encodings not implemented (custom XOR, compression) |
| Archive-delivered payload | Type each entry, zip-slip, bombs, encrypted entries | Encrypted entries are flagged, never inspected |
| Known-bad file | SHA-256 database; optional online lookup | Trivially defeated by one changed byte |
| Substituted download / hijacked update | Publisher pinning by digest | Only works for names you pinned first |
| Accidental execution of a fresh download | Execute bits cleared on arrival; blocked files vaulted | A user can `chmod +x`, or run `sh file` |

## Threats it does not address

Stated as flatly as possible, because a security tool that is vague about its
limits is worse than one with fewer features.

**Anything already running.** No memory scanning, no process monitoring, no
behavioural analysis. Airlock inspects files at rest.

**Execution prevention.** A userspace poller cannot stop a process from
starting. The window between a file landing and the watcher's verdict — seconds
— is uncovered, and a user who retrieves a file from quarantine and runs it
anyway is not prevented. Real pre-execution blocking requires an OS hook:
AppLocker or WDAC, Gatekeeper and Endpoint Security, or fanotify with
`FAN_OPEN_PERM`. Airlock is complementary to those.

**A competent targeted attacker.** Everything here is static and documented.
Someone who reads this repository can build a payload that avoids every
heuristic in it: a compiled binary that resolves all its APIs at runtime, with a
plain name, an honest extension, no packing, no notable strings, and its logic
in a second stage fetched after the file is already trusted. Airlock raises the
cost of commodity attacks. It does not stop a determined one.

**Exploits in the target application.** A PDF that is structurally unremarkable
but triggers a heap overflow in the renderer's font parser looks clean here,
because it is clean *as a document*.

**Supply-chain compromise of a trusted publisher.** If the vendor's signed build
is itself backdoored, the digest is consistent and the signature is valid. Pin
mismatch catches a swapped download, not a poisoned source.

**The platform.** A compromised OS, a malicious kernel module, or an attacker
with root can disable Airlock, read the audit key, or rewrite the vault. Nothing
here defends against an adversary already above it.

**Authenticode validation.** Airlock reports whether a signature block is
present. It does **not** validate the certificate chain, check revocation, or
verify the timestamp. A stolen, expired or self-signed certificate produces
exactly the same `PE_SIGNED` finding as a valid one. This is stated in the
finding text itself so nobody reads presence as validity.

## Attacks against Airlock itself

The scanner is a parser of hostile input running on the machine it protects.

| Attack | Defence |
| --- | --- |
| Symlink to a sensitive file, to have it read or hashed into a log | `O_NOFOLLOW`; symlinks are refused, not followed |
| FIFO or device node, to hang the scanner forever | `O_NONBLOCK` open, then `fstat` rejects non-regular files |
| Swap the file between the scan and the quarantine copy | Everything uses one pinned descriptor; the copy is from the fd, not the path |
| Decompression bomb, to exhaust disk or memory | Ratio and absolute-size caps; nothing is ever extracted to disk |
| Deeply nested archives or encodings, to exhaust the stack | `MAX_RECURSION_DEPTH`, enforced and tested |
| Malformed headers claiming huge structures | Every count and offset is clamped against the real file size |
| Catastrophic regex backtracking via a crafted sample | Nested quantifiers rejected at parse time; regex length capped; match window capped; scan timeout |
| A parser bug, to produce a clean verdict | Fail closed — every exception becomes an error finding and a blocking verdict |
| Edit the rules to blind the scanner | Ruleset is content-addressed; unpinned or modified rules refuse to load |
| Edit the audit log to hide an event | HMAC hash chain; `log verify` names the broken record |
| Escape the vault via a crafted filename on release | Held under a random ID; released names stripped of separators, controls and bidi overrides |
| Exfiltrate scanned content via the online lookup | Only the SHA-256 is sent; off by default; requires an explicit key |

### Known weaknesses

**Audit log truncation.** The chain detects edits, reordering and insertion. It
cannot detect records removed from the end — the head digest is not witnessed
anywhere outside the log. Mitigation is operational: ship the log, or its head
digest, off-host.

**Audit key compromise.** An attacker who reads `~/.airlock/audit.key` can
rewrite the entire chain consistently. The key is mode 0600 and nothing more;
this is same-user containment, not a hardware root of trust.

**Quarantine purge is not secure erasure.** `purge` overwrites in place and
unlinks. On a journalling filesystem, an SSD with wear levelling, or any
copy-on-write volume, the original blocks may survive. The CLI says so when you
run it.

**OLE2 analysis is a byte-level heuristic.** Legacy `.doc`/`.xls` macro
detection searches for UTF-16LE stream names rather than walking the compound-file
FAT. It can be defeated by a file that fragments its directory, and it tells you
a macro exists, not what it does.

**Entropy thresholds are statistical.** A small high-entropy section can occur
by chance, and a well-implemented packer can shape its output to sit below the
threshold. The size floor reduces the first; nothing here prevents the second.

## Assumptions

1. The host OS and Python runtime are not compromised.
2. The user running Airlock owns the files being scanned.
3. `~/.airlock/` is not writable by other users.
4. Findings are read by someone who can act on them. Airlock explains; it does
   not decide for you — except where it fails closed, which it always does.

## Reporting a weakness

Detection gaps and evasions are expected and worth knowing about. A sample that
should be caught and is not — or, more valuable, something legitimate that is
wrongly blocked — is the useful bug report. Both are reproducible against the
generated corpus in `src/airlock/samples.py`.
