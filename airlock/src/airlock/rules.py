"""A small, data-only signature engine.

Deliberately not a general rule language. Rules are *data*: there is no ``eval``,
no callable in a rule, and no way for a rule file to reach anything but the bytes
of the sample. The condition grammar is parsed by recursive descent into a tree
of tuples and walked; the worst a malformed rule can do is fail to load.

Format::

    rule Suspicious_Downloader : downloader {
        meta:
            severity = "high"
            description = "Fetches and runs a remote payload"
            attck = "T1105"
        strings:
            $dl1 = "DownloadString" nocase
            $dl2 = "URLDownloadToFile" nocase
            $exec = /Invoke-(Expression|Command)/ nocase
            $mz = { 4D 5A ?? ?? 00 }
        condition:
            2 of them
    }

Integrity: rule files are content-addressed. ``rules.lock`` pins the SHA-256 of
every ruleset Airlock will load, because a scanner that loads whatever rules it
finds on disk is a scanner an attacker can silence by editing one file.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import config
from .verdict import Decision, Finding, Severity

MAX_RULE_FILE_BYTES = 4 << 20
MAX_REGEX_LENGTH = 200
MAX_STRINGS_PER_RULE = 64


class RuleError(Exception):
    """A rule file could not be parsed or failed its integrity check."""


# --------------------------------------------------------------------------
@dataclass
class Pattern:
    name: str
    kind: str            # "text" | "hex" | "regex"
    raw: str
    nocase: bool = False
    wide: bool = False
    compiled: re.Pattern[bytes] | None = None
    literal: bytes | None = None

    def matches(self, data: bytes, lowered: bytes) -> bool:
        if self.literal is not None:
            return self.literal in (lowered if self.nocase else data)
        if self.compiled is not None:
            return self.compiled.search(data[:config.MAX_REGEX_WINDOW]) is not None
        return False


@dataclass
class Rule:
    name: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, str] = field(default_factory=dict)
    patterns: list[Pattern] = field(default_factory=list)
    condition: tuple = ("false",)
    source: str = ""

    @property
    def severity(self) -> Severity:
        return Severity.parse(self.meta.get("severity", "medium"))

    @property
    def decisive(self) -> Decision | None:
        value = self.meta.get("decisive", "").strip().upper()
        if not value:
            return None
        try:
            return Decision[value]
        except KeyError:
            return None

    @property
    def applies_to(self) -> set[str]:
        """File kinds this rule is valid for. Empty means all."""
        return {k.strip().lower() for k in self.meta.get("applies_to", "").split(",") if k.strip()}

    @property
    def excludes(self) -> set[str]:
        """File kinds this rule must not fire on."""
        return {k.strip().lower() for k in self.meta.get("excludes", "").split(",") if k.strip()}

    def applicable(self, kind: str) -> bool:
        kind = (kind or "").lower()
        if self.excludes and kind in self.excludes:
            return False
        return not self.applies_to or kind in self.applies_to

    def evaluate(self, data: bytes, lowered: bytes) -> list[str] | None:
        """Return the names of matching patterns, or None if the rule did not fire."""
        hits = {p.name for p in self.patterns if p.matches(data, lowered)}
        return sorted(hits) if _evaluate(self.condition, hits, {p.name for p in self.patterns}) else None


# --------------------------------------------------------------------------
# Condition evaluation
# --------------------------------------------------------------------------
def _evaluate(node: tuple, hits: set[str], universe: set[str]) -> bool:
    op = node[0]
    if op == "true":
        return True
    if op == "false":
        return False
    if op == "ident":
        return node[1] in hits
    if op == "not":
        return not _evaluate(node[1], hits, universe)
    if op == "and":
        return all(_evaluate(child, hits, universe) for child in node[1])
    if op == "or":
        return any(_evaluate(child, hits, universe) for child in node[1])
    if op == "count":
        _, quantifier, names = node
        pool = universe if names is None else set(names)
        matched = len(hits & pool)
        if quantifier == "all":
            return matched == len(pool) and bool(pool)
        if quantifier == "any":
            return matched >= 1
        return matched >= int(quantifier)
    raise RuleError(f"unknown condition node {op!r}")


_TOKEN = re.compile(r"\s*(\(|\)|,|\$[A-Za-z_][\w]*|\*|[A-Za-z_]\w*|\d+)")


def _tokenise(text: str) -> list[str]:
    tokens: list[str] = []
    pos = 0
    while pos < len(text):
        match = _TOKEN.match(text, pos)
        if not match:
            if text[pos].isspace():
                pos += 1
                continue
            raise RuleError(f"unexpected character {text[pos]!r} in condition")
        tokens.append(match.group(1))
        pos = match.end()
    return tokens


def parse_condition(text: str) -> tuple:
    tokens = _tokenise(text)
    if not tokens:
        raise RuleError("empty condition")
    node, rest = _parse_or(tokens)
    if rest:
        raise RuleError(f"trailing tokens in condition: {' '.join(rest)}")
    return node


def _parse_or(tokens: list[str]) -> tuple[tuple, list[str]]:
    node, tokens = _parse_and(tokens)
    parts = [node]
    while tokens and tokens[0].lower() == "or":
        node, tokens = _parse_and(tokens[1:])
        parts.append(node)
    return (parts[0] if len(parts) == 1 else ("or", parts)), tokens


def _parse_and(tokens: list[str]) -> tuple[tuple, list[str]]:
    node, tokens = _parse_unary(tokens)
    parts = [node]
    while tokens and tokens[0].lower() == "and":
        node, tokens = _parse_unary(tokens[1:])
        parts.append(node)
    return (parts[0] if len(parts) == 1 else ("and", parts)), tokens


def _parse_unary(tokens: list[str]) -> tuple[tuple, list[str]]:
    if not tokens:
        raise RuleError("condition ended early")
    head = tokens[0]
    low = head.lower()
    if low == "not":
        node, rest = _parse_unary(tokens[1:])
        return ("not", node), rest
    if head == "(":
        node, rest = _parse_or(tokens[1:])
        if not rest or rest[0] != ")":
            raise RuleError("unbalanced parenthesis in condition")
        return node, rest[1:]
    if low in ("all", "any") or head.isdigit():
        quantifier = low if low in ("all", "any") else head
        rest = tokens[1:]
        if not rest or rest[0].lower() != "of":
            raise RuleError(f"expected 'of' after {head!r}")
        rest = rest[1:]
        if not rest:
            raise RuleError("expected 'them' or a pattern list")
        if rest[0].lower() == "them":
            return ("count", quantifier, None), rest[1:]
        if rest[0] == "(":
            names: list[str] = []
            rest = rest[1:]
            while rest and rest[0] != ")":
                if rest[0] == ",":
                    rest = rest[1:]
                    continue
                if not rest[0].startswith("$"):
                    raise RuleError(f"expected a $pattern in list, got {rest[0]!r}")
                names.append(rest[0])
                rest = rest[1:]
            if not rest:
                raise RuleError("unterminated pattern list")
            return ("count", quantifier, names), rest[1:]
        raise RuleError(f"unexpected token after 'of': {rest[0]!r}")
    if head.startswith("$"):
        return ("ident", head), tokens[1:]
    if low in ("true", "false"):
        return (low,), tokens[1:]
    raise RuleError(f"unexpected token {head!r} in condition")


# --------------------------------------------------------------------------
# Rule file parsing
# --------------------------------------------------------------------------
_RULE_HEADER = re.compile(r"rule\s+([A-Za-z_]\w*)\s*(?::\s*([\w\s]+?))?\s*\{")
_META_LINE = re.compile(r'([A-Za-z_]\w*)\s*=\s*"((?:[^"\\]|\\.)*)"')
_STRING_LINE = re.compile(
    r'(\$[A-Za-z_]\w*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|\{([^}]*)\}|/((?:[^/\\]|\\.)+)/)'
    r'((?:\s+(?:nocase|wide|ascii))*)')


def parse_rules(text: str, source: str = "<memory>") -> list[Rule]:
    if len(text) > MAX_RULE_FILE_BYTES:
        raise RuleError(f"{source}: rule file exceeds {MAX_RULE_FILE_BYTES} bytes")
    text = re.sub(r"(?m)//.*$", "", text)
    rules: list[Rule] = []
    pos = 0
    while True:
        header = _RULE_HEADER.search(text, pos)
        if not header:
            break
        body, end = _extract_block(text, header.end() - 1)
        pos = end
        rule = Rule(name=header.group(1),
                    tags=(header.group(2) or "").split(),
                    source=source)
        rule.meta = {m.group(1): _unescape(m.group(2))
                     for m in _META_LINE.finditer(_section(body, "meta"))}
        rule.patterns = _parse_strings(_section(body, "strings"), rule.name)
        condition = _section(body, "condition").strip()
        if not condition:
            raise RuleError(f"{rule.name}: missing condition")
        rule.condition = parse_condition(condition)
        _validate(rule)
        rules.append(rule)
    if not rules:
        raise RuleError(f"{source}: no rules found")
    return rules


def _extract_block(text: str, brace_pos: int) -> tuple[str, int]:
    depth = 0
    for i in range(brace_pos, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace_pos + 1:i], i + 1
    raise RuleError("unterminated rule block")


def _section(body: str, name: str) -> str:
    match = re.search(rf"(?ms)^\s*{name}\s*:\s*(.*?)(?=^\s*(?:meta|strings|condition)\s*:|\Z)", body)
    return match.group(1) if match else ""


def _parse_strings(section: str, rule_name: str) -> list[Pattern]:
    patterns: list[Pattern] = []
    for match in _STRING_LINE.finditer(section):
        name, text_val, hex_val, regex_val, modifiers = match.groups()
        mods = (modifiers or "").split()
        nocase = "nocase" in mods
        pattern = Pattern(name=name, kind="", raw="", nocase=nocase, wide="wide" in mods)

        if text_val is not None:
            literal = _unescape(text_val).encode("utf-8", "surrogateescape")
            pattern.kind, pattern.raw = "text", text_val
            pattern.literal = literal.lower() if nocase else literal
        elif hex_val is not None:
            pattern.kind, pattern.raw = "hex", hex_val
            pattern.compiled = _compile_hex(hex_val, rule_name, name)
            pattern.nocase = False
        elif regex_val is not None:
            if len(regex_val) > MAX_REGEX_LENGTH:
                raise RuleError(f"{rule_name}/{name}: regex exceeds {MAX_REGEX_LENGTH} characters")
            _reject_catastrophic(regex_val, rule_name, name)
            pattern.kind, pattern.raw = "regex", regex_val
            try:
                pattern.compiled = re.compile(regex_val.encode(),
                                              re.I if nocase else 0)
            except re.error as exc:
                raise RuleError(f"{rule_name}/{name}: bad regex: {exc}") from exc
        else:
            continue
        patterns.append(pattern)
        if len(patterns) > MAX_STRINGS_PER_RULE:
            raise RuleError(f"{rule_name}: more than {MAX_STRINGS_PER_RULE} patterns")
    return patterns


def _compile_hex(spec: str, rule_name: str, pattern_name: str) -> re.Pattern[bytes]:
    """``{ 4D 5A ?? 00 }`` becomes a byte regex. ``??`` is a single-byte wildcard."""
    parts: list[bytes] = []
    for token in spec.split():
        if token == "??":
            parts.append(b"[\\s\\S]")
        elif re.fullmatch(r"[0-9A-Fa-f]{2}", token):
            parts.append(re.escape(bytes([int(token, 16)])))
        else:
            raise RuleError(f"{rule_name}/{pattern_name}: bad hex token {token!r}")
    if not parts:
        raise RuleError(f"{rule_name}/{pattern_name}: empty hex pattern")
    return re.compile(b"".join(parts), re.DOTALL)


_NESTED_QUANTIFIER = re.compile(r"\([^)]*[+*]\)[+*]|\((?:[^()]*\|[^()]*)\)[+*]\+")


def _reject_catastrophic(regex: str, rule_name: str, pattern_name: str) -> None:
    """Refuse the nested-quantifier shapes that cause exponential backtracking.

    Python's ``re`` has no match timeout, so a rule with ``(a+)+`` would let a
    crafted sample hang the scanner. Scans are also bounded by
    ``MAX_REGEX_WINDOW`` and a wall-clock timeout; this is the first of those
    three layers, not the only one.
    """
    if _NESTED_QUANTIFIER.search(regex):
        raise RuleError(
            f"{rule_name}/{pattern_name}: nested quantifier rejected (ReDoS risk)")


def _validate(rule: Rule) -> None:
    names = {p.name for p in rule.patterns}
    referenced = _referenced(rule.condition)
    missing = referenced - names
    if missing:
        raise RuleError(f"{rule.name}: condition references undefined {', '.join(sorted(missing))}")
    if rule.meta.get("severity"):
        try:
            Severity.parse(rule.meta["severity"])
        except ValueError as exc:
            raise RuleError(f"{rule.name}: {exc}") from exc


def _referenced(node: tuple) -> set[str]:
    op = node[0]
    if op == "ident":
        return {node[1]}
    if op == "not":
        return _referenced(node[1])
    if op in ("and", "or"):
        return set().union(*(_referenced(child) for child in node[1]))
    if op == "count" and node[2]:
        return set(node[2])
    return set()


def _unescape(text: str) -> str:
    return (text.replace('\\"', '"').replace("\\\\", "\\")
            .replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t"))


# --------------------------------------------------------------------------
# Ruleset loading with integrity enforcement
# --------------------------------------------------------------------------
@dataclass
class RuleSet:
    rules: list[Rule] = field(default_factory=list)
    digests: dict[str, str] = field(default_factory=dict)
    verified: bool = False

    def scan(self, data: bytes, layer: str = "", kind: str = "") -> list[Finding]:
        """Run every applicable rule over ``data``.

        ``kind`` is the detected file type. Rules declare ``applies_to`` or
        ``excludes`` so that, for example, "an MZ header inside this file" fires
        on a document and not on every executable ever scanned.
        """
        lowered = data.lower()
        out: list[Finding] = []
        for rule in self.rules:
            if not rule.applicable(kind):
                continue
            hits = rule.evaluate(data, lowered)
            if hits is None:
                continue
            out.append(Finding(
                id=f"RULE_{rule.name.upper()}",
                title=rule.meta.get("description") or f"Matched rule {rule.name}",
                severity=rule.severity,
                category=rule.meta.get("category", "signature"),
                detail=rule.meta.get("detail", ""),
                evidence=[f"rule: {rule.name}",
                          f"patterns: {', '.join(hits)}"]
                         + ([f"tags: {', '.join(rule.tags)}"] if rule.tags else []),
                attck=rule.meta.get("attck", ""),
                decisive=rule.decisive,
                layer=layer,
            ))
        return out

    @property
    def summary(self) -> dict:
        return {"rules": len(self.rules), "verified": self.verified,
                "files": self.digests}


def load_ruleset(paths: list[Path], lockfile: Path | None = None,
                 trust_unverified: bool = False) -> RuleSet:
    """Load rule files, refusing any whose digest is not pinned in ``lockfile``.

    Fails closed. An unpinned or modified ruleset raises rather than loading,
    because silently scanning with tampered rules is worse than not scanning:
    the operator believes they are covered.
    """
    pinned: dict[str, str] = {}
    if lockfile and lockfile.exists():
        try:
            pinned = json.loads(lockfile.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise RuleError(f"{lockfile}: unreadable rule lockfile: {exc}") from exc

    ruleset = RuleSet(verified=bool(pinned))
    for path in paths:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise RuleError(f"{path}: {exc}") from exc
        if len(raw) > MAX_RULE_FILE_BYTES:
            raise RuleError(f"{path}: rule file too large")
        digest = hashlib.sha256(raw).hexdigest()
        ruleset.digests[path.name] = digest
        expected = pinned.get(path.name)
        if expected is None:
            if not trust_unverified:
                raise RuleError(
                    f"{path.name} is not pinned in {lockfile.name if lockfile else 'rules.lock'}. "
                    "Re-pin with 'airlock rules pin' after reviewing it, or pass "
                    "--trust-rules to load it for this run only.")
            ruleset.verified = False
        elif expected != digest:
            if not trust_unverified:
                raise RuleError(
                    f"{path.name} does not match its pinned digest -- the rule file has "
                    f"changed since it was approved.\n  expected {expected}\n  found    {digest}")
            ruleset.verified = False
        ruleset.rules.extend(parse_rules(raw.decode("utf-8", "replace"), path.name))
    return ruleset


def write_lockfile(paths: list[Path], lockfile: Path) -> dict[str, str]:
    digests = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    lockfile.write_text(json.dumps(digests, indent=2, sort_keys=True) + "\n")
    return digests
