"""Findings, severities and the policy that turns them into a decision.

The scoring model is deliberately boring and auditable: every finding carries a
fixed weight, weights add up, thresholds decide. Two escape hatches exist for the
cases where arithmetic is the wrong tool — decisive findings (a known-bad hash is
malicious at any score) and the fail-closed rule (an error is never an ALLOW).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, text: str) -> "Severity":
        try:
            return cls[text.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity {text!r}") from exc


#: Default weight contributed by a finding of each severity.
SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 35,
    Severity.CRITICAL: 70,
}


class Decision(enum.IntEnum):
    """What the gate does with the file. Ordered by increasing restriction."""

    ALLOW = 0
    WARN = 1
    QUARANTINE = 2
    MALICIOUS = 3

    @property
    def label(self) -> str:
        return {
            Decision.ALLOW: "ALLOW",
            Decision.WARN: "WARN",
            Decision.QUARANTINE: "QUARANTINE",
            Decision.MALICIOUS: "MALICIOUS",
        }[self]

    @property
    def blocks(self) -> bool:
        return self >= Decision.QUARANTINE


#: Multiplier applied to the Nth-ranked non-critical finding within a category.
#: Corroboration is worth something, but the fourth restatement of the same
#: observation is worth almost nothing.
DAMPING = (1.0, 0.6, 0.35, 0.2, 0.12, 0.08, 0.05)


def _damping(rank: int) -> float:
    return DAMPING[rank] if rank < len(DAMPING) else DAMPING[-1] / (rank - len(DAMPING) + 2)


#: Score at which each decision starts applying.
#:
#: The gap between QUARANTINE and MALICIOUS is deliberate and is about what the
#: tool is willing to *claim*. QUARANTINE says "this is blocked, go and look at
#: it" and one CRITICAL finding is enough for that. MALICIOUS says "this is
#: malware, delete it", which is a much stronger assertion, and needs either a
#: decisive finding (a known-bad digest) or several independent strong signals.
#: Getting this wrong in the confident direction is how scanners lose trust.
THRESHOLDS = [
    (Decision.MALICIOUS, 100),
    (Decision.QUARANTINE, 55),
    (Decision.WARN, 20),
    (Decision.ALLOW, 0),
]


@dataclass(frozen=True)
class Finding:
    """One observation about a file.

    ``decisive`` marks a finding whose decision cannot be argued down by the
    absence of other findings — a known-bad hash, an executable wearing a
    document's name. ``attck`` is a MITRE ATT&CK technique ID where one applies.
    """

    id: str
    title: str
    severity: Severity
    category: str
    detail: str = ""
    evidence: list[str] = field(default_factory=list)
    attck: str = ""
    weight: int | None = None
    decisive: Decision | None = None
    layer: str = ""

    @property
    def score(self) -> int:
        return SEVERITY_WEIGHT[self.severity] if self.weight is None else self.weight

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.name,
            "category": self.category,
            "score": self.score,
        }
        if self.detail:
            out["detail"] = self.detail
        if self.evidence:
            out["evidence"] = self.evidence
        if self.attck:
            out["attck"] = self.attck
        if self.layer:
            out["layer"] = self.layer
        if self.decisive is not None:
            out["decisive"] = self.decisive.label
        return out


@dataclass
class Report:
    """The full result of scanning one file."""

    path: str
    display_name: str = ""
    size: int = 0
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    file_type: str = "unknown"
    type_description: str = ""
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    truncated: bool = False
    duration_ms: int = 0
    scanned_at: str = ""
    engine_version: str = ""
    ruleset: dict[str, Any] = field(default_factory=dict)

    def add(self, finding: Finding | None) -> None:
        if finding is not None:
            self.findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    @property
    def raw_score(self) -> int:
        """Straight sum of finding weights, before damping."""
        return sum(f.score for f in self.findings)

    @property
    def score(self) -> int:
        """Damped score: the number decisions are actually made on.

        A straight sum makes a scanner that cries wolf. Six MEDIUM observations
        about one property of a file -- it is packed, so it has high entropy, so
        it has few imports, so its entry point is unusual -- are not six
        independent reasons to distrust it. They are one reason, observed six
        ways, and summing them puts an ordinary UPX-packed installer over the
        malicious line.

        So within each category, findings are ranked and each successive one
        contributes less. CRITICAL and decisive findings are exempt: those are
        claims about the file that do not get quieter by being repeated.
        """
        by_category: dict[str, list[Finding]] = {}
        total = 0.0
        for finding in self.findings:
            if finding.severity is Severity.CRITICAL or finding.decisive is not None:
                total += finding.score
            else:
                by_category.setdefault(finding.category, []).append(finding)
        for group in by_category.values():
            for rank, finding in enumerate(sorted(group, key=lambda f: -f.score)):
                total += finding.score * _damping(rank)
        return int(round(total))

    @property
    def decision(self) -> Decision:
        # Fail closed: an error means we did not finish looking, and a file we
        # could not finish looking at is not a file we are willing to allow.
        if self.errors:
            base = Decision.QUARANTINE
        else:
            base = Decision.ALLOW
            score = self.score
            for decision, threshold in THRESHOLDS:
                if score >= threshold:
                    base = decision
                    break
        for finding in self.findings:
            if finding.decisive is not None and finding.decisive > base:
                base = finding.decisive
        # A file whose exact digest is on the operator's allowlist is trusted
        # back down to ALLOW -- but only if nothing decisive or CRITICAL fired.
        # Allowlisting is a statement about a digest, and a digest that now
        # parses as a process injector means the allowlist entry is the thing
        # that is wrong.
        if self.allowlisted and not self.errors:
            unarguable = any(
                f.decisive is not None or f.severity is Severity.CRITICAL
                for f in self.findings
            )
            if not unarguable:
                base = Decision.ALLOW
        return base

    @property
    def allowlisted(self) -> bool:
        return any(f.id == "REP_ALLOWLISTED" for f in self.findings)

    @property
    def top_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity, -f.score, f.id))

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "display_name": self.display_name or self.path,
            "size": self.size,
            "sha256": self.sha256,
            "sha1": self.sha1,
            "md5": self.md5,
            "file_type": self.file_type,
            "type_description": self.type_description,
            "decision": self.decision.label,
            "score": self.score,
            "raw_score": self.raw_score,
            "top_severity": self.top_severity.name,
            "truncated": self.truncated,
            "errors": self.errors,
            "duration_ms": self.duration_ms,
            "scanned_at": self.scanned_at,
            "engine_version": self.engine_version,
            "ruleset": self.ruleset,
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
