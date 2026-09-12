"""Scoring model, rule engine, audit chain and quarantine vault."""

from __future__ import annotations

import json
import stat

import pytest

from airlock import samples
from airlock.audit import AuditLog
from airlock.quarantine import QuarantineError, Vault, _safe_name
from airlock.rules import (RuleError, RuleSet, load_ruleset, parse_condition,
                           parse_rules, write_lockfile)
from airlock.safeio import SafeFile
from airlock.verdict import Decision, Finding, Report, Severity


def finding(fid="F", severity=Severity.MEDIUM, category="c", **kw):
    return Finding(id=fid, title="t", severity=severity, category=category, **kw)


# ==========================================================================
# Scoring and verdicts
# ==========================================================================
def test_empty_report_allows():
    assert Report(path="x").decision is Decision.ALLOW


def test_thresholds():
    report = Report(path="x")
    report.add(finding(severity=Severity.HIGH))          # 35
    assert report.decision is Decision.WARN
    report.add(finding("G", Severity.HIGH, "other"))     # +35 = 70
    assert report.decision is Decision.QUARANTINE


def test_single_critical_finding_blocks_but_does_not_claim_malicious():
    """QUARANTINE means "blocked, go and look". MALICIOUS means "this is
    malware". One CRITICAL observation earns the first, not the second."""
    report = Report(path="x")
    report.add(finding(severity=Severity.CRITICAL))
    assert report.decision is Decision.QUARANTINE
    assert report.decision.blocks


def test_several_critical_findings_reach_malicious():
    report = Report(path="x")
    report.add(finding("A", Severity.CRITICAL, "one"))
    report.add(finding("B", Severity.CRITICAL, "two"))
    assert report.decision is Decision.MALICIOUS


def test_decisive_finding_overrides_a_low_score():
    report = Report(path="x")
    report.add(finding(severity=Severity.LOW, decisive=Decision.QUARANTINE))
    assert report.score < 20
    assert report.decision is Decision.QUARANTINE


def test_errors_fail_closed():
    """The core safety property: a file we could not finish reading is blocked."""
    report = Report(path="x")
    report.errors.append("parser exploded")
    assert report.decision is Decision.QUARANTINE


def test_damping_stops_weak_signals_from_stacking_into_a_verdict():
    """Six MEDIUM observations about one property are one reason, not six."""
    report = Report(path="x")
    for i in range(6):
        report.add(finding(f"F{i}", Severity.MEDIUM, "obfuscation"))
    assert report.raw_score == 90
    assert report.score < report.raw_score
    assert report.decision is not Decision.MALICIOUS


def test_damping_is_per_category():
    """Independent categories corroborate each other and are not damped together."""
    same = Report(path="x")
    spread = Report(path="y")
    for i in range(4):
        same.add(finding(f"A{i}", Severity.HIGH, "obfuscation"))
        spread.add(finding(f"B{i}", Severity.HIGH, f"category{i}"))
    assert spread.score > same.score


def test_critical_findings_are_never_damped():
    report = Report(path="x")
    for i in range(3):
        report.add(finding(f"C{i}", Severity.CRITICAL, "same"))
    assert report.score == report.raw_score


def test_allowlist_pulls_a_noisy_file_back_to_allow():
    report = Report(path="x")
    report.add(finding("REP_ALLOWLISTED", Severity.INFO, "reputation"))
    report.add(finding("PE_UNSIGNED", Severity.HIGH, "provenance"))
    assert report.decision is Decision.ALLOW


def test_allowlist_does_not_override_a_critical_finding():
    """If an allowlisted digest now parses as an injector, the allowlist entry
    is the thing that is wrong."""
    report = Report(path="x")
    report.add(finding("REP_ALLOWLISTED", Severity.INFO, "reputation"))
    report.add(finding("PE_API_PROCESS_INJECTION", Severity.CRITICAL, "capability"))
    assert report.decision.blocks


def test_allowlist_does_not_override_an_error():
    report = Report(path="x")
    report.add(finding("REP_ALLOWLISTED", Severity.INFO, "reputation"))
    report.errors.append("truncated")
    assert report.decision.blocks


def test_report_serialises():
    report = Report(path="x", sha256="a" * 64)
    report.add(finding(severity=Severity.HIGH, attck="T1055"))
    blob = json.loads(json.dumps(report.to_dict()))
    assert blob["decision"] == "WARN"
    assert blob["findings"][0]["attck"] == "T1055"


# ==========================================================================
# Rule engine
# ==========================================================================
@pytest.mark.parametrize("condition,hits,expected", [
    ("$a", {"$a"}, True),
    ("$a", set(), False),
    ("$a and $b", {"$a"}, False),
    ("$a and $b", {"$a", "$b"}, True),
    ("$a or $b", {"$b"}, True),
    ("not $a", set(), True),
    ("not $a", {"$a"}, False),
    ("$a and not $b", {"$a"}, True),
    ("($a or $b) and $c", {"$b", "$c"}, True),
    ("($a or $b) and $c", {"$b"}, False),
    ("2 of them", {"$a", "$b"}, True),
    ("2 of them", {"$a"}, False),
    ("all of them", {"$a", "$b", "$c"}, True),
    ("all of them", {"$a", "$b"}, False),
    ("any of them", {"$c"}, True),
    ("2 of ($a, $b, $c)", {"$a", "$c"}, True),
    ("2 of ($a, $b)", {"$a", "$c"}, False),
])
def test_condition_evaluation(condition, hits, expected):
    from airlock.rules import _evaluate
    node = parse_condition(condition)
    assert _evaluate(node, hits, {"$a", "$b", "$c"}) is expected


def test_text_hex_and_regex_patterns():
    rules = parse_rules('''
rule R {
    meta:
        severity = "high"
        description = "d"
    strings:
        $t = "Hello" nocase
        $h = { 4D 5A ?? 00 }
        $r = /ab[0-9]+cd/
    condition:
        all of them
}
''', "t")
    rs = RuleSet(rules=rules)
    assert rs.scan(b"hELLO \x4d\x5a\x99\x00 ab123cd")
    assert not rs.scan(b"hELLO ab123cd")


def test_rules_are_gated_by_file_kind():
    rules = parse_rules('''
rule OnlyDocuments {
    meta:
        severity = "high"
        description = "d"
        excludes = "pe"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz
}
''', "t")
    rs = RuleSet(rules=rules)
    assert rs.scan(b"MZ blah", kind="pdf")
    assert not rs.scan(b"MZ blah", kind="pe")


@pytest.mark.parametrize("source,message", [
    ('rule R {\n strings:\n  $a = /(x+)+y/\n condition:\n  $a\n}', "nested quantifier"),
    ('rule R {\n strings:\n  $a = "x"\n condition:\n  $zz\n}', "undefined"),
    ('rule R {\n strings:\n  $a = "x"\n condition:\n  2 of\n}', "them"),
    ('rule R {\n strings:\n  $a = { ZZ }\n condition:\n  $a\n}', "hex"),
    ('rule R {\n meta:\n  severity = "wrong"\n strings:\n  $a = "x"\n condition:\n  $a\n}', "severity"),
    ('rule R {\n strings:\n  $a = "x"\n condition:\n  ($a\n}', "parenthesis"),
    ('not a rule file at all', "no rules"),
])
def test_malformed_rules_are_rejected(source, message):
    with pytest.raises(RuleError, match=message):
        parse_rules(source, "bad")


def test_rules_never_execute_rule_content():
    """Rules are data. A rule that looks like code stays a string."""
    rules = parse_rules('''
rule R {
    meta:
        severity = "low"
        description = "d"
    strings:
        $a = "__import__('os').system('touch /tmp/pwned')"
    condition:
        $a
}
''', "t")
    assert RuleSet(rules=rules).scan(b"nothing here") == []
    import os
    assert not os.path.exists("/tmp/pwned")


def test_ruleset_integrity_is_enforced(tmp_path):
    rules_file = tmp_path / "r.rules"
    rules_file.write_text('rule R {\n meta:\n  severity = "low"\n  description = "d"\n'
                          ' strings:\n  $a = "x"\n condition:\n  $a\n}')
    lock = tmp_path / "rules.lock"

    with pytest.raises(RuleError, match="not pinned"):
        load_ruleset([rules_file], lock)

    write_lockfile([rules_file], lock)
    assert load_ruleset([rules_file], lock).verified

    rules_file.write_text(rules_file.read_text() + "\n// tampered\n")
    with pytest.raises(RuleError, match="does not match its pinned digest"):
        load_ruleset([rules_file], lock)

    # An explicit override still loads, but records that it is unverified.
    assert not load_ruleset([rules_file], lock, trust_unverified=True).verified


def test_shipped_ruleset_is_pinned_and_parses(ruleset):
    assert ruleset.verified
    assert len(ruleset.rules) >= 10
    assert all(rule.patterns for rule in ruleset.rules)


def test_eicar_rule_fires(ruleset):
    hits = {f.id for f in ruleset.scan(samples.eicar())}
    assert "RULE_EICAR_TEST_FILE" in hits


def test_shipped_rules_do_not_fire_on_benign_content(ruleset):
    assert ruleset.scan(samples.benign_text(), kind="text") == []
    assert ruleset.scan(samples.benign_pdf(), kind="pdf") == []
    assert ruleset.scan(samples.benign_pe(), kind="pe") == []


# ==========================================================================
# Audit log
# ==========================================================================
def test_chain_verifies(tmp_path):
    log = AuditLog(tmp_path / "a.log", tmp_path / "a.key")
    for i in range(5):
        log.append("scan", {"n": i})
    ok, problems = log.verify()
    assert ok and not problems


def test_key_and_log_are_private(tmp_path):
    log = AuditLog(tmp_path / "a.log", tmp_path / "a.key")
    log.append("scan", {})
    assert stat.S_IMODE((tmp_path / "a.key").stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "a.log").stat().st_mode) == 0o600


def test_modified_record_is_detected(tmp_path):
    log = AuditLog(tmp_path / "a.log", tmp_path / "a.key")
    for i in range(4):
        log.append("scan", {"decision": "ALLOW", "n": i})
    lines = (tmp_path / "a.log").read_text().splitlines()
    record = json.loads(lines[1])
    record["data"]["decision"] = "MALICIOUS"
    lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    (tmp_path / "a.log").write_text("\n".join(lines) + "\n")

    ok, problems = log.verify()
    assert not ok
    assert any("modified after it was written" in p for p in problems)


def test_removed_record_breaks_the_chain(tmp_path):
    log = AuditLog(tmp_path / "a.log", tmp_path / "a.key")
    for i in range(4):
        log.append("scan", {"n": i})
    lines = (tmp_path / "a.log").read_text().splitlines()
    del lines[1]
    (tmp_path / "a.log").write_text("\n".join(lines) + "\n")

    ok, problems = log.verify()
    assert not ok
    assert any("sequence" in p for p in problems)
    assert any("chain is broken" in p for p in problems)


def test_forged_record_without_the_key_is_detected(tmp_path):
    """An attacker who can write the log but not read the key cannot extend it."""
    log = AuditLog(tmp_path / "a.log", tmp_path / "a.key")
    entry = log.append("scan", {"n": 1})
    forged = {"seq": 2, "ts": "2026-01-01T00:00:00Z", "event": "scan",
              "data": {"decision": "ALLOW"}, "prev": entry.digest, "digest": "0" * 64}
    with open(tmp_path / "a.log", "a") as fh:
        fh.write(json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n")
    ok, problems = log.verify()
    assert not ok
    assert any("authenticator" in p for p in problems)


def test_entries_survive_a_reopen(tmp_path):
    AuditLog(tmp_path / "a.log", tmp_path / "a.key").append("scan", {"n": 1})
    AuditLog(tmp_path / "a.log", tmp_path / "a.key").append("scan", {"n": 2})
    reopened = AuditLog(tmp_path / "a.log", tmp_path / "a.key")
    assert [e.seq for e in reopened.entries()] == [1, 2]
    assert reopened.verify()[0]


# ==========================================================================
# Quarantine
# ==========================================================================
def _blocked_report(sf, decision=Decision.MALICIOUS):
    report = Report(path=str(sf.path), display_name=sf.path.name,
                    sha256="a" * 64, size=sf.size)
    report.add(finding(severity=Severity.CRITICAL, decisive=decision))
    return report


def test_store_contains_the_file(tmp_path, write_sample):
    source = write_sample("bad.exe", samples.injector_pe())
    source.chmod(0o755)
    vault = Vault(tmp_path / "vault")
    with SafeFile(source) as sf:
        item = vault.store(sf, _blocked_report(sf), remove_original=True)

    blob = vault.root / item.blob_name
    assert stat.S_IMODE(blob.stat().st_mode) == 0o600
    assert stat.S_IMODE(vault.root.stat().st_mode) == 0o700
    assert blob.suffix == ".quarantined"
    assert not source.exists()
    assert blob.read_bytes() == samples.injector_pe()


def test_release_refuses_malicious_without_force(tmp_path, write_sample):
    source = write_sample("bad.exe", b"MZ payload")
    vault = Vault(tmp_path / "vault")
    with SafeFile(source) as sf:
        item = vault.store(sf, _blocked_report(sf))
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(QuarantineError, match="MALICIOUS"):
        vault.release(item.id, out)
    released = vault.release(item.id, out, force=True)
    assert released.read_bytes() == b"MZ payload"


def test_release_will_not_overwrite(tmp_path, write_sample):
    source = write_sample("f.bin", b"data")
    vault = Vault(tmp_path / "vault")
    with SafeFile(source) as sf:
        item = vault.store(sf, _blocked_report(sf, Decision.QUARANTINE))
    out = tmp_path / "out"
    out.mkdir()
    (out / "f.bin").write_bytes(b"existing")
    with pytest.raises(QuarantineError, match="refusing to overwrite"):
        vault.release(item.id, out)


def test_purge_removes_blob_and_metadata(tmp_path, write_sample):
    source = write_sample("f.bin", b"data" * 100)
    vault = Vault(tmp_path / "vault")
    with SafeFile(source) as sf:
        item = vault.store(sf, _blocked_report(sf))
    vault.purge(item.id)
    assert not (vault.root / item.blob_name).exists()
    assert vault.items() == []


def test_unknown_id_raises(tmp_path):
    with pytest.raises(QuarantineError, match="no quarantined item"):
        Vault(tmp_path / "vault").get("nope")


@pytest.mark.parametrize("name,expected", [
    ("../../etc/passwd", "_.._etc_passwd"),  # separators neutralised, leading dots dropped
    ("annexe‮gnp.exe", "annexegnp.exe"),
    ("with​zero.txt", "withzero.txt"),
    ("trailing.  ", "trailing"),
    ("", "released_file"),
    ("...", "released_file"),
])
def test_released_names_are_sanitised(name, expected):
    assert _safe_name(name) == expected


# ==========================================================================
# Reputation and the optional online lookup
# ==========================================================================
def _fake_response(payload):
    """Stand in for urlopen's context-manager response."""
    import json as _json

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def read(self, _n=None):
            return _json.dumps(payload).encode()
    return lambda _request, timeout=None: _Response()


def test_online_malicious_verdict_is_decisive():
    from airlock.reputation import online_lookup
    payload = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 41, "suspicious": 2, "undetected": 20},
        "popular_threat_classification": {"suggested_threat_label": "trojan.agent"}}}}
    finding = online_lookup("a" * 64, "key", opener=_fake_response(payload))[0]
    assert finding.id == "REP_ONLINE_MALICIOUS"
    assert finding.decisive is Decision.MALICIOUS
    assert "trojan.agent" in finding.detail


def test_online_clean_verdict_does_not_lower_anything():
    from airlock.reputation import online_lookup
    payload = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 70}}}}
    finding = online_lookup("a" * 64, "key", opener=_fake_response(payload))[0]
    assert finding.id == "REP_ONLINE_CLEAN"
    assert finding.severity is Severity.INFO
    assert finding.decisive is None
    assert finding.score == 0


def test_online_minority_detection_is_suspicious_not_malicious():
    from airlock.reputation import online_lookup
    payload = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 1, "suspicious": 0, "undetected": 69}}}}
    finding = online_lookup("a" * 64, "key", opener=_fake_response(payload))[0]
    assert finding.id == "REP_ONLINE_SUSPICIOUS"
    assert finding.decisive is None


def test_online_failure_never_lowers_a_verdict():
    """A network outage is not evidence of innocence."""
    from airlock.reputation import online_lookup

    def broken(_request, timeout=None):
        raise OSError("connection refused")

    finding = online_lookup("a" * 64, "key", opener=broken)[0]
    assert finding.id == "REP_ONLINE_ERROR"
    assert finding.score == 0


def test_online_lookup_sends_only_the_digest():
    """The privacy property: the file never leaves the machine."""
    from airlock.reputation import online_lookup
    seen = {}

    def capture(request, timeout=None):
        seen["url"] = request.full_url
        seen["headers"] = dict(request.header_items())
        seen["body"] = request.data
        raise OSError("stop here")

    online_lookup("b" * 64, "secret-key", opener=capture)
    assert seen["url"].endswith("b" * 64)
    assert seen["body"] is None
    assert any(v == "secret-key" for v in seen["headers"].values())


def test_known_bad_and_allowlist_lookup(tmp_path):
    import hashlib

    from airlock.reputation import Database, check
    digest = hashlib.sha256(b"x").hexdigest()
    db = Database(known_bad={digest: {"name": "Bad", "family": "test"}})
    assert check(digest, db)[0].decisive is Decision.MALICIOUS
    assert check("c" * 64, db) == []

    db = Database(allowlist={digest: {"name": "Approved"}})
    assert check(digest, db)[0].id == "REP_ALLOWLISTED"


def test_corrupt_reputation_database_does_not_break_scanning(tmp_path):
    """A malformed database file must degrade, not crash: the scanner still
    needs to run."""
    from airlock.reputation import load_database
    bad = tmp_path / "known_bad.json"
    bad.write_text("{ this is not json")
    db = load_database([bad])
    assert db.known_bad == {}


def test_pins_are_stored_privately(tmp_path):
    from airlock.reputation import add_pin, load_pins
    path = tmp_path / "pins.json"
    add_pin("setup.exe", "d" * 64, 100, path=path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert load_pins(path)["setup.exe"].sha256 == "d" * 64
