"""End-to-end: the scanner over the whole corpus, the watcher, and the CLI."""

from __future__ import annotations

import json
import os
import stat
import time

import pytest

from airlock import reputation, samples
from airlock.audit import AuditLog
from airlock.cli import EXIT_BLOCKED, EXIT_ERROR, EXIT_OK, EXIT_WARN, main
from airlock.quarantine import Vault
from airlock.report import render_html, render_json, render_text
from airlock.scanner import Policy, Scanner
from airlock.verdict import Decision
from airlock import watch as watch_module
from airlock.watch import Watcher


# ==========================================================================
# The corpus is ground truth
# ==========================================================================
@pytest.mark.parametrize("name", list(samples.CATALOGUE))
def test_corpus_verdicts(scanner, corpus, name):
    """Each sample must still produce the verdict it was built to produce.

    These are the regression tests that stop a heuristic change from quietly
    reclassifying something.
    """
    _builder, expected = samples.CATALOGUE[name]
    report = scanner.scan_path(corpus[name], name)
    assert report.errors == []
    assert report.decision.label == expected, (
        f"{name}: got {report.decision.label} (score {report.score}); "
        f"findings: {[f.id for f in report.sorted_findings()]}")


def test_benign_samples_have_no_blocking_findings(scanner, corpus):
    for name in ("notes.txt", "report.pdf"):
        report = scanner.scan_path(corpus[name], name)
        assert report.score == 0
        assert report.decision is Decision.ALLOW


def test_known_bad_digest_is_decisive(scanner, corpus):
    report = scanner.scan_path(corpus["eicar.com"], "eicar.com")
    assert report.decision is Decision.MALICIOUS
    assert "REP_KNOWN_BAD" in {f.id for f in report.findings}


def test_masquerade_is_caught_on_content_not_name(scanner, write_sample):
    """The whole premise: rename a PE to .pdf and it is still a PE."""
    path = write_sample("Q3_Results.pdf", samples.injector_pe())
    report = scanner.scan_path(path, "Q3_Results.pdf")
    assert report.decision.blocks
    assert "TYPE_EXECUTABLE_MASQUERADE" in {f.id for f in report.findings}


# ==========================================================================
# Fail-closed behaviour
# ==========================================================================
def test_symlink_is_refused_and_fails_closed(scanner, tmp_path):
    target = tmp_path / "secret"
    target.write_bytes(b"sensitive")
    link = tmp_path / "report.pdf"
    link.symlink_to(target)
    report = scanner.scan_path(link)
    assert report.errors
    assert report.decision.blocks


def test_missing_file_fails_closed(scanner, tmp_path):
    report = scanner.scan_path(tmp_path / "nope.exe")
    assert report.errors
    assert report.decision.blocks


def test_analyser_crash_fails_closed(scanner, corpus, monkeypatch):
    """A bug in a parser must never become a clean bill of health."""
    from airlock.formats import pe as pe_mod

    def explode(*_a, **_k):
        raise RuntimeError("simulated parser bug")

    monkeypatch.setattr(pe_mod, "analyse", explode)
    report = scanner.scan_path(corpus["hello-cli.exe"], "hello-cli.exe")
    assert report.errors
    assert report.decision.blocks


def test_timeout_fails_closed(ruleset, corpus):
    scanner = Scanner(ruleset=ruleset, database=reputation.load_database(), timeout=-1)
    report = scanner.scan_path(corpus["updater.exe"], "updater.exe")
    assert any("fails closed" in e for e in report.errors)
    assert report.decision.blocks


def test_malformed_file_of_a_declared_type_is_reported(scanner, write_sample):
    blob = bytearray(samples.benign_pe())
    blob[0x3C:0x40] = (0x7FFFFFFF).to_bytes(4, "little")
    path = write_sample("broken.exe", bytes(blob))
    report = scanner.scan_path(path, "broken.exe")
    assert "SCAN_MALFORMED_STRUCTURE" in {f.id for f in report.findings}


# ==========================================================================
# Policy profiles
# ==========================================================================
def test_profiles_only_escalate(ruleset, corpus):
    db = reputation.load_database()
    previous = {}
    for profile in ("permissive", "standard", "strict", "paranoid"):
        scanner = Scanner(ruleset=ruleset, database=db, policy=Policy.named(profile))
        for name in corpus:
            report = scanner.scan_path(corpus[name], name)
            if name in previous:
                assert report.decision >= previous[name][profile_index(profile) - 1], (
                    f"{name} became less restrictive under {profile}")
            previous.setdefault(name, {})[profile_index(profile)] = report.decision


def profile_index(profile):
    return ("permissive", "standard", "strict", "paranoid").index(profile)


def test_strict_blocks_honest_macro_documents(ruleset, corpus):
    db = reputation.load_database()
    standard = Scanner(ruleset=ruleset, database=db).scan_path(
        corpus["timesheet.docm"], "timesheet.docm")
    strict = Scanner(ruleset=ruleset, database=db, policy=Policy.named("strict")).scan_path(
        corpus["timesheet.docm"], "timesheet.docm")
    assert not standard.decision.blocks
    assert strict.decision.blocks


def test_paranoid_blocks_unsigned_executables(ruleset, corpus):
    db = reputation.load_database()
    report = Scanner(ruleset=ruleset, database=db,
                     policy=Policy.named("paranoid")).scan_path(
        corpus["hello-cli.exe"], "hello-cli.exe")
    assert report.decision.blocks
    assert "POLICY_BLOCK" in {f.id for f in report.findings}


def test_unknown_profile_is_rejected():
    with pytest.raises(ValueError, match="unknown policy profile"):
        Policy.named("ludicrous")


# ==========================================================================
# Publisher pinning
# ==========================================================================
def test_pin_mismatch_is_reported(ruleset, tmp_path, write_sample, isolated_home):
    original = write_sample("setup.exe", samples.benign_pe())
    with __import__("airlock.safeio", fromlist=["SafeFile"]).SafeFile(original) as sf:
        digest = sf.digests().sha256
    reputation.add_pin("setup.exe", digest, original.stat().st_size)

    pins = reputation.load_pins()
    scanner = Scanner(ruleset=ruleset, pins=pins)
    same = scanner.scan_path(original, "setup.exe")
    assert "REP_PIN_MATCH" in {f.id for f in same.findings}

    swapped = write_sample("setup.exe", samples.injector_pe())
    changed = scanner.scan_path(swapped, "setup.exe")
    assert "REP_PIN_MISMATCH" in {f.id for f in changed.findings}


# ==========================================================================
# Reporting
# ==========================================================================
def test_text_report_names_the_finding_and_the_action(scanner, corpus):
    report = scanner.scan_path(corpus["contract.docx"], "contract.docx")
    text = render_text(report, colour=False)
    assert "MALICIOUS" in text
    assert report.sha256 in text
    assert "remote template" in text.lower()
    assert "Do not open" in text


def test_json_report_is_valid_and_complete(scanner, corpus):
    reports = [scanner.scan_path(corpus[n], n) for n in ("notes.txt", "updater.exe")]
    blob = json.loads(render_json(reports))
    assert len(blob["airlock"]) == 2
    entry = blob["airlock"][1]
    assert entry["decision"] == "MALICIOUS"
    assert entry["findings"] and entry["sha256"]


def test_html_report_is_self_contained(scanner, corpus):
    reports = [scanner.scan_path(corpus[n], n) for n in list(corpus)[:5]]
    html = render_html(reports)
    assert "<!doctype html>" in html
    # No external requests: a page about hostile files should not make any.
    for marker in ("http://", "https://", "<script"):
        assert marker not in html.replace("https://www.virustotal.com", "")
    assert "prefers-color-scheme" in html


def test_html_escapes_hostile_filenames(scanner, write_sample):
    path = write_sample("a.txt", b"x")
    report = scanner.scan_path(path, '<img src=x onerror=alert(1)>.txt')
    html = render_html([report])
    assert "<img src=x" not in html
    assert "&lt;img" in html


# ==========================================================================
# Watcher
# ==========================================================================
def _watcher(scanner, directory, home, **kwargs):
    return Watcher(scanner=scanner, directories=[directory],
                   vault=Vault(home / "quarantine"),
                   audit=AuditLog(home / "audit.log", home / "audit.key"),
                   settle_seconds=0.0, **kwargs)


def test_watcher_quarantines_a_blocked_arrival(scanner, tmp_path, isolated_home):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    watcher = _watcher(scanner, inbox, isolated_home)

    bad = inbox / "Invoice.pdf.exe"
    bad.write_bytes(samples.injector_pe())
    bad.chmod(0o755)
    good = inbox / "notes.txt"
    good.write_bytes(samples.benign_text())

    events = watcher.poll_once()
    actions = {e.path.name: e.action for e in events}
    assert actions["Invoice.pdf.exe"] == "quarantined"
    assert not bad.exists()
    assert actions["notes.txt"] in ("left", "contained")
    assert good.exists()
    assert len(watcher.vault.items()) == 1


def test_watcher_strips_execute_bits_before_scanning(scanner, tmp_path, isolated_home):
    """Containment happens first, because the scan takes time and that time is
    exactly when a fresh download gets double-clicked."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    sample = inbox / "tool.sh"
    sample.write_bytes(b"#!/bin/bash\necho hello\n")
    sample.chmod(0o755)

    _watcher(scanner, inbox, isolated_home).poll_once()
    assert not stat.S_IMODE(sample.stat().st_mode) & stat.S_IXUSR


def test_watcher_ignores_partial_downloads(scanner, tmp_path, isolated_home):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "big.iso.part").write_bytes(samples.injector_pe())
    (inbox / "x.crdownload").write_bytes(samples.injector_pe())
    assert _watcher(scanner, inbox, isolated_home).poll_once() == []


def test_watcher_waits_for_a_file_to_settle(scanner, tmp_path, isolated_home):
    """Scanning a prefix of a still-downloading file yields a confident wrong
    answer, which is worse than no answer."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    watcher = _watcher(scanner, inbox, isolated_home)
    watcher.settle_seconds = 30.0  # nothing can settle by mtime within the test

    target = inbox / "download.bin"
    target.write_bytes(b"a" * 100)
    assert watcher.poll_once() == []          # first sighting: record the size
    target.write_bytes(b"a" * 200)            # still growing: size changed, reset
    assert watcher.poll_once() == []
    # Size is now stable. STABLE_POLLS consecutive confirmations are required.
    for _ in range(watch_module.STABLE_POLLS):
        assert watcher.poll_once() == []
    assert len(watcher.poll_once()) == 1      # settled


def test_watcher_does_not_follow_symlinks(scanner, tmp_path, isolated_home):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    outside = tmp_path / "outside.exe"
    outside.write_bytes(samples.injector_pe())
    (inbox / "link.exe").symlink_to(outside)
    assert _watcher(scanner, inbox, isolated_home).poll_once() == []
    assert outside.exists()


def test_watcher_prime_skips_existing_files(scanner, tmp_path, isolated_home):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "old.exe").write_bytes(samples.injector_pe())
    watcher = _watcher(scanner, inbox, isolated_home)
    assert watcher.prime() == 1
    assert watcher.poll_once() == []
    (inbox / "new.exe").write_bytes(samples.injector_pe())
    assert len(watcher.poll_once()) == 1


def test_watcher_dry_run_moves_nothing(scanner, tmp_path, isolated_home):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    bad = inbox / "bad.exe"
    bad.write_bytes(samples.injector_pe())
    events = _watcher(scanner, inbox, isolated_home, dry_run=True).poll_once()
    assert bad.exists()
    assert "dry run" in events[0].message
    assert Vault(isolated_home / "quarantine").items() == []


def test_watcher_writes_an_audit_record(scanner, tmp_path, isolated_home):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "bad.exe").write_bytes(samples.injector_pe())
    watcher = _watcher(scanner, inbox, isolated_home)
    watcher.poll_once()
    entries = list(watcher.audit.entries())
    assert entries and entries[-1].data["action"] == "quarantined"
    assert watcher.audit.verify()[0]


# ==========================================================================
# CLI
# ==========================================================================
def test_cli_exit_codes(corpus, capsys):
    assert main(["scan", str(corpus["notes.txt"]), "-q"]) == EXIT_OK
    assert main(["scan", str(corpus["hello-cli.exe"]), "-q"]) == EXIT_WARN
    assert main(["scan", str(corpus["updater.exe"]), "-q"]) == EXIT_BLOCKED


def test_cli_gate_semantics(corpus):
    assert main(["gate", str(corpus["notes.txt"])]) == EXIT_OK
    assert main(["gate", str(corpus["hello-cli.exe"])]) == EXIT_WARN
    assert main(["gate", str(corpus["hello-cli.exe"]), "--allow-warn"]) == EXIT_OK
    assert main(["gate", str(corpus["contract.docx"])]) == EXIT_BLOCKED


def test_cli_scan_json_output(corpus, capsys):
    main(["scan", str(corpus["statement.pdf"]), "--json"])
    blob = json.loads(capsys.readouterr().out)
    assert blob["airlock"][0]["decision"] == "MALICIOUS"


def test_cli_scan_directory_and_html(corpus, tmp_path, capsys):
    out = tmp_path / "report.html"
    code = main(["scan", str(next(iter(corpus.values())).parent), "-q", "--html", str(out)])
    assert code == EXIT_BLOCKED
    assert out.exists() and "<!doctype html>" in out.read_text()


def test_cli_quarantine_roundtrip(corpus, tmp_path, capsys):
    main(["scan", str(corpus["locker.exe"]), "-q", "--quarantine"])
    assert not corpus["locker.exe"].exists()

    capsys.readouterr()  # discard the scan output
    main(["quarantine", "list"])
    listing = capsys.readouterr().out
    item_id = next(line.split()[0] for line in listing.splitlines()
                   if "locker.exe" in line)

    out = tmp_path / "released"
    # A MALICIOUS verdict is refused without --force, and the refusal explains why.
    assert main(["quarantine", "release", item_id, "--to", str(out)]) == EXIT_ERROR
    assert "MALICIOUS" in capsys.readouterr().err
    assert main(["quarantine", "release", item_id, "--to", str(out), "--force"]) == EXIT_OK
    assert (out / "locker.exe").exists()
    assert main(["quarantine", "purge", item_id]) == EXIT_OK


def test_cli_log_verify(corpus, capsys):
    main(["scan", str(corpus["notes.txt"]), "-q"])
    assert main(["log", "verify"]) == EXIT_OK
    assert "intact" in capsys.readouterr().out


def test_cli_detects_a_tampered_log(corpus, isolated_home, capsys):
    main(["scan", str(corpus["updater.exe"]), "-q"])
    log = isolated_home / "audit.log"
    lines = log.read_text().splitlines()
    record = json.loads(lines[0])
    record["data"]["decision"] = "ALLOW"
    log.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    assert main(["log", "verify"]) == EXIT_BLOCKED


def test_cli_refuses_an_unpinned_ruleset(corpus, tmp_path, capsys):
    rules = tmp_path / "mine.rules"
    rules.write_text('rule R {\n meta:\n  severity = "low"\n  description = "d"\n'
                     ' strings:\n  $a = "x"\n condition:\n  $a\n}')
    assert main(["scan", str(corpus["notes.txt"]), "-q", "--rules", str(rules)]) == EXIT_ERROR
    assert "not pinned" in capsys.readouterr().err
    assert main(["scan", str(corpus["notes.txt"]), "-q",
                 "--rules", str(rules), "--trust-rules"]) == EXIT_OK


def test_cli_rules_and_pin_commands(corpus, capsys):
    assert main(["rules", "verify"]) == EXIT_OK
    assert "verified" in capsys.readouterr().out
    assert main(["rules", "list"]) == EXIT_OK
    assert main(["pin", "add", str(corpus["hello-cli.exe"])]) == EXIT_OK
    assert main(["pin", "list"]) == EXIT_OK
    assert "hello-cli.exe" in capsys.readouterr().out


def test_cli_selftest(capsys):
    assert main(["selftest"]) == EXIT_OK
    assert "all 18 samples" in capsys.readouterr().out


def test_cli_online_without_key_is_an_error(corpus, monkeypatch, capsys):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert main(["scan", str(corpus["notes.txt"]), "--online"]) == EXIT_ERROR
    assert "VT_API_KEY" in capsys.readouterr().err
