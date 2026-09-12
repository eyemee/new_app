"""Command-line interface.

Exit codes are part of the contract, because the main use of ``airlock gate`` is
inside a shell function or a CI step:

    0  allowed
    1  warnings only
    2  blocked (quarantine or malicious)
    3  usage or configuration error (including a failed ruleset integrity check)
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from . import __version__, config, reputation
from .audit import AuditError, AuditLog
from .quarantine import QuarantineError, Vault
from .report import (render_json, render_summary_line, render_text, use_colour,
                     write_html)
from .rules import RuleError, RuleSet, load_ruleset, write_lockfile
from .safeio import SafeFile, UnsafeFile, secure_mkdir
from .scanner import PROFILES, Policy, Scanner
from .verdict import Decision, Report
from .watch import Watcher, default_watch_directories

EXIT_OK, EXIT_WARN, EXIT_BLOCKED, EXIT_ERROR = 0, 1, 2, 3

DEFAULT_RULES = [config.package_data("rules", "default.rules")]
RULES_LOCK = config.package_data("rules", "rules.lock")


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="airlock",
        description="Inspect files before they are opened. Static analysis only: "
                    "nothing Airlock examines is ever executed.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit codes: 0 allowed · 1 warnings · 2 blocked · 3 error",
    )
    parser.add_argument("--version", action="version", version=f"airlock {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--profile", choices=PROFILES, default="standard",
                        help="policy profile (default: standard)")
    common.add_argument("--rules", action="append", type=Path, metavar="FILE",
                        help="rule file to load (repeatable; default: the shipped ruleset)")
    common.add_argument("--trust-rules", action="store_true",
                        help="load rule files whose digest is not pinned (this run only)")
    common.add_argument("--no-rules", action="store_true", help="skip signature rules")
    common.add_argument("--online", action="store_true",
                        help="query the online reputation service (needs VT_API_KEY; "
                             "sends only the SHA-256, never the file)")
    common.add_argument("--timeout", type=float, default=config.SCAN_TIMEOUT_SECONDS,
                        metavar="SECONDS", help="per-file scan timeout")
    common.add_argument("--no-audit", action="store_true",
                        help="do not write to the audit log")

    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", parents=[common], help="scan files or directories")
    scan.add_argument("paths", nargs="+", type=Path)
    scan.add_argument("-r", "--recursive", action="store_true")
    scan.add_argument("-v", "--verbose", action="store_true",
                      help="include informational findings")
    scan.add_argument("-q", "--quiet", action="store_true",
                      help="one line per file")
    scan.add_argument("--json", action="store_true", help="machine-readable output")
    scan.add_argument("--html", type=Path, metavar="FILE", help="write an HTML report")
    scan.add_argument("--quarantine", action="store_true",
                      help="move blocked files into the vault")

    gate = sub.add_parser("gate", parents=[common],
                          help="scan one file and exit non-zero if it is not allowed")
    gate.add_argument("path", type=Path)
    gate.add_argument("--allow-warn", action="store_true",
                      help="treat WARN as a pass (exit 0)")

    watch = sub.add_parser("watch", parents=[common],
                           help="watch directories and gate files as they arrive")
    watch.add_argument("directories", nargs="*", type=Path)
    watch.add_argument("--interval", type=float, default=2.0)
    watch.add_argument("--recursive", action="store_true")
    watch.add_argument("--dry-run", action="store_true",
                       help="report what would be quarantined without moving anything")
    watch.add_argument("--once", action="store_true", help="poll once and exit")
    watch.add_argument("--scan-existing", action="store_true",
                       help="also gate files already present when the watch starts")

    quar = sub.add_parser("quarantine", help="inspect and manage the vault")
    quar_sub = quar.add_subparsers(dest="quarantine_command", required=True)
    quar_sub.add_parser("list", help="list held files")
    show = quar_sub.add_parser("show", help="show the full record for a held file")
    show.add_argument("id")
    release = quar_sub.add_parser("release", help="restore a held file")
    release.add_argument("id")
    release.add_argument("--to", type=Path, required=True, metavar="DIR")
    release.add_argument("--force", action="store_true",
                         help="release a file judged MALICIOUS")
    purge = quar_sub.add_parser("purge", help="overwrite and delete a held file")
    purge.add_argument("id")

    rules_cmd = sub.add_parser("rules", help="inspect and pin the ruleset")
    rules_sub = rules_cmd.add_subparsers(dest="rules_command", required=True)
    rules_list = rules_sub.add_parser("list", help="list loaded rules")
    rules_list.add_argument("--rules", action="append", type=Path)
    rules_verify = rules_sub.add_parser("verify", help="check ruleset integrity")
    rules_verify.add_argument("--rules", action="append", type=Path)
    rules_pin = rules_sub.add_parser("pin", help="pin the current rule file digests")
    rules_pin.add_argument("--rules", action="append", type=Path)

    pin_cmd = sub.add_parser("pin", help="pin a publisher's build by digest")
    pin_sub = pin_cmd.add_subparsers(dest="pin_command", required=True)
    pin_add = pin_sub.add_parser("add", help="pin a file under a name")
    pin_add.add_argument("path", type=Path)
    pin_add.add_argument("--name", help="name to pin under (default: the filename)")
    pin_sub.add_parser("list", help="list pinned digests")

    log_cmd = sub.add_parser("log", help="read the audit log")
    log_sub = log_cmd.add_subparsers(dest="log_command", required=True)
    log_tail = log_sub.add_parser("tail", help="show recent records")
    log_tail.add_argument("-n", type=int, default=20)
    log_sub.add_parser("verify", help="verify the audit chain")

    selftest = sub.add_parser("selftest", parents=[common],
                              help="build the synthetic corpus and check every verdict")
    selftest.add_argument("--keep", type=Path, metavar="DIR",
                          help="write the corpus here instead of a temporary directory")
    return parser


# --------------------------------------------------------------------------
def build_scanner(args) -> Scanner:
    ruleset = RuleSet()
    if not getattr(args, "no_rules", False):
        paths = args.rules or DEFAULT_RULES
        lock = RULES_LOCK if not args.rules else None
        ruleset = load_ruleset(paths, lock, trust_unverified=args.trust_rules)

    online_key = ""
    if getattr(args, "online", False):
        online_key = os.environ.get("VT_API_KEY", "")
        if not online_key:
            raise SystemExit2("--online needs VT_API_KEY in the environment")

    return Scanner(
        ruleset=ruleset,
        database=reputation.load_database(),
        pins=reputation.load_pins(),
        policy=Policy.named(args.profile),
        online_key=online_key,
        timeout=args.timeout,
    )


class SystemExit2(Exception):
    """A usage or configuration error, reported cleanly rather than as a traceback."""


def collect_paths(paths: list[Path], recursive: bool) -> list[Path]:
    out: list[Path] = []
    for path in paths:
        if path.is_dir():
            walker = sorted(path.rglob("*")) if recursive else sorted(path.iterdir())
            out.extend(p for p in walker if p.is_file() and not p.is_symlink())
        else:
            out.append(path)
    return out


def exit_code_for(reports: list[Report]) -> int:
    worst = max((r.decision for r in reports), default=Decision.ALLOW)
    if worst >= Decision.QUARANTINE:
        return EXIT_BLOCKED
    return EXIT_WARN if worst is Decision.WARN else EXIT_OK


# --------------------------------------------------------------------------
def cmd_scan(args) -> int:
    scanner = build_scanner(args)
    audit = None if args.no_audit else AuditLog()
    vault = Vault()
    targets = collect_paths(args.paths, args.recursive)
    if not targets:
        print("nothing to scan", file=sys.stderr)
        return EXIT_ERROR

    reports: list[Report] = []
    for path in targets:
        report = scanner.scan_path(path)
        reports.append(report)
        if audit:
            _audit_scan(audit, report, "scan")

        if args.quarantine and report.decision.blocks:
            try:
                with SafeFile(path) as sf:
                    item = vault.store(sf, report, remove_original=True)
                print(f"  quarantined as {item.id}", file=sys.stderr)
            except (UnsafeFile, QuarantineError, OSError) as exc:
                print(f"  could not quarantine {path}: {exc}", file=sys.stderr)

        if not args.json:
            if args.quiet:
                print(render_summary_line(report))
            else:
                print(render_text(report, verbose=args.verbose))

    if args.json:
        print(render_json(reports), end="")
    if args.html:
        write_html(reports, args.html)
        print(f"HTML report written to {args.html}", file=sys.stderr)
    if len(reports) > 1 and not args.json and not args.quiet:
        _print_totals(reports)
    return exit_code_for(reports)


def cmd_gate(args) -> int:
    scanner = build_scanner(args)
    report = scanner.scan_path(args.path)
    if not args.no_audit:
        _audit_scan(AuditLog(), report, "gate")
    print(render_text(report), file=sys.stderr)
    code = exit_code_for([report])
    if code == EXIT_WARN and args.allow_warn:
        return EXIT_OK
    return code


def cmd_watch(args) -> int:
    scanner = build_scanner(args)
    directories = args.directories or default_watch_directories()
    directories = [Path(d) for d in directories]
    missing = [d for d in directories if not d.is_dir()]
    if missing:
        for d in missing:
            print(f"not a directory: {d}", file=sys.stderr)
        return EXIT_ERROR
    if not directories:
        print("no directories to watch (pass them explicitly)", file=sys.stderr)
        return EXIT_ERROR

    watcher = Watcher(
        scanner=scanner, directories=directories,
        vault=Vault(), audit=AuditLog(), interval=args.interval,
        dry_run=args.dry_run, recursive=args.recursive,
        on_event=lambda e: _print_event(e),
    )
    if not args.scan_existing:
        primed = watcher.prime()
        print(f"ignoring {primed} file(s) already present; "
              "pass --scan-existing to gate them too", file=sys.stderr)

    colour = use_colour(sys.stderr)
    banner = ", ".join(str(d) for d in directories)
    print(f"airlock {__version__} watching {banner}"
          f"  [profile: {args.profile}{', dry run' if args.dry_run else ''}]",
          file=sys.stderr)
    print("New files are contained on arrival, then scanned. Ctrl-C to stop.\n",
          file=sys.stderr)

    try:
        if args.once:
            events = watcher.poll_once()
        else:
            events = watcher.run()
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
        return EXIT_OK
    blocked = [e for e in events if e.action == "quarantined"]
    return EXIT_BLOCKED if blocked else EXIT_OK


def _print_event(event) -> None:
    line = render_summary_line(event.report, colour=use_colour(sys.stderr))
    print(f"{time.strftime('%H:%M:%S')}  {line}", file=sys.stderr)
    if event.message:
        print(f"            {event.message}", file=sys.stderr)


def cmd_quarantine(args) -> int:
    vault = Vault()
    if args.quarantine_command == "list":
        items = vault.items()
        if not items:
            print("quarantine is empty")
            return EXIT_OK
        print(f"{'id':34} {'verdict':11} {'size':>9}  name")
        for item in items:
            state = item.decision + ("*" if item.released_at else "")
            print(f"{item.id:34} {state:11} {item.size:>9}  {item.original_name}")
        print(f"\n{len(items)} item(s) in {vault.root}")
        print("* released at least once")
        return EXIT_OK

    if args.quarantine_command == "show":
        item = vault.get(args.id)
        print(f"id            {item.id}")
        print(f"original      {item.original_path}")
        print(f"verdict       {item.decision}  (score {item.score})")
        print(f"type          {item.file_type}")
        print(f"sha256        {item.sha256}")
        print(f"size          {item.size}")
        print(f"quarantined   {item.quarantined_at}")
        if item.released_at:
            print(f"released      {item.released_at}")
        if item.note:
            print(f"note          {item.note}")
        print(f"\nfindings ({len(item.findings)}):")
        for f in item.findings:
            print(f"  [{f.get('severity', '?'):8}] {f.get('title', '')}")
            for e in f.get("evidence", [])[:3]:
                print(f"             · {e}")
        return EXIT_OK

    if args.quarantine_command == "release":
        if not args.to.exists():
            secure_mkdir(args.to, 0o700)
        destination = vault.release(args.id, args.to, force=args.force)
        AuditLog().append("quarantine.release",
                          {"id": args.id, "to": str(destination), "forced": args.force})
        print(f"released to {destination}")
        print("Execute bits are not restored. Verify the file before using it.")
        return EXIT_OK

    item = vault.purge(args.id)
    AuditLog().append("quarantine.purge", {"id": item.id, "sha256": item.sha256})
    print(f"purged {item.id} ({item.original_name})")
    print("Overwritten in place then unlinked. On a journalling or copy-on-write "
          "filesystem the original blocks may still exist.")
    return EXIT_OK


def cmd_rules(args) -> int:
    paths = args.rules or DEFAULT_RULES
    lock = RULES_LOCK if not args.rules else None

    if args.rules_command == "pin":
        digests = write_lockfile(paths, RULES_LOCK)
        print(f"pinned {len(digests)} rule file(s) in {RULES_LOCK}")
        for name, digest in digests.items():
            print(f"  {name}  {digest}")
        return EXIT_OK

    ruleset = load_ruleset(paths, lock, trust_unverified=args.rules_command == "list")
    if args.rules_command == "verify":
        print(f"ruleset verified: {len(ruleset.rules)} rule(s) across {len(paths)} file(s)")
        for name, digest in ruleset.digests.items():
            print(f"  {name}  {digest}")
        return EXIT_OK

    print(f"{len(ruleset.rules)} rule(s)"
          f"{'' if ruleset.verified else '  [UNVERIFIED: digests are not pinned]'}\n")
    for rule in ruleset.rules:
        tags = f"  :{' '.join(rule.tags)}" if rule.tags else ""
        print(f"  {rule.severity.name:8} {rule.name}{tags}")
        if rule.meta.get("description"):
            print(f"           {rule.meta['description']}")
        print(f"           {len(rule.patterns)} pattern(s)"
              + (f" · ATT&CK {rule.meta['attck']}" if rule.meta.get("attck") else ""))
    return EXIT_OK


def cmd_pin(args) -> int:
    if args.pin_command == "list":
        pins = reputation.load_pins()
        if not pins:
            print("no pinned digests")
            return EXIT_OK
        for name, pin in sorted(pins.items()):
            print(f"{pin.sha256}  {name}  ({pin.size} bytes, pinned {pin.first_seen})")
        return EXIT_OK

    name = args.name or args.path.name
    with SafeFile(args.path) as sf:
        digest = sf.digests().sha256
        size = sf.size
    pin = reputation.add_pin(name, digest, size, str(args.path.resolve()))
    AuditLog().append("pin.add", {"name": name, "sha256": digest})
    print(f"pinned {name}\n  sha256 {pin.sha256}\n  size   {pin.size}")
    print("\nFuture files arriving under this name are compared against this digest. "
          "A mismatch is reported, not blocked -- an update is a mismatch too.")
    return EXIT_OK


def cmd_log(args) -> int:
    log = AuditLog()
    if args.log_command == "verify":
        ok, problems = log.verify()
        total = sum(1 for _ in log.entries())
        if ok:
            print(f"audit chain intact: {total} record(s) verified")
            print("Note: this proves no record was altered or reordered. It cannot prove "
                  "records were not removed from the end.")
            return EXIT_OK
        print(f"AUDIT CHAIN BROKEN ({len(problems)} problem(s)):", file=sys.stderr)
        for problem in problems:
            print(f"  · {problem}", file=sys.stderr)
        return EXIT_BLOCKED

    entries = log.tail(args.n)
    if not entries:
        print("audit log is empty")
        return EXIT_OK
    for entry in entries:
        data = entry.data
        summary = data.get("decision") or data.get("action") or ""
        name = data.get("name") or data.get("path") or data.get("id") or ""
        print(f"{entry.seq:>6}  {entry.ts}  {entry.event:18} {summary:11} {name}")
    return EXIT_OK


def cmd_selftest(args) -> int:
    """Build the synthetic corpus and confirm every verdict still holds."""
    import tempfile

    from . import samples

    scanner = build_scanner(args)
    directory = args.keep or Path(tempfile.mkdtemp(prefix="airlock-selftest-"))
    paths = samples.write_samples(directory)
    print(f"airlock {__version__} selftest — {len(paths)} synthetic samples in {directory}")
    print("Every sample is generated inert: no sample here contains a payload.\n")
    print(f"{'sample':30} {'type':11} {'score':>5}  {'verdict':11} expected")
    print("-" * 82)

    failures = 0
    for name, (_builder, expected) in samples.CATALOGUE.items():
        report = scanner.scan_path(paths[name], name)
        actual = report.decision.label
        mark = "" if actual == expected else "  <-- FAIL"
        if mark:
            failures += 1
        print(f"{name:30} {report.file_type:11} {report.score:5}  {actual:11} {expected}{mark}")
        if report.errors:
            print(f"    errors: {'; '.join(report.errors)}")

    print()
    if failures:
        print(f"{failures} of {len(paths)} samples did not produce the expected verdict.",
              file=sys.stderr)
        return EXIT_BLOCKED
    print(f"all {len(paths)} samples produced the expected verdict")
    if not args.keep:
        import shutil
        shutil.rmtree(directory, ignore_errors=True)
    return EXIT_OK


# --------------------------------------------------------------------------
def _audit_scan(log: AuditLog, report: Report, event: str) -> None:
    try:
        log.append(event, {
            "path": report.path, "name": report.display_name,
            "sha256": report.sha256, "decision": report.decision.label,
            "score": report.score,
            "top_findings": [f.id for f in report.sorted_findings()[:5]],
        })
    except (AuditError, OSError) as exc:
        print(f"warning: could not write the audit record: {exc}", file=sys.stderr)


def _print_totals(reports: list[Report]) -> None:
    counts: dict[str, int] = {}
    for report in reports:
        counts[report.decision.label] = counts.get(report.decision.label, 0) + 1
    parts = [f"{counts[d.label]} {d.label.lower()}" for d in Decision if d.label in counts]
    print(f"  {len(reports)} file(s): " + ", ".join(parts))


HANDLERS = {
    "scan": cmd_scan, "gate": cmd_gate, "watch": cmd_watch,
    "quarantine": cmd_quarantine, "rules": cmd_rules, "pin": cmd_pin,
    "log": cmd_log, "selftest": cmd_selftest,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return HANDLERS[args.command](args)
    except SystemExit2 as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except RuleError as exc:
        print(f"ruleset error: {exc}", file=sys.stderr)
        print("Airlock will not scan with rules it cannot verify.", file=sys.stderr)
        return EXIT_ERROR
    except (QuarantineError, AuditError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except UnsafeFile as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
