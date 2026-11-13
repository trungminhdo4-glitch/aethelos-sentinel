"""Kommandozeile: sentinel <befehl>. Exit 2 = Sentinel konnte nicht pruefen (nie 'gruen' raten)."""
from __future__ import annotations

import argparse
import sys

from sentinel import __version__, config
from sentinel.checks import accounts, integrity
from sentinel.model import exit_code
from sentinel.scan import scan, suid_scan
from sentinel.store import Store, dumps

EXIT_INTERNAL = 2
TODO = ("tui", "export")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description="Integritaets- und Diagnose-Waechter fuer Aethelos")
    p.add_argument("--version", action="version", version=f"sentinel {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    for c, h in (("baseline", "Soll-Zustand aufnehmen"), ("check", "gegen Baseline pruefen"),
                 ("report", "letzten Lauf anzeigen"), ("tui", "Dashboard (M4)"), ("export", "Baseline exportieren (M3)")):
        s = sub.add_parser(c, help=h)
        s.add_argument("--root", default="/", help="Wurzel des zu pruefenden Systems (Tests)")
        s.add_argument("--db", default=config.DEFAULT_DB)
        s.add_argument("--json", action="store_true")
    return p


def fail(msg: str) -> int:
    print(f"sentinel: {msg}", file=sys.stderr)
    return EXIT_INTERNAL


def cmd_baseline(a) -> int:
    res = scan(a.root)
    if res.errors:
        return fail("Baseline abgebrochen, nicht lesbar:\n  " + "\n  ".join(res.errors[:20]))
    digest = Store(a.db).save_baseline(res.entries, suid_scan(a.root))
    print(f"Baseline gespeichert: {len(res.entries)} Eintraege, digest {digest[:16]}…")
    return 0


def cmd_check(a) -> int:
    st = Store(a.db)
    try:
        b = st.load_baseline()
    except ValueError as e:
        return fail(str(e))
    if b is None:
        return fail(f"keine Baseline in {a.db} (zuerst: sudo sentinel baseline)")
    base, base_suid, _ = b
    res = scan(a.root)
    if res.errors:
        return fail("Pruefung unvollstaendig, nicht lesbar:\n  " + "\n  ".join(res.errors[:20]))
    try:
        findings = integrity.check(base, base_suid, res.entries, suid_scan(a.root)) + accounts.check(a.root)
    except OSError as e:
        return fail(f"Konten-Pruefung nicht moeglich: {e}")
    rc = exit_code(findings)
    st.record_run(findings, rc)
    if a.json:
        print(dumps({"exit": rc, "findings": [f.to_dict() for f in findings]}))
    else:
        _print_table([f.to_dict() for f in findings], rc)
    return rc


def cmd_report(a) -> int:
    run, fs = Store(a.db).last_run()
    if run is None:
        return fail("noch kein Lauf gespeichert")
    if a.json:
        print(dumps({"run": run, "findings": fs}))
    else:
        print(f"Lauf #{run['id']} um {run['ts']} (UTC)")
        _print_table(fs, run["exit"])
    return run["exit"]


def _print_table(fs: list[dict], rc: int) -> None:
    for f in fs:
        print(f"{f['severity']:<4}  {f['check']:<9}  {f['subject']}  {f['evidence']}")
    label = {0: "OK", 10: "WARNUNG", 11: "KRITISCH"}.get(rc, str(rc))
    print(f"-- {len(fs)} Befund(e), Ergebnis: {label} (exit {rc})")


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.command in TODO:
        return fail(f"{a.command}: noch nicht implementiert (Meilenstein M3/M4)")
    return {"baseline": cmd_baseline, "check": cmd_check, "report": cmd_report}[a.command](a)

