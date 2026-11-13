"""Kommandozeile: sentinel <befehl>. Exit 2 = Sentinel konnte nicht pruefen (nie 'gruen' raten)."""
from __future__ import annotations

import argparse
import os
import sys

from sentinel import __version__, config, journal, sysprobe
from sentinel.checks import accounts, boot, integrity, logs, network, resources, services
from sentinel.model import exit_code
from sentinel.scan import scan, suid_scan
from sentinel.store import Store, dumps

EXIT_INTERNAL = 2
TODO = ()
FILE_CHECKS = ("integrity", "accounts")
ALL_CHECKS = FILE_CHECKS + ("services", "network", "logs", "resources", "boot")
PRIORITY = {0: 6, 10: 5, 11: 4}     # info / notice / warning -- nie 'err', sonst meldet der logs-Check Sentinel selbst


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description="Integritaets- und Diagnose-Waechter fuer Aethelos")
    p.add_argument("--version", action="version", version=f"sentinel {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    for c, h in (("baseline", "Soll-Zustand aufnehmen"), ("check", "gegen Baseline pruefen"),
                 ("report", "letzten Lauf anzeigen"), ("tui", "Terminal-Dashboard (liest die Datenbank)"), ("watch", "Dauerbetrieb: inotify + Live-Checks"), ("export", "Baseline als JSON fuer den Host (sentinel-host pin/verify)")):
        s = sub.add_parser(c, help=h)
        s.add_argument("--root", default="/", help="Wurzel des zu pruefenden Systems (Tests)")
        s.add_argument("--db", default=config.DEFAULT_DB)
        s.add_argument("--json", action="store_true")
        if c == "tui":
            s.add_argument("--once", action="store_true", help="einmal als Text ausgeben (ohne curses)")
            s.add_argument("--interval", type=float, default=2.0)
        s.add_argument("--checks", help=f"Komma-Liste aus {','.join(ALL_CHECKS)} "
                                        "(Default: alle bei --root /, sonst nur integrity,accounts)")
    return p


def default_checks(root: str) -> list[str]:
    """Live-Checks (systemctl, journal, Netz ...) gelten nur fuer das laufende System, nie fuer ein fremdes --root."""
    return list(ALL_CHECKS) if os.path.realpath(root) == "/" else list(FILE_CHECKS)


def selected(a) -> list[str]:
    if not a.checks:
        return default_checks(a.root)
    names = [c.strip() for c in a.checks.split(",") if c.strip()]
    bad = [c for c in names if c not in ALL_CHECKS]
    if bad:
        raise ValueError(f"unbekannte Checks: {', '.join(bad)} (bekannt: {', '.join(ALL_CHECKS)})")
    return names


def fail(msg: str) -> int:
    print(f"sentinel: {msg}", file=sys.stderr)
    return EXIT_INTERNAL


def _run(cmd, timeout=10):
    return sysprobe.run(cmd, timeout)        # zur Laufzeit nachschlagen (Tests ersetzen sysprobe.run)


def cmd_baseline(a) -> int:
    try:
        names = selected(a)
        res = scan(a.root)
        if res.errors:
            return fail("Baseline abgebrochen, nicht lesbar:\n  " + "\n  ".join(res.errors[:20]))
        cursor = logs.current_cursor(_run) if "logs" in names else None
    except (ValueError, sysprobe.ProbeError) as e:
        return fail(str(e))
    st = Store(a.db)
    digest = st.save_baseline(res.entries, suid_scan(a.root))
    st.set_meta("logs_cursor", cursor)
    print(f"Baseline gespeichert: {len(res.entries)} Eintraege, digest {digest[:16]}…")
    return 0


def run_checks(names: list[str], a, st: Store, base, base_suid) -> list:
    findings = []
    if "integrity" in names:
        res = scan(a.root)
        if res.errors:
            raise sysprobe.ProbeError("Pruefung unvollstaendig, nicht lesbar:\n  " + "\n  ".join(res.errors[:20]))
        findings += integrity.check(base, base_suid, res.entries, suid_scan(a.root))
    if "accounts" in names:
        try:
            findings += accounts.check(a.root)
        except OSError as e:
            raise sysprobe.ProbeError(f"Konten-Pruefung nicht moeglich: {e}") from None
    if "services" in names:
        findings += services.check(_run)
    if "network" in names:
        findings += network.check()
    if "logs" in names:
        fs, cursor = logs.check(_run, st.get_meta("logs_cursor"))
        findings += fs
        a._new_cursor = cursor
    if "resources" in names:
        findings += resources.check()
    if "boot" in names:
        findings += boot.check(_run)
    return findings


def cmd_check(a) -> int:
    try:
        names = selected(a)
    except ValueError as e:
        return fail(str(e))
    st = Store(a.db)
    try:
        b = st.load_baseline()
    except ValueError as e:
        return fail(str(e))
    if b is None:
        return fail(f"keine Baseline in {a.db} (zuerst: sudo sentinel baseline)")
    base, base_suid, _ = b
    a._new_cursor = None
    try:
        findings = run_checks(names, a, st, base, base_suid)
    except (sysprobe.ProbeError, OSError) as e:
        return fail(str(e))
    rc = exit_code(findings)
    st.record_run(findings, rc, names)
    if "logs" in names:
        st.set_meta("logs_cursor", a._new_cursor)
    if os.path.realpath(a.root) == "/":     # nur das echte System meldet ans Journal (Tests mit --root nicht)
        _journal(findings, rc, names)
    if a.json:
        print(dumps({"exit": rc, "checks": names, "findings": [f.to_dict() for f in findings]}))
    else:
        _print_table([f.to_dict() for f in findings], rc)
    return rc


def _journal(findings, rc, names) -> None:
    journal.send({"MESSAGE": f"sentinel check: {len(findings)} Befund(e), exit {rc}", "PRIORITY": PRIORITY.get(rc, 4),
                  "SENTINEL_EXIT": rc, "SENTINEL_FINDINGS": len(findings),
                  "SENTINEL_CRIT": sum(f.severity.name == "CRIT" for f in findings),
                  "SENTINEL_WARN": sum(f.severity.name == "WARN" for f in findings),
                  "SENTINEL_CHECKS": ",".join(names)})


def cmd_export(a) -> int:
    from sentinel import host
    try:
        b = Store(a.db).load_baseline()
    except ValueError as e:
        return fail(str(e))
    if b is None:
        return fail(f"keine Baseline in {a.db} (zuerst: sudo sentinel baseline)")
    print(dumps(host.to_export(*b)))
    return 0


def cmd_tui(a) -> int:
    from sentinel import tui
    return tui.main(a.db, once=a.once, interval=a.interval)


def cmd_watch(a) -> int:
    from sentinel import watch
    return watch.main(a.root, a.db)


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
        return fail(f"{a.command}: noch nicht implementiert (Meilenstein M4)")
    return {"baseline": cmd_baseline, "check": cmd_check, "report": cmd_report, "export": cmd_export,
            "tui": cmd_tui, "watch": cmd_watch}[a.command](a)
