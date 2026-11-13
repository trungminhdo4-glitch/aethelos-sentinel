"""Journal: neue Meldungen mit Prioritaet err oder schlimmer seit dem letzten Lauf (Cursor), je Absender zusammengefasst."""
from __future__ import annotations

import json

from sentinel.model import Finding, Severity
from sentinel.sysprobe import ProbeError

CHECK = "logs"
BASE = ["journalctl", "-p", "err", "-o", "json", "--no-pager"]
IGNORE_IDENT = {"sentinel"}          # eigene Meldungen nicht als Befund zaehlen


def _parse(out: str) -> list[dict]:
    try:
        return [json.loads(l) for l in out.splitlines() if l.strip()]
    except json.JSONDecodeError:
        raise ProbeError("journalctl: Ausgabe ist kein JSON") from None


def _msg(e: dict) -> str:
    m = e.get("MESSAGE", "")
    if isinstance(m, list):                       # binaere Meldung: Liste von Bytes
        m = bytes(m).decode("utf-8", "replace")
    return str(m).replace("\n", " ")[:200]


def _sender(e: dict) -> str:
    if e.get("_TRANSPORT") == "kernel":
        return "kernel"
    return e.get("SYSLOG_IDENTIFIER") or e.get("_COMM") or e.get("_SYSTEMD_UNIT") or "unbekannt"


def check(run, cursor: str | None) -> tuple[list[Finding], str | None]:
    """Liefert (Befunde, neuer Cursor). Ohne Cursor: der aktuelle Boot."""
    rc, out = run(BASE + ([f"--after-cursor={cursor}"] if cursor else ["-b"]))
    if rc != 0 and cursor:                        # Cursor veraltet (z.B. fluechtiges Journal) -> aktueller Boot
        cursor = None
        rc, out = run(BASE + ["-b"])
    if rc != 0:
        raise ProbeError(f"journalctl: exit {rc}")
    entries = _parse(out)
    new_cursor = entries[-1].get("__CURSOR", cursor) if entries else cursor
    groups: dict[str, list[dict]] = {}
    for e in entries:
        s = _sender(e)
        if s not in IGNORE_IDENT:
            groups.setdefault(s, []).append(e)
    findings = []
    for s, es in groups.items():
        more = f" (+{len(es) - 1} weitere)" if len(es) > 1 else ""
        findings.append(Finding(CHECK, Severity.WARN, s, f"PRIORITY {es[0].get('PRIORITY', '?')}: {_msg(es[0])}{more}"))
    return findings, new_cursor


def current_cursor(run) -> str | None:
    """Cursor der neuesten Journal-Zeile: ab hier zaehlt der naechste Lauf."""
    rc, out = run(["journalctl", "-n", "1", "-o", "json", "--no-pager"])
    if rc != 0:
        raise ProbeError(f"journalctl -n 1: exit {rc}")
    es = _parse(out)
    return es[-1].get("__CURSOR") if es else None
