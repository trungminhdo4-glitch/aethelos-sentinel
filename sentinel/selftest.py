"""Integrationstest auf dem ECHTEN System: Baseline -> je Fehler inject/check/undo/check. Nur als root.
Exit 0 = alle erkannt und sauber zurueckgesetzt, 1 = mindestens ein Fehler nicht erkannt/nicht sauber, 2 = konnte nicht laufen."""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import time

from sentinel import cli, faults


def _run(*args) -> tuple[int, dict]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cli.main(list(args))
    try:
        return rc, json.loads(out.getvalue()) if out.getvalue().strip() else {}
    except json.JSONDecodeError:
        return rc, {}


def main(argv: list[str] | None = None) -> int:
    argv = list(argv or [])
    as_json = "--json" in argv
    argv = [x for x in argv if x != "--json"]
    if os.geteuid() != 0:
        print("sentinel-selftest: braucht root (sudo sentinel-selftest)", file=sys.stderr)
        return 2
    if faults.active():
        print(f"sentinel-selftest: Fehler noch aktiv: {faults.active()} (erst sentinel-fault undo)", file=sys.stderr)
        return 2
    os.makedirs("/var/lib/sentinel", mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(dir="/var/lib/sentinel", prefix="selftest-") as td:
        db = os.path.join(td, "selftest.db")
        if _run("baseline", "--db", db)[0] != 0:
            return 2
        rc, _ = _run("check", "--db", db, "--json")
        if rc != 0:
            print(f"sentinel-selftest: System schon vor dem Test nicht sauber (exit {rc})", file=sys.stderr)
            return 2
        rows, ok_all = [], True
        only = [f.upper() for f in argv] if argv else list(faults.FAULTS)
        bad = [f for f in only if f not in faults.FAULTS]
        if bad:
            print(f"sentinel-selftest: unbekannt: {bad}", file=sys.stderr)
            return 2
        for fid in only:
            spec = faults.FAULTS[fid]
            chk, expect, want_rc = faults.expected(fid)
            try:
                faults.inject(fid)
                rc, data = _run("check", "--db", db, "--json")
            finally:
                faults.undo(fid)
            for _ in range(5):               # Live-Fehler (Dienst-Neustart, DNS) brauchen kurz, bis alles wieder steht
                rc_after, _ = _run("check", "--db", db, "--json")
                if rc_after == 0:
                    break
                time.sleep(3)
            hits = [f for f in data.get("findings", []) if f["subject"] == expect and f["check"] == chk]
            ok = rc == want_rc and bool(hits) and rc_after == 0
            ok_all &= ok
            rows.append((fid, spec["desc"], rc, hits[0]["severity"] if hits else "-", rc_after, "PASS" if ok else "FAIL"))
    if as_json:
        print(json.dumps([{"id": r[0], "desc": r[1], "exit": r[2], "severity": r[3], "exit_after": r[4], "result": r[5]}
                          for r in rows], ensure_ascii=False))
        return 0 if ok_all else 1
    print(f"{'ID':<4} {'erkannt':<8} {'exit':<5} {'danach':<7} {'':<5} Fehler")
    for fid, desc, rc, sev, rc_after, res in rows:
        print(f"{fid:<4} {sev:<8} {rc:<5} {rc_after:<7} {res:<5} {desc}")
    passed = sum(r[-1] == "PASS" for r in rows)
    print(f"-- {passed}/{len(rows)} erkannt und sauber zurueckgesetzt")
    return 0 if ok_all else 1
