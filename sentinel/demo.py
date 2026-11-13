"""Demo-Ablauf mit Stoppuhr (als root, sentinel-watch muss laufen). Spielt die Demo aus SENTINEL-PLAN Abschnitt 1 durch
und misst, wie schnell das Dashboard (= die Datenbank) rot und wieder gruen wird. Exit 0 = alle Schritte in der Zeit."""
from __future__ import annotations

import os
import subprocess
import sys
import time

from sentinel import config, faults
from sentinel.store import Store

LIMIT_INTEGRITY = 15.0       # Ziel aus dem Plan: Zeile innerhalb von 15 s rot
LIMIT_SERVICE = 30.0         # Live-Checks laufen alle 15 s


def wait_for(pred, timeout: float, poll: float = 0.5, clock=time.monotonic, sleep=time.sleep):
    """(True, Sekunden, Wert) sobald pred() etwas Wahres liefert, sonst (False, timeout, None)."""
    t0 = clock()
    while True:
        v = pred()
        if v:
            return True, clock() - t0, v
        if clock() - t0 >= timeout:
            return False, timeout, None
        sleep(poll)


def _latest(db: str) -> dict:
    st = Store(db)
    try:
        return st.latest_by_check()
    finally:
        st.close()


def _finding(db: str, check: str, subject: str, after: int):
    s = _latest(db).get(check)
    if s and s["run_id"] > after:
        return next((f for f in s["findings"] if f["subject"] == subject), None)
    return None


def _clean(db: str, check: str, after: int):
    s = _latest(db).get(check)
    return s if s and s["run_id"] > after and not s["findings"] else None


def _last_id(db: str, check: str) -> int:
    s = _latest(db).get(check)
    return s["run_id"] if s else 0


def main(argv=None, db: str = config.DEFAULT_DB) -> int:
    if os.geteuid() != 0:
        print("sentinel-demo: braucht root (sudo sentinel-demo)", file=sys.stderr)
        return 2
    if subprocess.run(["systemctl", "is-active", "-q", "sentinel-watch.service"]).returncode != 0:
        print("sentinel-demo: sentinel-watch.service laeuft nicht (sudo systemctl start sentinel-watch)", file=sys.stderr)
        return 2
    if faults.active():
        print(f"sentinel-demo: Fehler noch aktiv: {faults.active()}", file=sys.stderr)
        return 2
    rows = []

    def step(name, ok, secs, limit, detail=""):
        rows.append((name, "PASS" if ok and secs <= limit else "FAIL", secs, limit))
        print(f"  {'✓' if ok and secs <= limit else '✗'} {name}: {secs:.1f} s (Ziel ≤ {limit:.0f} s) {detail}", flush=True)

    print("1) Ausgangslage: integrity und services gruen?")
    for c in ("integrity", "services"):
        ok, secs, _ = wait_for(lambda c=c: (s := _latest(db).get(c)) is not None and not s["findings"], 20)
        step(f"{c} gruen", ok, secs, 20)

    print("2) sentinel-fault inject F1 (/usr/bin/ls manipuliert)")
    before = _last_id(db, "integrity")
    faults.inject("F1")
    try:
        ok, secs, f = wait_for(lambda: _finding(db, "integrity", "/usr/bin/ls", before), LIMIT_INTEGRITY + 5)
        step("Dashboard rot", ok, secs, LIMIT_INTEGRITY, f"[{f['severity']}] {f['evidence']} seit {f['first_seen']}" if f else "")
    finally:
        before = _last_id(db, "integrity")
        faults.undo("F1")
    print("3) sentinel-fault undo F1")
    ok, secs, _ = wait_for(lambda: _clean(db, "integrity", before), LIMIT_INTEGRITY + 5)
    step("wieder gruen", ok, secs, LIMIT_INTEGRITY)

    print("4) sshd stoppen (F4)")
    before = _last_id(db, "services")
    faults.inject("F4")
    try:
        ok, secs, f = wait_for(lambda: _finding(db, "services", "sshd.service", before), LIMIT_SERVICE + 5)
        step("Dienst-Befund mit Journal-Zeile", ok and "Journal:" in (f or {}).get("evidence", ""), secs, LIMIT_SERVICE,
             f["evidence"] if f else "")
    finally:
        before = _last_id(db, "services")
        faults.undo("F4")
    ok, secs, _ = wait_for(lambda: _clean(db, "services", before), LIMIT_SERVICE + 5)
    step("sshd wieder gruen", ok, secs, LIMIT_SERVICE)

    passed = sum(r[1] == "PASS" for r in rows)
    print(f"-- Demo: {passed}/{len(rows)} Schritte in der Zeit")
    return 0 if passed == len(rows) else 1
