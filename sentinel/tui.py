"""Terminal-Dashboard: eine Kachel je Check, darunter die Befunde. Liest nur die Datenbank (Checks laufen per
watch/timer). build_view ist eine reine Funktion -> testbar ohne Terminal; --once gibt den gleichen Inhalt als Text aus."""
from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone

from sentinel import __version__

CHECKS = ("integrity", "accounts", "services", "network", "logs", "resources", "boot")
RANK = {"CRIT": 2, "WARN": 1}
ATTR = {2: "crit", 1: "warn", 0: "ok"}
LABEL = {2: "KRITISCH", 1: "WARNUNG", 0: "OK"}


def _age(ts: str, now: str | None) -> str:
    try:
        n = datetime.fromisoformat(now) if now else datetime.now(timezone.utc)
        s = int((n - datetime.fromisoformat(ts)).total_seconds())
    except (TypeError, ValueError):
        return "?"
    return f"vor {s} s" if s < 120 else f"vor {s // 60} min" if s < 7200 else f"vor {s // 3600} h"


def _cut(t: str, w: int) -> str:
    return t if len(t) <= w else t[:max(0, w - 1)] + "…"


def build_view(state: dict, width: int = 80, now: str | None = None) -> list[tuple[str, str]]:
    lines: list[tuple[str, str]] = []
    worst = max((max((RANK.get(f["severity"], 0) for f in s["findings"]), default=0) for s in state.values()), default=0)
    head = f"Sentinel {__version__} · Aethelos" + (f" · Gesamt: {LABEL[worst]}" if state else "")
    lines.append((_cut(head, width), ATTR[worst] if state else "dim"))
    lines.append(("─" * min(width, 60), "dim"))
    if not state:
        lines.append((_cut("noch kein Lauf gespeichert (sudo sentinel baseline, dann check/watch)", width), "dim"))
        return lines
    for c in CHECKS:
        s = state.get(c)
        if s is None:
            lines.append((_cut(f"  {c:<10} —         noch nie gelaufen", width), "dim"))
            continue
        r = max((RANK.get(f["severity"], 0) for f in s["findings"]), default=0)
        n = len(s["findings"])
        lines.append((_cut(f"  {c:<10} {LABEL[r]:<9} {n} Befund(e)  {_age(s['ts'], now)}  (Lauf #{s['run_id']})", width),
                      ATTR[r]))
    fs = sorted((f for s in state.values() for f in s["findings"]), key=lambda f: -RANK.get(f["severity"], 0))
    lines.append(("─" * min(width, 60), "dim"))
    if not fs:
        lines.append((_cut("keine Befunde", width), "ok"))
    for f in fs:
        r = RANK.get(f["severity"], 0)
        lines.append((_cut(f"{f['severity']:<4} {f['check']:<9} {f['subject']}", width), ATTR[r]))
        lines.append((_cut(f"     {f['evidence']}  (seit {f['first_seen']})", width), "dim"))
    return lines


def _state(db: str) -> dict:
    from sentinel.store import Store
    st = Store(db)
    try:
        return st.latest_by_check()
    finally:
        st.close()


def main(db: str, once: bool = False, interval: float = 2.0) -> int:
    if not os.path.exists(db):
        print(f"sentinel tui: keine Datenbank {db} (zuerst: sudo sentinel baseline; Lesen braucht root)", file=sys.stderr)
        return 2
    if once:
        for t, _ in build_view(_state(db), width=120):
            print(t)
        return 0
    import curses
    return curses.wrapper(_loop, db, interval)


def _loop(scr, db: str, interval: float) -> int:
    import curses
    curses.curs_set(0)
    colors = {"ok": 0, "warn": 0, "crit": 0, "dim": curses.A_DIM}
    if curses.has_colors():
        curses.use_default_colors()
        for i, (k, col) in enumerate((("ok", curses.COLOR_GREEN), ("warn", curses.COLOR_YELLOW),
                                      ("crit", curses.COLOR_RED)), start=1):
            curses.init_pair(i, col, -1)
            colors[k] = curses.color_pair(i) | (curses.A_BOLD if k == "crit" else 0)
    scr.timeout(int(interval * 1000))
    while True:
        h, w = scr.getmaxyx()
        scr.erase()
        try:
            view = build_view(_state(db), width=w - 1)
        except Exception as e:                      # DB kurz gesperrt o.ae.: anzeigen statt abstuerzen
            view = [(f"Fehler beim Lesen: {e}", "crit")]
        for y, (t, a) in enumerate(view[:h - 1]):
            scr.addstr(y, 0, t, colors.get(a, 0))
        scr.addstr(h - 1, 0, _cut(f"q = beenden · aktualisiert {time.strftime('%H:%M:%S')}", w - 1), curses.A_DIM)
        scr.refresh()
        if scr.getch() in (ord("q"), ord("Q"), 27):
            return 0
