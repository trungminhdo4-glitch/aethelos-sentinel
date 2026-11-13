"""Dauerbetrieb (sentinel watch / sentinel-watch.service):
- inotify auf alle Integritaets-Pfade: relevante Aenderung -> nach kurzer Ruhepause (debounce) voller Check
- alle INTERVAL Sekunden die Live-Checks (Dienste, Netz, Journal, Ressourcen, Boot)
"""
from __future__ import annotations

import contextlib
import fnmatch
import io
import os
import signal
import sys
import time

from sentinel import config
from sentinel.inotify import OVERFLOW, Inotify

DEBOUNCE = 2.0
INTERVAL = 15.0
LIVE = ("services", "network", "logs", "resources", "boot")


class Scheduler:
    """Reine Zeitlogik, ohne Uhr: 'full' nach Ereignis + Ruhepause, sonst 'live' im festen Abstand."""

    def __init__(self, debounce=DEBOUNCE, interval=INTERVAL, now=0.0):
        self.debounce, self.interval = debounce, interval
        self.last_event = None
        self.last_live = now

    def event(self, now: float) -> None:
        self.last_event = now

    def due(self, now: float):
        if self.last_event is not None and now - self.last_event >= self.debounce:
            return "full"
        if now - self.last_live >= self.interval:
            return "live"
        return None

    def ran(self, kind: str, now: float) -> None:
        if kind == "full":
            self.last_event = None
        self.last_live = now                  # ein voller Lauf enthaelt die Live-Checks

    def timeout(self, now: float) -> float:
        t = self.last_live + self.interval - now
        if self.last_event is not None:
            t = min(t, self.last_event + self.debounce - now)
        return max(0.0, t)


class TargetWatcher:
    """Beobachtet config.TARGETS unter root und meldet nur Pfade, die der Integritaets-Check auch erfasst."""

    def __init__(self, root: str, targets=config.TARGETS, exclude=config.EXCLUDE):
        self.root, self.targets, self.exclude = root, targets, exclude
        self.ino = Inotify()
        self.count = 0
        for top in sorted({t for t, _ in targets}):
            base = os.path.join(root, top)
            if os.path.isdir(base):
                self.count += self.ino.add_tree(base)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.ino.close()

    def is_relevant(self, rel: str) -> bool:
        if rel in self.exclude:
            return False
        name = os.path.basename(rel)
        return any((rel + "/").startswith(top + "/") and fnmatch.fnmatch(name, pat) for top, pat in self.targets)

    def relevant(self, timeout: float) -> list[str]:
        """Relevante Pfade (relativ zu root); sammelt bis 0,2 s Ruhe nach dem ersten Ereignis."""
        out: list[str] = []
        evs = self.ino.read(timeout)
        while evs:
            for path, _mask in evs:
                if path == OVERFLOW:
                    out.append(OVERFLOW)
                    continue
                rel = os.path.relpath(path, self.root)
                if self.is_relevant(rel) and rel not in out:
                    out.append(rel)
            evs = self.ino.read(0.2)
        return out


def _check(root: str, db: str, kind: str) -> int:
    from sentinel import cli
    args = ["check", "--root", root, "--db", db]
    if kind == "live":
        args += ["--checks", ",".join(LIVE)]
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cli.main(args)
    if rc != 0:                                    # Befunde ins Journal (stdout der Unit), OK-Laeufe still
        print(out.getvalue().rstrip(), flush=True)
    return rc


def main(root: str, db: str, interval: float = INTERVAL, debounce: float = DEBOUNCE) -> int:
    if not os.path.exists(db):
        print(f"sentinel watch: keine Datenbank {db} (zuerst: sudo sentinel baseline)", file=sys.stderr)
        return 2
    stop = []
    signal.signal(signal.SIGTERM, lambda *a: stop.append(1))
    with TargetWatcher(root) as w:
        print(f"sentinel watch: {w.count} Verzeichnisse beobachtet, Live-Checks alle {interval:.0f} s", flush=True)
        sched = Scheduler(debounce, interval, now=time.monotonic())
        _check(root, db, "full")
        sched.ran("full", time.monotonic())
        while not stop:
            changed = w.relevant(sched.timeout(time.monotonic()))
            if changed:
                print(f"sentinel watch: Aenderung: {', '.join('/' + c for c in changed[:5])}"
                      + (f" (+{len(changed) - 5})" if len(changed) > 5 else ""), flush=True)
                sched.event(time.monotonic())
            kind = sched.due(time.monotonic())
            if kind:
                if _check(root, db, kind) == 2:
                    print("sentinel watch: Check fehlgeschlagen (exit 2)", file=sys.stderr, flush=True)
                sched.ran(kind, time.monotonic())
    return 0
