"""Zeichnet das Dashboard auf: alle INTERVAL Sekunden genau die Zeilen, die das curses-TUI zeichnet (tui.build_view),
dazu Marker und zeitgesteuerte Befehle (z.B. Fehler injizieren). Ausgabe: JSON 'sentinel-dash/1' fuer die Demo-Seite.

  sudo python3 tools/record_dash.py --out /tmp/dash.json --duration 75 \\
       --at '6|F1: /usr/bin/ls manipuliert|sentinel-fault inject F1' --at '18|undo F1|sentinel-fault undo F1'
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel import config, tui  # noqa: E402
from sentinel.store import Store  # noqa: E402


def parse_at(spec: str) -> tuple[float, str, str | None]:
    parts = spec.split("|", 2)
    return float(parts[0]), parts[1], parts[2] if len(parts) > 2 and parts[2] else None


def _push(frames: list, t: float, lines: list) -> None:
    lines = [list(x) for x in lines]
    if not frames or frames[-1]["lines"] != lines:
        frames.append({"t": round(t, 2), "lines": lines})


def _view(db: str, width: int) -> list:
    st = Store(db)
    try:
        return tui.build_view(st.latest_by_check(), width=width)
    finally:
        st.close()


def record(db: str, duration: float, interval: float = 0.5, schedule=(), width: int = 100) -> dict:
    frames, markers, pending = [], [], sorted(schedule)
    t0 = time.monotonic()
    while True:
        now = time.monotonic() - t0
        while pending and pending[0][0] <= now:
            _t, label, cmd = pending.pop(0)
            markers.append({"t": round(now, 2), "label": label, "cmd": cmd})
            if cmd:
                subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            _push(frames, time.monotonic() - t0, _view(db, width))
        except Exception as e:                       # DB kurz gesperrt: Frame auslassen, nicht abbrechen
            print(f"record: {e}", file=sys.stderr)
        if now >= duration:
            break
        time.sleep(interval)
    return {"format": "sentinel-dash/1", "width": width, "duration": round(time.monotonic() - t0, 2),
            "frames": frames, "markers": markers}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--db", default=config.DEFAULT_DB)
    p.add_argument("--out", required=True)
    p.add_argument("--duration", type=float, default=60)
    p.add_argument("--interval", type=float, default=0.5)
    p.add_argument("--width", type=int, default=100)
    p.add_argument("--at", action="append", default=[], help="'sekunden|beschriftung|befehl' (Befehl optional)")
    a = p.parse_args(argv)
    cast = record(a.db, a.duration, a.interval, [parse_at(s) for s in a.at], a.width)
    with open(a.out, "w") as f:
        json.dump(cast, f, ensure_ascii=False)
    print(f"record: {len(cast['frames'])} Frames, {len(cast['markers'])} Marker, {cast['duration']} s -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
