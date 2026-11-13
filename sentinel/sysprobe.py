"""Befehle des Systems ausfuehren (systemctl, journalctl ...). Fehlt ein Werkzeug oder haengt es -> ProbeError (fail-closed)."""
from __future__ import annotations

import subprocess


class ProbeError(Exception):
    pass


def run(cmd: list[str], timeout: float = 10) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={"PATH": "/usr/bin:/usr/sbin", "LANG": "C.UTF-8", "SYSTEMD_COLORS": "0"})
    except FileNotFoundError:
        raise ProbeError(f"Werkzeug fehlt: {cmd[0]}") from None
    except subprocess.TimeoutExpired:
        raise ProbeError(f"Zeitlimit {timeout}s ueberschritten: {' '.join(cmd)}") from None
    return r.returncode, r.stdout
