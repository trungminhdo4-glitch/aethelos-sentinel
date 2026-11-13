"""Konten-Pruefung: zusaetzliche UID-0-Konten, leere Passwortfelder. Unlesbares -> PermissionError (fail-closed)."""
from __future__ import annotations

import os

from sentinel.model import Finding, Severity

CHECK = "accounts"


def _rows(path: str) -> list[list[str]]:
    with open(path, encoding="utf-8") as f:
        return [l.rstrip("\n").split(":") for l in f if l.strip() and not l.startswith("#")]


def check(root: str) -> list[Finding]:
    out: list[Finding] = []
    for row in _rows(os.path.join(root, "etc/passwd")):
        if len(row) >= 3 and row[2] == "0" and row[0] != "root":
            out.append(Finding(CHECK, Severity.CRIT, row[0], "zusaetzliches Konto mit UID 0 in /etc/passwd"))
    for row in _rows(os.path.join(root, "etc/shadow")):
        if len(row) >= 2 and row[1] == "":
            out.append(Finding(CHECK, Severity.CRIT, row[0], "leeres Passwortfeld in /etc/shadow (Login ohne Passwort)"))
    return out

