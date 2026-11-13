"""Vergleich Baseline <-> aktueller Scan. Reine Funktion, kein Dateizugriff."""
from __future__ import annotations

import stat

from sentinel import config
from sentinel.model import Finding, Severity
from sentinel.scan import Entry

CHECK = "integrity"
SUID_BITS = stat.S_ISUID | stat.S_ISGID


def _is_etc(rel: str) -> bool:
    return rel.startswith("etc/")


def _critical_etc(rel: str) -> bool:
    return rel in config.CRITICAL_ETC or rel.startswith(config.CRITICAL_ETC_PREFIXES)


def _short(h: str) -> str:
    return h if h.startswith("link:") else h[:12] + "…"


def check(base: dict[str, Entry], base_suid: set[str],
          cur: dict[str, Entry], cur_suid: set[str]) -> list[Finding]:
    out: list[Finding] = []

    def add(sev, rel, ev):
        out.append(Finding(CHECK, sev, "/" + rel, ev))

    for rel in sorted(base.keys() | cur.keys()):
        b, c = base.get(rel), cur.get(rel)
        if b and not c:
            add(Severity.WARN, rel, "fehlt (war in der Baseline)")
            continue
        if c and not b:
            if c.mode & SUID_BITS:
                add(Severity.CRIT, rel, f"neue Datei mit SUID/SGID (mode {c.mode:o})")
            else:
                add(Severity.WARN, rel, "neue Datei")
            continue
        if b.sha256 != c.sha256:
            sev = Severity.WARN if _is_etc(rel) and not _critical_etc(rel) else Severity.CRIT
            add(sev, rel, f"sha256 geaendert: {_short(b.sha256)} -> {_short(c.sha256)}")
        if (c.mode & SUID_BITS) and not (b.mode & SUID_BITS):
            add(Severity.CRIT, rel, f"SUID/SGID-Bit neu gesetzt (mode {b.mode:o} -> {c.mode:o})")
        elif b.mode != c.mode or b.uid != c.uid or b.gid != c.gid:
            add(Severity.WARN, rel, f"Rechte/Besitzer geaendert ({b.mode:o} {b.uid}:{b.gid} -> {c.mode:o} {c.uid}:{c.gid})")

    # SUID/SGID-Dateien ausserhalb der ueberwachten Pfade (z.B. /tmp, /home)
    for rel in sorted(cur_suid - base_suid):
        if rel not in cur and rel not in base:
            add(Severity.CRIT, rel, "neue Datei mit SUID/SGID ausserhalb der Baseline-Pfade")
    return out
