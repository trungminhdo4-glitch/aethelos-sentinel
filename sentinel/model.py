"""Befund-Modell und Exit-Code-Abbildung (0 ok, 10 Warnung, 11 kritisch)."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone


class Severity(enum.IntEnum):
    OK = 0
    WARN = 10
    CRIT = 11


@dataclass(frozen=True)
class Finding:
    check: str          # z.B. "integrity", "services"
    severity: Severity
    subject: str        # betroffenes Objekt: Datei, Unit, Interface ...
    evidence: str       # was genau gesehen wurde
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def to_dict(self) -> dict:
        return {"check": self.check, "severity": self.severity.name, "subject": self.subject,
                "evidence": self.evidence, "first_seen": self.first_seen}


def exit_code(findings: list[Finding]) -> int:
    """Hoechste Severity bestimmt den Exit-Code; keine Befunde = 0."""
    return max((int(f.severity) for f in findings), default=int(Severity.OK))

