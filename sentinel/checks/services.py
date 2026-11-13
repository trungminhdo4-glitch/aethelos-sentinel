"""Dienste: fehlgeschlagene Units und Pflicht-Dienste. Jeder Befund nennt die letzte Journal-Zeile der Unit."""
from __future__ import annotations

import json

from sentinel import config
from sentinel.model import Finding, Severity
from sentinel.sysprobe import ProbeError

CHECK = "services"


def _last_journal_line(run, unit: str) -> str:
    """Letzte Meldung von systemd (PID 1) zu dieser Unit, ohne die 'Consumed ... CPU time'-Statistik.
    Nicht 'journalctl -u': ohne logind laufen SSH-Sitzungen im sshd-cgroup, dann kaeme sudo-Rauschen."""
    try:
        rc, out = run(["journalctl", f"UNIT={unit}", "_PID=1", "-n", "5", "-o", "cat", "--no-pager"])
    except ProbeError:
        return ""
    lines = [l for l in out.strip().splitlines() if l.strip() and " Consumed " not in l] if rc == 0 else []
    return f" | Journal: {lines[-1]}" if lines else ""


def check(run, required=config.REQUIRED_UNITS) -> list[Finding]:
    rc, out = run(["systemctl", "list-units", "--failed", "--output=json", "--no-pager"])
    if rc != 0:
        raise ProbeError(f"systemctl list-units --failed: exit {rc}")
    try:
        failed = json.loads(out)
    except json.JSONDecodeError:
        raise ProbeError("systemctl list-units: Ausgabe ist kein JSON") from None
    findings = [Finding(CHECK, Severity.WARN, u["unit"],
                        f"Unit fehlgeschlagen (active={u.get('active')}, sub={u.get('sub')})" + _last_journal_line(run, u["unit"]))
                for u in failed]
    seen = {f.subject for f in findings}
    if required:
        # is-active: rc 0 = alle aktiv, 3 = mindestens einer nicht aktiv; eine Zeile pro Unit
        rc, out = run(["systemctl", "is-active", *required])
        states = out.split()
        if len(states) != len(required):
            raise ProbeError(f"systemctl is-active: {len(states)} Zeilen fuer {len(required)} Units")
        for unit, state in zip(required, states):
            if state != "active" and unit not in seen:
                findings.append(Finding(CHECK, Severity.WARN, unit,
                                        f"Pflicht-Dienst nicht aktiv: {state}" + _last_journal_line(run, unit)))
    return findings
