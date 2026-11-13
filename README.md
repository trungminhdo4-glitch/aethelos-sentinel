# Sentinel

Integritäts- und Diagnose-Wächter für **Aethelos**, ein selbst gebautes Linux auf Basis von LFS 13.1-systemd.
Entsteht und läuft komplett in der LFS-VM. Nur Python-3.14-Standardbibliothek, keine Fremdpakete.

Plan, Architektur und Meilensteine: siehe `SENTINEL-PLAN.md` im Host-Projekt (`Dev/sandbox/lfs/`).

## Stand: M0 (Gerüst)
- `sentinel --version`
- Befehle `baseline | check | report | tui | export` existieren, antworten aber noch mit Exit 2 („nicht implementiert“). Sentinel meldet nie „grün“, ohne geprüft zu haben.

## Exit-Codes
| Code | Bedeutung |
|---|---|
| 0  | alles ok |
| 10 | Warnung (mindestens ein Befund WARN) |
| 11 | kritisch (mindestens ein Befund CRIT) |
| 2  | Sentinel konnte nicht prüfen |

## Tests
```
python3 -m unittest discover -s tests -t . -v
```

