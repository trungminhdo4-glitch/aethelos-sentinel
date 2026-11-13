# Sentinel

Integritäts- und Diagnose-Wächter für **Aethelos**, ein selbst gebautes Linux auf Basis von LFS 13.1-systemd.
Entsteht und läuft komplett in der LFS-VM. Nur Python-3.14-Standardbibliothek, keine Fremdpakete.

Plan, Architektur und Meilensteine: siehe `SENTINEL-PLAN.md` im Host-Projekt (`Dev/sandbox/lfs/`).

## Stand: M3 (v0.3.0)
| Check | prüft | Befund |
|---|---|---|
| `integrity` | SHA-256, Rechte, Besitzer von `/usr/bin`, `/usr/sbin`, `/usr/lib/*.so*`, `*.ko*`, `/etc`, `/boot`; neue SUID-Dateien | CRIT/WARN |
| `accounts` | zusätzliche UID-0-Konten, leere Passwortfelder | CRIT |
| `services` | fehlgeschlagene Units, Pflicht-Dienste (sshd, networkd, resolved, journald), mit letzter Journal-Zeile | WARN |
| `network` | Link, IPv4-Adresse, DNS (3 Versuche); HTTPS optional (`config.HTTPS_URL`, aus) | WARN |
| `logs` | neue Journal-Meldungen `err` und schlimmer seit dem letzten Lauf (Cursor), je Absender | WARN |
| `resources` | Platte und Inodes ≥ 90 %, RAM < 10 % frei, Load > 2 × CPUs | WARN |
| `boot` | Kernel-taint, Boot-Dauer > 60 s | WARN |

Mit `--root /` (Standard) laufen alle Checks, mit einem anderen `--root` nur die Datei-Checks. Auswahl: `--checks a,b`.

Befehle (als root): `sentinel baseline | check | report [--json]`, `sentinel-fault list|inject|undo|status <F1..F8>`, `sentinel-selftest [F..]`.
Jeder `check` schreibt eine Zusammenfassung ins Journal (`SYSLOG_IDENTIFIER=sentinel`, Felder `SENTINEL_EXIT`, `SENTINEL_CRIT`, `SENTINEL_WARN` ...):
`journalctl -t sentinel` bzw. `journalctl SENTINEL_EXIT=11`.

## Host als Vertrauensanker (M3)
Wer in der VM root ist, kann eine Datei ändern **und** die Baseline neu schreiben. Dann ist `sentinel check` in der VM grün.
Deshalb gibt es eine zweite Seite außerhalb der VM, in WSL, als root:

| Befehl | was |
|---|---|
| `sentinel-host pin` | holt `sudo sentinel export` per `lfs-ssh`, rechnet den Digest selbst nach und legt den Stand in `/srv/lfs/trust/` ab |
| `sentinel-host verify` | vergleicht die aktuelle Baseline der VM mit dem gepinnten Stand. Weicht sie ab: exit 11 mit Liste der Pfade |
| `sentinel-host offline` | VM aus: hängt das Platten-Image read-only ein und scannt es mit dem **Host-Code**. Sentinel in der VM wird dafür gar nicht gebraucht |
| `sentinel-e2e` | bootet eine Wegwerf-Kopie der Platte und prüft F1–F8 sowie F9 (root ändert `/usr/bin/ls` und schreibt die Baseline neu) |

Installation der Host-Seite aus einem Bundle: `sh host/install-host.sh <bundle>` legt den Code nach `/opt/sentinel-host`.
Ehrliche Grenze: Das Bundle kommt einmal aus der VM („trust on first use“). Danach lädt der Host nichts mehr aus der VM nach.
Sentinel überwacht außerdem seinen eigenen Code (`/home/agent/sentinel/sentinel/*.py`).

## systemd
- `sentinel-boot.service`: Selbstcheck einmal nach jedem Boot.
- `sentinel.timer` → `sentinel.service`: alle 15 Minuten.
- Beide laufen nur, wenn eine Baseline existiert. Befunde (exit 10/11) gelten als Ergebnis, nur exit 2 macht die Unit „failed“.
- Installieren: `sudo sh systemd/install.sh`, danach `sudo sentinel baseline` (die Units liegen in `/etc` und gehören selbst zum Soll-Zustand).

## Exit-Codes
| Code | Bedeutung |
|---|---|
| 0  | alles ok |
| 10 | Warnung (mindestens ein Befund WARN) |
| 11 | kritisch (mindestens ein Befund CRIT) |
| 2  | Sentinel konnte nicht prüfen |

## Tests
```
python3 -m unittest discover -s tests -t . -v      # Unit, Fake-System
sudo sentinel-selftest                              # Integration, echtes System: nur in einer Wegwerf-VM
```
