# Demo von Hand (etwa 3 Minuten)

Voraussetzung: Die VM hat eine Baseline, und `sentinel-watch` läuft (`sudo sh systemd/install.sh && sudo sentinel baseline && sudo systemctl start sentinel-watch`).

1. **Terminal 1**, die VM-Konsole (`lfs-vm`, root-Autologin): `sentinel tui`. Alle Kacheln sind grün.
2. **Terminal 2** (WSL): `lfs-ssh -n 'sudo sentinel-fault inject F1'`. Nach etwa 4 s wird `integrity` rot und zeigt `/usr/bin/ls` mit altem und neuem SHA-256.
3. `lfs-ssh -n 'sudo sentinel report'` zeigt dieselben Befunde als Text, mit Zeitpunkt. Danach `lfs-ssh -n 'sudo sentinel-fault undo F1'`, die Kachel wird grün.
4. `lfs-ssh -n 'sudo sentinel-fault inject F3'` fügt ein zusätzliches UID-0-Konto hinzu. `integrity` und `accounts` werden rot. Danach `undo F3`.
5. `lfs-ssh -n 'sudo sentinel-fault inject F4'` stoppt sshd, die laufende Sitzung bleibt offen. Spätestens nach 15 s wird `services` gelb und zeigt „Stopped OpenSSH Daemon.“. Danach `undo F4`.
6. Zum Schluss auf dem Host, VM aus: `sentinel-e2e`. Es bootet eine Wegwerf-Kopie und zeigt die Tabelle mit 14 Zeilen, darunter F9, den root-Angreifer, den nur der Host erkennt.

Automatisch mit Stoppuhr: `sudo sentinel-demo`. Aufzeichnung für die Demo-Seite: `tools/record_dash.py`.
