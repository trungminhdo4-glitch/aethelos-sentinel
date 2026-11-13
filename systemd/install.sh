#!/bin/sh
# Installiert die Sentinel-Units (als root). Danach Baseline neu anlegen: die Units liegen unter /etc/systemd/system
# und gehoeren damit selbst zum ueberwachten Soll-Zustand.
set -e
cd "$(dirname "$0")"
install -m 0644 sentinel-boot.service sentinel.service sentinel.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable sentinel-boot.service sentinel.timer
echo "installiert. Jetzt: sudo sentinel baseline"
