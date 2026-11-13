#!/bin/sh
# Installiert Sentinel-Wrapper und -Units (als root). Danach Baseline neu anlegen: die Units liegen unter
# /etc/systemd/system und gehoeren damit selbst zum ueberwachten Soll-Zustand. Dann: systemctl start sentinel-watch
set -e
cd "$(dirname "$0")"
install -m 0755 ../bin/sentinel ../bin/sentinel-fault ../bin/sentinel-selftest ../bin/sentinel-demo /usr/bin/
install -m 0644 sentinel-boot.service sentinel.service sentinel.timer sentinel-watch.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable sentinel-boot.service sentinel.timer sentinel-watch.service
echo "installiert. Jetzt: sudo sentinel baseline && sudo systemctl start sentinel-watch"
