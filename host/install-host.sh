#!/bin/sh
# Installiert die Host-Werkzeuge in WSL aus einem Sentinel-Bundle (als root):  sh install-host.sh <bundle>
# Vertrauen: das Bundle stammt aus der VM. Es wird beim Installieren einmal geprueft (Hash, Log) und danach
# nicht mehr aus der VM nachgeladen ("trust on first use").
set -e
B=${1:?Bundle fehlt}
T=/opt/sentinel-host
rm -rf "$T.new"
git -c init.defaultBranch=main clone -q "$B" "$T.new"
[ -d "$T" ] && rm -rf "$T.old" && mv "$T" "$T.old"
mv "$T.new" "$T"
ln -sf "$T/host/sentinel-host" /usr/local/sbin/sentinel-host
ln -sf "$T/host/sentinel-e2e" /usr/local/sbin/sentinel-e2e
chmod 0755 "$T/host/sentinel-host" "$T/host/sentinel-e2e"
echo "Host-Werkzeuge: $(git -C "$T" log --oneline -1) aus $(sha256sum "$B" | cut -c1-16)…"
