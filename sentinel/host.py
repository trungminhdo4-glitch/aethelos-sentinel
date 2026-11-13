"""Host-Seite (WSL, ausserhalb der VM): externer Vertrauensanker fuer Sentinel.

  pin      Baseline der VM holen (sudo sentinel export), Digest selbst nachrechnen, ausserhalb der VM ablegen
  verify   aktuelle Baseline der VM gegen den gepinnten Stand vergleichen (faellt auf, wenn root in der VM
           eine Datei aendert UND die Baseline neu schreibt)
  offline  VM aus: Platten-Image read-only einhaengen und mit DIESEM (Host-)Code pruefen. Die VM luegt hier nicht mit,
           auch wenn Sentinel in der VM manipuliert waere.

Laeuft mit der Python-Version des Hosts (Debian: 3.13), nur Standardbibliothek. Exit 0 ok, 10/11 Befund, 2 Fehler.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

from sentinel.checks import accounts, integrity
from sentinel.model import Finding, Severity, exit_code
from sentinel.scan import Entry, scan, suid_scan
from sentinel.store import baseline_digest

FORMAT = "sentinel-export/1"
DEFAULT_TRUST = "/srv/lfs/trust"
DEFAULT_IMAGE = "/srv/lfs/lfs.img"
SSH = ["lfs-ssh", "-n", "sudo sentinel export"]


class HostError(Exception):
    pass


def to_export(entries: dict, suid: set, meta: dict) -> dict:
    """Wird in der VM von 'sentinel export' benutzt (gleicher Code wie auf dem Host)."""
    return {"format": FORMAT, "version": meta.get("version"), "created": meta.get("created"),
            "digest": meta["digest"], "count": len(entries),
            "entries": {p: [e.kind, e.sha256, e.mode, e.uid, e.gid, e.size] for p, e in sorted(entries.items())},
            "suid": sorted(suid)}


def _parts(ex: dict) -> tuple[dict, set]:
    try:
        return {p: Entry(*v) for p, v in ex["entries"].items()}, set(ex["suid"])
    except (KeyError, TypeError) as e:
        raise HostError(f"Export unvollstaendig: {e}") from None


def validate(ex: dict) -> str:
    """Digest aus der Liste selbst nachrechnen. Passt er nicht zum angegebenen, ist der Export manipuliert."""
    if not isinstance(ex, dict) or ex.get("format") != FORMAT:
        raise HostError(f"unbekanntes Exportformat (erwartet {FORMAT})")
    entries, suid = _parts(ex)
    d = baseline_digest(entries, suid)
    if d != ex.get("digest"):
        raise HostError(f"Export-Digest passt nicht zur Liste ({str(ex.get('digest'))[:16]}… != {d[:16]}…)")
    return d


def compare(pinned: dict, current: dict) -> list[tuple[str, str]]:
    a, b = pinned["entries"], current["entries"]
    out = [("/" + p, "geaendert") for p in sorted(a.keys() & b.keys()) if a[p] != b[p]]
    out += [("/" + p, "neu") for p in sorted(b.keys() - a.keys())]
    out += [("/" + p, "fehlt") for p in sorted(a.keys() - b.keys())]
    sa, sb = set(pinned["suid"]), set(current["suid"])
    out += [(f"suid:/{p}", "neu") for p in sorted(sb - sa)] + [(f"suid:/{p}", "fehlt") for p in sorted(sa - sb)]
    return out


def offline_findings(mnt: str, pinned: dict) -> list[Finding]:
    entries, suid = _parts(pinned)
    res = scan(mnt)
    if res.errors:
        raise HostError("Offline-Scan unvollstaendig:\n  " + "\n  ".join(res.errors[:20]))
    return integrity.check(entries, suid, res.entries, suid_scan(mnt)) + accounts.check(mnt)


def fetch_via_ssh() -> dict:
    try:
        r = subprocess.run(SSH, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise HostError(f"lfs-ssh: {e}") from None
    if r.returncode != 0:
        raise HostError(f"sentinel export in der VM: exit {r.returncode} {r.stderr.strip()[:300]}")
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        raise HostError("sentinel export: Ausgabe ist kein JSON") from None


def _load_pin(trust: str) -> dict:
    p = os.path.join(trust, "pinned.json")
    try:
        with open(p) as f:
            pinned = json.load(f)
    except FileNotFoundError:
        raise HostError(f"kein gepinnter Stand in {p} (zuerst: sentinel-host pin)") from None
    validate(pinned)
    return pinned


def cmd_pin(a, fetch) -> int:
    ex = fetch()
    d = validate(ex)
    os.makedirs(a.trust, mode=0o700, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for name in (f"pinned-{stamp}.json", "pinned.json"):
        tmp = os.path.join(a.trust, name + ".tmp")
        with open(tmp, "w") as f:
            json.dump(ex, f)
        os.replace(tmp, os.path.join(a.trust, name))
    print(f"gepinnt: {ex['count']} Eintraege, digest {d[:16]}… -> {a.trust}/pinned.json")
    return 0


def cmd_verify(a, fetch) -> int:
    pinned = _load_pin(a.trust)
    cur = fetch()
    d = validate(cur)
    if d == pinned["digest"]:
        print(f"OK: Baseline der VM = gepinnter Stand (digest {d[:16]}…)")
        return 0
    diffs = compare(pinned, cur)
    for subject, what in diffs[:50]:
        print(f"CRIT  host-verify  {subject}  {what} gegenueber gepinntem Stand")
    print(f"-- Baseline der VM weicht vom gepinnten Stand ab: {len(diffs)} Unterschied(e), "
          f"digest {pinned['digest'][:16]}… -> {d[:16]}… (exit 11)")
    return 11


def _vm_uses(image: str) -> bool:
    return subprocess.run(["pgrep", "-f", f"file={image}[,]"], capture_output=True).returncode == 0


def cmd_offline(a, fetch=None) -> int:
    pinned = _load_pin(a.trust)
    if _vm_uses(a.image):
        raise HostError(f"{a.image} ist in einer laufenden VM, offline nur bei ausgeschalteter VM")
    if not shutil.which("losetup"):
        raise HostError("losetup fehlt")
    loop = subprocess.run(["losetup", "-r", "-f", "-P", "--show", a.image], capture_output=True, text=True)
    if loop.returncode != 0:
        raise HostError(f"losetup: {loop.stderr.strip()}")
    dev = loop.stdout.strip()
    mnt = tempfile.mkdtemp(prefix="sentinel-offline-")
    try:
        m = subprocess.run(["mount", "-o", "ro,noload", dev + "p1", mnt], capture_output=True, text=True)
        if m.returncode != 0:
            raise HostError(f"mount: {m.stderr.strip()}")
        try:
            fs = offline_findings(mnt, pinned)
        finally:
            subprocess.run(["umount", mnt])
    finally:
        subprocess.run(["losetup", "-d", dev])
        os.rmdir(mnt)
    for f in fs:
        print(f"{f.severity.name:<4}  offline    {f.subject}  {f.evidence}")
    rc = exit_code(fs)
    print(f"-- offline {a.image} gegen gepinnten Stand: {len(fs)} Befund(e) (exit {rc})")
    return rc


def main(argv: list[str] | None = None, fetch=None) -> int:
    p = argparse.ArgumentParser(prog="sentinel-host", description="Sentinel-Vertrauensanker ausserhalb der VM")
    p.add_argument("command", choices=("pin", "verify", "offline"))
    p.add_argument("--trust", default=DEFAULT_TRUST, help="Ablage des gepinnten Stands (ausserhalb der VM)")
    p.add_argument("--image", default=DEFAULT_IMAGE, help="Platten-Image fuer offline")
    a = p.parse_args(argv)
    try:
        return {"pin": cmd_pin, "verify": cmd_verify, "offline": cmd_offline}[a.command](a, fetch or fetch_via_ssh)
    except (HostError, OSError) as e:
        print(f"sentinel-host: {e}", file=sys.stderr)
        return 2
