"""Fehler-Injektionen mit Undo. NUR fuer Tests und Demo. Jede Injektion sichert vorher den Originalzustand."""
from __future__ import annotations

import argparse
import glob
import json
import math
import os
import shutil
import sys

from sentinel import config, sysprobe

DEFAULT_STATE = "/var/lib/sentinel/faults"
FILL_PCT = 93          # F6: Platte bis hierhin fuellen (Warngrenze ist config.DISK_WARN_PCT)

# expect = (Check, Subjekt, erwarteter Exit-Code); {target} = aufgeloester Zielpfad
FAULTS = {
    "F1": {"desc": "Binary manipuliert: Bytes an /usr/bin/ls anhaengen", "kind": "append", "target": "usr/bin/ls",
           "data": b"\0SENTINEL-F1", "expect": ("integrity", "{target}", 11)},
    "F2": {"desc": "neue SUID-Datei /usr/local/bin/sentinel-f2-suid", "kind": "suid",
           "target": "usr/local/bin/sentinel-f2-suid", "src": "usr/bin/true", "expect": ("integrity", "{target}", 11)},
    "F3": {"desc": "zusaetzliches UID-0-Konto f3evil in /etc/passwd", "kind": "append", "target": "etc/passwd",
           "data": b"f3evil:x:0:0:Sentinel F3:/root:/bin/false\n", "expect": ("accounts", "f3evil", 11)},
    "F4": {"desc": "Dienst gestoppt: sshd.service (offene SSH-Sitzungen bleiben)", "kind": "service",
           "unit": "sshd.service", "expect": ("services", "sshd.service", 10)},
    "F5": {"desc": "DNS kaputt: Link-DNS-Server auf 127.0.0.1 (dort lauscht nichts)", "kind": "dns",
           "server": "127.0.0.1", "expect": ("network", f"dns:{config.DNS_NAME}", 10)},
    "F6": {"desc": f"Platte ueber {FILL_PCT}% gefuellt (fallocate, Datei im Fault-State)", "kind": "fill",
           "expect": ("resources", "disk:/", 10)},
    "F7": {"desc": "Fehlermeldung ins Journal (logger -p user.err)", "kind": "log",
           "expect": ("logs", "sentinel-f7", 10)},
    "F8": {"desc": "Kernel manipuliert: Bytes an /boot/vmlinuz-* anhaengen", "kind": "append", "target": "boot/vmlinuz-*",
           "data": b"\0SENTINEL-F8", "expect": ("integrity", "{target}", 11)},
}

FILE_KINDS = ("append", "suid")


def _run(cmd):
    return sysprobe.run(cmd, 60)


def _statvfs(path):
    return os.statvfs(path)


def _fill(path: str, size: int) -> None:
    with open(path, "wb") as f:
        os.posix_fallocate(f.fileno(), 0, size)


def _must(cmd) -> str:
    rc, out = _run(cmd)
    if rc != 0:
        raise FaultError(f"{' '.join(cmd)}: exit {rc}")
    return out


class FaultError(Exception):
    pass


def _spec(fid: str) -> dict:
    if fid not in FAULTS:
        raise FaultError(f"unbekannter Fehler {fid} (bekannt: {', '.join(FAULTS)})")
    return FAULTS[fid]


def resolve_target(fid: str, root: str = "/") -> str:
    """Relativer Zielpfad (Glob aufgeloest, erster Treffer)."""
    t = _spec(fid)["target"]
    if any(c in t for c in "*?["):
        hits = sorted(glob.glob(os.path.join(root, t)))
        if not hits:
            raise FaultError(f"{fid}: kein Ziel fuer {t}")
        return os.path.relpath(hits[0], root)
    return t


def _restore(backup: str, target: str) -> None:
    tmp = target + ".sentinel-restore"
    shutil.copy2(backup, tmp)
    st = os.stat(backup)
    try:
        os.chown(tmp, st.st_uid, st.st_gid)
    except PermissionError:
        pass
    os.replace(tmp, target)


def inject(fid: str, root: str = "/", state: str = DEFAULT_STATE) -> str:
    s = _spec(fid)
    sd = os.path.join(state, fid)
    if os.path.exists(os.path.join(sd, "marker.json")):
        raise FaultError(f"{fid} ist schon aktiv (zuerst undo)")
    if s["kind"] not in FILE_KINDS:
        return _inject_live(fid, s, root, sd)
    rel = resolve_target(fid, root)
    target = os.path.join(root, rel)
    os.makedirs(sd, mode=0o700, exist_ok=True)
    if s["kind"] == "append":
        shutil.copy2(target, os.path.join(sd, "backup"))
        st = os.stat(target)
        os.chown(os.path.join(sd, "backup"), st.st_uid, st.st_gid) if os.geteuid() == 0 else None
        with open(target, "ab") as f:
            f.write(s["data"])
    elif s["kind"] == "suid":
        if os.path.exists(target):
            raise FaultError(f"{fid}: {target} existiert schon")
        shutil.copy2(os.path.join(root, s["src"]), target)
        os.chmod(target, 0o4755)
    with open(os.path.join(sd, "marker.json"), "w") as f:
        json.dump({"fault": fid, "target": rel}, f)
    return "/" + rel


def undo(fid: str, root: str = "/", state: str = DEFAULT_STATE) -> str:
    s = _spec(fid)
    sd = os.path.join(state, fid)
    try:
        with open(os.path.join(sd, "marker.json")) as f:
            rel = json.load(f)["target"]
    except FileNotFoundError:
        raise FaultError(f"{fid} ist nicht aktiv") from None
    if s["kind"] not in FILE_KINDS:
        if s["kind"] == "service":
            _must(["systemctl", "start", s["unit"]])
        elif s["kind"] == "dns":
            with open(os.path.join(sd, "marker.json")) as f:
                saved = json.load(f)["saved"]
            _must(["resolvectl", "dns", saved["iface"], *saved["servers"]])
            _must(["resolvectl", "flush-caches"])
        shutil.rmtree(sd)            # F6: Fuelldatei liegt im State-Ordner und verschwindet mit ihm
        return rel
    target = os.path.join(root, rel)
    if s["kind"] == "append":
        _restore(os.path.join(sd, "backup"), target)
    elif s["kind"] == "suid":
        if os.path.exists(target):
            os.remove(target)
    shutil.rmtree(sd)
    return "/" + rel


def _inject_live(fid: str, s: dict, root: str, sd: str) -> str:
    if s["kind"] == "service":
        rc, out = _run(["systemctl", "is-active", s["unit"]])
        if out.strip() != "active":
            raise FaultError(f"{fid}: {s['unit']} laeuft gar nicht ({out.strip() or rc})")
        os.makedirs(sd, mode=0o700, exist_ok=True)
        _write_marker(sd, fid, s["unit"])          # Marker zuerst: undo startet den Dienst auch nach halbem Fehlschlag
        _must(["systemctl", "stop", s["unit"]])
        return s["unit"]
    if s["kind"] == "dns":
        # Nicht resolved stoppen: systemd 261 startet es per Socket-Aktivierung sofort neu (in der VM gemessen)
        links = _link_dns(_must(["resolvectl", "dns"]))
        if not links:
            raise FaultError(f"{fid}: kein Interface mit DNS-Server (resolvectl dns)")
        iface, servers = links[0]
        os.makedirs(sd, mode=0o700, exist_ok=True)
        _write_marker(sd, fid, f"dns:{iface}", saved={"iface": iface, "servers": servers})
        _must(["resolvectl", "dns", iface, s["server"]])
        _must(["resolvectl", "flush-caches"])
        return f"{iface}: {' '.join(servers)} -> {s['server']}"
    os.makedirs(sd, mode=0o700, exist_ok=True)
    if s["kind"] == "fill":
        v = _statvfs(root)
        used = v.f_blocks - v.f_bfree
        need = max(1, math.ceil(FILL_PCT / 100 * (used + v.f_bavail) - used) + 1)
        path = os.path.join(sd, "fill")
        _write_marker(sd, fid, path)
        _fill(path, need * v.f_frsize)
        return f"{path} ({need * v.f_frsize / 2**30:.1f} GiB)"
    if s["kind"] == "log":
        _write_marker(sd, fid, "journal")
        _must(["logger", "-p", "user.err", "-t", "sentinel-f7", "SENTINEL-F7: provozierte Fehlermeldung (Test)"])
        _must(["journalctl", "--sync"])
        return "journal (sentinel-f7)"
    raise FaultError(f"{fid}: unbekannte Art {s['kind']}")


def _write_marker(sd: str, fid: str, target: str, **extra) -> None:
    with open(os.path.join(sd, "marker.json"), "w") as f:
        json.dump({"fault": fid, "target": target, **extra}, f)


def _link_dns(out: str) -> list[tuple[str, list[str]]]:
    """'Link 2 (ens4): 10.0.2.3 10.0.2.4' -> [('ens4', ['10.0.2.3', '10.0.2.4'])], nur Links mit Servern."""
    res = []
    for line in out.splitlines():
        head, _, rest = line.partition(":")
        if head.startswith("Link ") and "(" in head and rest.split():
            res.append((head[head.index("(") + 1:head.rindex(")")], rest.split()))
    return res


def expected(fid: str, root: str = "/") -> tuple[str, str, int]:
    chk, subject, rc = _spec(fid)["expect"]
    if "{target}" in subject:
        subject = subject.replace("{target}", "/" + resolve_target(fid, root))
    return chk, subject, rc


def active(state: str = DEFAULT_STATE) -> list[str]:
    return sorted(f for f in FAULTS if os.path.exists(os.path.join(state, f, "marker.json")))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sentinel-fault", description="Fehler-Injektion fuer Tests/Demo (mit Undo)")
    p.add_argument("action", choices=("list", "inject", "undo", "status"))
    p.add_argument("fault", nargs="?")
    p.add_argument("--root", default="/")
    p.add_argument("--state", default=DEFAULT_STATE)
    a = p.parse_args(argv)
    try:
        if a.action == "list":
            for k, v in FAULTS.items():
                print(f"{k}  {v['desc']}")
        elif a.action == "status":
            act = active(a.state)
            print("aktiv: " + (", ".join(act) if act else "keine"))
        elif not a.fault:
            raise FaultError("Fehler-ID fehlt (z.B. F1)")
        elif a.action == "inject":
            print(f"{a.fault} injiziert: {inject(a.fault, a.root, a.state)}")
        else:
            print(f"{a.fault} rueckgaengig: {undo(a.fault, a.root, a.state)}")
    except (FaultError, OSError) as e:
        print(f"sentinel-fault: {e}", file=sys.stderr)
        return 2
    return 0
