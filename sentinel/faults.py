"""Fehler-Injektionen mit Undo. NUR fuer Tests und Demo. Jede Injektion sichert vorher den Originalzustand."""
from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import sys

DEFAULT_STATE = "/var/lib/sentinel/faults"

FAULTS = {
    "F1": {"desc": "Binary manipuliert: Bytes an /usr/bin/ls anhaengen", "kind": "append", "target": "usr/bin/ls",
           "data": b"\0SENTINEL-F1"},
    "F2": {"desc": "neue SUID-Datei /usr/local/bin/sentinel-f2-suid", "kind": "suid",
           "target": "usr/local/bin/sentinel-f2-suid", "src": "usr/bin/true"},
    "F3": {"desc": "zusaetzliches UID-0-Konto f3evil in /etc/passwd", "kind": "append", "target": "etc/passwd",
           "data": b"f3evil:x:0:0:Sentinel F3:/root:/bin/false\n"},
    "F8": {"desc": "Kernel manipuliert: Bytes an /boot/vmlinuz-* anhaengen", "kind": "append", "target": "boot/vmlinuz-*",
           "data": b"\0SENTINEL-F8"},
}


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
    target = os.path.join(root, rel)
    if s["kind"] == "append":
        _restore(os.path.join(sd, "backup"), target)
    elif s["kind"] == "suid":
        if os.path.exists(target):
            os.remove(target)
    shutil.rmtree(sd)
    return "/" + rel


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

