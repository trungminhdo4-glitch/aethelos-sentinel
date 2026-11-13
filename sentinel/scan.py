"""Dateisystem-Scan: SHA-256 + Metadaten. Symlinks werden nie verfolgt, unlesbares wird als Fehler gemeldet."""
from __future__ import annotations

import fnmatch
import hashlib
import os
import stat
from dataclasses import dataclass, field

from sentinel import config


@dataclass(frozen=True)
class Entry:
    kind: str       # "file" | "link"
    sha256: str     # Datei: Hex-Hash; Link: "link:<ziel>"
    mode: int       # Rechte inkl. SUID/SGID/Sticky (st_mode & 0o7777)
    uid: int
    gid: int
    size: int


@dataclass
class ScanResult:
    entries: dict[str, Entry] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _entry(path: str) -> Entry | None:
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        return Entry("link", "link:" + os.readlink(path), 0, st.st_uid, st.st_gid, 0)
    if stat.S_ISREG(st.st_mode):
        return Entry("file", _sha256(path), stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid, st.st_size)
    return None  # Geraete, FIFOs, Sockets: nicht relevant


def scan(root: str, targets=config.TARGETS, exclude=config.EXCLUDE) -> ScanResult:
    res = ScanResult()
    for top, pattern in targets:
        base = os.path.join(root, top)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base, onerror=lambda e: res.errors.append(f"{e.filename}: {e.strerror}")):
            dirnames.sort()
            # Symlinks auf Verzeichnisse als Eintrag erfassen, aber nicht hineinlaufen
            names = filenames + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]
            for name in sorted(names):
                if not fnmatch.fnmatch(name, pattern):
                    continue
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root)
                if rel in exclude or rel in res.entries:
                    continue
                try:
                    e = _entry(full)
                except OSError as ex:
                    res.errors.append(f"{rel}: {ex.strerror}")
                    continue
                if e is not None:
                    res.entries[rel] = e
    return res


def suid_scan(root: str, skip=config.SUID_SKIP) -> set[str]:
    """Alle regulaeren Dateien mit SUID/SGID unter root (gleiches Dateisystem, ohne Pseudo-FS)."""
    found: set[str] = set()
    root_dev = os.lstat(root).st_dev
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == ".":
            dirnames[:] = [d for d in dirnames if d not in skip]
        keep = []
        for d in dirnames:
            p = os.path.join(dirpath, d)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if not stat.S_ISLNK(st.st_mode) and st.st_dev == root_dev:
                keep.append(d)
        dirnames[:] = keep
        for name in filenames:
            p = os.path.join(dirpath, name)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                found.add(os.path.relpath(p, root))
    return found

