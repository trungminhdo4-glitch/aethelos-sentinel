"""Ressourcen: Platte und Inodes (wie df), freier RAM, Load."""
from __future__ import annotations

import os

from sentinel import config
from sentinel.model import Finding, Severity

CHECK = "resources"


def _pct(total_used: int, avail: int) -> float:
    denom = total_used + avail                 # wie df: belegt / (belegt + fuer Nutzer verfuegbar)
    return 100.0 * total_used / denom if denom else 0.0


def _meminfo(path: str) -> dict[str, int]:
    with open(path) as f:
        return {k.strip(): int(v.split()[0]) for k, v in (l.split(":", 1) for l in f if ":" in l)}


def check(paths=config.DISK_PATHS, statvfs=os.statvfs, meminfo="/proc/meminfo", loadavg=os.getloadavg,
          ncpu=None) -> list[Finding]:
    out: list[Finding] = []
    for p in paths:
        v = statvfs(p)
        used = v.f_blocks - v.f_bfree
        pct = _pct(used, v.f_bavail)
        if pct >= config.DISK_WARN_PCT:
            free_gib = v.f_bavail * v.f_frsize / 2**30
            out.append(Finding(CHECK, Severity.WARN, f"disk:{p}", f"{pct:.0f}% belegt, {free_gib:.1f} GiB frei "
                                                                  f"(Grenze {config.DISK_WARN_PCT}%)"))
        ipct = _pct(v.f_files - v.f_ffree, v.f_favail)
        if v.f_files and ipct >= config.DISK_WARN_PCT:
            out.append(Finding(CHECK, Severity.WARN, f"inodes:{p}", f"{ipct:.0f}% der Inodes belegt"))
    m = _meminfo(meminfo)
    if m.get("MemTotal") and "MemAvailable" in m:
        avail = 100.0 * m["MemAvailable"] / m["MemTotal"]
        if avail < config.MEM_MIN_AVAIL_PCT:
            out.append(Finding(CHECK, Severity.WARN, "memory", f"nur {avail:.0f}% RAM verfuegbar "
                                                               f"({m['MemAvailable'] // 1024} MiB)"))
    n = ncpu or os.cpu_count() or 1
    l1 = loadavg()[0]
    if l1 > config.LOAD_PER_CPU * n:
        out.append(Finding(CHECK, Severity.WARN, "load", f"Load {l1:.2f} > {config.LOAD_PER_CPU} x {n} CPUs"))
    return out
