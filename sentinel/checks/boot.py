"""Boot: Kernel-taint und Boot-Dauer (systemd-analyze). Boot noch nicht fertig -> kein Befund (beim Boot-Selbstcheck normal)."""
from __future__ import annotations

import re

from sentinel import config
from sentinel.model import Finding, Severity

CHECK = "boot"
UNITS = {"h": 3600, "min": 60, "s": 1, "ms": 0.001, "us": 0.000001}


def parse_seconds(text: str) -> float:
    """'1min 32.500s' -> 92.5"""
    parts = re.findall(r"([\d.]+)\s*(h|min|ms|us|s)\b", text)
    if not parts:
        raise ValueError(f"keine Zeitangabe: {text!r}")
    return sum(float(n) * UNITS[u] for n, u in parts)


def check(run, tainted_path="/proc/sys/kernel/tainted", max_boot_s=config.BOOT_MAX_S) -> list[Finding]:
    out: list[Finding] = []
    with open(tainted_path) as f:
        t = f.read().strip()
    if t != "0":
        out.append(Finding(CHECK, Severity.WARN, "kernel", f"Kernel tainted={t} (siehe Documentation/admin-guide/tainted-kernels)"))
    rc, text = run(["systemd-analyze", "time"])
    m = re.search(r"=\s*([^\n]+)", text) if rc == 0 else None
    if m:
        secs = parse_seconds(m.group(1))
        if secs > max_boot_s:
            out.append(Finding(CHECK, Severity.WARN, "boot-time", f"Boot dauerte {secs:.1f}s (Grenze {max_boot_s}s)"))
    return out
