"""Baut ein kleines Fake-Root-Dateisystem fuer Tests (nie das echte System anfassen)."""
import os
import tempfile

PASSWD = "root:x:0:0:root:/root:/bin/bash\nagent:x:1000:1000::/home/agent:/bin/bash\n"
SHADOW = "root:x:20000:0:99999:7:::\nagent:*:20000:0:99999:7:::\n"


def make_root() -> tempfile.TemporaryDirectory:
    td = tempfile.TemporaryDirectory(prefix="sentinel-fakeroot-")
    r = td.name
    write(r, "usr/bin/ls", b"\x7fELF-ls")
    write(r, "usr/bin/bash", b"\x7fELF-bash")
    write(r, "usr/sbin/sshd", b"\x7fELF-sshd")
    write(r, "usr/lib/libc.so.6", b"\x7fELF-libc")
    write(r, "usr/lib/python3/notalib.py", b"print('x')")      # kein *.so -> nicht in Baseline
    write(r, "etc/hostname", b"lfs\n")
    write(r, "etc/passwd", PASSWD.encode())
    write(r, "etc/shadow", SHADOW.encode(), mode=0o600)
    write(r, "etc/ld.so.cache", b"cache")                      # ausgeschlossen
    write(r, "boot/vmlinuz-7.1.8", b"bzImage")
    os.makedirs(os.path.join(r, "usr/local/bin"), exist_ok=True)
    os.makedirs(os.path.join(r, "proc"), exist_ok=True)
    os.symlink("/proc/self/mounts", os.path.join(r, "etc/mtab"))
    return td


def write(root: str, rel: str, data: bytes, mode: int = 0o755) -> str:
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)
    os.chmod(p, mode)
    return p
