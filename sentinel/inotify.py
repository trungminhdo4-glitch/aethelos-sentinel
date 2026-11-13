"""inotify per ctypes (nur stdlib). Beobachtet Verzeichnisbaeume, neue Unterverzeichnisse kommen automatisch dazu."""
from __future__ import annotations

import ctypes
import os
import select
import struct

IN_MODIFY = 0x002
IN_ATTRIB = 0x004
IN_CLOSE_WRITE = 0x008
IN_MOVED_FROM = 0x040
IN_MOVED_TO = 0x080
IN_CREATE = 0x100
IN_DELETE = 0x200
IN_DELETE_SELF = 0x400
IN_Q_OVERFLOW = 0x4000
IN_IGNORED = 0x8000
IN_ISDIR = 0x40000000
IN_DONT_FOLLOW = 0x02000000
IN_ONLYDIR = 0x01000000
IN_NONBLOCK = 0o4000
IN_CLOEXEC = 0o2000000

MASK = IN_CLOSE_WRITE | IN_ATTRIB | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_MODIFY
_EV = struct.Struct("iIII")
OVERFLOW = "<overflow>"          # Ereignisse verloren -> Aufrufer muss voll pruefen


class Inotify:
    def __init__(self):
        self._libc = ctypes.CDLL("libc.so.6", use_errno=True)
        self.fd = self._libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1")
        self.paths: dict[int, str] = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def add(self, path: str) -> int:
        wd = self._libc.inotify_add_watch(self.fd, os.fsencode(path), MASK | IN_DONT_FOLLOW | IN_ONLYDIR)
        if wd < 0:
            raise OSError(ctypes.get_errno(), f"inotify_add_watch {path}")
        self.paths[wd] = path
        return wd

    def add_tree(self, top: str) -> int:
        n = 0
        for dirpath, dirnames, _ in os.walk(top):
            dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
            self.add(dirpath)
            n += 1
        return n

    def read(self, timeout: float) -> list[tuple[str, int]]:
        """[(voller Pfad, mask)] oder [] nach timeout. Neue Verzeichnisse werden mitbeobachtet."""
        r, _, _ = select.select([self.fd], [], [], max(0.0, timeout))
        if not r:
            return []
        try:
            buf = os.read(self.fd, 65536)
        except BlockingIOError:
            return []
        out, i = [], 0
        while i + _EV.size <= len(buf):
            wd, mask, _cookie, ln = _EV.unpack_from(buf, i)
            name = buf[i + _EV.size:i + _EV.size + ln].rstrip(b"\0").decode("utf-8", "surrogateescape")
            i += _EV.size + ln
            if mask & IN_Q_OVERFLOW:
                out.append((OVERFLOW, mask))
                continue
            if mask & IN_IGNORED:
                self.paths.pop(wd, None)
                continue
            base = self.paths.get(wd)
            if base is None:
                continue
            full = os.path.join(base, name) if name else base
            if mask & IN_ISDIR and mask & (IN_CREATE | IN_MOVED_TO):
                try:
                    self.add_tree(full)
                except OSError:
                    pass
            out.append((full, mask))
        return out
