"""Strukturierte Meldung ans systemd-Journal (natives Protokoll, nur stdlib). Best effort: ohne Journal kein Fehler."""
from __future__ import annotations

import socket

SOCKET = "/run/systemd/journal/socket"


def send(fields: dict, path: str = SOCKET) -> bool:
    fields = {"SYSLOG_IDENTIFIER": "sentinel", **fields}
    payload = "".join(f"{k}={str(v).replace(chr(10), ' ')}\n" for k, v in fields.items()).encode()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.sendto(payload, path)
        return True
    except OSError:
        return False
