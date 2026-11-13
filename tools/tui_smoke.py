"""Rauchtest fuer das curses-Dashboard: startet 'sentinel tui' in einem Pseudo-Terminal (100x30), liest 4 s mit,
drueckt q und prueft Exit-Code + sichtbare Kacheln. Als root (die Datenbank ist root-only). Exit 0 = ok."""
import fcntl
import os
import pty
import re
import select
import struct
import sys
import termios
import time

pid, fd = pty.fork()
if pid == 0:
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
    os.environ.update(TERM="xterm-256color", LINES="30", COLUMNS="100")
    os.execvp("sentinel", ["sentinel", "tui", "--interval", "1"])
buf, t = b"", time.time()
while time.time() - t < 4:
    if select.select([fd], [], [], 0.2)[0]:
        try:
            buf += os.read(fd, 65536)
        except OSError:
            break
os.write(fd, b"q")
rc = None
for _ in range(50):
    p, st = os.waitpid(pid, os.WNOHANG)
    if p:
        rc = os.waitstatus_to_exitcode(st)
        break
    try:
        while select.select([fd], [], [], 0.1)[0]:
            buf += os.read(fd, 65536)
    except OSError:
        pass
if rc is None:
    os.kill(pid, 9)
text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]|\x1b[=>]", " ", buf.decode("utf-8", "replace"))
need = ("Sentinel", "integrity", "services", "logs", "Gesamt")
missing = [n for n in need if n not in text]
print(f"tui: exit={rc}, {len(buf)} Bytes, Farben={'ja' if b'[3' in buf or b'[1;3' in buf else 'nein'}, fehlt={missing or '-'}")
sys.exit(0 if rc == 0 and not missing else 1)
