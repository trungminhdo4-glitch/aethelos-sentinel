"""Kommandozeile: sentinel <befehl>. Exit 2 = Sentinel konnte nicht pruefen (nie 'gruen' raten)."""
from __future__ import annotations

import argparse
import sys

from sentinel import __version__

EXIT_INTERNAL = 2
COMMANDS = ("baseline", "check", "report", "tui", "export")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description="Integritaets- und Diagnose-Waechter fuer Aethelos")
    p.add_argument("--version", action="version", version=f"sentinel {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    for c in COMMANDS:
        sub.add_parser(c)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print(f"sentinel {args.command}: noch nicht implementiert (Meilenstein M1+)", file=sys.stderr)
    return EXIT_INTERNAL

