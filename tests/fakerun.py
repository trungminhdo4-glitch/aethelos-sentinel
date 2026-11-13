"""Gefaelschte Befehlsausfuehrung: Antworten je Befehls-Praefix, jeder Aufruf wird mitgeschrieben."""
from sentinel.sysprobe import ProbeError


class FakeRun:
    def __init__(self, responses):
        # responses: Liste von (praefix-tupel, rc, stdout) oder (praefix-tupel, Exception)
        self.responses = responses
        self.calls: list[list[str]] = []

    def __call__(self, cmd, timeout=10):
        self.calls.append(list(cmd))
        for r in self.responses:
            pre = r[0]
            if tuple(cmd[:len(pre)]) == tuple(pre):
                if isinstance(r[1], BaseException):
                    raise r[1]
                return r[1], r[2]
        raise ProbeError(f"FakeRun: unerwarteter Befehl {cmd}")
