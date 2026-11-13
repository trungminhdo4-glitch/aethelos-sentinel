"""sqlite3-Speicher: Baseline, SUID-Liste, Laeufe und Befunde."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone

from sentinel import __version__
from sentinel.model import Finding
from sentinel.scan import Entry

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS baseline(path TEXT PRIMARY KEY, kind TEXT, sha256 TEXT, mode INT, uid INT, gid INT, size INT);
CREATE TABLE IF NOT EXISTS suid(path TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, ts TEXT, exit INT);
CREATE TABLE IF NOT EXISTS findings(run_id INT, check_name TEXT, severity TEXT, subject TEXT, evidence TEXT, first_seen TEXT);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def baseline_digest(entries: dict[str, Entry], suid: set[str]) -> str:
    """Ein Hash ueber die ganze Baseline -> spaeter extern vergleichbar (M3)."""
    h = hashlib.sha256()
    for p in sorted(entries):
        e = entries[p]
        h.update(f"{p}\0{e.kind}\0{e.sha256}\0{e.mode}\0{e.uid}\0{e.gid}\n".encode())
    for p in sorted(suid):
        h.update(f"suid\0{p}\n".encode())
    return h.hexdigest()


class Store:
    def __init__(self, path: str):
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, mode=0o700, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    def __del__(self):
        db = getattr(self, "db", None)
        if db is not None:
            db.close()

    def save_baseline(self, entries: dict[str, Entry], suid: set[str]) -> str:
        digest = baseline_digest(entries, suid)
        with self.db:
            self.db.execute("DELETE FROM baseline")
            self.db.execute("DELETE FROM suid")
            self.db.executemany("INSERT INTO baseline VALUES(?,?,?,?,?,?,?)",
                                [(p, e.kind, e.sha256, e.mode, e.uid, e.gid, e.size) for p, e in entries.items()])
            self.db.executemany("INSERT INTO suid VALUES(?)", [(p,) for p in suid])
            for k, v in {"created": _now(), "version": __version__, "count": str(len(entries)), "digest": digest}.items():
                self.db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (k, v))
        return digest

    def load_baseline(self):
        meta = dict(self.db.execute("SELECT key, value FROM meta"))
        if "digest" not in meta:
            return None
        entries = {r[0]: Entry(*r[1:]) for r in self.db.execute(
            "SELECT path, kind, sha256, mode, uid, gid, size FROM baseline")}
        suid = {r[0] for r in self.db.execute("SELECT path FROM suid")}
        if baseline_digest(entries, suid) != meta["digest"]:
            raise ValueError("Baseline in der Datenbank passt nicht zu ihrem Digest (manipuliert/beschaedigt)")
        return entries, suid, meta

    def get_meta(self, key: str) -> str | None:
        r = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return r[0] if r else None

    def set_meta(self, key: str, value: str | None) -> None:
        with self.db:
            if value is None:
                self.db.execute("DELETE FROM meta WHERE key=?", (key,))
            else:
                self.db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (key, value))

    def record_run(self, findings: list[Finding], exit_code: int) -> int:
        with self.db:
            cur = self.db.execute("INSERT INTO runs(ts, exit) VALUES(?,?)", (_now(), exit_code))
            rid = cur.lastrowid
            self.db.executemany("INSERT INTO findings VALUES(?,?,?,?,?,?)",
                                [(rid, f.check, f.severity.name, f.subject, f.evidence, f.first_seen) for f in findings])
        return rid

    def last_run(self):
        r = self.db.execute("SELECT id, ts, exit FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        if not r:
            return None, []
        fs = [dict(zip(("check", "severity", "subject", "evidence", "first_seen"), row)) for row in self.db.execute(
            "SELECT check_name, severity, subject, evidence, first_seen FROM findings WHERE run_id=? ORDER BY rowid", (r[0],))]
        return {"id": r[0], "ts": r[1], "exit": r[2]}, fs


def dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)
