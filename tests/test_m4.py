import contextlib
import io
import os
import sqlite3
import tempfile
import time
import unittest

from sentinel import tui, watch
from sentinel.cli import main
from sentinel.inotify import Inotify
from sentinel.model import Finding, Severity
from sentinel.store import Store
from tests.fakeroot import make_root, write


def F(check, sev, subject, first_seen):
    return Finding(check, sev, subject, "ev", first_seen)


class TestStorePerCheck(unittest.TestCase):
    def setUp(self):
        self.dd = tempfile.TemporaryDirectory()
        self.st = Store(os.path.join(self.dd.name, "s.db"))

    def tearDown(self):
        self.st.close()
        self.dd.cleanup()

    def test_latest_by_check_combines_partial_runs(self):
        self.st.record_run([F("integrity", Severity.CRIT, "/usr/bin/ls", "T1")], 11, ["integrity", "services"])
        self.st.record_run([], 0, ["services"])                    # Live-Lauf ohne integrity
        latest = self.st.latest_by_check()
        self.assertEqual(latest["integrity"]["findings"][0]["subject"], "/usr/bin/ls")
        self.assertEqual(latest["services"]["findings"], [])
        self.assertGreater(latest["services"]["run_id"], latest["integrity"]["run_id"])
        self.assertNotIn("logs", latest)

    def test_first_seen_is_carried_while_finding_persists(self):
        self.st.record_run([F("services", Severity.WARN, "sshd.service", "T1")], 10, ["services"])
        self.st.record_run([F("services", Severity.WARN, "sshd.service", "T2")], 10, ["services"])
        self.assertEqual(self.st.latest_by_check()["services"]["findings"][0]["first_seen"], "T1")
        self.st.record_run([], 0, ["services"])
        self.st.record_run([F("services", Severity.WARN, "sshd.service", "T4")], 10, ["services"])
        self.assertEqual(self.st.latest_by_check()["services"]["findings"][0]["first_seen"], "T4")

    def test_first_seen_not_reset_by_run_without_that_check(self):
        self.st.record_run([F("integrity", Severity.CRIT, "/usr/bin/ls", "T1")], 11, ["integrity"])
        self.st.record_run([], 0, ["services"])
        self.st.record_run([F("integrity", Severity.CRIT, "/usr/bin/ls", "T3")], 11, ["integrity"])
        self.assertEqual(self.st.latest_by_check()["integrity"]["findings"][0]["first_seen"], "T1")

    def test_old_schema_is_migrated(self):
        p = os.path.join(self.dd.name, "old.db")
        db = sqlite3.connect(p)
        db.executescript("CREATE TABLE runs(id INTEGER PRIMARY KEY, ts TEXT, exit INT);"
                         "INSERT INTO runs(ts, exit) VALUES('2026-11-13T10:00:00+00:00', 0);")
        db.commit()
        db.close()
        st = Store(p)
        st.record_run([], 0, ["integrity"])
        self.assertIn("integrity", st.latest_by_check())
        st.close()


class TestTui(unittest.TestCase):
    def state(self):
        return {"integrity": {"run_id": 2, "ts": "2026-11-13T12:00:00+00:00", "exit": 11,
                              "findings": [{"check": "integrity", "severity": "CRIT", "subject": "/usr/bin/ls",
                                            "evidence": "sha256 geaendert: aaaa… -> bbbb…", "first_seen": "T"}]},
                "services": {"run_id": 3, "ts": "2026-11-13T12:00:05+00:00", "exit": 0, "findings": []}}

    def test_view_has_tile_per_check_and_findings(self):
        lines = tui.build_view(self.state(), width=80, now="2026-11-13T12:00:10+00:00")
        text = "\n".join(t for t, _ in lines)
        attrs = dict(lines)
        for c in ("integrity", "accounts", "services", "network", "logs", "resources", "boot"):
            self.assertIn(c, text)
        tile = next(t for t, _ in lines if t.lstrip().startswith("integrity"))
        self.assertEqual(attrs[tile], "crit")
        self.assertEqual(attrs[next(t for t, _ in lines if t.lstrip().startswith("services"))], "ok")
        self.assertEqual(attrs[next(t for t, _ in lines if t.lstrip().startswith("logs"))], "dim")   # noch nie gelaufen
        self.assertIn("/usr/bin/ls", text)
        self.assertIn("KRITISCH", text)

    def test_lines_never_exceed_width(self):
        for w in (40, 80, 120):
            for t, _ in tui.build_view(self.state(), width=w, now="2026-11-13T12:00:10+00:00"):
                self.assertLessEqual(len(t), w)

    def test_empty_db(self):
        text = "\n".join(t for t, _ in tui.build_view({}, width=80))
        self.assertIn("noch kein Lauf", text)

    def test_cli_once(self):
        with make_root() as r, tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "s.db")
            with contextlib.redirect_stdout(io.StringIO()):
                main(["baseline", "--root", r, "--db", db])
                write(r, "usr/bin/ls", b"x")
                main(["check", "--root", r, "--db", db])
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = main(["tui", "--once", "--root", r, "--db", db])
        self.assertEqual(rc, 0)
        self.assertIn("/usr/bin/ls", out.getvalue())
        self.assertIn("integrity", out.getvalue())


class TestScheduler(unittest.TestCase):
    def test_event_debounced_then_full_then_live_interval(self):
        s = watch.Scheduler(debounce=2, interval=15, now=0)
        self.assertIsNone(s.due(1))
        s.event(10)
        s.event(11)                        # zweites Ereignis verlaengert die Wartezeit
        self.assertIsNone(s.due(12.5))
        self.assertEqual(s.due(13), "full")
        s.ran("full", 13)
        self.assertIsNone(s.due(20))
        self.assertEqual(s.due(28), "live")
        s.ran("live", 28)
        self.assertAlmostEqual(s.timeout(30), 13)

    def test_first_live_run_due_at_interval(self):
        s = watch.Scheduler(debounce=2, interval=15, now=0)
        self.assertIsNone(s.due(14))
        self.assertEqual(s.due(15), "live")
        s.event(16)
        self.assertLessEqual(s.timeout(16), 2)


class TestInotify(unittest.TestCase):
    def test_detects_write_and_new_subdir(self):
        with tempfile.TemporaryDirectory() as d, Inotify() as ino:
            ino.add_tree(d)
            with open(os.path.join(d, "a"), "w") as f:
                f.write("x")
            self.assertIn(os.path.join(d, "a"), [p for p, _ in ino.read(2)])
            os.mkdir(os.path.join(d, "sub"))
            ino.read(1)                                  # neues Verzeichnis wird automatisch beobachtet
            with open(os.path.join(d, "sub", "b"), "w") as f:
                f.write("y")
            self.assertIn(os.path.join(d, "sub", "b"), [p for p, _ in ino.read(2)])

    def test_timeout_returns_empty(self):
        with tempfile.TemporaryDirectory() as d, Inotify() as ino:
            ino.add_tree(d)
            t = time.monotonic()
            self.assertEqual(ino.read(0.2), [])
            self.assertLess(time.monotonic() - t, 1.5)


class TestTargetFilter(unittest.TestCase):
    def test_only_target_patterns_count(self):
        with make_root() as r, watch.TargetWatcher(r) as w:
            write(r, "usr/lib/python3/neu.py", b"x")           # kein *.so -> egal
            write(r, "usr/lib/libneu.so.1", b"x")               # Bibliothek -> relevant
            write(r, "etc/ld.so.cache", b"y")                   # ausgeschlossen
            rel = w.relevant(2)
        self.assertIn("usr/lib/libneu.so.1", rel)
        self.assertNotIn("usr/lib/python3/neu.py", rel)
        self.assertNotIn("etc/ld.so.cache", rel)


if __name__ == "__main__":
    unittest.main()
