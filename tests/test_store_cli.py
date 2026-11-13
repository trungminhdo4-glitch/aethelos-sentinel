import contextlib
import io
import json
import os
import tempfile
import unittest

from sentinel.cli import main
from sentinel.model import Finding, Severity
from sentinel.scan import scan
from sentinel.store import Store
from tests.fakeroot import make_root, write


class TestStore(unittest.TestCase):
    def test_baseline_roundtrip_and_runs(self):
        with make_root() as r, tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "s.db"))
            self.assertIsNone(st.load_baseline())
            entries = scan(r).entries
            st.save_baseline(entries, {"usr/bin/passwd"})
            got, suid, meta = st.load_baseline()
            self.assertEqual(got, entries)
            self.assertEqual(suid, {"usr/bin/passwd"})
            self.assertEqual(int(meta["count"]), len(entries))
            st.record_run([Finding("integrity", Severity.CRIT, "/usr/bin/ls", "sha256")], 11)
            run, fs = st.last_run()
            self.assertEqual(run["exit"], 11)
            self.assertEqual(fs[0]["subject"], "/usr/bin/ls")


class TestCliFlow(unittest.TestCase):
    def setUp(self):
        self.td = make_root()
        self.r = self.td.name
        self.dd = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.dd.name, "s.db")

    def tearDown(self):
        self.td.cleanup()
        self.dd.cleanup()

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(list(args) + ["--root", self.r, "--db", self.db])
        return rc, out.getvalue(), err.getvalue()

    def test_check_without_baseline_is_2(self):
        rc, _, err = self.cli("check")
        self.assertEqual(rc, 2)
        self.assertIn("Baseline", err)

    def test_full_flow(self):
        self.assertEqual(self.cli("baseline")[0], 0)
        self.assertEqual(self.cli("check")[0], 0)
        write(self.r, "usr/bin/ls", b"tampered")
        rc, out, _ = self.cli("check")
        self.assertEqual(rc, 11)
        self.assertIn("/usr/bin/ls", out)
        rc, out, _ = self.cli("report", "--json")
        data = json.loads(out)
        self.assertEqual(data["run"]["exit"], 11)
        self.assertEqual(data["findings"][0]["subject"], "/usr/bin/ls")

    def test_check_json(self):
        self.cli("baseline")
        write(self.r, "usr/local/bin/x", b"x", mode=0o4755)
        rc, out, _ = self.cli("check", "--json")
        self.assertEqual(rc, 11)
        self.assertEqual(json.loads(out)["exit"], 11)

    def test_tui_and_export_still_fail_closed(self):
        for c in ("tui", "export"):
            self.assertEqual(self.cli(c)[0], 2)


if __name__ == "__main__":
    unittest.main()

