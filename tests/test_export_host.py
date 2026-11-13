import contextlib
import io
import json
import os
import tempfile
import unittest

from sentinel import host
from sentinel.cli import main
from sentinel.store import Store
from tests.fakeroot import make_root, write


class Base(unittest.TestCase):
    def setUp(self):
        self.td = make_root()
        self.r = self.td.name
        self.dd = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.dd.name, "s.db")
        self.trust = os.path.join(self.dd.name, "trust")

    def tearDown(self):
        self.td.cleanup()
        self.dd.cleanup()

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(list(args) + ["--root", self.r, "--db", self.db])
        return rc, out.getvalue(), err.getvalue()

    def export(self) -> dict:
        rc, out, err = self.cli("export")
        self.assertEqual(rc, 0, err)
        return json.loads(out)

    def host(self, *args, fetch):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = host.main(list(args) + ["--trust", self.trust], fetch=fetch)
        return rc, out.getvalue(), err.getvalue()


class TestExport(Base):
    def test_export_without_baseline_is_2(self):
        self.assertEqual(self.cli("export")[0], 2)

    def test_export_matches_stored_digest_and_is_recomputable(self):
        self.assertEqual(self.cli("baseline")[0], 0)
        ex = self.export()
        _, _, meta = Store(self.db).load_baseline()
        self.assertEqual(ex["format"], host.FORMAT)
        self.assertEqual(ex["digest"], meta["digest"])
        self.assertEqual(ex["count"], len(ex["entries"]))
        self.assertIn("usr/bin/ls", ex["entries"])
        self.assertEqual(host.validate(ex), ex["digest"])

    def test_tampered_export_is_rejected(self):
        self.cli("baseline")
        ex = self.export()
        ex["entries"]["usr/bin/ls"][1] = "0" * 64      # Liste geaendert, Digest nicht -> faellt auf
        with self.assertRaises(host.HostError):
            host.validate(ex)
        with self.assertRaises(host.HostError):
            host.validate({"format": "quatsch"})


class TestHostCompare(Base):
    def test_pin_then_verify_ok(self):
        self.cli("baseline")
        ex = self.export()
        self.assertEqual(self.host("pin", fetch=lambda: ex)[0], 0)
        self.assertTrue(os.path.exists(os.path.join(self.trust, "pinned.json")))
        self.assertEqual(self.host("verify", fetch=lambda: ex)[0], 0)

    def test_rebaselined_vm_is_caught_by_host(self):
        # Angreifer mit root: Binary aendern UND Baseline neu schreiben -> in der VM gruen, der Host merkt es
        self.cli("baseline")
        self.host("pin", fetch=lambda: self.export())
        write(self.r, "usr/bin/ls", b"trojan")
        self.cli("baseline")
        self.assertEqual(self.cli("check")[0], 0)          # VM selbst ist blind
        rc, out, _ = self.host("verify", fetch=lambda: self.export())
        self.assertEqual(rc, 11)
        self.assertIn("/usr/bin/ls", out)

    def test_verify_without_pin_is_2(self):
        self.cli("baseline")
        self.assertEqual(self.host("verify", fetch=lambda: self.export())[0], 2)

    def test_fetch_failure_is_2(self):
        def boom():
            raise host.HostError("ssh weg")
        rc, _, err = self.host("pin", fetch=boom)
        self.assertEqual(rc, 2)
        self.assertIn("ssh weg", err)

    def test_compare_lists_changed_added_removed(self):
        self.cli("baseline")
        a = self.export()
        b = json.loads(json.dumps(a))
        b["entries"]["usr/bin/ls"][1] = "f" * 64
        b["entries"]["usr/bin/neu"] = ["file", "a" * 64, 0o755, 0, 0, 1]
        del b["entries"]["usr/bin/bash"]
        b["suid"].append("usr/bin/neu")
        diffs = dict(host.compare(a, b))
        self.assertEqual(diffs["/usr/bin/ls"], "geaendert")
        self.assertEqual(diffs["/usr/bin/neu"], "neu")
        self.assertEqual(diffs["/usr/bin/bash"], "fehlt")
        self.assertEqual(diffs["suid:/usr/bin/neu"], "neu")
        self.assertEqual(host.compare(a, a), [])


class TestOffline(Base):
    def test_offline_findings_on_mounted_tree(self):
        self.cli("baseline")
        pinned = self.export()
        self.assertEqual(host.offline_findings(self.r, pinned), [])
        write(self.r, "usr/bin/ls", b"trojan")
        fs = host.offline_findings(self.r, pinned)
        self.assertIn(("/usr/bin/ls", "CRIT"), [(f.subject, f.severity.name) for f in fs])


if __name__ == "__main__":
    unittest.main()
