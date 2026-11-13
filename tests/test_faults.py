import os
import stat
import tempfile
import unittest

from sentinel import faults
from sentinel.checks import accounts, integrity
from sentinel.scan import scan, suid_scan
from tests.fakeroot import make_root


class TestFaults(unittest.TestCase):
    def setUp(self):
        self.td = make_root()
        self.r = self.td.name
        # F2 kopiert usr/bin/true; im Fake-Root anlegen
        with open(os.path.join(self.r, "usr/bin/true"), "wb") as f:
            f.write(b"\x7fELF-true")
        self.sd = tempfile.TemporaryDirectory()
        self.base = scan(self.r).entries
        self.base_suid = suid_scan(self.r)

    def tearDown(self):
        self.td.cleanup()
        self.sd.cleanup()

    def findings(self):
        return integrity.check(self.base, self.base_suid, scan(self.r).entries, suid_scan(self.r)) + accounts.check(self.r)

    def roundtrip(self, fid, expect_subject):
        faults.inject(fid, root=self.r, state=self.sd.name)
        subjects = {f.subject for f in self.findings()}
        self.assertIn(expect_subject, subjects, f"{fid} nicht erkannt")
        faults.undo(fid, root=self.r, state=self.sd.name)
        self.assertEqual(self.findings(), [], f"{fid}: undo nicht sauber")

    def test_f1_binary(self):
        self.roundtrip("F1", "/usr/bin/ls")

    def test_f2_suid(self):
        self.roundtrip("F2", "/usr/local/bin/sentinel-f2-suid")

    def test_f3_uid0(self):
        self.roundtrip("F3", "f3evil")

    def test_f8_kernel(self):
        self.roundtrip("F8", "/boot/vmlinuz-7.1.8")

    def test_undo_restores_mode(self):
        p = os.path.join(self.r, "usr/bin/ls")
        before = stat.S_IMODE(os.stat(p).st_mode)
        faults.inject("F1", root=self.r, state=self.sd.name)
        faults.undo("F1", root=self.r, state=self.sd.name)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), before)

    def test_double_inject_refused(self):
        faults.inject("F1", root=self.r, state=self.sd.name)
        with self.assertRaises(faults.FaultError):
            faults.inject("F1", root=self.r, state=self.sd.name)
        faults.undo("F1", root=self.r, state=self.sd.name)

    def test_undo_without_inject_refused(self):
        with self.assertRaises(faults.FaultError):
            faults.undo("F3", root=self.r, state=self.sd.name)

    def test_unknown_fault(self):
        with self.assertRaises(faults.FaultError):
            faults.inject("F99", root=self.r, state=self.sd.name)


if __name__ == "__main__":
    unittest.main()

