import hashlib
import os
import unittest

from sentinel.scan import scan, suid_scan
from tests.fakeroot import make_root, write


class TestScan(unittest.TestCase):
    def setUp(self):
        self.td = make_root()
        self.r = self.td.name

    def tearDown(self):
        self.td.cleanup()

    def test_hashes_targets(self):
        res = scan(self.r)
        self.assertEqual(res.errors, [])
        e = res.entries["usr/bin/ls"]
        self.assertEqual(e.kind, "file")
        self.assertEqual(e.sha256, hashlib.sha256(b"\x7fELF-ls").hexdigest())
        self.assertIn("usr/lib/libc.so.6", res.entries)
        self.assertIn("boot/vmlinuz-7.1.8", res.entries)
        self.assertIn("etc/shadow", res.entries)

    def test_only_shared_objects_in_usr_lib(self):
        self.assertNotIn("usr/lib/python3/notalib.py", scan(self.r).entries)

    def test_excluded_file_not_in_baseline(self):
        self.assertNotIn("etc/ld.so.cache", scan(self.r).entries)

    def test_symlink_recorded_not_followed(self):
        e = scan(self.r).entries["etc/mtab"]
        self.assertEqual(e.kind, "link")
        self.assertEqual(e.sha256, "link:/proc/self/mounts")

    @unittest.skipIf(os.geteuid() == 0, "root kann alles lesen")
    def test_unreadable_file_is_error_not_silence(self):
        os.chmod(os.path.join(self.r, "etc/shadow"), 0o000)
        res = scan(self.r)
        self.assertTrue(any("etc/shadow" in e for e in res.errors))

    def test_suid_scan_finds_setuid_anywhere(self):
        write(self.r, "tmp/evil", b"x", mode=0o4755)
        write(self.r, "usr/bin/passwd", b"x", mode=0o4755)
        found = suid_scan(self.r)
        self.assertEqual(found, {"tmp/evil", "usr/bin/passwd"})

    def test_suid_scan_skips_pseudo_fs(self):
        write(self.r, "proc/1/fake", b"x", mode=0o4755)
        self.assertNotIn("proc/1/fake", suid_scan(self.r))


if __name__ == "__main__":
    unittest.main()
