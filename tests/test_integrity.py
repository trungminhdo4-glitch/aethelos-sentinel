import os
import unittest

from sentinel.checks import integrity
from sentinel.model import Severity
from sentinel.scan import scan, suid_scan
from tests.fakeroot import make_root, write


class TestIntegrity(unittest.TestCase):
    def setUp(self):
        self.td = make_root()
        self.r = self.td.name
        b = scan(self.r)
        self.base, self.base_suid = b.entries, suid_scan(self.r)

    def tearDown(self):
        self.td.cleanup()

    def run_check(self):
        return integrity.check(self.base, self.base_suid, scan(self.r).entries, suid_scan(self.r))

    def by_subject(self, fs):
        return {f.subject: f for f in fs}

    def test_unchanged_is_clean(self):
        self.assertEqual(self.run_check(), [])

    def test_modified_binary_is_critical(self):                      # F1
        write(self.r, "usr/bin/ls", b"\x7fELF-ls-TAMPERED")
        f = self.by_subject(self.run_check())["/usr/bin/ls"]
        self.assertEqual(f.severity, Severity.CRIT)
        self.assertIn("sha256", f.evidence)

    def test_modified_kernel_is_critical(self):                      # F8
        write(self.r, "boot/vmlinuz-7.1.8", b"bzImage-evil")
        self.assertEqual(self.by_subject(self.run_check())["/boot/vmlinuz-7.1.8"].severity, Severity.CRIT)

    def test_new_suid_file_is_critical(self):                        # F2
        write(self.r, "usr/local/bin/backdoor", b"x", mode=0o4755)
        f = self.by_subject(self.run_check())["/usr/local/bin/backdoor"]
        self.assertEqual(f.severity, Severity.CRIT)
        self.assertIn("SUID", f.evidence)

    def test_gained_suid_bit_is_critical(self):
        os.chmod(os.path.join(self.r, "usr/bin/bash"), 0o4755)
        self.assertEqual(self.by_subject(self.run_check())["/usr/bin/bash"].severity, Severity.CRIT)

    def test_new_plain_file_is_warning(self):
        write(self.r, "usr/bin/newtool", b"x")
        self.assertEqual(self.by_subject(self.run_check())["/usr/bin/newtool"].severity, Severity.WARN)

    def test_missing_file_is_warning(self):
        os.remove(os.path.join(self.r, "usr/sbin/sshd"))
        self.assertEqual(self.by_subject(self.run_check())["/usr/sbin/sshd"].severity, Severity.WARN)

    def test_plain_etc_change_is_warning(self):
        write(self.r, "etc/hostname", b"other\n", mode=0o644)
        self.assertEqual(self.by_subject(self.run_check())["/etc/hostname"].severity, Severity.WARN)

    def test_security_etc_change_is_critical(self):                  # F3 (Dateiseite)
        with open(os.path.join(self.r, "etc/passwd"), "a") as f:
            f.write("evil:x:0:0::/root:/bin/sh\n")
        self.assertEqual(self.by_subject(self.run_check())["/etc/passwd"].severity, Severity.CRIT)


if __name__ == "__main__":
    unittest.main()

