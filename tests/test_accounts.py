import os
import unittest

from sentinel.checks import accounts
from sentinel.model import Severity
from tests.fakeroot import make_root, write, PASSWD, SHADOW


class TestAccounts(unittest.TestCase):
    def setUp(self):
        self.td = make_root()
        self.r = self.td.name

    def tearDown(self):
        self.td.cleanup()

    def test_normal_accounts_clean(self):
        self.assertEqual(accounts.check(self.r), [])

    def test_second_uid0_is_critical(self):                          # F3
        write(self.r, "etc/passwd", (PASSWD + "f3evil:x:0:0::/root:/bin/false\n").encode(), mode=0o644)
        fs = accounts.check(self.r)
        self.assertEqual([(f.subject, f.severity) for f in fs], [("f3evil", Severity.CRIT)])
        self.assertIn("UID 0", fs[0].evidence)

    def test_empty_password_is_critical(self):
        write(self.r, "etc/shadow", (SHADOW + "nopw::20000:0:99999:7:::\n").encode(), mode=0o600)
        fs = accounts.check(self.r)
        self.assertEqual([(f.subject, f.severity) for f in fs], [("nopw", Severity.CRIT)])

    @unittest.skipIf(os.geteuid() == 0, "root kann alles lesen")
    def test_unreadable_shadow_raises(self):
        os.chmod(os.path.join(self.r, "etc/shadow"), 0o000)
        with self.assertRaises(PermissionError):
            accounts.check(self.r)


if __name__ == "__main__":
    unittest.main()
