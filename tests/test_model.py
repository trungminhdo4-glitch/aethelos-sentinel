import unittest

from sentinel.model import Finding, Severity, exit_code


class TestSeverity(unittest.TestCase):
    def test_order(self):
        self.assertLess(Severity.OK, Severity.WARN)
        self.assertLess(Severity.WARN, Severity.CRIT)


class TestExitCode(unittest.TestCase):
    def test_no_findings_is_ok(self):
        self.assertEqual(exit_code([]), 0)

    def test_warning_is_10(self):
        self.assertEqual(exit_code([Finding("services", Severity.WARN, "sshd", "inactive")]), 10)

    def test_critical_wins_over_warning(self):
        fs = [Finding("services", Severity.WARN, "sshd", "inactive"),
              Finding("integrity", Severity.CRIT, "/usr/bin/ls", "sha256 changed")]
        self.assertEqual(exit_code(fs), 11)


class TestFinding(unittest.TestCase):
    def test_to_dict_has_all_fields(self):
        d = Finding("integrity", Severity.CRIT, "/usr/bin/ls", "sha256 changed").to_dict()
        self.assertEqual(d["check"], "integrity")
        self.assertEqual(d["severity"], "CRIT")
        self.assertEqual(d["subject"], "/usr/bin/ls")
        self.assertEqual(d["evidence"], "sha256 changed")
        self.assertIn("first_seen", d)


if __name__ == "__main__":
    unittest.main()

