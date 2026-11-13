import json
import unittest

from sentinel.checks import services
from sentinel.model import Severity
from sentinel.sysprobe import ProbeError
from tests.fakerun import FakeRun

REQ = ("sshd.service", "systemd-resolved.service")
FAILED = ("systemctl", "list-units", "--failed")
ACTIVE = ("systemctl", "is-active")


class TestServices(unittest.TestCase):
    def test_all_ok(self):
        run = FakeRun([(FAILED, 0, "[]"), (ACTIVE, 0, "active\nactive\n")])
        self.assertEqual(services.check(run, REQ), [])

    def test_failed_unit_is_warning(self):
        units = [{"unit": "foo.service", "load": "loaded", "active": "failed", "sub": "failed", "description": "Foo"}]
        run = FakeRun([(FAILED, 0, json.dumps(units)), (ACTIVE, 0, "active\nactive\n"),
                       (("journalctl",), 0, "foo: kaputt\n")])
        fs = services.check(run, REQ)
        self.assertEqual([(f.subject, f.severity) for f in fs], [("foo.service", Severity.WARN)])
        self.assertIn("foo: kaputt", fs[0].evidence)

    def test_required_inactive_shows_journal_line(self):
        run = FakeRun([(FAILED, 0, "[]"), (ACTIVE, 3, "inactive\nactive\n"),
                       (("journalctl", "UNIT=sshd.service", "_PID=1"), 0,
                        "Stopping OpenSSH Daemon...\nStopped OpenSSH Daemon.\nsshd.service: Consumed 2.494s CPU time.\n")])
        fs = services.check(run, REQ)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].subject, "sshd.service")
        self.assertEqual(fs[0].severity, Severity.WARN)
        self.assertIn("inactive", fs[0].evidence)
        self.assertIn("Stopped OpenSSH Daemon.", fs[0].evidence)
        self.assertNotIn("Consumed", fs[0].evidence)         # Statistikzeile ist keine Aussage

    def test_systemctl_broken_is_probe_error(self):
        with self.assertRaises(ProbeError):
            services.check(FakeRun([(FAILED, 1, "")]), REQ)
        with self.assertRaises(ProbeError):
            services.check(FakeRun([(FAILED, 0, "kein json")]), REQ)

    def test_is_active_wrong_line_count_is_probe_error(self):
        with self.assertRaises(ProbeError):
            services.check(FakeRun([(FAILED, 0, "[]"), (ACTIVE, 0, "active\n")]), REQ)


if __name__ == "__main__":
    unittest.main()
