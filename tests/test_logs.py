import json
import unittest

from sentinel.checks import logs
from sentinel.model import Severity
from sentinel.sysprobe import ProbeError
from tests.fakerun import FakeRun

J = ("journalctl",)


def entries(*items) -> str:
    return "".join(json.dumps(i) + "\n" for i in items)


class TestLogs(unittest.TestCase):
    def test_no_cursor_reads_current_boot(self):
        run = FakeRun([(J, 0, "")])
        fs, cur = logs.check(run, None)
        self.assertEqual((fs, cur), ([], None))
        self.assertIn("-b", run.calls[0])
        self.assertIn("err", run.calls[0])

    def test_cursor_is_used_and_advanced(self):
        out = entries({"__CURSOR": "c1", "PRIORITY": "3", "SYSLOG_IDENTIFIER": "sentinel-f7", "MESSAGE": "SENTINEL-F7"},
                      {"__CURSOR": "c2", "PRIORITY": "3", "SYSLOG_IDENTIFIER": "sentinel-f7", "MESSAGE": "noch einer"})
        run = FakeRun([(J, 0, out)])
        fs, cur = logs.check(run, "c0")
        self.assertIn("--after-cursor=c0", run.calls[0])
        self.assertNotIn("-b", run.calls[0])
        self.assertEqual(cur, "c2")
        self.assertEqual(len(fs), 1)                       # pro Absender zusammengefasst
        self.assertEqual(fs[0].subject, "sentinel-f7")
        self.assertEqual(fs[0].severity, Severity.WARN)
        self.assertIn("SENTINEL-F7", fs[0].evidence)
        self.assertIn("+1", fs[0].evidence)

    def test_empty_keeps_cursor(self):
        self.assertEqual(logs.check(FakeRun([(J, 0, "")]), "c5"), ([], "c5"))

    def test_own_messages_are_ignored(self):
        out = entries({"__CURSOR": "c9", "PRIORITY": "3", "SYSLOG_IDENTIFIER": "sentinel", "MESSAGE": "selbst"})
        self.assertEqual(logs.check(FakeRun([(J, 0, out)]), None), ([], "c9"))

    def test_binary_message_and_kernel(self):
        out = entries({"__CURSOR": "k1", "PRIORITY": "3", "_TRANSPORT": "kernel", "MESSAGE": list(b"ata1: fehler")})
        fs, _ = logs.check(FakeRun([(J, 0, out)]), None)
        self.assertEqual(fs[0].subject, "kernel")
        self.assertIn("ata1: fehler", fs[0].evidence)

    def test_stale_cursor_falls_back_to_boot(self):
        run = FakeRun([(("journalctl", "-p", "err", "-o", "json", "--no-pager", "--after-cursor=alt"), 1, ""), (J, 0, "")])
        self.assertEqual(logs.check(run, "alt"), ([], None))
        self.assertIn("-b", run.calls[1])

    def test_journalctl_broken_is_probe_error(self):
        with self.assertRaises(ProbeError):
            logs.check(FakeRun([(J, 1, "")]), None)
        with self.assertRaises(ProbeError):
            logs.check(FakeRun([(J, 0, "{kaputt\n")]), None)

    def test_current_cursor(self):
        run = FakeRun([(J, 0, entries({"__CURSOR": "now", "MESSAGE": "x"}))])
        self.assertEqual(logs.current_cursor(run), "now")
        self.assertIsNone(logs.current_cursor(FakeRun([(J, 0, "")])))


if __name__ == "__main__":
    unittest.main()
