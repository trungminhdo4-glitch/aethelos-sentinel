import contextlib
import io
import json
import os
import socket
import tempfile
import unittest
from unittest import mock

from sentinel import cli, journal, sysprobe
from sentinel.cli import main
from tests.fakerun import FakeRun
from tests.fakeroot import make_root


class TestJournal(unittest.TestCase):
    def test_send_native_fields(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sock")
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            srv.bind(path)
            try:
                self.assertTrue(journal.send({"MESSAGE": "zwei\nzeilen", "SENTINEL_EXIT": 10}, path))
                data = srv.recv(65536)
            finally:
                srv.close()
        self.assertIn(b"MESSAGE=zwei zeilen\n", data)
        self.assertIn(b"SENTINEL_EXIT=10\n", data)
        self.assertIn(b"SYSLOG_IDENTIFIER=sentinel\n", data)

    def test_missing_socket_is_not_fatal(self):
        self.assertFalse(journal.send({"MESSAGE": "x"}, "/nonexistent/sock"))


class TestCliLiveChecks(unittest.TestCase):
    def setUp(self):
        self.td = make_root()
        self.dd = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.dd.name, "s.db")

    def tearDown(self):
        self.td.cleanup()
        self.dd.cleanup()

    def cli(self, *args, run=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(sysprobe, "run", run or FakeRun([])), mock.patch.object(journal, "send", lambda *a, **k: False):
            rc = main(list(args) + ["--root", self.td.name, "--db", self.db])
        return rc, out.getvalue(), err.getvalue()

    def test_services_check_via_cli(self):
        self.assertEqual(self.cli("baseline")[0], 0)
        run = FakeRun([(("systemctl", "list-units"), 0, "[]"),
                       (("systemctl", "is-active"), 3, "\n".join(["inactive"] + ["active"] * 3) + "\n"),
                       (("journalctl",), 0, "Stopped.\n")])
        rc, out, _ = self.cli("check", "--checks", "integrity,services", run=run)
        self.assertEqual(rc, 10)
        self.assertIn("sshd.service", out)

    def test_probe_error_is_exit_2(self):
        self.assertEqual(self.cli("baseline")[0], 0)
        rc, _, err = self.cli("check", "--checks", "services", run=FakeRun([(("systemctl",), sysprobe.ProbeError("weg"))]))
        self.assertEqual(rc, 2)
        self.assertIn("weg", err)

    def test_unknown_check_is_exit_2(self):
        self.assertEqual(self.cli("baseline")[0], 0)
        self.assertEqual(self.cli("check", "--checks", "quatsch")[0], 2)

    def test_logs_cursor_from_baseline_and_advanced(self):
        start = json.dumps({"__CURSOR": "b0", "MESSAGE": "x"}) + "\n"
        self.assertEqual(self.cli("baseline", "--checks", "integrity,logs", run=FakeRun([(("journalctl",), 0, start)]))[0], 0)
        err = json.dumps({"__CURSOR": "e1", "PRIORITY": "3", "SYSLOG_IDENTIFIER": "sentinel-f7", "MESSAGE": "F7"}) + "\n"
        r1 = FakeRun([(("journalctl",), 0, err)])
        rc, out, _ = self.cli("check", "--checks", "logs", run=r1)
        self.assertEqual(rc, 10)
        self.assertIn("--after-cursor=b0", r1.calls[0])
        r2 = FakeRun([(("journalctl",), 0, "")])
        self.assertEqual(self.cli("check", "--checks", "logs", run=r2)[0], 0)
        self.assertIn("--after-cursor=e1", r2.calls[0])

    def test_default_checks_with_foreign_root_are_file_checks_only(self):
        self.assertEqual(cli.default_checks(self.td.name), ["integrity", "accounts"])
        self.assertEqual(cli.default_checks("/"), list(cli.ALL_CHECKS))


if __name__ == "__main__":
    unittest.main()
