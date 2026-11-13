import os
import tempfile
import unittest
from unittest import mock

from sentinel import faults
from tests.fakerun import FakeRun
from tests.fakeroot import make_root


class TestLiveFaults(unittest.TestCase):
    def setUp(self):
        self.td = make_root()
        self.r = self.td.name
        self.sd = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.td.cleanup()
        self.sd.cleanup()

    def kw(self):
        return {"root": self.r, "state": self.sd.name}

    def test_f4_stops_and_starts_sshd(self):
        run = FakeRun([(("systemctl", "is-active"), 0, "active\n"), (("systemctl",), 0, "")])
        with mock.patch.object(faults, "_run", run):
            faults.inject("F4", **self.kw())
            self.assertIn(["systemctl", "stop", "sshd.service"], run.calls)
            self.assertEqual(faults.active(self.sd.name), ["F4"])
            faults.undo("F4", **self.kw())
            self.assertIn(["systemctl", "start", "sshd.service"], run.calls)
        self.assertEqual(faults.active(self.sd.name), [])

    def test_f4_refused_when_service_not_running(self):
        run = FakeRun([(("systemctl", "is-active"), 3, "inactive\n")])
        with mock.patch.object(faults, "_run", run), self.assertRaises(faults.FaultError):
            faults.inject("F4", **self.kw())
        self.assertEqual(faults.active(self.sd.name), [])

    def test_f5_sets_dead_dns_server_and_restores_original(self):
        # resolved nur stoppen reicht nicht: systemd 261 startet es per Socket-Aktivierung sofort neu
        run = FakeRun([(("resolvectl", "dns"), 0, "Global:\nLink 2 (ens4): 10.0.2.3 10.0.2.4\n"), (("resolvectl",), 0, "")])
        with mock.patch.object(faults, "_run", run):
            faults.inject("F5", **self.kw())
            self.assertIn(["resolvectl", "dns", "ens4", "127.0.0.1"], run.calls)
            self.assertIn(["resolvectl", "flush-caches"], run.calls)
            faults.undo("F5", **self.kw())
        self.assertEqual(run.calls[-2], ["resolvectl", "dns", "ens4", "10.0.2.3", "10.0.2.4"])
        self.assertEqual(run.calls[-1], ["resolvectl", "flush-caches"])
        self.assertEqual(faults.active(self.sd.name), [])

    def test_f5_refused_without_link_dns(self):
        run = FakeRun([(("resolvectl", "dns"), 0, "Global:\nLink 2 (ens4):\n")])
        with mock.patch.object(faults, "_run", run), self.assertRaises(faults.FaultError):
            faults.inject("F5", **self.kw())
        self.assertEqual(faults.active(self.sd.name), [])

    def test_f6_fills_disk_above_threshold_and_undo_frees(self):
        class V:   # 1000 Bloecke a 4096, 500 frei
            f_frsize, f_blocks, f_bfree, f_bavail = 4096, 1000, 500, 500
        sizes = []

        def fake_fill(path, size):
            sizes.append(size)
            with open(path, "wb") as f:
                f.write(b"x")
        with mock.patch.object(faults, "_statvfs", lambda p: V), mock.patch.object(faults, "_fill", fake_fill):
            faults.inject("F6", **self.kw())
        fill = os.path.join(self.sd.name, "F6", "fill")
        self.assertTrue(os.path.exists(fill))
        used_after = (500 + sizes[0] / 4096) / 1000 * 100
        self.assertGreaterEqual(used_after, faults.FILL_PCT)
        faults.undo("F6", **self.kw())
        self.assertFalse(os.path.exists(fill))

    def test_f7_logs_error_and_syncs(self):
        run = FakeRun([(("logger",), 0, ""), (("journalctl", "--sync"), 0, "")])
        with mock.patch.object(faults, "_run", run):
            faults.inject("F7", **self.kw())
            faults.undo("F7", **self.kw())
        self.assertEqual(run.calls[0][:3], ["logger", "-p", "user.err"])
        self.assertIn("sentinel-f7", run.calls[0])
        self.assertEqual(run.calls[1], ["journalctl", "--sync"])

    def test_expected_detection_for_all_faults(self):
        self.assertEqual(sorted(faults.FAULTS), ["F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8"])
        self.assertEqual(faults.expected("F1", self.r), ("integrity", "/usr/bin/ls", 11))
        self.assertEqual(faults.expected("F3", self.r), ("accounts", "f3evil", 11))
        self.assertEqual(faults.expected("F8", self.r), ("integrity", "/boot/vmlinuz-7.1.8", 11))
        self.assertEqual(faults.expected("F4", self.r), ("services", "sshd.service", 10))
        self.assertEqual(faults.expected("F5", self.r)[0], "network")
        self.assertEqual(faults.expected("F6", self.r), ("resources", "disk:/", 10))
        self.assertEqual(faults.expected("F7", self.r), ("logs", "sentinel-f7", 10))


if __name__ == "__main__":
    unittest.main()
