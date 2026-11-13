import os
import tempfile
import unittest
from collections import namedtuple

from sentinel.checks import boot, resources
from sentinel.model import Severity
from tests.fakerun import FakeRun

VFS = namedtuple("VFS", "f_bsize f_frsize f_blocks f_bfree f_bavail f_files f_ffree f_favail")


def vfs(used_pct, inode_pct=10):
    blocks, files = 1000, 1000
    free = blocks * (100 - used_pct) // 100
    ffree = files * (100 - inode_pct) // 100
    return VFS(4096, 4096, blocks, free, free, files, ffree, ffree)


MEM_OK = "MemTotal: 2000000 kB\nMemFree: 1000000 kB\nMemAvailable: 1500000 kB\n"
MEM_LOW = "MemTotal: 2000000 kB\nMemFree: 50000 kB\nMemAvailable: 100000 kB\n"


class TestResources(unittest.TestCase):
    def run_check(self, v=None, mem=MEM_OK, load=(0.1, 0.1, 0.1)):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(mem)
        try:
            return resources.check(paths=("/",), statvfs=lambda p: v or vfs(9), meminfo=f.name,
                                   loadavg=lambda: load, ncpu=4)
        finally:
            os.unlink(f.name)

    def test_ok(self):
        self.assertEqual(self.run_check(), [])

    def test_disk_full_warns(self):
        fs = self.run_check(vfs(93))
        self.assertEqual([(f.subject, f.severity) for f in fs], [("disk:/", Severity.WARN)])
        self.assertIn("93%", fs[0].evidence)

    def test_inodes_warn(self):
        self.assertEqual([f.subject for f in self.run_check(vfs(9, 95))], ["inodes:/"])

    def test_memory_low(self):
        self.assertEqual([f.subject for f in self.run_check(mem=MEM_LOW)], ["memory"])

    def test_load_high(self):
        self.assertEqual([f.subject for f in self.run_check(load=(9.5, 1, 1))], ["load"])


AN = ("systemd-analyze", "time")


class TestBoot(unittest.TestCase):
    def run_check(self, tainted="0", analyze=(0, "Startup finished in 2.572s (kernel) + 4.297s (userspace) = 6.870s \n")):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(tainted + "\n")
        try:
            return boot.check(FakeRun([(AN,) + analyze]), tainted_path=f.name, max_boot_s=60)
        finally:
            os.unlink(f.name)

    def test_ok(self):
        self.assertEqual(self.run_check(), [])

    def test_tainted(self):
        fs = self.run_check(tainted="4096")
        self.assertEqual([(f.subject, f.severity) for f in fs], [("kernel", Severity.WARN)])
        self.assertIn("4096", fs[0].evidence)

    def test_slow_boot(self):
        fs = self.run_check(analyze=(0, "Startup finished in 1min 2.5s (kernel) + 30.0s (userspace) = 1min 32.500s\n"))
        self.assertEqual([f.subject for f in fs], ["boot-time"])

    def test_boot_not_finished_is_no_finding(self):
        self.assertEqual(self.run_check(analyze=(1, "")), [])

    def test_parse_seconds(self):
        self.assertAlmostEqual(boot.parse_seconds("6.870s"), 6.87)
        self.assertAlmostEqual(boot.parse_seconds("1min 32.500s"), 92.5)
        self.assertAlmostEqual(boot.parse_seconds("870ms"), 0.87)
        self.assertAlmostEqual(boot.parse_seconds("1h 2min 3s"), 3723)


if __name__ == "__main__":
    unittest.main()
