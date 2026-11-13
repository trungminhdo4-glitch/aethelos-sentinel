import configparser
import os
import unittest

D = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "systemd")


def unit(name):
    c = configparser.ConfigParser(strict=False, interpolation=None)
    c.optionxform = str
    c.read(os.path.join(D, name))
    return c


class TestUnits(unittest.TestCase):
    def test_check_services_treat_findings_as_success(self):
        for n in ("sentinel-boot.service", "sentinel.service"):
            s = unit(n)["Service"]
            self.assertEqual(s["Type"], "oneshot")
            self.assertEqual(s["ExecStart"], "/usr/bin/sentinel check")
            self.assertEqual(s["SuccessExitStatus"].split(), ["10", "11"])   # exit 2 bleibt ein Fehler
            self.assertEqual(s["SyslogIdentifier"], "sentinel")              # logs-Check ignoriert sich selbst
            self.assertEqual(unit(n)["Unit"]["ConditionPathExists"], "/var/lib/sentinel/sentinel.db")

    def test_boot_runs_after_boot_and_timer_points_to_service(self):
        self.assertIn("multi-user.target", unit("sentinel-boot.service")["Unit"]["After"])
        self.assertEqual(unit("sentinel-boot.service")["Install"]["WantedBy"], "multi-user.target")
        t = unit("sentinel.timer")["Timer"]
        self.assertEqual(t["Unit"], "sentinel.service")
        self.assertEqual(t["OnUnitActiveSec"], "15min")


    def test_watch_service(self):
        u = unit("sentinel-watch.service")
        self.assertEqual(u["Service"]["ExecStart"], "/usr/bin/sentinel watch")
        self.assertEqual(u["Service"]["Restart"], "on-failure")
        self.assertEqual(u["Service"]["SyslogIdentifier"], "sentinel")
        self.assertEqual(u["Unit"]["ConditionPathExists"], "/var/lib/sentinel/sentinel.db")
        self.assertEqual(u["Install"]["WantedBy"], "multi-user.target")


class TestDemoWait(unittest.TestCase):
    def test_wait_for(self):
        from sentinel.demo import wait_for
        t = [0.0]
        vals = iter([None, None, "rot"])
        ok, secs, v = wait_for(lambda: next(vals), 10, poll=0.5, clock=lambda: t[0],
                               sleep=lambda s: t.__setitem__(0, t[0] + s))
        self.assertEqual((ok, secs, v), (True, 1.0, "rot"))
        ok, secs, v = wait_for(lambda: None, 2, poll=0.5, clock=lambda: t[0], sleep=lambda s: t.__setitem__(0, t[0] + s))
        self.assertEqual((ok, v), (False, None))


if __name__ == "__main__":
    unittest.main()
