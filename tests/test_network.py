import os
import tempfile
import unittest

from sentinel.checks import network
from sentinel.model import Severity


def sysnet(ifaces: dict) -> tempfile.TemporaryDirectory:
    td = tempfile.TemporaryDirectory()
    for name, state in ifaces.items():
        os.makedirs(os.path.join(td.name, name))
        with open(os.path.join(td.name, name, "operstate"), "w") as f:
            f.write(state + "\n")
    return td


class TestNetwork(unittest.TestCase):
    def setUp(self):
        self.sleeps = []

    def run_check(self, ifaces, addr="10.0.2.15", resolve=None, **kw):
        with sysnet(ifaces) as d:
            return network.check(net_dir=d, ifaddr=lambda n: addr, resolve=resolve or (lambda h: [("ok",)]),
                                 dns_name="example.org", sleep=self.sleeps.append, **kw)

    def test_all_ok(self):
        self.assertEqual(self.run_check({"lo": "unknown", "ens4": "up"}), [])

    def test_no_link(self):
        fs = self.run_check({"lo": "unknown", "ens4": "down"})
        self.assertEqual([f.subject for f in fs], ["link"])
        self.assertEqual(fs[0].severity, Severity.WARN)

    def test_no_ipv4(self):
        fs = self.run_check({"ens4": "up"}, addr=None)
        self.assertEqual([f.subject for f in fs], ["ipv4"])

    def test_dns_failure_retries_then_warns(self):
        calls = []

        def bad(h):
            calls.append(h)
            raise OSError("Temporary failure in name resolution")
        fs = self.run_check({"ens4": "up"}, resolve=bad)
        self.assertEqual([f.subject for f in fs], ["dns:example.org"])
        self.assertIn("name resolution", fs[0].evidence)
        self.assertEqual(len(calls), network.DNS_ATTEMPTS)
        self.assertEqual(len(self.sleeps), network.DNS_ATTEMPTS - 1)

    def test_dns_hang_counts_as_failure(self):
        fs = self.run_check({"ens4": "up"}, resolve=lambda h: __import__("time").sleep(5), dns_timeout=0.05)
        self.assertEqual([f.subject for f in fs], ["dns:example.org"])
        self.assertIn("Zeitlimit", fs[0].evidence)

    def test_dns_recovers_on_retry(self):
        calls = []

        def flaky(h):
            calls.append(h)
            if len(calls) == 1:
                raise OSError("noch nicht")
            return [("ok",)]
        self.assertEqual(self.run_check({"ens4": "up"}, resolve=flaky), [])

    def test_https_off_by_default_and_checked_when_set(self):
        seen = []
        self.assertEqual(self.run_check({"ens4": "up"}, fetch=seen.append), [])
        self.assertEqual(seen, [])

        def boom(url):
            raise OSError("connection refused")
        fs = self.run_check({"ens4": "up"}, https_url="https://example.org/", fetch=boom)
        self.assertEqual([f.subject for f in fs], ["https:https://example.org/"])


if __name__ == "__main__":
    unittest.main()
