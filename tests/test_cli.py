import contextlib
import io
import os
import subprocess
import sys
import unittest

from sentinel import __version__
from sentinel.cli import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestCli(unittest.TestCase):
    def test_version(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertEqual(out.getvalue().strip(), f"sentinel {__version__}")

    def test_unimplemented_command_is_fail_closed(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = main(["tui"])
        self.assertEqual(rc, 2)              # nie "gruen" ohne echte Pruefung
        self.assertIn("nicht implementiert", err.getvalue())

    def test_no_command_shows_usage(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            main([])
        self.assertEqual(cm.exception.code, 2)

    def test_module_entrypoint(self):
        r = subprocess.run([sys.executable, "-m", "sentinel", "--version"],
                           cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.startswith("sentinel "))


if __name__ == "__main__":
    unittest.main()
