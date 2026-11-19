import os
import tempfile
import unittest
from unittest.mock import patch

from sentinel import watch


class TestTargetWatcher(unittest.TestCase):
    def test_returns_after_one_batch_even_when_more_events_are_ready(self):
        with tempfile.TemporaryDirectory() as root, patch.object(watch, "Inotify") as inotify:
            first = os.path.join(root, "usr/bin/ls")
            second = os.path.join(root, "usr/bin/cat")
            read = inotify.return_value.read
            read.side_effect = [
                [(first, 0), (first, 0), (os.path.join(root, "var/log/ignored"), 0), (watch.OVERFLOW, 0)],
                [(second, 0)],
                [],
            ]
            with watch.TargetWatcher(root, targets=[("usr/bin", "*")]) as watcher:
                self.assertEqual(watcher.relevant(0.5), ["usr/bin/ls", watch.OVERFLOW])
                read.assert_called_once_with(0.5)
                self.assertEqual(watcher.relevant(0), ["usr/bin/cat"])


class TestWatchStartup(unittest.TestCase):
    def test_initial_probe_error_exits_before_waiting(self):
        with (
            patch.object(watch.os.path, "exists", return_value=True),
            patch.object(watch.signal, "signal"),
            patch.object(watch, "TargetWatcher") as watcher,
            patch.object(watch, "_check", return_value=2) as check,
        ):
            active = watcher.return_value.__enter__.return_value
            active.count = 0
            active.relevant.side_effect = AssertionError("watch waited after failed startup")
            self.assertEqual(watch.main("/", "sentinel.db"), 2)

        check.assert_called_once_with("/", "sentinel.db", "full")
        active.relevant.assert_not_called()
        watcher.return_value.__exit__.assert_called_once()
