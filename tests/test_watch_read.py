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
