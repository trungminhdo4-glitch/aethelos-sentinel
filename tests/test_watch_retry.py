"""Synthetic watch scheduling checks: no Linux watcher or system probes run."""
import contextlib
import io
import unittest
from unittest.mock import patch

from sentinel import watch


class TestRetryScheduler(unittest.TestCase):
    def test_failed_full_retries_after_interval_and_keeps_live_deadline(self):
        scheduler = watch.Scheduler(debounce=2, interval=15, now=0)
        scheduler.event(0)
        self.assertEqual(scheduler.due(2), "full")
        scheduler.failed("full", 2)
        self.assertIsNone(scheduler.due(2))
        self.assertEqual(scheduler.timeout(2), 13)
        self.assertEqual(scheduler.due(15), "live")
        scheduler.ran("live", 15)
        self.assertEqual(scheduler.timeout(16), 1)
        self.assertEqual(scheduler.due(17), "full")

    def test_failed_live_attempt_does_not_spin(self):
        scheduler = watch.Scheduler(interval=15, now=0)
        self.assertEqual(scheduler.due(15), "live")
        scheduler.failed("live", 15)
        self.assertIsNone(scheduler.due(15))
        self.assertEqual(scheduler.timeout(15), 15)
        self.assertEqual(scheduler.due(30), "live")

    def test_live_deadline_wins_when_full_retry_is_also_due(self):
        scheduler = watch.Scheduler(interval=15, now=0)
        scheduler.failed("full", 0)
        self.assertEqual(scheduler.due(15), "live")
        scheduler.ran("live", 15)
        self.assertEqual(scheduler.due(15), "full")
        scheduler.failed("full", 15)
        self.assertIsNone(scheduler.due(15))
        self.assertEqual(scheduler.timeout(15), 15)

    def test_successful_full_resets_retry_and_normal_debounce_resumes(self):
        scheduler = watch.Scheduler(debounce=2, interval=15, now=0)
        scheduler.event(0)
        scheduler.failed("full", 2)
        scheduler.ran("full", 17)
        self.assertIsNone(scheduler.due(18))
        self.assertEqual(scheduler.timeout(18), 14)
        scheduler.event(18)
        self.assertIsNone(scheduler.due(19))
        self.assertEqual(scheduler.due(20), "full")

    def test_event_stream_neither_postpones_retry_nor_starves_live_checks(self):
        scheduler = watch.Scheduler(debounce=2, interval=15, now=0)
        scheduler.event(1)
        scheduler.failed("full", 3)
        attempts = []
        for now in range(4, 42):
            scheduler.event(now)
            kind = scheduler.due(now)
            if kind:
                attempts.append((now, kind))
                if kind == "full":
                    scheduler.failed(kind, now)
                else:
                    scheduler.ran(kind, now)
        self.assertEqual(attempts, [(15, "live"), (18, "full"), (30, "live"), (33, "full")])


class TestWatchRecovery(unittest.TestCase):
    def run_mock_loop(self, codes):
        now = [0.0]
        attempts = []
        stop = []
        batches = [["usr/bin/changed"]]

        def check(_root, _db, kind):
            attempts.append((now[0], kind))
            result = codes[len(attempts) - 1]
            if len(attempts) == len(codes):
                stop[0](None, None)
            return result

        def relevant(timeout):
            if batches:
                now[0] += 1
                return batches.pop(0)
            now[0] += timeout
            return []

        with (
            patch.object(watch.os.path, "exists", return_value=True),
            patch.object(watch.signal, "signal", side_effect=lambda _sig, cb: stop.append(cb)),
            patch.object(watch, "TargetWatcher") as target,
            patch.object(watch, "_check", side_effect=check),
            patch.object(watch.time, "monotonic", side_effect=lambda: now[0]),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            active = target.return_value.__enter__.return_value
            active.count = 0
            active.relevant.side_effect = relevant
            self.assertEqual(watch.main("/fake", "/fake.db"), 0)
        return attempts

    def test_event_full_failure_retries_without_a_second_event(self):
        self.assertEqual(self.run_mock_loop([0, 2, 0, 0]),
                         [(0, "full"), (3, "full"), (15, "live"), (18, "full")])

    def test_completed_full_with_findings_does_not_schedule_retry(self):
        self.assertEqual(self.run_mock_loop([0, 11, 0]),
                         [(0, "full"), (3, "full"), (18, "live")])
