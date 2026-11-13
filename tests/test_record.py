import os
import tempfile
import unittest

from sentinel.model import Finding, Severity
from sentinel.store import Store
from tools import record_dash


class TestRecordDash(unittest.TestCase):
    def test_frames_markers_and_commands(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "s.db")
            st = Store(db)
            st.record_run([], 0, ["integrity"])
            st.close()
            flag = os.path.join(d, "ran")
            cast = record_dash.record(db, duration=1.0, interval=0.2,
                                      schedule=[(0.3, "F1 injiziert", f"touch {flag}")], width=80)
            self.assertTrue(os.path.exists(flag))                    # Befehl wurde zur Zeit ausgefuehrt
        self.assertEqual(cast["format"], "sentinel-dash/1")
        self.assertEqual([m["label"] for m in cast["markers"]], ["F1 injiziert"])
        self.assertGreaterEqual(len(cast["frames"]), 1)
        f0 = cast["frames"][0]
        self.assertIn("integrity", "\n".join(t for t, _ in f0["lines"]))
        self.assertTrue(all(len(t) <= 80 for fr in cast["frames"] for t, _ in fr["lines"]))
        ts = [fr["t"] for fr in cast["frames"]]
        self.assertEqual(ts, sorted(ts))

    def test_identical_frames_are_not_repeated(self):
        frames = []
        record_dash._push(frames, 0.0, [("a", "ok")])
        record_dash._push(frames, 0.5, [("a", "ok")])
        record_dash._push(frames, 1.0, [("b", "crit")])
        self.assertEqual([f["t"] for f in frames], [0.0, 1.0])

    def test_parse_at(self):
        self.assertEqual(record_dash.parse_at("6|F1 injiziert|sentinel-fault inject F1"),
                         (6.0, "F1 injiziert", "sentinel-fault inject F1"))
        self.assertEqual(record_dash.parse_at("4|Alles gruen"), (4.0, "Alles gruen", None))


if __name__ == "__main__":
    unittest.main()
