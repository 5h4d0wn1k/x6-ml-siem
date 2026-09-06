"""Tests for alert threshold behavior and the alert emitter."""
import json
import os
import tempfile
import unittest

from siem.alert import AlertEmitter
from siem.scorer import flagged
from siem.pipeline import Pipeline


class TestAlertThreshold(unittest.TestCase):
    def test_flagged_threshold(self):
        feats = [
            {"anomaly_score": 0.95, "host": "a"},
            {"anomaly_score": 0.5, "host": "b"},
            {"anomaly_score": 0.87, "host": "c"},
        ]
        out = flagged(feats, threshold=0.8)
        self.assertEqual([f["host"] for f in out], ["a", "c"])

    def test_emitter_writes_jsonl(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "alerts.jsonl")
            em = AlertEmitter(jsonl_path=path, console=False)
            em.emit({"host": "lab-a", "anomaly_score": 0.99, "threshold": 0.8,
                     "window_start": "2026-09-04T14:00:00+00:00"})
            with open(path) as fh:
                rec = json.loads(fh.readline())
            self.assertEqual(rec["host"], "lab-a")
            self.assertEqual(rec["anomaly_score"], 0.99)

    def test_pipeline_alert_records(self):
        cfg = {
            "feature": {"window_sec": 60, "features": ["packet_count", "byte_count"]},
            "scoring": {"threshold": 0.8},
            "detector": {},
            "alert": {"console": False, "jsonl": None},
        }
        pipe = Pipeline(cfg)
        events = [
            {"ts": "2026-09-04T14:00:%02dZ" % i, "host": "lab-a",
             "src": "192.0.2.10", "dst": "192.0.2.1:80",
             "packets": (100 if i == 5 else 5), "bytes": 1000,
             "duration": 0.1, "session": f"s{i}"}
            for i in range(8)
        ]
        pipe.train(events, force_stdlib=True)
        feats = pipe.score(events)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "alerts.jsonl")
            em = AlertEmitter(jsonl_path=path, console=False)
            recs = pipe.alert(feats, emitter=em, threshold=0.8)
            self.assertIsInstance(recs, list)
            for r in recs:
                self.assertIn("anomaly_score", r)


if __name__ == "__main__":
    unittest.main()
