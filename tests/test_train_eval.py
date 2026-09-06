"""Tests: train/evaluate run on a small corpus, detector behavior."""
import unittest

from siem.model import StdlibBaseline, make_detector, SKLEARN_AVAILABLE
from siem.features import FeatureBuilder


def _feat_grid(name, vals):
    return [{"host": "lab-a", "window_start": f"2026-09-04T14:{v:02d}:00Z",
             "feature_names": ["x", "y"], "vector": [v, v]} for v in vals]


class TestStyleDetector(unittest.TestCase):
    def setUp(self):
        self.fb = FeatureBuilder(window_sec=60)
        self.det = StdlibBaseline(["x", "y", "z"])

    def test_fit_and_score_baseline(self):
        # build a tight normal cluster around 10, plus far anomaly at 100
        normal = [[10, 11, 9], [9, 10, 11], [11, 9, 10], [10, 10, 10]]
        self.det.fit(normal)
        self.assertTrue(self.det.is_fitted())
        normal_score = self.det.score([10, 10, 10])
        anomaly_score = self.det.score([100, 100, 100])
        self.assertLess(normal_score, anomaly_score)
        self.assertGreater(anomaly_score, 0.9)
        self.assertLess(normal_score, 0.5)

    def test_score_dict_input(self):
        self.det.fit([[1, 2, 3], [2, 3, 4], [3, 4, 5]])
        s = self.det.score({"x": 2, "y": 3, "z": 4})
        self.assertGreaterEqual(s, 0.0)

    def test_persistence_roundtrip(self):
        import tempfile, os
        normal = [[10, 11, 9], [9, 10, 11], [11, 9, 10], [10, 10, 10]]
        self.det.fit(normal)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "model.json")
            self.det.save(p)
            loaded = StdlibBaseline.load(p)
            self.assertTrue(loaded.is_fitted())
            self.assertEqual(loaded.detector_path, "stdlib")
            self.assertAlmostEqual(loaded.score([10, 10, 10]),
                                   self.det.score([10, 10, 10]))


class TestDetectorSelection(unittest.TestCase):
    def test_make_detector_stdlib_when_forced(self):
        det = make_detector({}, force_stdlib=True)
        self.assertEqual(det.detector_path, "stdlib")

    def test_sklearn_available_flag(self):
        # environment may or may not have sklearn; model must always import
        self.assertIn(SKLEARN_AVAILABLE, (True, False))


if __name__ == "__main__":
    unittest.main()
