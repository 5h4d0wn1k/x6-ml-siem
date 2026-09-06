"""Tests for label encoding and metrics (AUC/precision/recall)."""
import os
import tempfile
import unittest

from siem.metrics import evaluate, load_labels


class TestMetrics(unittest.TestCase):
    def test_auc_separated(self):
        # clear separation: positives high, negatives low
        scores = [0.9, 0.85, 0.95, 0.2, 0.1, 0.15]
        labels = [1, 1, 1, 0, 0, 0]
        m = evaluate(scores, labels, threshold=0.8)
        self.assertAlmostEqual(m["auc"], 1.0, places=2)
        self.assertEqual(m["true_positives"], 3)
        self.assertEqual(m["false_positives"], 0)

    def test_precision_recall(self):
        scores = [0.95, 0.9, 0.6, 0.3, 0.2, 0.1]
        labels = [1, 1, 1, 0, 0, 1]  # 4 positives, 2 negatives
        m = evaluate(scores, labels, threshold=0.8)
        # TP=2 (0.95,0.9), FP=0, FN=2 (0.6,0.1 -> 0.6 and 0.1 are pos <0.8)
        self.assertEqual(m["true_positives"], 2)
        self.assertEqual(m["false_positives"], 0)
        self.assertEqual(m["false_negatives"], 2)
        self.assertAlmostEqual(m["precision"], 1.0)
        self.assertAlmostEqual(m["recall"], 0.5)

    def test_load_labels(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "labels.csv")
            with open(p, "w") as fh:
                fh.write("host,window_start,label\n")
                fh.write("lab-a,2026-09-04T14:00:00+00:00,1\n")
                fh.write("lab-b,2026-09-04T14:00:00+00:00,0\n")
            table = load_labels(p)
            self.assertEqual(table[("lab-a", "2026-09-04T14:00:00Z")], 1)
            self.assertEqual(table[("lab-b", "2026-09-04T14:00:00Z")], 0)


if __name__ == "__main__":
    unittest.main()
