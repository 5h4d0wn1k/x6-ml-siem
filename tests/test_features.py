"""Tests for the feature builder correctness on tiny fixtures."""
import unittest

from siem.features import FeatureBuilder, iso_to_epoch, parse_port


def ev(ts, host, packets, bytes_, dst, duration):
    return {
        "ts": ts, "host": host, "src": "192.0.2.10",
        "dst": dst, "proto": "tcp", "packets": packets,
        "bytes": bytes_, "duration": duration,
        "session": f"192.0.2.10->{dst}",
    }


class TestFeatureBuilder(unittest.TestCase):
    def test_iso_to_epoch_basic(self):
        self.assertAlmostEqual(iso_to_epoch("2026-09-04T14:00:00Z"),
                               1788530400.0, places=0)

    def test_parse_port(self):
        self.assertEqual(parse_port("192.0.2.55:443"), 443)
        self.assertIsNone(parse_port("192.0.2.55"))

    def test_count_features(self):
        events = [
            ev("2026-09-04T14:00:00Z", "lab-a", 10, 5120, "192.0.2.1:443", 0.5),
            ev("2026-09-04T14:00:01Z", "lab-a", 20, 2048, "192.0.2.2:53", 0.3),
            ev("2026-09-04T14:00:02Z", "lab-b", 1, 100, "192.0.2.3:80", 0.1),
        ]
        fb = FeatureBuilder(window_sec=60)
        feats = fb.build_windows(events)
        self.assertEqual(len(feats), 2)  # two hosts
        by_host = {f["host"]: f for f in feats}
        a = by_host["lab-a"]
        self.assertEqual(a["packet_count"], 30)
        self.assertEqual(a["byte_count"], 5120 + 2048)
        self.assertEqual(a["ports_breadth"], 2)  # 443 and 53
        self.assertEqual(a["session_count"], 2)
        self.assertEqual(a["duration_total"], 0.8)
        self.assertAlmostEqual(a["avg_pkt_size"], (5120 + 2048) / 30)
        # feature_names aligned with vector
        self.assertEqual(len(a["vector"]), len(a["feature_names"]))

    def test_timing_regularity_beacon(self):
        # Perfectly periodic events -> regularity close to 1.0
        events = [
            ev(f"2026-09-04T14:00:{i:02d}Z", "lab-x", 3, 100, "192.0.2.1:443", 0.1)
            for i in range(0, 30, 5)  # every 5 seconds
        ]
        fb = FeatureBuilder(window_sec=60)
        feats = fb.build_windows(events)
        self.assertGreater(feats[0]["timing_regularity"], 0.9)

    def test_scan_burst_breadth(self):
        events = [
            ev("2026-09-04T14:00:00.00Z", "lab-s", 1, 48,
               f"192.0.2.1:{port}", 0.01)
            for port in range(1, 60)
        ]
        fb = FeatureBuilder(window_sec=60)
        feats = fb.build_windows(events)
        self.assertGreater(feats[0]["ports_breadth"], 50)


if __name__ == "__main__":
    unittest.main()
