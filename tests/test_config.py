"""Tests for config loading and validation."""
import json
import os
import tempfile
import unittest

from siem.config import load_config, validate_config, DEFAULTS


class TestConfig(unittest.TestCase):
    def test_defaults_valid(self):
        cfg = load_config(env_path="__nonexistent__")
        validate_config(cfg)  # should not raise

    def test_validate_missing_section(self):
        bad = dict(DEFAULTS)
        del bad["scoring"]
        with self.assertRaises(ValueError):
            validate_config(bad)

    def test_validate_threshold_range(self):
        cfg = dict(DEFAULTS)
        cfg["scoring"]["threshold"] = 1.5
        with self.assertRaises(ValueError):
            validate_config(cfg)

    def test_yaml_load_real(self):
        # Real config ships with the repo
        p = os.path.join(os.path.dirname(__file__), "..", "config", "siem.yaml")
        if os.path.exists(p):
            cfg = load_config(path=p)
            validate_config(cfg)
            self.assertEqual(cfg["feature"]["window_sec"], 60)
            self.assertIn("home_lab_note", cfg)


if __name__ == "__main__":
    unittest.main()
