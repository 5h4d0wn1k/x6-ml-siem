"""Pipeline — collector → features → model → scorer → alert."""
import logging

from .alert import AlertEmitter
from .features import FeatureBuilder
from .model import make_detector
from .scorer import flagged

logger = logging.getLogger("siem.pipeline")


class Pipeline:
    """End-to-end ML SIEM pipeline facade."""

    def __init__(self, config=None):
        self.config = config or {}
        self.feature_builder = FeatureBuilder(
            window_sec=self.config.get("feature", {}).get("window_sec", 60),
            features=self.config.get("feature", {}).get("features", []),
        )
        self.detector = None
        self.threshold = self.config.get("scoring", {}).get("threshold", 0.85)

    def train(self, events, force_stdlib=None):
        """Fit the detector on a baseline of normal feature windows."""
        features = self.feature_builder.build_windows(events)
        cfg = self.config.get("detector", {})
        force = force_stdlib if force_stdlib is not None else cfg.get("force_stdlib", False)
        self.detector = make_detector(self.config, force_stdlib=force)
        self.detector.fit(
            [f["vector"] for f in features],
            feature_names=self.feature_builder.features,
            config=self.config.get("detector", {}),
        )
        logger.info("model trained on %d feature windows via %s",
                    len(features), self.detector.detector_path)
        return features

    def score(self, events):
        """Return feature windows with anomaly_score computed."""
        features = self.feature_builder.build_windows(events)
        if self.detector is None:
            raise RuntimeError("model not trained/loaded; run train or provide --model")
        from .scorer import score_features
        score_features(self.detector, features)
        return features

    def alert(self, feature_list, emitter=None, threshold=None):
        """Emit alerts for flagged windows. Returns list of alert records."""
        threshold = threshold if threshold is not None else self.threshold
        emitter = emitter or AlertEmitter(
            jsonl_path=self.config.get("alert", {}).get("jsonl", "alerts/alerts.jsonl"),
            console=self.config.get("alert", {}).get("console", True),
            webhook_url=self.config.get("alert", {}).get("webhook_url", ""),
        )
        records = []
        for feat in flagged(feature_list, threshold):
            record = {
                "ts": feat["window_start"],
                "host": feat["host"],
                "window_start": feat["window_start"],
                "anomaly_score": round(feat.get("anomaly_score", 0.0), 4),
                "threshold": threshold,
                "detector_path": self.detector.detector_path if self.detector else "n/a",
                "features": {k: round(float(v), 4) for k, v in feat.items()
                             if k in self.feature_builder.features},
            }
            emitter.emit(record)
            records.append(record)
        return records
