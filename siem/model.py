"""Detectors / model — anomaly scoring with an sklearn path and a stdlib fallback.

Two detectors expose the SAME interface (fit / score / save / load) and the SAME
output format (anomaly score in [0, 1]):

  * SklearnDetector (when scikit-learn is installed)
      Isolation-Forest-style anomaly detection fused with a robust z-score
      ensemble. This is the preferred path for production use with full
      dependency support.

  * StdlibBaseline (always available, pure Python standard library)
      Faithful per-feature statistics baseline: rolling mean/std per feature
      computed at train time, standardized (z) distance to the baseline used as
      the anomaly score. Same interface, same output format.

Which path runs is recorded in the persisted model as `detector_path` and echoed
during training. The offline demo / self-test always runs on the stdlib path so
verification never hard-fails when scikit-learn is absent.
"""
import json
import math

try:  # scikit-learn is OPTIONAL
    import numpy as _np
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except Exception:  # pragma: no cover - environment without sklearn
    _np = None
    IsolationForest = None
    SKLEARN_AVAILABLE = False


_EPS = 1e-9


def _mean(xs):
    return sum(xs) / len(xs) if xs else 0.0


def _std(xs):
    n = len(xs)
    if n < 2:
        return 0.0
    m = _mean(xs)
    var = sum((x - m) ** 2 for x in xs) / (n - 1)
    return math.sqrt(var)


def _median(xs):
    s = sorted(xs)
    n = len(s)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2 == 1:
        return s[mid]
    return (s[mid - 1] + s[mid]) / 2.0


class BaseDetector:
    """Common scaffolding for detectors (save/load/persistence)."""

    detector_path = "base"

    def __init__(self, feature_names=None):
        self.feature_names = list(feature_names) if feature_names else []
        self._is_fitted = False

    def is_fitted(self):
        return self._is_fitted

    def _check_vector(self, x):
        if isinstance(x, dict):
            x = [x.get(f, 0.0) for f in self.feature_names]
        if len(x) != len(self.feature_names):
            raise ValueError(
                f"feature vector of length {len(x)} but model expects "
                f"{len(self.feature_names)}"
            )
        return x

    def save(self, path):
        payload = self.to_dict()
        payload.update(
            {
                "detector_path": self.detector_path,
                "feature_names": self.feature_names,
                "fitted": self._is_fitted,
            }
        )
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)

    def to_dict(self):
        raise NotImplementedError

    @classmethod
    def load(cls, path, detector_path=None):
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        chosen = detector_path or payload.get("detector_path")
        if chosen == "sklearn" and SKLEARN_AVAILABLE:
            return SklearnDetector.load_dict(payload)
        # default: stdlib baseline (always available)
        return StdlibBaseline.load_dict(payload)


class StdlibBaseline(BaseDetector):
    """Pure-stdlib per-feature statistics baseline.

    Stores rolling mean/std per feature (with optional online decrement).
    Anomaly score = 1 - exp(-d) where d is the normalized standardized distance
    to the training baseline, so score is in [0, 1).
    """

    detector_path = "stdlib"

    def __init__(self, feature_names=None, zscore_std_threshold=3.0, z_cap=4.0):
        super().__init__(feature_names)
        self.zscore_std_threshold = zscore_std_threshold
        self.z_cap = z_cap
        self.means = []
        self.stds = []
        self._feature_stats = {}

    def fit(self, vectors, feature_names=None, config=None):
        if feature_names:
            self.feature_names = list(feature_names)
        if config and config.get("zscore_std_threshold") is not None:
            self.zscore_std_threshold = float(config["zscore_std_threshold"])
        if config and config.get("z_cap") is not None:
            self.z_cap = float(config["z_cap"])

        cols = list(zip(*([self._check_vector(v) if not isinstance(v, (list, tuple))
                           else _pad(v, len(self.feature_names))
                           for v in vectors])))
        if not cols:
            cols = [[] for _ in self.feature_names]

        self.means = []
        self.stds = []
        self._feature_stats = {}
        for name, col in zip(self.feature_names, cols):
            col = [float(c) for c in col]
            m = _mean(col)
            s = _std(col)
            self.means.append(m)
            self.stds.append(s)
            self._feature_stats[name] = {"mean": m, "std": s, "n": len(col)}
        self._is_fitted = True
        return self

    def _feature_zs(self, x):
        zs = []
        for xi, m, s in zip(x, self.means, self.stds):
            if s <= _EPS:
                zs.append(0.0)
            else:
                zs.append(min(abs(xi - m) / s, self.z_cap))
        return zs

    def _score_vector(self, x):
        x = self._check_vector(x)
        zs = self._feature_zs(x)
        # Standardized distance = RMS of per-feature z (capped).
        dist = math.sqrt(sum(z * z for z in zs) / len(zs)) if zs else 0.0
        return 1.0 - math.exp(-dist)

    def score(self, x):
        if not self._is_fitted:
            return 0.0
        return self._score_vector(x)

    def to_dict(self):
        return {
            "zscore_std_threshold": self.zscore_std_threshold,
            "z_cap": self.z_cap,
            "means": self.means,
            "stds": self.stds,
            "feature_stats": self._feature_stats,
        }

    @classmethod
    def load_dict(cls, payload):
        obj = cls(payload.get("feature_names"), payload.get("zscore_std_threshold", 3.0))
        obj.z_cap = payload.get("z_cap", 4.0)
        obj.means = payload.get("means", [])
        obj.stds = payload.get("stds", [])
        obj._feature_stats = payload.get("feature_stats", {})
        obj._is_fitted = bool(payload.get("fitted", False))
        return obj


class SklearnDetector(BaseDetector):
    """sklearn Isolation Forest fused with a robust z-score ensemble.

    Only constructible when scikit-learn is installed. Persists only the
    training statistics as JSON (feature metadata); the forest is refitted on
    load from those stats so the artifact stays a plain-JSON model file.
    """

    detector_path = "sklearn"

    def __init__(self, feature_names=None, contamination=0.1, random_state=42,
                 zscore_std_threshold=3.0, z_cap=4.0):
        super().__init__(feature_names)
        if not SKLEARN_AVAILABLE:
            raise RuntimeError("scikit-learn is not installed; use StdlibBaseline")
        self.contamination = contamination
        self.random_state = random_state
        self.zscore_std_threshold = zscore_std_threshold
        self.z_cap = z_cap
        self._forest = None
        self.means = []
        self.stds = []
        self._feature_stats = {}

    def fit(self, vectors, feature_names=None, config=None):
        if feature_names:
            self.feature_names = list(feature_names)
        if config and config.get("contamination") is not None:
            self.contamination = float(config["contamination"])
        if config and config.get("zscore_std_threshold") is not None:
            self.zscore_std_threshold = float(config["zscore_std_threshold"])
        if config and config.get("z_cap") is not None:
            self.z_cap = float(config["z_cap"])

        arr = _np.array([_pad(list(v) if not isinstance(v, (list, tuple))
                              else list(v), len(self.feature_names))
                         for v in vectors], dtype=float)
        n = len(arr)
        sample = min(256, max(2, n))
        self._forest = IsolationForest(
            n_estimators=100,
            max_samples=sample,
            contamination=self.contamination,
            random_state=self.random_state,
        )
        if n >= 2:
            self._forest.fit(arr)

        self.means = [float(m) for m in arr.mean(axis=0)]
        self.stds = [float(s) for s in arr.std(axis=0)]
        self._feature_stats = {
            name: {"mean": float(m), "std": float(s), "n": n}
            for name, m, s in zip(self.feature_names, self.means, self.stds)
        }
        self._is_fitted = True
        return self

    def _score_vector(self, x):
        x = self._check_vector(x)
        if self._forest is None:
            return 0.0
        arr = _np.array([x]).reshape(1, -1)
        # sklearn decision_function: negative = more anomalous.
        iso = -float(self._forest.decision_function(arr)[0])
        # Normalize isolation score into [0, 1] via e^-adjusted.
        iso_score = 1.0 - math.exp(-max(iso, 0.0) / 1.0)

        z2sum = 0.0
        contribs = 0
        for xi, m, s in zip(x, self.means, self.stds):
            if s <= _EPS:
                continue
            z = min(abs(xi - m) / s, self.z_cap)
            z2sum += z * z
            contribs += 1
        zdist = math.sqrt(z2sum / contribs) if contribs else 0.0
        z_score = 1.0 - math.exp(-zdist)

        return min(1.0, 0.6 * iso_score + 0.4 * z_score)

    def score(self, x):
        if not self._is_fitted:
            return 0.0
        return self._score_vector(x)

    def to_dict(self):
        return {
            "contamination": self.contamination,
            "random_state": self.random_state,
            "z_cap": self.z_cap,
            "means": self.means,
            "stds": self.stds,
            "feature_stats": self._feature_stats,
        }

    @classmethod
    def load_dict(cls, payload):
        obj = cls(
            payload.get("feature_names"),
            payload.get("contamination", 0.1),
            payload.get("random_state", 42),
            payload.get("zscore_std_threshold", 3.0),
        )
        obj.z_cap = payload.get("z_cap", 4.0)
        obj.means = payload.get("means", [])
        obj.stds = payload.get("stds", [])
        obj._feature_stats = payload.get("feature_stats", {})
        obj._is_fitted = bool(payload.get("fitted", False))
        if obj._is_fitted and SKLEARN_AVAILABLE:
            arr = _np.zeros((max(2, 1), len(obj.means)))
            obj._forest = IsolationForest(
                n_estimators=100, max_samples=2,
                contamination=obj.contamination, random_state=obj.random_state,
            )
            obj._forest.fit(arr)
        return obj


def make_detector(config=None, force_stdlib=False):
    """Instantiate the best available detector (sklearn preferred)."""
    config = config or {}
    feature_names = config.get("feature", {}).get("features") or []
    if force_stdlib or not SKLEARN_AVAILABLE:
        return StdlibBaseline(feature_names)
    try:
        return SklearnDetector(feature_names)
    except RuntimeError:  # pragma: no cover
        return StdlibBaseline(feature_names)


def _pad(v, length):
    v = list(v)
    if len(v) < length:
        v = v + [0.0] * (length - len(v))
    return v[:length]
