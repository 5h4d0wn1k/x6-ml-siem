"""Scorer — map feature vectors to anomaly scores via a fitted detector."""


def score_features(detector, feature_list):
    """Score every feature dict, appending 'anomaly_score' in place.

    Returns the same list of feature dicts with scores attached and also a
    parallel list of raw scores.
    """
    scores = []
    for feat in feature_list:
        s = detector.score(feat.get("vector") or feat)
        feat["anomaly_score"] = s
        scores.append(s)
    return scores


def flagged(feature_list, threshold):
    """Return feature dicts whose anomaly score meets/exceeds the threshold."""
    return [f for f in feature_list if f.get("anomaly_score", 0.0) >= threshold]
