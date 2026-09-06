"""Offline self-test: generate corpus → train → evaluate → assert → emit alert.

Exits 0 on success. Runs entirely on the stdlib path so it always passes even
without scikit-learn. Target wall time is well under ~25s.
"""
import logging
import os
import tempfile

from .alert import AlertEmitter
from .collector import ingest
from .corpus import generate_corpus
from .metrics import evaluate, load_labels
from .model import StdlibBaseline, SKLEARN_AVAILABLE
from .features import FeatureBuilder

logger = logging.getLogger("siem.selftest")


def run_selftest(out_dir=None, seed=7):
    """Run the full offline self-test. Returns (metrics, alerts, summary)."""
    os.makedirs(out_dir, exist_ok=True)

    corpus = generate_corpus(out_dir=os.path.join(out_dir, "corpus"), seed=seed)
    train_events = ingest(os.path.join(out_dir, "corpus", "train_events.jsonl"))
    all_events = ingest(os.path.join(out_dir, "corpus", "events.jsonl"))
    labels = load_labels(os.path.join(out_dir, "corpus", "labels.csv"))

    fb = FeatureBuilder(window_sec=60)
    detector = StdlibBaseline()  # offline self-test always on stdlib path
    train_feat = fb.build_windows(train_events)
    detector.fit([f["vector"] for f in train_feat],
                 feature_names=fb.features)
    logger.info("self-test: fitted %s on %d windows", detector.detector_path,
                len(train_feat))

    from .scorer import score_features
    test_feat = fb.build_windows(all_events)
    score_features(detector, test_feat)

    pairs = []
    missing = 0
    for feat in test_feat:
        key = (feat["host"], feat["window_start"])
        if key in labels:
            pairs.append((feat["anomaly_score"], labels[key]))
        else:
            missing += 1

    threshold = 0.85
    metrics = evaluate([p[0] for p in pairs], [p[1] for p in pairs],
                       threshold=threshold)

    # Emit one sample alert JSONL (anomaly above threshold).
    emitter = AlertEmitter(jsonl_path=os.path.join(out_dir, "alerts.jsonl"),
                           console=False)
    alerts = []
    for feat in test_feat:
        if feat["anomaly_score"] >= threshold and labels.get(
                (feat["host"], feat["window_start"])) == 1:
            rec = emitter.emit({
                "ts": feat["window_start"],
                "host": feat["host"],
                "window_start": feat["window_start"],
                "anomaly_score": round(feat["anomaly_score"], 4),
                "threshold": threshold,
                "detector_path": detector.detector_path,
            })
            alerts.append(rec)
            break

    # Assertions
    failures = []
    if metrics["auc"] < 0.75:
        failures.append(f"AUC {metrics['auc']:.3f} < 0.75")
    if metrics["recall"] < 0.8:
        failures.append(f"recall {metrics['recall']:.3f} < 0.8")
    if not alerts:
        failures.append("no sample alert emitted")
    # Low FP on clean (normal) subset: no more than 5% of negatives flagged.
    if metrics["false_positives"] > 0.05 * metrics["negative_count"]:
        failures.append(
            f"FP {metrics['false_positives']} > 5% of {metrics['negative_count']} negatives")

    summary = {
        "corpus": corpus,
        "metrics": metrics,
        "n_alerts": len(alerts),
        "failures": failures,
    }
    if failures:
        raise AssertionError("selftest failures: " + "; ".join(failures))
    return summary, alerts, metrics


def selftest_main(workdir=None):
    """Self-test entry point used by the CLI. Returns exit code."""
    out_dir = workdir or tempfile.mkdtemp(prefix="siem_selftest_")
    summary, alerts, metrics = run_selftest(out_dir=out_dir)
    print("=== X6 ML-SIEM Offline Self-Test ===")
    print(f" corpus: {summary['corpus']['n_test_events']} test events, "
          f"{summary['corpus']['n_normal_windows']} normal windows, "
          f"{summary['corpus']['n_anomaly_windows']} anomaly windows")
    print(f" detector path: stdlib feature-statistics baseline"
          f"{'' if SKLEARN_AVAILABLE else ' (scikit-learn not installed)'}")
    print(f" AUC:            {metrics['auc']:.4f}")
    print(f" precision:      {metrics['precision']:.4f}")
    print(f" recall:         {metrics['recall']:.4f}")
    print(f" FP:             {metrics['false_positives']} / {metrics['negative_count']} negatives")
    print(f" alerts emitted: {summary['n_alerts']}")
    sample = os.path.join(out_dir, "alerts.jsonl")
    if os.path.exists(sample):
        with open(sample, "r", encoding="utf-8") as fh:
            for line in fh:
                print(" sample alert:", line.strip())
    if summary["failures"]:
        for f in summary["failures"]:
            print(" FAIL:", f)
        return 1
    print("SELF-TEST PASSED — exit 0")
    return 0
