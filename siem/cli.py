#!/usr/bin/env python3
"""x6-ml-siem CLI — production ML SIEM (blue team, own-lab telemetry only).

Subcommands:
  ingest      feed JSONL (file or '-') through the scoring pipeline
  train       fit a baseline model and persist it as JSON
  run         live scoring on an ingested stream using a model
  evaluate    AUC/precision/recall on a labeled lab corpus
  alert       replay a scored stream and emit alerts
  corpus      generate a synthetic labeled lab corpus
  selftest    run the offline self-test
"""
import argparse
import json
import logging
import os
import sys

from .alert import AlertEmitter
from .collector import ingest, iterate_events
from .config import load_config, validate_config
from .corpus import generate_corpus
from .features import FeatureBuilder
from .logging_setup import setup_logging
from .metrics import evaluate, load_labels
from .model import make_detector, BaseDetector
from .scorer import flagged
from .selftest import selftest_main

LOGGER = logging.getLogger("siem.cli")


def _load_cfg(args):
    cfg = load_config()
    if args.config:
        cfg = load_config(args.config)
    return validate_config(cfg)


def _feature_builder(cfg):
    return FeatureBuilder(
        window_sec=cfg.get("feature", {}).get("window_sec", 60),
        features=cfg.get("feature", {}).get("features", []),
    )


def cmd_ingest(args):
    cfg = _load_cfg(args)
    events = ingest(args.file)
    print(f"Ingested {len(events)} events from {args.file}")
    fb = _feature_builder(cfg)
    features = fb.build_windows(events)
    print(f"Built {len(features)} feature windows")
    for feat in features[:10]:
        print(json.dumps({
            "host": feat["host"], "window_start": feat["window_start"],
            "vector": feat["vector"],
        }))
    return 0


def cmd_corpus(args):
    desc = generate_corpus(out_dir=args.out, seed=args.seed)
    print(json.dumps(desc, indent=2))
    return 0


def cmd_train(args):
    cfg = _load_cfg(args)
    events = []
    for root, _dirs, files in os.walk(args.data):
        for fn in sorted(files):
            if fn.endswith(".jsonl"):
                events.extend(ingest(os.path.join(root, fn)))
    # Optional: take a train-split events file if present.
    train_file = os.path.join(args.data, "train_events.jsonl")
    if os.path.exists(train_file):
        events = ingest(train_file)

    if not events:
        print("error: no events found under --data", file=sys.stderr)
        return 2

    fb = _feature_builder(cfg)
    features = fb.build_windows(events)
    if len(features) < 2:
        print("error: too few feature windows to train", file=sys.stderr)
        return 2

    force_stdlib = args.force_stdlib or cfg.get("detector", {}).get("force_stdlib", False)
    detector = make_detector(cfg, force_stdlib=force_stdlib)
    detector.fit([f["vector"] for f in features], feature_names=fb.features,
                 config=cfg.get("detector", {}))
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    detector.save(args.out)
    print(f"Trained {detector.detector_path} detector on {len(features)} windows")
    print(f"Saved model -> {args.out}")
    print(f"Detector path in use: {detector.detector_path}")
    return 0


def cmd_run(args):
    cfg = _load_cfg(args)
    detector = BaseDetector.load(args.model)
    fb = _feature_builder(cfg)
    if not detector.is_fitted():
        print("error: model not fitted", file=sys.stderr)
        return 2
    events = list(iterate_events(args.file))
    features = fb.build_windows(events)
    from .scorer import score_features as _sf
    _sf(detector, features)
    for feat in features:
        print(json.dumps({
            "host": feat["host"],
            "window_start": feat["window_start"],
            "anomaly_score": round(feat.get("anomaly_score", 0.0), 4),
        }))
    LOGGER.info("run scored %d windows on stream %s", len(features), args.file)
    return 0


def cmd_evaluate(args):
    cfg = _load_cfg(args)
    labels = load_labels(args.labels)
    detector = BaseDetector.load(args.model)
    fb = _feature_builder(cfg)
    events = ingest(args.data if os.path.isfile(args.data) else
                    os.path.join(args.data, "events.jsonl"))
    features = fb.build_windows(events)
    from .scorer import score_features as _sf
    _sf(detector, features)

    pairs = []
    for feat in features:
        key = (feat["host"], feat["window_start"])
        if key in labels:
            pairs.append((feat["anomaly_score"], labels[key]))
    if not pairs:
        print("error: no label matches for feature windows", file=sys.stderr)
        return 2
    th = args.threshold if args.threshold is not None else cfg["scoring"]["threshold"]
    metrics = evaluate([p[0] for p in pairs], [p[1] for p in pairs], threshold=th)
    print(json.dumps({**metrics, "n_scored": len(pairs),
                      "detector_path": detector.detector_path,
                      "threshold": th}, indent=2))
    return 0


def cmd_alert(args):
    cfg = _load_cfg(args)
    detector = BaseDetector.load(args.model)
    fb = _feature_builder(cfg)
    events = ingest(args.file)
    features = fb.build_windows(events)
    from .scorer import score_features as _sf
    _sf(detector, features)
    threshold = args.threshold if args.threshold is not None else cfg["scoring"]["threshold"]
    emitter = AlertEmitter(
        jsonl_path=cfg.get("alert", {}).get("jsonl", "alerts/alerts.jsonl"),
        console=cfg.get("alert", {}).get("console", True),
        webhook_url=cfg.get("alert", {}).get("webhook_url", ""),
    )
    n = 0
    for feat in flagged(features, threshold):
        emitter.emit({
            "ts": feat["window_start"],
            "host": feat["host"],
            "window_start": feat["window_start"],
            "anomaly_score": round(feat.get("anomaly_score", 0.0), 4),
            "threshold": threshold,
            "detector_path": detector.detector_path,
        })
        n += 1
    print(f"Emitted {n} alerts (threshold {threshold})")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="siem",
        description="Production-grade ML SIEM (blue team, own-lab telemetry only).",
    )
    p.add_argument("--config", default=None, help="path to config yaml")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("ingest", help="feed JSONL (file or '-') through the pipeline")
    sp.add_argument("file", help="path to flow/event JSONL, or '-' for stdin")
    sp.set_defaults(func=cmd_ingest)

    sp = sub.add_parser("corpus", help="generate synthetic labeled lab corpus")
    sp.add_argument("--out", default="data/corpus")
    sp.add_argument("--seed", type=int, default=7)
    sp.set_defaults(func=cmd_corpus)

    sp = sub.add_parser("train", help="fit baseline and persist model.json")
    sp.add_argument("--data", required=True, help="dir with flow/event JSONL")
    sp.add_argument("--out", required=True, help="output model.json path")
    sp.add_argument("--force-stdlib", action="store_true",
                    help="force the stdlib baseline even if sklearn is present")
    sp.set_defaults(func=cmd_train)

    sp = sub.add_parser("run", help="live scoring on an ingested stream")
    sp.add_argument("--model", required=True, help="model.json path")
    sp.add_argument("file", help="path to flow/event JSONL, or '-' for stdin")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("evaluate", help="AUC/precision/recall on labeled corpus")
    sp.add_argument("--data", required=True, help="dir with events.jsonl")
    sp.add_argument("--model", required=True, help="model.json path")
    sp.add_argument("--labels", required=True, help="labels.csv path")
    sp.add_argument("--threshold", type=float, default=None)
    sp.set_defaults(func=cmd_evaluate)

    sp = sub.add_parser("alert", help="replay scored stream and emit alerts")
    sp.add_argument("--model", required=True, help="model.json path")
    sp.add_argument("--threshold", type=float, default=None)
    sp.add_argument("file", help="path to JSONL, or '-' for stdin")
    sp.set_defaults(func=cmd_alert)

    sp = sub.add_parser("selftest", help="run the offline self-test (exit 0)")
    sp.add_argument("--out", default=None, help="work directory (default temp)")
    sp.set_defaults(func=lambda a: sys.exit(selftest_main(a.out)))
    return p


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)

    # Configure logging early (best-effort, before subcommand work).
    try:
        cfg0 = load_config()
        setup_logging(level=cfg0.get("logging", {}).get("level", "INFO"),
                      log_file=cfg0.get("logging", {}).get("file", "logs/siem.log"))
    except Exception:
        setup_logging(level="INFO", log_file=None)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
