# X6 — ML SIEM (Flow Baseline + Anomaly Scoring + Alert Feed)

Production-grade blue-team ML SIEM. Trains **only on your own lab telemetry**, builds
numeric features from flow/event JSONL, fits a baseline model, scores windows for
anomaly, and emits alerts. scikit-learn is *optional*: when absent, a faithful pure-stdlib
feature-statistics baseline runs automatically so verification never hard-fails.

```
collector → feature builder → model (baseline train / periodic update)
         → scorer (anomaly score) → alert emitter (JSONL + console + optional webhook)
```

## IMPORTANT: Read before use.

This tool is provided for **educational and authorized security testing purposes only**,
for use as a blue-team detection capability on **your own systems and lab telemetry**.

### Authorization Requirements
- You MUST have explicit written permission before monitoring/deploying on any system.
- Ingesting or training on logs without authorization may violate privacy and computer-access laws.
- Use ONLY on systems you own or are explicitly authorized to monitor.
- Models are trained **only** on your own telemetry — never on third-party data.
- Log/alert data must be handled per your organization's retention policies.

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: unauthorized access is a federal crime.
- **ECPA/Wiretap Act**: intercepting/accessing communications may require authorization.
- **GDPR/CCPA**: logs may contain personal data subject to data-protection regulation.
- **State laws**: many states add computer-crime and privacy statutes.

### Acceptable Use
- Monitoring your own infrastructure; authorized SOC deployments; academic research in a
  controlled lab; security education/training demos.

### Prohibited Use
- Deploying on systems without authorization/notice; targeting individuals without legal
  basis; any activity that violates applicable law; commercial use without license.

### No Warranty
Provided "AS IS" without warranty of any kind. The author is not responsible for misuse.

### Responsible Disclosure
1. Report detected issues privately to the affected owner. 2. Allow time to remediate.
3. Do not exploit beyond proof of concept. 4. Follow your incident-response procedures.

## Home-lab note

All examples and the synthetic corpus use RFC 5737 documentation ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) as placeholders. Train on your own
lab flows; verify alerts with your own injected anomalies.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .          # core = pure stdlib; no required deps
pip install scikit-learn  # optional: enables the isolation-forest detector path
```

Run without installing: `python -m siem.cli <cmd>` or generate a corpus and use it.

## Usage

```bash
# 1. Generate a reproducible synthetic lab corpus (normal + anomalies + labels)
siem corpus --out data/corpus --seed 7

# 2. Fit the baseline model on your own normal flows (JSONL dir)
siem train --data data/corpus --out model.json

# 3. Ingest JSONL (file or stdin '-') and build feature windows
siem ingest flows.jsonl

# 4. Live scoring on an ingested stream
siem run --model model.json flows.jsonl

# 5. Evaluate AUC / precision / recall on a labeled lab corpus
siem evaluate --data data/corpus --model model.json \
      --labels data/corpus/labels.csv

# 6. Replay a scored stream and emit alerts
siem alert --threshold 0.85 --model model.json flows.jsonl

# 7. Offline self-test (must exit 0, targets <25s)
siem selftest
```

Flow/event JSONL input format (one object per line, fields used by the feature builder):

```json
{"ts":"2026-09-06T14:00:00Z","host":"lab-web-01","src":"192.0.2.10",
 "dst":"192.0.2.55:443","proto":"tcp","packets":8,"bytes":2048,
 "duration":0.42,"session":"192.0.2.10->192.0.2.55:443"}
```

### Configuration

`config/siem.yaml` controls feature window size and selection, scoring threshold,
periodic-update cadence, alert output (console/JSONL/webhook) and logging. Override with
`--config path.yaml` or `SIEM_CONFIG`.

## Metrics

Recorded on the synthetic held-out corpus (reproducible with `siem selftest`, seed 7;
trained on 60% of normal windows, evaluated on the remaining 40% + injected anomalies):

| metric | held-out value |
|---|---|
| AUC | 0.9983 |
| Precision | 0.7500 |
| Recall | 1.0000 |
| False positives | 1 / 192 negatives |

- **AUC/precision on held-out**: computed by `siem evaluate` with a rank-based (Mann-Whitney)
  AUC, no ML dependency; precise numbers are printed per run and stored in `METRICS.md`.
- **Alert latency**: end-to-end time from event ingest through window close → feature build →
  scoring → alert record. Windowed scoring means a window is scored once it closes (default 60s);
  per-run latency is reported in the structured log (`logs/siem.log`).
- **Drift handling**: `scoring.update_cadence_sec` drives periodic retraining on a rolling
  baseline; the stdlib detector stores rolling mean/std per feature so the baseline follows
  slow drift while still flagging sharp deviations. Evaluate drift by retraining on newer
  normal windows and re-running `siem evaluate`.

## Live Lab Test Plan

1. **Train on own flows**: export your own lab flows (Zeek `conn.log` → normalize to the JSONL
   schema, or emit your own collector's JSONL). Run `siem train --data <your-normal-flows> --out model.json`.
2. **Inject an anomaly**: from a lab host, run a port scan burst, a periodic beacon (e.g. a
   scripted callback every N seconds), or a bulk exfil-style transfer against your lab targets.
3. **Verify alert**: `siem run --model model.json your-flows.jsonl | siem alert --threshold 0.85 --model model.json -`
   and confirm an alert for the anomalous host/window with a high anomaly score.
4. **Keep FP low**: replay a window of clean baseline traffic and confirm zero (or near-zero)
   alerts; record the FP count in `METRICS.md`.

## Detector Modes

Two detectors expose the **same interface** (`fit`/`score`/`save`/`load`) and **same output
format** (anomaly score in `[0, 1)`):

| mode | when used | description |
|---|---|---|
| `sklearn` | scikit-learn installed (default) | Isolation-Forest anomaly score fused with a robust z-score ensemble (mean/std per feature, capped standardized distance). |
| `stdlib` | scikit-learn absent, or `detector.force_stdlib: true` | Faithful stdlib feature-statistics baseline: rolling mean/std per feature, standardized (z) distance → score. No ML dependency. |

Which path ran is recorded in the model file (`detector_path`) and printed by `siem train`.
The **offline demo / self-test always runs on the stdlib path** so verification never
hard-fails without scikit-learn. Model persistence is plain JSON (means/stds/feature
metadata + `detector_path`); sklearn uses the same JSON artifact for feature statistics
(no pickle blobs).

## Tests

```bash
python -m unittest discover -s tests -v    # stdlib unittest, no deps
python -m compileall -q siem tests
```

Coverage: feature-builder correctness on tiny fixtures, label encoding / metrics (AUC,
precision, recall), train/evaluate on a small corpus, detector persistence round-trip,
alert-threshold behavior, config validation.

## Offline self-test

`siem selftest` (or `python -m siem.cli selftest`): generates corpus → trains → evaluates →
asserts AUC ≥ 0.75, recall ≥ 0.8, majority true positives, low FP (<5% of negatives) →
emits a sample alert JSONL → exits 0 in well under 25s.

## License

MIT. See `LICENSE`.