# X6 — SIEM with ML Anomaly Detection

Full SIEM pipeline MVP in pure Python: parses normalized JSON event logs, builds feature windows, runs from-scratch Isolation-Forest-like and SVD/PCA-based anomaly detectors, fuses scores, tags ATT&CK techniques, and renders a text-based triage dashboard.

## Overview

This project implements a complete SIEM detection pipeline without external ML libraries:
- **Event Ingestion**: Parses normalized JSON events (auditd/sysmon/zeek-style lines)
- **Feature Engineering**: Event counts, ratios, temporal windows per host/user
- **Isolation-Forest-like Scorer**: Pure Python random partitioning anomaly detector
- **SVD/PCA Reconstruction**: Autoencoder-ish detector via truncated SVD reconstruction error
- **Score Fusion**: Combines both detector outputs with configurable weighting
- **ATT&CK Mapping**: Tags detected anomalies with MITRE ATT&CK technique IDs
- **Triage Dashboard**: Text-based table output with precision/recall on labeled corpus

## Features

- **Dual Detector Engine**: Isolation-Forest-like tree scorer + SVD reconstruction error
- **Feature Windows**: Sliding window feature extraction from event streams
- **ATT&CK Technique Tagging**: Maps anomaly clusters to T-numbers (T1053, T1059, etc.)
- **Precision/Recall Scoring**: Built-in evaluation against labeled embedded test corpus
- **Zero Dependencies**: Pure Python standard library, no numpy/sklearn required
- **Offline Demo**: Fully self-contained with embedded sample event data

## Installation

```bash
# No external dependencies required — pure Python stdlib
python3 ml_siem.py
```

## Usage

```bash
# Run full pipeline demo (offline, embedded data)
python3 ml_siem.py

# Programmatic usage
from ml_siem import SIEMPipeline, parse_event_line

pipeline = SIEMPipeline()
pipeline.ingest_lines(sample_lines)
pipeline.build_feature_windows(window_sec=60)
anomalies = pipeline.detect(threshold=0.75)
pipeline.render_dashboard()
```

## Example Output

```
============================================================
  X6 — SIEM with ML Anomaly Detection
============================================================

[+] Ingested 480 events from 12 hosts
[+] Feature windows: 48 windows @ 60s each
[+] Isolation-Forest-like detector: 48 candidates
[+] SVD reconstruction detector: 48 candidates
[+] Score fusion complete

=== Triage Dashboard ===
 Host          | Time Window  | Score | Technique        | Alert
---------------|--------------|-------|------------------|--------
 web-srv-01    | 14:02-14:03  | 0.93  | T1053.005        | HIGH
 db-primary    | 14:05-14:06  | 0.87  | T1059.001        | HIGH
 dns-resolver  | 14:08-14:09  | 0.81  | T1071.004        | MEDIUM
 workstation-3 | 14:11-14:12  | 0.72  | T1078            | LOW

=== Evaluation ===
 Precision: 0.85
 Recall:    0.78
 F1:        0.81
 True Positives: 11  False Positives: 2  False Negatives: 3
```

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission before deploying this SIEM on monitored systems
- Ingesting system logs without authorization may violate privacy and computer access laws
- This tool should ONLY be used on systems you own or have written authorization to monitor
- Log data must be handled in accordance with organizational data retention policies

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **ECPA/Wiretap Act**: Intercepting or accessing communications may require authorization
- **GDPR/CCPA**: System logs may contain personal data subject to data protection regulations
- **State Laws**: Many states have additional computer crime and privacy statutes

### Acceptable Use
- Monitoring your own infrastructure for security threats
- Authorized security operations center (SOC) deployments with proper authorization
- Academic research in controlled lab environments
- Security education and training demonstrations

### Prohibited Use
- Deploying this SIEM on systems without proper authorization and notice
- Using detection results to target individuals without legal basis
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If this tool detects real vulnerabilities, follow responsible disclosure practices:
1. Report to the affected system owner privately
2. Allow reasonable time for remediation
3. Do not exploit detected weaknesses beyond proof of concept
4. Follow your organization's incident response procedures

## License

MIT
