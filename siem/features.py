"""Feature builder — derive numeric features from flow/event windows.

Features are computed per (host, fixed-size time window):
  packet_count       total packets
  byte_count         total bytes
  duration_total     sum of flow durations (seconds)
  ports_breadth      number of unique destination ports touched
  timing_regularity  measure of inter-arrival regularity (0 = noisy, 1 = beacon)
  session_count      number of distinct flows/sessions initiated by the host
  avg_pkt_size       byte_count / max(packet_count, 1)
  flow_rate          session_count / window seconds

Everything is implemented in the Python standard library.
"""
import math
from collections import defaultdict
from datetime import datetime, timezone


def iso_to_epoch(ts):
    """Parse an ISO-8601 timestamp (with optional 'Z' or offset) to epoch seconds."""
    if not ts:
        return 0.0
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return 0.0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def canonical_ts(epoch):
    """Render an epoch in the canonical 'YYYY-MM-DDTHH:MM:SSZ' form."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_port(dst):
    """Extract the destination port number from a 'ip:port' string, else None."""
    if not dst:
        return None
    part = str(dst)
    if ":" in part:
        part = part.rsplit(":", 1)[-1]
    try:
        return int(part)
    except ValueError:
        return None


DEFAULT_FEATURES = [
    "packet_count",
    "byte_count",
    "duration_total",
    "ports_breadth",
    "timing_regularity",
    "session_count",
    "avg_pkt_size",
    "flow_rate",
]


def _regularity(intervals):
    """1/(1+rel_std) of inter-arrival times. 1.0 = perfectly periodic beacon."""
    if len(intervals) < 2:
        return 0.0
    mean = sum(intervals) / len(intervals)
    if mean <= 0:
        return 0.0
    var = sum((iv - mean) ** 2 for iv in intervals) / len(intervals)
    rel_std = math.sqrt(var) / mean if var > 0 else 0.0
    return 1.0 / (1.0 + rel_std)


class FeatureBuilder:
    """Build per-(host, window) numeric feature dicts from raw event dicts."""

    def __init__(self, window_sec=60, features=DEFAULT_FEATURES):
        self.window_sec = window_sec
        self.features = list(features)

    def build_windows(self, events):
        """Return a list of feature dicts: {host, window_start, epoch, vector, raw}.

        Each dict carries a 'vector' ordered per self.features (README-compat
        metadata key is stored as 'feature_names').
        """
        if not events:
            return []

        buckets = defaultdict(list)
        for ev in events:
            epoch = iso_to_epoch(ev.get("ts"))
            bucket = int(epoch // self.window_sec)
            buckets[bucket].append((epoch, ev))

        out = []
        for bucket in sorted(buckets):
            rows = buckets[bucket]
            grouped = defaultdict(list)
            for epoch, ev in rows:
                grouped[_host_of(ev)].append((epoch, ev))
            for host, hrows in grouped.items():
                feat = self._extract(hrows, bucket)
                feat["host"] = host
                feat["window_start"] = _bucket_iso(bucket, self.window_sec)
                feat["feature_names"] = self.features
                feat["vector"] = [feat[f] for f in self.features]
                out.append(feat)
        return out

    def _extract(self, rows, bucket):
        ts_sorted = [ep for ep, _ in rows]
        ports = set()
        sessions = set()
        packet_count = 0
        byte_count = 0
        duration_total = 0.0
        for ep, ev in rows:
            packets = _num(ev.get("packets"))
            bytes_ = _num(ev.get("bytes"))
            dur = _num(ev.get("duration"))
            packet_count += packets
            byte_count += bytes_
            duration_total += dur if dur is not None else 0.0
            port = parse_port(ev.get("dst"))
            if port is not None:
                ports.add(port)
            sess = ev.get("session") or ev.get("session_id")
            if sess:
                sessions.add(sess)

        session_count = len(sessions) if sessions else len(rows)
        ports_breadth = len(ports) if ports else min(session_count, 1)

        intervals = [b - a for a, b in zip(ts_sorted, ts_sorted[1:])]
        timing_regularity = _regularity([iv for iv in intervals if iv > 0])

        return {
            "packet_count": float(packet_count),
            "byte_count": float(byte_count),
            "duration_total": float(duration_total),
            "ports_breadth": float(ports_breadth),
            "timing_regularity": float(timing_regularity),
            "session_count": float(session_count),
            "avg_pkt_size": float(byte_count / max(packet_count, 1)),
            "flow_rate": float(session_count / max(self.window_sec, 1)),
        }

    def to_vector(self, feat):
        return [feat.get(f, 0.0) for f in self.features]


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _host_of(ev):
    return ev.get("host") or ev.get("src") or "unknown"


def _bucket_iso(bucket, window_sec):
    return canonical_ts(bucket * window_sec)
