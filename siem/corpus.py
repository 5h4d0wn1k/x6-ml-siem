"""Synthetic lab corpus generator.

Builds a small labeled lab corpus entirely from this machine's own conventions
(no external data): normal baseline flows with varied sessions, plus injected
anomalies (scan burst, beacon regularity, exfil bytes). Uses a fixed RNG seed so
the corpus is reproducible for train / evaluate / self-test.

Outputs:
  <dir>/events.jsonl         all events (normal + anomaly), one JSON object/line
  <dir>/labels.csv           (host,window_start,label) mapping every window
  <dir>/train_events.jsonl   normal-only events usable to fit the baseline
"""
import json
import os
import random
import time
from datetime import datetime, timezone

from .features import DEFAULT_FEATURES

LAB_HOSTS = ["lab-web-01", "lab-db-01", "lab-dns-01", "lab-ws-01"]
LAB_LAN = "192.0.2."  # RFC 5737 documentation range — placeholder home-lab net

# Common lab destination ports (normal breadth is small and stable)
NORMAL_PORTS = [80, 443, 8080, 53, 3306, 22]


def _iso(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def generate_corpus(out_dir="data/corpus", seed=7, n_normal_windows=120,
                    window_sec=60, anomaly_modes=("scan_burst", "beacon", "exfil")):
    """Generate a reproducible, held-out-labeled corpus. Returns a dict.

    Train subset: first 60% of normal windows (per host, time-ordered).
    Test subset : remaining 40% of normal windows + all injected anomalies.
    labels.csv  : covers ONLY test windows (honest held-out evaluation).
    """
    rng = random.Random(seed)
    os.makedirs(out_dir, exist_ok=True)

    split = int(n_normal_windows * 0.6)
    base_epoch = int(time.time()) // window_sec * window_sec
    train_events = []   # normal, split 0..split
    test_events = []    # normal, split..N  (anomalies appended later)
    labels = []         # test windows only
    anom_labels = []

    base_epoch -= split * window_sec  # leave whole corpus fresh in the past
    host_t0 = {h: base_epoch + i * window_sec for i, h in enumerate(LAB_HOSTS)}

    for wi in range(n_normal_windows):
        for host in LAB_HOSTS:
            start = host_t0[host] + wi * window_sec
            n_sessions = rng.randint(3, 12)
            prev_ts = None
            for _ in range(n_sessions):
                port = rng.choice(NORMAL_PORTS)
                packets = rng.randint(1, 12)
                bytes_ = rng.randint(200, 8000)
                duration = round(rng.uniform(0.05, 1.5), 3)
                t = start + rng.random() * (window_sec - 2)
                if prev_ts is not None and t < prev_ts + 0.01:
                    t = prev_ts + 0.01
                prev_ts = t
                src_ip = f"{LAB_LAN}{rng.randint(2, 200)}"
                ev = {
                    "ts": _iso(t),
                    "host": host,
                    "src": src_ip,
                    "dst": f"{LAB_LAN}{rng.randint(220, 240)}:{port}",
                    "proto": "tcp" if port not in (53,) else "udp",
                    "packets": packets,
                    "bytes": bytes_,
                    "duration": duration,
                    "session": f"{src_ip}->{LAB_LAN}{rng.randint(220, 240)}:{port}",
                }
                if wi < split:
                    train_events.append(ev)
                else:
                    test_events.append(ev)
            if wi >= split:
                labels.append((host, _iso(start), 0))

    # Inject anomalies in fresh (non-overlapping) windows after normal windows.
    n_anom = 0
    anom_host = LAB_HOSTS[0]
    base = base_epoch + (n_normal_windows + 1) * window_sec
    for mode in anomaly_modes:
        start = base + n_anom * window_sec
        evs = _make_anomaly(mode, anom_host, start, rng)
        test_events.extend(evs)
        labels.append((anom_host, _iso(start), 1))
        n_anom += 1

    test_events.sort(key=lambda e: e["ts"])
    train_events.sort(key=lambda e: e["ts"])
    with open(os.path.join(out_dir, "events.jsonl"), "w", encoding="utf-8") as fh:
        for ev in test_events:
            fh.write(json.dumps(ev) + "\n")
    with open(os.path.join(out_dir, "train_events.jsonl"), "w", encoding="utf-8") as fh:
        for ev in train_events:
            fh.write(json.dumps(ev) + "\n")
    with open(os.path.join(out_dir, "labels.csv"), "w", encoding="utf-8") as fh:
        fh.write("host,window_start,label\n")
        for host, win, lab in labels:
            fh.write(f"{host},{win},{lab}\n")

    return {
        "out_dir": out_dir,
        "seed": seed,
        "n_test_events": len(test_events),
        "n_train_events": len(train_events),
        "n_normal_windows": n_normal_windows * len(LAB_HOSTS),
        "n_anomaly_windows": n_anom,
        "n_labeled_windows": len(labels),
        "features": DEFAULT_FEATURES,
    }


def _make_anomaly(mode, host, start, rng):
    evs = []
    window_sec = 60
    if mode == "scan_burst":
        # Sudden port scan: many short flows to many distinct ports.
        n = rng.randint(80, 120)
        for i in range(n):
            port = rng.randint(1, 1024)
            t = start + (i / n) * (window_sec - 1)
            src_ip = f"{LAB_LAN}{rng.randint(2, 200)}"
            evs.append({
                "ts": _iso(t), "host": host, "src": src_ip,
                "dst": f"{LAB_LAN}240:{port}", "proto": "tcp",
                "packets": 1, "bytes": 48, "duration": 0.01,
                "session": f"{src_ip}->{LAB_LAN}240:{port}",
            })
    elif mode == "beacon":
        # Highly regular beacon: near-constant interval, small payload.
        interval = 3.0
        for i in range(int(window_sec // interval)):
            t = start + i * interval
            src_ip = f"{LAB_LAN}66"
            evs.append({
                "ts": _iso(t), "host": host, "src": src_ip,
                "dst": f"{LAB_LAN}244:443", "proto": "tcp",
                "packets": 3, "bytes": 512, "duration": 0.1,
                "session": f"{src_ip}->{LAB_LAN}244:443",
            })
    elif mode == "exfil":
        # Large-data exfil: few sessions but huge byte totals / large packets.
        for _ in range(rng.randint(3, 6)):
            port = rng.choice([443, 53, 22])
            packets = rng.randint(500, 2000)
            bytes_ = rng.randint(5_000_000, 40_000_000)
            duration = rng.uniform(5, 20)
            t = start + rng.random() * (window_sec - 5)
            src_ip = f"{LAB_LAN}77"
            evs.append({
                "ts": _iso(t), "host": host, "src": src_ip,
                "dst": f"{LAB_LAN}250:{port}", "proto": "tcp",
                "packets": packets, "bytes": bytes_, "duration": round(duration, 2),
                "session": f"{src_ip}->{LAB_LAN}250:{port}",
            })
    return evs
