"""Evaluation metrics — AUC, precision, recall (pure standard library).

AUC is computed with the rank-based (Mann-Whitney U) estimator, so it needs no
machine-learning dependencies.
"""
from .features import iso_to_epoch, canonical_ts


def _canon(v):
    return canonical_ts(iso_to_epoch(v))


def _rank_auc(pos_scores, neg_scores):
    """Area under ROC using Mann-Whitney rank-sum over raw anomaly scores."""
    if not pos_scores or not neg_scores:
        return 0.0
    n_pos = len(pos_scores)
    n_neg = len(neg_scores)
    combined = [(s, 1) for s in pos_scores] + [(s, 0) for s in neg_scores]
    combined.sort(key=lambda t: t[0])
    rank_sum = 0.0
    i = 0
    total = len(combined)
    while i < total:
        j = i
        while j + 1 < total and combined[j + 1][0] == combined[i][0]:
            j += 1
        avg_rank = (i + 1 + j + 1) / 2.0
        for k in range(i, j + 1):
            if combined[k][1] == 1:
                rank_sum += avg_rank
        i = j + 1
    auc = (rank_sum - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)
    return auc


def evaluate(scores, labels, threshold=0.5):
    """Compute AUC/precision/recall over a list of (score, label) pairs.

    labels are truthy (anomalous=1) or falsy (normal=0).
    Returns a dict of metrics.
    """
    pos = [s for s, l in zip(scores, labels) if l]
    neg = [s for s, l in zip(scores, labels) if not l]

    tp = sum(1 for s, l in zip(scores, labels) if l and s >= threshold)
    fp = sum(1 for s, l in zip(scores, labels) if not l and s >= threshold)
    fn = sum(1 for s, l in zip(scores, labels) if l and s < threshold)
    tn = sum(1 for s, l in zip(scores, labels) if not l and s < threshold)

    precision = tp / max(tp + fp, 1)
    recall = tp / max((tp + fn), 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)

    return {
        "auc": _rank_auc(pos, neg),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "positive_count": len(pos),
        "negative_count": len(neg),
        "threshold": threshold,
    }


def load_labels(labels_csv):
    """Load labels.csv (host,window_start,label) into a dict keyed by identity."""
    table = {}
    with open(labels_csv, "r", encoding="utf-8") as fh:
        header = fh.readline().strip().split(",")
        idx_host = header.index("host")
        idx_win = header.index("window_start")
        idx_lab = header.index("label")
        for line in fh:
            parts = line.strip().split(",")
            if len(parts) < 3:
                continue
            table[(parts[idx_host].strip(), _canon(parts[idx_win].strip()))] = int(parts[idx_lab])
    return table
