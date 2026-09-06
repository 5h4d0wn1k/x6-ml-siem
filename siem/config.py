"""Configuration loading + validation for config/siem.yaml.

Uses PyYAML when available; otherwise falls back to a minimal stdlib parser that
handles the simple scalar/list/nested structure used by this project's config.
"""
import os

try:
    import yaml
    HAS_YAML = True
except Exception:  # pragma: no cover
    yaml = None
    HAS_YAML = False

_REQUIRED_KEYS = (
    "feature",
    "scoring",
    "detector",
    "alert",
    "logging",
    "home_lab_note",
)


DEFAULTS = {
    "feature": {
        "window_sec": 60,
        "features": [
            "packet_count", "byte_count", "duration_total", "ports_breadth",
            "timing_regularity", "session_count", "avg_pkt_size", "flow_rate",
        ],
    },
    "scoring": {
        "threshold": 0.85,
        "update_cadence_sec": 300,
    },
    "detector": {
        "zscore_std_threshold": 3.0,
        "contamination": 0.1,
        "force_stdlib": False,
    },
    "alert": {
        "console": True,
        "jsonl": "alerts/alerts.jsonl",
        "webhook_url": "",
    },
    "logging": {
        "file": "logs/siem.log",
        "level": "INFO",
    },
    "home_lab_note": (
        "Trains and detects ONLY on your own lab telemetry. Placeholder network "
        "192.0.2.0/24 (RFC 5737 documentation range) is used in examples; never "
        "train on third-party data."
    ),
}


def _merge(default, override):
    out = dict(default)
    if isinstance(override, dict):
        for k, v in override.items():
            if k in out and isinstance(out[k], dict) and isinstance(v, dict):
                out[k] = _merge(out[k], v)
            else:
                out[k] = v
    return out


def load_config(path=None, env_path="config/siem.yaml"):
    """Load and merge configuration from YAML (or fallback parser)."""
    path = path or os.environ.get("SIEM_CONFIG") or env_path
    data = {}
    if os.path.exists(path):
        data = _parse_file(path)
    return _merge(DEFAULTS, data)


def _parse_file(path):
    if HAS_YAML:
        with open(path, "r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        return loaded if isinstance(loaded, dict) else {}
    return _fallback_parse(path)


def _strip_comment(text):
    """Remove an inline '#' comment, ignoring '#' inside quoted strings."""
    in_s = None
    for i, ch in enumerate(text):
        if ch in "'\"":
            if in_s == ch:
                in_s = None
            elif in_s is None:
                in_s = ch
        elif ch == "#" and in_s is None:
            return text[:i]
    return text


def _read_lines(path):
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            stripped = _strip_comment(stripped).strip()
            if not stripped:
                continue
            indent = len(line) - len(line.lstrip(" "))
            out.append((indent, stripped))
    return out


def _fallback_parse(path):
    """Minimal YAML subset parser: scalars, lists, nested maps, literal blocks."""
    lines = _read_lines(path)
    root = {}
    stack = [(0, root)]   # (indent, dict-or-list)
    pending = None        # (indent, parent_dict, key) of an empty placeholder
    i = 0
    n = len(lines)

    def pop_for(indent):
        while len(stack) > 1:
            top_indent, top = stack[-1]
            if top_indent > indent or (top_indent == indent and not isinstance(top, list)):
                stack.pop()
                continue
            break

    while i < n:
        indent, text = lines[i]
        if text.startswith("- "):
            item = _coerce(text[2:].strip())
            if pending is not None and pending[0] < indent:
                parent, key = pending[1], pending[2]
                if isinstance(parent[key], dict) and not parent[key]:
                    parent[key] = [item]
                    stack.append((indent, parent[key]))
                    pending = None
                    i += 1
                    continue
            pop_for(indent)
            container = stack[-1][1]
            if isinstance(container, list):
                container.append(item)
            elif isinstance(container, dict) and container:
                last_key = next(reversed(container))
                if isinstance(container[last_key], list):
                    container[last_key].append(item)
            i += 1
            continue

        key, sep, val = text.partition(":")
        key = key.strip().strip("'\"")
        val = val.strip()
        if not sep:
            i += 1
            continue
        if val in ("|", ">"):
            block = []
            i += 1
            while i < n and lines[i][0] > indent:
                block.append(lines[i][1])
                i += 1
            pop_for(indent)
            scope = stack[-1][1]
            scope[key] = "\n".join(block) + ("\n" if val == "|" else "")
            pending = None
            continue
        pop_for(indent)
        scope = stack[-1][1]
        if val == "":
            node = {}
            scope[key] = node
            pending = (indent, scope, key)
            stack.append((indent, node))
        else:
            scope[key] = _coerce(val)
            pending = None
        i += 1
    return root


def _coerce(val):
    if val.lower() == "true":
        return True
    if val.lower() == "false":
        return False
    if val in ("null", "~"):
        return None
    try:
        if "." in val or "e" in val.lower():
            return float(val)
        return int(val)
    except ValueError:
        return val.strip("\"'")


def validate_config(cfg):
    """Validate a loaded config; raise ValueError on errors."""
    for key in _REQUIRED_KEYS:
        if key not in cfg:
            raise ValueError(f"config missing required section: {key!r}")
    feats = cfg["feature"].get("features")
    if not isinstance(feats, list) or not feats:
        raise ValueError("config: feature.features must be a non-empty list")
    if not isinstance(cfg["scoring"].get("threshold"), (int, float)):
        raise ValueError("config: scoring.threshold must be numeric")
    th = cfg["scoring"]["threshold"]
    if not (0.0 <= th <= 1.0):
        raise ValueError("config: scoring.threshold must be in [0, 1]")
    return cfg
