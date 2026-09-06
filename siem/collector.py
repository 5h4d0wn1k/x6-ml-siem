"""Collector — ingest flow/event JSONL from files or stdin."""
import json
import sys


def parse_event_line(line):
    """Parse a single JSONL line into a dict, or None if malformed/blank."""
    if isinstance(line, dict):
        return line
    if isinstance(line, bytes):
        line = line.decode("utf-8", errors="replace")
    line = (line or "").strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None


def iter_lines(source):
    """Yield raw lines from a file path, or '-' for stdin."""
    if source == "-":
        for line in sys.stdin:
            yield line
        return
    with open(source, "r", encoding="utf-8") as fh:
        for line in fh:
            yield line


def ingest(source):
    """Ingest all events from a file path (or '-'). Returns a list of dicts."""
    events = []
    for line in iter_lines(source):
        ev = parse_event_line(line)
        if ev is not None:
            events.append(ev)
    return events


def ingest_lines(lines):
    """Ingest from an iterable of lines. Returns a list of dicts."""
    events = []
    for line in lines:
        ev = parse_event_line(line)
        if ev is not None:
            events.append(ev)
    return events


def iterate_events(source):
    """Yield parsed events from a file path (or '-') lazily."""
    for line in iter_lines(source):
        ev = parse_event_line(line)
        if ev is not None:
            yield ev
