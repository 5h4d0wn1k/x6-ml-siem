"""Structured logging to file + stdout."""
import json
import logging
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    """Render log records as single-line JSON for easy machine parsing."""

    def format(self, record):
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key in ("component", "host", "window_start", "anomaly_score", "threshold"):
            val = getattr(record, key, None)
            if val is not None:
                payload[key] = val
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def setup_logging(level="INFO", log_file="logs/siem.log", stream=True):
    """Configure root logging with a console handler and an optional file handler.

    Returns the root logger. Never raises if the log directory is unwritable.
    """
    logger = logging.getLogger("siem")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()
    logger.propagate = False

    if stream:
        console = logging.StreamHandler(stream=sys.stdout)
        console.setFormatter(JsonFormatter())
        logger.addHandler(console)

    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(JsonFormatter())
            logger.addHandler(file_handler)
        except OSError:  # keep going even if logs/ is unwritable
            pass

    return logger
