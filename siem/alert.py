"""Alert emitter — JSONL + console + optional webhook."""
import json
import logging
import os
import urllib.request

logger = logging.getLogger("siem.alert")


class AlertEmitter:
    """Emit alerts to a JSONL file, the console, and/or an HTTP webhook."""

    def __init__(self, jsonl_path="alerts/alerts.jsonl", console=True,
                 webhook_url=""):
        self.jsonl_path = jsonl_path
        self.console = console
        self.webhook_url = webhook_url

    def _ensure_dir(self):
        if self.jsonl_path:
            d = os.path.dirname(self.jsonl_path)
            if d:
                os.makedirs(d, exist_ok=True)

    def emit(self, record):
        """Emit one alert record (dict). Returns record."""
        line = json.dumps(record, default=str)
        if self.jsonl_path:
            self._ensure_dir()
            with open(self.jsonl_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        if self.console:
            print("ALERT\t" + line, flush=True)
        logger.log(logging.WARNING if record.get("anomaly_score", 0) >= 0.9
                   else logging.INFO, "alert emitted",
                   extra={"component": "alert", "host": record.get("host"),
                          "window_start": record.get("window_start"),
                          "anomaly_score": record.get("anomaly_score"),
                          "threshold": record.get("threshold")})
        if self.webhook_url:
            self._post_webhook(line)
        return record

    def _post_webhook(self, payload):
        if not self.webhook_url:
            return
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=payload.encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5):
                pass
        except Exception as exc:  # webhook must never crash the pipeline
            logger.info("webhook failed: %s", exc)
