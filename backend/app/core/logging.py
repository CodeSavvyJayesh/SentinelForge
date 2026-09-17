"""Structured logging.

Every log record is emitted either as a single JSON object per line
(``LOG_FORMAT=json``, default, machine-readable) or as readable text
(``LOG_FORMAT=text``, handy locally). The current request ID is attached to
every record automatically so all logs of one request can be correlated.

Log events use a short snake_case event name as the message
(e.g. ``request_completed``) and put data in ``extra={...}``.
Never log secrets, tokens, passwords or full database URLs.
"""

import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

# Set by RequestContextMiddleware for the duration of each HTTP request.
request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)

# Attributes present on every LogRecord; anything else came from ``extra``.
_STANDARD_RECORD_ATTRS: frozenset[str] = frozenset(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()
) | {"message", "asctime", "request_id", "taskName", "color_message"}


class RequestIdFilter(logging.Filter):
    """Attach the current request ID (or ``None``) to each record."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = request_id_ctx.get()
        return True


class JsonFormatter(logging.Formatter):
    """Render a log record as one JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
            "request_id": getattr(record, "request_id", None),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_RECORD_ATTRS and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class TextFormatter(logging.Formatter):
    """Human-readable single-line format for local development."""

    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)-8s [%(request_id)s] %(name)s: %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extras = {
            key: value
            for key, value in record.__dict__.items()
            if key not in _STANDARD_RECORD_ATTRS and not key.startswith("_")
        }
        return f"{base} {extras}" if extras else base


def configure_logging(level: str = "INFO", log_format: str = "json") -> None:
    """Configure the root logger once for the whole process.

    Uvicorn's own loggers are routed through the same handler; its access log
    is silenced because ``RequestContextMiddleware`` logs every request with
    more context (request ID, duration).
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if log_format == "json" else TextFormatter())
    handler.addFilter(RequestIdFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    for name in ("uvicorn", "uvicorn.error"):
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.propagate = True
    logging.getLogger("uvicorn.access").disabled = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
