"""Structured log formatting."""

import json
import logging

from app.core.logging import JsonFormatter, RequestIdFilter, request_id_ctx


def make_record(message: str, **extra: object) -> logging.LogRecord:
    record = logging.LogRecord("sentinelforge.test", logging.INFO, __file__, 1, message, (), None)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_json_formatter_emits_event_extra_fields_and_request_id() -> None:
    token = request_id_ctx.set("req-123")
    try:
        record = make_record("scan_started", scan_id=42)
        RequestIdFilter().filter(record)
        payload = json.loads(JsonFormatter().format(record))
    finally:
        request_id_ctx.reset(token)

    assert payload["event"] == "scan_started"
    assert payload["level"] == "INFO"
    assert payload["request_id"] == "req-123"
    assert payload["scan_id"] == 42
    assert payload["timestamp"].endswith("+00:00")


def test_json_formatter_includes_exception_text() -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        record = logging.LogRecord(
            "sentinelforge.test", logging.ERROR, __file__, 1, "failed", (), sys.exc_info()
        )
    payload = json.loads(JsonFormatter().format(record))
    assert "ValueError: boom" in payload["exception"]


def test_request_id_is_none_outside_a_request() -> None:
    record = make_record("app_started")
    RequestIdFilter().filter(record)
    assert record.request_id is None
