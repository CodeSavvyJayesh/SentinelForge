"""HTTP middleware.

Implemented as plain ASGI middleware (not ``BaseHTTPMiddleware``) so that
context variables and streaming responses behave correctly.
"""

import re
import time
from uuid import uuid4

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.logging import get_logger, request_id_ctx

REQUEST_ID_HEADER = "X-Request-ID"

# Only accept client-supplied request IDs that are short and harmless, so they
# cannot be used for log injection.
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}

logger = get_logger("sentinelforge.http")


def resolve_request_id(incoming: str | None) -> str:
    """Reuse a well-formed incoming request ID, otherwise generate a new one."""
    if incoming and _VALID_REQUEST_ID.fullmatch(incoming):
        return incoming
    return uuid4().hex


class RequestContextMiddleware:
    """Assign a request ID, expose it in the response, and log each request.

    The ID is stored in ``request.state.request_id`` and in a context variable
    that the logging system reads.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = resolve_request_id(Headers(scope=scope).get(REQUEST_ID_HEADER))
        scope.setdefault("state", {})["request_id"] = request_id
        token = request_id_ctx.set(request_id)
        started = time.perf_counter()
        status_code = 500  # stays 500 if the app crashes before responding

        async def send_with_request_id(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            # Path only: query strings may carry sensitive values.
            logger.info(
                "request_completed",
                extra={
                    "method": scope["method"],
                    "path": scope["path"],
                    "status_code": status_code,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                },
            )
            request_id_ctx.reset(token)


class SecurityHeadersMiddleware:
    """Add conservative security headers to every HTTP response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers.setdefault(name, value)
            await send(message)

        await self.app(scope, receive, send_with_headers)
