# API conventions

Base path: `/api/v1`. Interactive docs: `/docs` (Swagger UI), `/redoc`, schema at `/openapi.json`
(disable with `ENABLE_API_DOCS=false`).

## Error envelope

Every non-2xx response (except the health report, see below) has this shape:

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Not Found",
    "details": null,
    "request_id": "9f1c2b7e4a6d4f0c8e2b1a3d5c7e9f10"
  }
}
```

| Field | Meaning |
| --- | --- |
| `code` | Stable machine-readable code. Clients switch on this, never on `message`. |
| `message` | Human-readable summary, safe to display. |
| `details` | Optional structured data (e.g. validation field errors). |
| `request_id` | Same value as the `X-Request-ID` response header; use it to find server logs. |

Standard codes: `BAD_REQUEST`, `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`, `METHOD_NOT_ALLOWED`,
`CONFLICT`, `VALIDATION_ERROR`, `RATE_LIMITED`, `SERVICE_UNAVAILABLE`, `INTERNAL_ERROR`,
`HTTP_ERROR`. Feature code adds domain codes by raising `AppError`
(e.g. `AppError("PROJECT_NOT_FOUND", "Project not found", status_code=404)`).

Security rules:

- Unexpected exceptions return `INTERNAL_ERROR` with a generic message. The stack trace is
  logged server-side only.
- Validation errors list the field location and reason but **never echo submitted values**
  (they may contain passwords, tokens or source code).

### Validation error example

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": [
      { "location": ["body", "email"], "message": "Field required", "type": "missing" }
    ],
    "request_id": "…"
  }
}
```

## Request IDs

- Every response includes `X-Request-ID`.
- Clients may send their own `X-Request-ID` (1–64 chars of `A-Z a-z 0-9 . _ -`), e.g. a CI run ID;
  anything else is replaced with a generated ID (prevents log injection).
- All log lines written while handling the request carry the same `request_id`.

## Health endpoints

| Endpoint | Purpose | Touches DB | Responses |
| --- | --- | --- | --- |
| `GET /api/v1/health/live` | Is the process running? | No | `200 {"status":"alive","version":…}` |
| `GET /api/v1/health` | Can the service do real work? | Yes | `200` healthy, `503` unhealthy |

The `503` response intentionally uses the **health report body** (not the error envelope) so
monitors and the UI can show which dependency is down:

```json
{
  "status": "unhealthy",
  "version": "0.1.0",
  "checked_at": "2026-09-17T16:05:52.938946Z",
  "checks": {
    "database": { "status": "down", "latency_ms": null, "message": "Database connection failed" }
  }
}
```

Failure messages are generic; hostnames, ports and credentials are never included.

## Response headers

| Header | Value |
| --- | --- |
| `X-Request-ID` | Correlation ID |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |

## CORS

Only origins listed in `CORS_ALLOWED_ORIGINS` (comma-separated, no `*`) may call the API from a
browser. Credentials (cookies) are disabled; authentication will use the `Authorization` header.
