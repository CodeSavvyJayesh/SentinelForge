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

## Authentication

| Endpoint | Auth | Notes |
| --- | --- | --- |
| `POST /api/v1/auth/register` | none | rate limited; first account becomes `ADMIN` |
| `POST /api/v1/auth/login` | none | rate limited; returns an access token, sets `sf_refresh` (httpOnly) and `sf_csrf` cookies |
| `POST /api/v1/auth/refresh` | refresh cookie + `X-CSRF-Token` | rotates the refresh token |
| `POST /api/v1/auth/logout` | refresh cookie + `X-CSRF-Token` | 204; revokes the session |
| `GET /api/v1/auth/me` | `Authorization: Bearer` | current user |
| `GET /api/v1/users` | `Authorization: Bearer` + `ADMIN` | paginated account list |

Protected endpoints expect `Authorization: Bearer <access token>` and answer
`401 UNAUTHORIZED` (with `WWW-Authenticate: Bearer`) when the token is missing,
expired, forged, or belongs to a deactivated account — the reason is never
disclosed. A role mismatch answers `403 FORBIDDEN`.

Too many login or registration attempts from one IP answer `429 RATE_LIMITED`
with a `Retry-After` header (seconds).

Cookie-authenticated endpoints additionally require the double-submit CSRF
token: send the value of the readable `sf_csrf` cookie in `X-CSRF-Token`.
Missing or mismatched → `403 CSRF_TOKEN_INVALID`.

Full design and trade-offs: [security/authentication.md](../security/authentication.md).

## Projects

| Endpoint | Auth | Notes |
| --- | --- | --- |
| `POST /api/v1/projects` | Bearer | 201; name unique per owner |
| `GET /api/v1/projects` | Bearer | your projects only; `search`, `limit`, `offset` |
| `GET /api/v1/projects/{id}` | Bearer | 404 if missing **or owned by someone else** |
| `PATCH /api/v1/projects/{id}` | Bearer | partial update |
| `DELETE /api/v1/projects/{id}` | Bearer | 204 |

Ownership is taken from the access token. `owner_id` in a request body is
ignored, and a project belonging to another user is indistinguishable from one
that does not exist: same status, same message. Returning `403` there would
confirm the id exists and let someone map the database by walking ids.

Codes: `PROJECT_NOT_FOUND` (404), `PROJECT_NAME_TAKEN` (409),
`PROJECT_LIMIT_REACHED` (409).

## Repositories

| Endpoint | Auth | Notes |
| --- | --- | --- |
| `POST /api/v1/projects/{id}/repositories/upload` | Bearer | `multipart/form-data`, field `file`; a `.zip` archive |
| `POST /api/v1/projects/{id}/repositories/git` | Bearer | JSON `{repository_url, branch?}`; clones one commit |
| `GET /api/v1/projects/{id}/repositories` | Bearer | repositories of that project |
| `GET /api/v1/repositories/{id}` | Bearer | one repository |
| `DELETE /api/v1/repositories/{id}` | Bearer | 204; also deletes the workspace |

A repository is reached through its project, so a project or repository owned by
someone else answers the same `404` as one that does not exist. `workspace_path`
is never returned: where the code sits on disk is infrastructure, not data.

Ingestion is refused rather than sanitised, and the reason is a stable code:

| Code | Status | Meaning |
| --- | --- | --- |
| `ARCHIVE_TOO_LARGE` | 413 | over `MAX_ARCHIVE_BYTES` |
| `ARCHIVE_INVALID` | 400 | not a readable zip |
| `ARCHIVE_UNSAFE` | 400 | path escaping the target folder, symlink, or special file |
| `ARCHIVE_TOO_MANY_FILES` | 400 | over `MAX_FILES` |
| `ARCHIVE_EXPANDS_TOO_MUCH` | 400 | zip bomb: expanded size or compression ratio over the limit |
| `REPOSITORY_EMPTY` | 400 | nothing analysable after ignored folders were skipped |
| `REPOSITORY_URL_INVALID` | 400 | scheme not `https://`, private/loopback host, credentials in the URL, or a leading `-` |
| `CLONE_FAILED` | 400 | git could not clone (missing branch, private repo, unreachable host, timeout) |
| `GIT_UNAVAILABLE` | 503 | git is not installed on the server |
| `REPOSITORY_LIMIT_REACHED` | 409 | over `MAX_REPOSITORIES_PER_PROJECT` |
| `REPOSITORY_NOT_FOUND` | 404 | no such repository, or not yours |

A rejected upload or clone still leaves a row with `status: "FAILED"` and a
safe `error_message`, so the attempt is visible instead of silently vanishing.
The workspace is deleted in that case.

## Analysis and findings

| Endpoint | Auth | Notes |
| --- | --- | --- |
| `POST /api/v1/repositories/{id}/analyze` | Bearer | runs the analysers over the ingested code; replaces the previous findings |
| `GET /api/v1/repositories/{id}/findings` | Bearer | `severity`, `limit`, `offset` |
| `GET /api/v1/findings/{id}` | Bearer | one finding |

The analyse response is a summary, not the findings themselves:

```json
{"repository_id": 5, "findings": 6, "by_severity": {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 2},
 "files_scanned": 3, "files_skipped": 0, "unparsable_files": 0,
 "truncated": false, "duration_ms": 41, "analyzed_at": "2026-09-25T12:01:04Z"}
```

`truncated: true` means the finding cap was reached and the list is partial —
the API says so rather than presenting a capped list as complete. `by_severity`
in the findings list counts the **whole repository**, so a severity filter
cannot make the totals shown beside it lie.

Codes: `REPOSITORY_NOT_ANALYSABLE` (409 — the repository failed to ingest, or
its stored copy is gone; deliberately not "0 findings", which would read as
"clean"), `FINDING_NOT_FOUND` (404), `REPOSITORY_NOT_FOUND` (404 for someone
else's repository, exactly as in Phase 4).

Findings carry `severity` **and** `confidence`: how bad it would be, and how
sure the analyser is. `snippet` is code from the analysed repository with any
credential already redacted server-side; clients render it as text.

## CORS

Only origins listed in `CORS_ALLOWED_ORIGINS` (comma-separated, no `*`) may call the API from a
browser. Credentialed requests are allowed because the refresh token is a cookie — which is
exactly why the origin list must stay explicit. Allowed request headers:
`Authorization`, `Content-Type`, `X-Request-ID`, `X-CSRF-Token`.
