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

## Security knowledge

| Endpoint | Auth | Notes |
| --- | --- | --- |
| `GET /api/v1/findings/{id}/knowledge` | Bearer | reference material explaining one finding |
| `GET /api/v1/knowledge/status` | Bearer | whether the knowledge base has been built, and from what |

Both are reads. The knowledge base is built by `scripts/build_knowledge.py` from
files on disk — there is deliberately no endpoint that triggers indexing, since
it costs minutes of CPU and would let a caller put arbitrary text into the
advice every user sees.

Each passage says where it came from and **why it was retrieved**:

```json
{"finding_id": 41, "rule_id": "JV003", "cwe_id": "CWE-327",
 "query": "Weak hash algorithm (MD5 or SHA-1) CWE-327 in Java",
 "passages": [
   {"source": "SENTINELFORGE", "external_id": "JV003", "section": "Fix",
    "matched_by": "rule", "score": 0.81, "url": null,
    "text": "Change the algorithm string to \"SHA-256\"..."},
   {"source": "CWE", "external_id": "CWE-327", "section": "Mitigations",
    "matched_by": "cwe", "score": 0.74,
    "url": "https://cwe.mitre.org/data/definitions/327.html", "text": "..."}
 ]}
```

`matched_by` is `rule`, `cwe`, `owasp` or `semantic`, most specific first. A
reader is entitled to know whether a passage was written for this exact rule or
merely scored well against a vector.

An installation with no knowledge base answers **503 `KNOWLEDGE_BASE_NOT_BUILT`**
rather than an empty list: "no passages" reads as a statement about the
vulnerability, and this is a statement about the installation. The same code is
returned when the stored vectors came from a different embedding model than the
one configured, because their scores cannot be compared.

## Risk

| Endpoint | Auth | Notes |
| --- | --- | --- |
| `GET /api/v1/repositories/{id}/risk` | Bearer | the current score, with the arithmetic behind it |
| `GET /api/v1/repositories/{id}/risk/history` | Bearer | one point per completed scan, oldest first |

Both are cheap reads — the score is arithmetic over findings already in the
database, which is why there is no queue here and no worker.

```json
{"repository_id": 4, "score": 52.4, "grade": "D", "policy_version": 1,
 "finding_count": 18, "counts_by_severity": {"CRITICAL": 3, "HIGH": 10},
 "top": [
   {"finding_id": 33, "score": 13.6, "base": 40.0,
    "explanation": "40 base × 0.8 confidence × 0.4 test path × 1.06 age = 13.6",
    "factors": [
      {"name": "confidence", "value": 0.8, "reason": "MEDIUM confidence that this is a real match"},
      {"name": "test path", "value": 0.4, "reason": "in test or fixture code"}
    ]}
 ]}
```

`factors` and `explanation` are the point of the endpoint, not decoration. A
score a reviewer cannot take apart is one they can only accept or ignore.

`policy_version` is on every score and every history point. Two scores produced
by different policies are not two points on the same line, and a client that
plots them together should be able to tell.

History omits scans that carry no score rather than sending zero — they ran
before this scoring existed, and a zero would draw an improvement that never
happened.

## Explanations

| Endpoint | Auth | Notes |
| --- | --- | --- |
| `POST /api/v1/findings/{id}/explanation` | Bearer | **202 Accepted** — queues a generation and returns immediately |
| `GET /api/v1/explanations/{id}` | Bearer | poll this while the status is `QUEUED` or `RUNNING` |
| `GET /api/v1/findings/{id}/explanation` | Bearer | the latest attempt, or **204** when one was never requested |

202 rather than 200 for the same reason as scans, and more so: a 7B model on a
CPU takes tens of seconds. There is no synchronous endpoint, and none that
accepts a prompt — the prompt is built by the server from a finding and its
indexed passages, and letting a client supply one would turn this into a
general-purpose model endpoint wearing the application's credentials.

204 distinguishes "nobody has asked" from "asked and produced nothing"; a failed
generation is returned with its reason rather than hidden, so the UI can name
the command that fixes it instead of showing an empty panel.

```json
{"id": 12, "finding_id": 41, "status": "COMPLETED",
 "summary": "…", "impact": "…", "remediation": "…",
 "model": "qwen2.5-coder:7b", "prompt_version": 1,
 "grounded": true, "dropped_citations": 1, "links_removed": 0,
 "citations": [
   {"number": 1, "chunk_id": 903, "source": "CWE", "external_id": "CWE-327",
    "section": "Mitigations", "url": "https://cwe.mitre.org/data/definitions/327.html"}
 ],
 "duration_ms": 24180, "error_message": null}
```

Everything under `citations` except `number` is read from our own knowledge
base, never from the model — which is what makes the link safe to render.
`dropped_citations` counts references the model made to passages it was never
given, and `grounded` is false when none survived. Both are part of the
response rather than a log line: they are the clearest evidence available that
a model invented a source, and a reader is entitled to see them.

## Scans

| Endpoint | Auth | Notes |
| --- | --- | --- |
| `POST /api/v1/repositories/{id}/scans` | Bearer | **202 Accepted** — queues a scan and returns immediately |
| `GET /api/v1/repositories/{id}/scans` | Bearer | history, newest first |
| `GET /api/v1/scans/{id}` | Bearer | poll this while the scan is `QUEUED` or `RUNNING` |

Queueing answers `202`, not `200`: the work has been accepted, not done. A
background worker claims the scan and runs it; the client polls the scan until
its status leaves `QUEUED`/`RUNNING`.

```json
{"id": 12, "repository_id": 5, "status": "COMPLETED",
 "files_scanned": 3, "total_findings": 6, "new_findings": 2, "fixed_findings": 1,
 "truncated": false, "duration_ms": 41, "started_at": "...", "finished_at": "..."}
```

Those counts are **frozen when the scan ran** — a history row still tells the
truth after the findings have moved on. `truncated: true` means the finding cap
was reached and the result is partial, said out loud rather than presented as
complete.

Codes: `SCAN_ALREADY_RUNNING` (409 — one scan at a time per repository, because
two would race and the loser's view of what is fixed would be silently
overwritten), `REPOSITORY_NOT_SCANNABLE` (409 — nothing ingested, or the stored
copy is gone; deliberately not "0 findings", which would read as "clean"),
`SCAN_NOT_FOUND` (404).

Phase 5's synchronous `POST /repositories/{id}/analyze` is **gone**. It held the
request open for the whole analysis and left no record that a run happened.

## Findings

| Endpoint | Auth | Notes |
| --- | --- | --- |
| `GET /api/v1/repositories/{id}/findings` | Bearer | `severity`, `finding_status`, `limit`, `offset` |
| `GET /api/v1/findings/{id}` | Bearer | one finding |

Every finding carries a lifecycle:

| `status` | Meaning |
| --- | --- |
| `NEW` | the last scan is the first that saw it |
| `OPEN` | it was there before and is still there |
| `FIXED` | it was there before and the last scan could not find it |

Fixed findings are **kept**, not deleted: "you fixed two things" is information.
They are excluded from `by_severity`, because a CRITICAL fixed last week is not
still a CRITICAL. `by_severity` and `by_status` always describe the whole
repository, so a filter cannot make the numbers shown beside it lie.

Codes: `FINDING_NOT_FOUND` (404), `REPOSITORY_NOT_FOUND` (404 for someone else's
repository, exactly as in Phase 4).

Findings carry `severity` **and** `confidence`: how bad it would be, and how
sure the analyser is. `snippet` is code from the analysed repository with any
credential already redacted server-side; clients render it as text.

## CORS

Only origins listed in `CORS_ALLOWED_ORIGINS` (comma-separated, no `*`) may call the API from a
browser. Credentialed requests are allowed because the refresh token is a cookie — which is
exactly why the origin list must stay explicit. Allowed request headers:
`Authorization`, `Content-Type`, `X-Request-ID`, `X-CSRF-Token`.
