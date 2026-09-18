# Phase 2 — Authentication: report

**Goal:** real accounts, sessions and roles, built so the security choices are
defensible — not just "login works".

**Scope rule followed:** no project/repository/scan features (Phase 3+).
Phase 1 code was extended, never rewritten.

---

## 1. Summary

| | |
| --- | --- |
| Backend | 14 files added, 8 changed |
| Database | 1 migration (`66e5151881d9`): `users.role`, `refresh_sessions`, `audit_logs` |
| Endpoints | `POST /auth/register`, `/auth/login`, `/auth/refresh`, `/auth/logout`, `GET /auth/me`, `GET /users` (admin) |
| Backend tests | 51 new (82 total) |
| Frontend | sign-in / sign-up screens, session restore, admin panel; 11 new tests (29 total) |
| Docs | [security/authentication.md](../../security/authentication.md) + this report |

Two decisions you made before the work started:

1. **scrypt** (Python built-in) instead of Argon2id — one less dependency, and
   every hashing path is testable here. Swappable later; see the trade-off note
   in the security doc.
2. **Access token in memory + refresh token in an httpOnly cookie** instead of
   `localStorage` — costs an extra endpoint and CSRF protection, and removes the
   most common way student projects leak sessions.

---

## 2. How a session works now

```
Sign in ──► access token (15 min) ──► kept in a JavaScript variable
        └─► refresh token (14 days) ─► httpOnly cookie, JS cannot read it
                                     └─► rotated on every refresh
Page reload ─► access token is gone ─► silent POST /auth/refresh ─► signed in again
Sign out ───► session revoked in the database + cookies cleared
```

Why not `localStorage`: any injected script can read it. Why the extra CSRF
token: a cookie is sent automatically by the browser, so another website could
trigger a refresh; that site cannot read our `sf_csrf` cookie, so echoing it in
a header proves the request came from our own page.

---

## 3. Backend, file by file

### 3.1 `app/core/security.py` — the security primitives

| Function | What it does |
| --- | --- |
| `hash_password` / `verify_password` | scrypt with per-user salt; hash string records its own cost parameters |
| `needs_rehash` | true when a stored hash is weaker than current policy → login upgrades it silently |
| `create_access_token` / `decode_access_token` | HS256 JWT with issuer, audience, `jti`, required claims |
| `generate_refresh_token` / `hash_refresh_token` | 32 random bytes; only the SHA-256 hash is stored |
| `generate_csrf_token` / `csrf_tokens_match` | double-submit CSRF pair, compared in constant time |

Deliberate details: the JWT algorithm is a module constant (not configuration),
so nobody can downgrade it to `none` through the environment; passwords are
capped at 1024 bytes; comparisons use `hmac.compare_digest`.

### 3.2 Models and migration

- `users.role` — PostgreSQL enum (`USER`/`ADMIN`), default `USER`.
- `refresh_sessions` — one row per issued refresh token: `token_hash` (unique),
  `family_id`, `expires_at`, `revoked_at`, `user_agent`.
- `audit_logs` — append-only: action, user, IP, user agent, `request_id`, JSONB
  details, `created_at`. `ON DELETE SET NULL` keeps history after a user is removed.

**Migration review caught a real bug:** autogenerate emitted
`ALTER TABLE users ADD COLUMN role user_role`, but PostgreSQL does not create
the enum *type* for an added column. On any database without that type the
migration fails. Fixed by creating the type explicitly first, and dropping it in
the downgrade so a second upgrade does not hit "type already exists".

### 3.3 Repository layer (new)

`app/repositories/` holds every query (`UserRepository`,
`RefreshSessionRepository`, `AuditLogRepository`). Services orchestrate, endpoints
speak HTTP, repositories speak SQL. This is the layer Phase 3 will reuse for
projects, and it keeps `AuthService` readable.

### 3.4 `AuthService`

`register`, `authenticate`, `login`, `refresh`, `logout`. It never sees HTTP
objects: endpoints pass a small `RequestContext` (IP, user agent, request ID)
used for audit rows.

Points worth defending in a viva:

- **No user enumeration.** Unknown username still verifies a dummy hash, so the
  response time matches a wrong password, and both return the same 401 body.
- **First account becomes admin.** No default password ships with the system.
- **Refresh rotation with reuse detection.** Presenting an already-used refresh
  token revokes every session in that family and writes
  `auth.refresh_reuse_detected` to the audit log.
- **Failed logins are recorded.** The endpoint commits the transaction even when
  login fails, otherwise the audit row would roll back with the error.

### 3.5 Dependencies and rate limiting

`app/core/deps.py` gained `get_current_user` (token → database user),
`require_roles(...)`, `verify_csrf_token`, and an auth rate limiter.
`app/core/rate_limit.py` implements a sliding window behind a `RateLimiter`
Protocol — swap in Redis later without touching endpoints. Limits are per IP and
per path; exceeding them returns `429` with `Retry-After`.

`AppError` can now carry response headers, so 401 sends `WWW-Authenticate` and
429 sends `Retry-After` through the standard error envelope.

---

## 4. Frontend

| File | Role |
| --- | --- |
| `services/tokenStore.ts` | The access token, in a module variable. No storage APIs at all. |
| `services/apiClient.ts` | New options: `auth` (bearer header), `withCredentials` (cookies), `csrf` (header). On a 401 it refreshes **once** and replays the request. |
| `services/authService.ts` | register / login / refresh / logout / me |
| `context/AuthProvider.tsx` | Restores the session on load, schedules a refresh 60 s before expiry, exposes `login` / `register` / `logout` |
| `pages/LoginPage.tsx`, `RegisterPage.tsx` | Forms with per-field validation, error and loading states |
| `pages/UsersPanel.tsx` | Admin-only account list — visible proof that roles work |
| `layouts/AppLayout.tsx` | Shows the signed-in user, their role and a sign-out button |

Small detail with a real effect: if no CSRF cookie exists, the app skips the
restore request entirely instead of firing a doomed call on every first visit.

---

## 5. Verification

| Check | Result |
| --- | --- |
| `pytest` — 82 tests (51 new) incl. PostgreSQL integration | ✅ pass |
| `ruff check` / `ruff format --check` | ✅ pass |
| `alembic upgrade` → `check` → `downgrade` → `upgrade` round trip | ✅ pass |
| Frontend type-check (strict) and 29 unit tests | ✅ pass |
| **Browser run against the live backend** | ✅ register → wrong password → sign in → reload keeps session → sign out → reload stays signed out |
| Browser storage inspection after login | ✅ `localStorage` and `sessionStorage` empty; only `sf_csrf` readable from JavaScript |
| Audit trail after that run | ✅ `user.registered`, `auth.login_failed`, `auth.login_succeeded`, `auth.token_refreshed`, `auth.logout` |
| On your Windows PC (`scripts/verify.ps1`) | ✅ backend 83 passed, Vitest 29 passed, production build — after fixing two ESLint findings, below |

**The browser run found a real bug** that no unit test would have caught: CORS
did not allow the `X-CSRF-Token` header, so the browser blocked `/auth/refresh`
before it was ever sent — sessions silently failed to restore after a reload.
Fixed, with a regression test for the preflight.

**Your ESLint run found two more**, both genuine, in `AuthProvider.tsx`:
`applySession` and `endSession` referenced each other before declaration (the
scheduled refresh could capture a stale function), and the restore effect called
`setState` synchronously, causing a cascading render. Fixed with a ref for the
scheduling cycle and a lazy initial state. Those React Compiler rules could not
run in my sandbox at the time; the project's exact ESLint (10.10 with
typescript-eslint 8.70 and react-hooks 7.1) now runs there too, so this class of
finding is caught before delivery from here on.

### Do the security tests actually bite?

Each control was deliberately broken to confirm a test fails (and then restored):

| Control removed | Tests failing |
| --- | --- |
| CSRF check on refresh/logout | 2 |
| `httpOnly` on the refresh cookie | 1 |
| Refresh-reuse detection | 1 |
| Login rate limiting | 1 |
| "Is the account still active?" check | 1 |

---

## 6. What you must do on your PC

`JWT_SECRET` is **required** — the API refuses to start without it.

```powershell
cd C:\SentinelForge\backend
.\venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
```

Add to `backend\.env` (plus the optional settings from `.env.example`):

```
JWT_SECRET=<the value printed above>
```

Then:

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt   # adds pyjwt
.\venv\Scripts\python.exe -m alembic upgrade head
cd C:\SentinelForge
.\scripts\verify.ps1
```

Run the app, open <http://localhost:5173>, create your first account (it becomes
the admin) and sign in.

---

## 7. Status

- **COMPLETED:** password hashing, JWT access tokens, rotating refresh sessions
  with reuse detection, CSRF protection, rate limiting, roles with an admin-only
  endpoint, audit logging, sign-in/sign-up UI with session restore, docs.
- **TESTED:** everything in section 5 marked ✅.
- **REMAINING (yours):** set `JWT_SECRET`, run migrations, run `verify.ps1`, commit and push.
- **Deferred on purpose:** password reset and email verification (need an email
  service), two-factor authentication, Redis-backed rate limiting, session
  management UI ("sign out everywhere"), `X-Forwarded-For` handling.

## 8. Next milestone — Phase 3: Projects

- `projects` table owned by a user; create / list / read / update / delete
- Ownership enforced in the service layer: user A must not reach user B's project
  by changing an ID in the URL — with tests that prove it
- Project list and detail screens, and the first use of a router in the frontend
- Audit entries for project changes

## 9. Study checklist

1. Why is the access token kept in a variable instead of `localStorage`?
2. What exactly stops another website from calling `/auth/refresh` with your cookie?
3. Why does the server store only a SHA-256 hash of the refresh token — and why is a
   fast hash acceptable there but not for passwords?
4. What happens when an old refresh token is replayed, and why is signing the real user out the right response?
5. Why does an unknown username still run a password verification?
6. Why is the JWT algorithm a constant instead of a setting?
7. Why re-load the user from the database when the token already contains the role?
8. Why did the enum type break the autogenerated migration?
9. Why does the login endpoint commit the transaction even when login fails?
10. Which parts of the rate limiter would break with two backend workers?
