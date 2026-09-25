# Phase 3 — Projects: report

**Goal:** users can create projects, and **only** see their own. This is the
phase where security stops being about passwords and becomes about data access.

**Scope rule followed:** no repository ingestion (Phase 4), no scanning
(Phase 6). Nothing in the UI pretends those exist.

---

## 1. Summary

| | |
| --- | --- |
| Backend | 5 files added, 5 changed |
| Database | 1 migration (`5e575e845395`): `projects` |
| Endpoints | `POST/GET /projects`, `GET/PATCH/DELETE /projects/{id}` |
| Backend tests | 24 new (107 total) |
| Frontend | routing + project list / create / detail / edit / delete; 8 new tests (37 total) |
| Docs | this report, API conventions, architecture, README |

---

## 2. The ownership rule

One sentence: **a project belongs to one user, and every query is scoped to
that user before the database is asked anything.**

Three places enforce it, and they reinforce each other:

1. **The repository never offers an unscoped read.** There is no
   `get(project_id)`. The only lookup is `get_for_owner(project_id, owner_id)`,
   so a forgotten check in a service cannot leak data — the unsafe query does
   not exist to be called.
2. **The service turns "not yours" into "not found."**
3. **The endpoint takes the user from the access token**, never from the
   request body. `owner_id` is not in any input schema; sending it changes
   nothing (there is a test).

### Why 404 and not 403

A `403 Forbidden` on someone else's project answers a question the attacker
asked: *does project 7 exist?* Walk the ids, collect the 403s, and you have
mapped the database. `404` answers nothing. The test asserts that a stranger's
project and a non-existent project return **the same status and the same
message**, and that the project name never appears in the response.

This is the same reasoning as Phase 2's login screen, where a wrong password
and an unknown username are indistinguishable.

---

## 3. Data model

| Column | Notes |
| --- | --- |
| `owner_id` | → `users.id`, `ON DELETE CASCADE`, indexed |
| `name` | unique **per owner** (`uq_projects_owner_id_name`), not globally |
| `description`, `repository_url`, `language` | nullable; `language` is detected in Phase 4, never guessed |
| `default_branch` | defaults to `main` |
| `created_at`, `updated_at` | the `TimestampMixin` from Phase 1 |

Two users may both have a project called "SecureBank"; one user may not have
two. Deleting a user deletes their projects and nobody else's — there is a test
for exactly that, because a wrong cascade is the kind of bug that only shows up
when it has already destroyed data.

The migration needed no hand-editing this time; it was still read line by line
before being applied.

---

## 4. Validation choices

- **Names** are trimmed and compared case-insensitively: "SecureBank" and
  "securebank" are the same project name.
- **Repository URLs** must start with `http://`, `https://` or `git@`. This
  blocks `javascript:` and `file:` before they ever reach a browser or a git
  client in Phase 4.
- **Branch names** reject the characters git itself forbids (spaces, `~^:?*[\`).
- **Search** escapes `%` and `_` before building the `ILIKE` pattern. Without
  that, searching for `%` returns everything — the wildcard equivalent of an
  injection. A test searches for a literal `%` and expects one row.
- **100 projects per user**, so one account cannot fill the database.

---

## 5. Audit trail

`project.created`, `project.updated` and `project.deleted` join the Phase 2
audit log. The update entry records **which fields changed, not their values**:

```json
{"fields": ["description"]}
```

Values could contain private repository URLs or descriptions, and an audit log
is read by more people than the data it describes.

---

## 6. Frontend

| Route | Screen |
| --- | --- |
| `/projects` | list with search, real empty state, link to each project |
| `/projects/new` | create form |
| `/projects/:id` | detail, inline edit, danger-zone delete |
| `/status` | the Phase 1 system status page |
| `/users` | admin-only account list |

React Router arrives here because there is finally more than one screen. Two
details worth noticing:

- **Delete asks you to type the project name.** A misclick cannot destroy work.
- **A stranger's project shows "This project does not exist, or it is not
  yours."** The UI does not invent a friendlier explanation than the API can
  honestly give, because the API deliberately cannot tell the difference.

The `/users` route is hidden for non-admins *and* refused by the API. Hiding a
button is convenience; the server-side check is the security.

---

## 7. Verification

| Check | Result |
| --- | --- |
| `pytest` — 107 tests (24 new) against real PostgreSQL | ✅ pass |
| `ruff check` / `ruff format --check` | ✅ pass |
| `alembic upgrade` → `check` → `downgrade` → `upgrade` | ✅ pass |
| Frontend type-check, ESLint (your exact config), Vitest | see section 9 |
| Browser run with **two separate accounts** | see section 9 |

### Do the isolation tests bite?

Each control was deliberately broken, the suite re-run, and the control
restored:

| Control removed | Tests that failed |
| --- | --- |
| Ownership filter in `get_for_owner` | 4 |
| Ownership filter in the project listing | 3 |
| 404 replaced by 403 for other users' projects | 5 |
| Search wildcard escaping | 1 |

A security test that passes with the protection removed is decoration. These
do not.

---

## 8. Status

- **COMPLETED:** projects table with per-user ownership, repository/service/API
  layers, validation, search, pagination, audit entries, project screens with
  routing, documentation.
- **REMAINING (yours):** run `alembic upgrade head`, `npm install`, then
  `scripts/verify.ps1`; commit and push.
- **Deferred on purpose:** soft delete (add in Phase 12 if reports need
  history), admin visibility over all projects (belongs with the dashboard),
  project sharing between users (not in the specification).

## 9. Next milestone — Phase 4: Repository ingestion

- `repositories` table linked to a project
- Upload a zip or clone a Git URL into an isolated per-scan workspace
- Path-traversal, size and file-count limits; no repository script is ever run
- Language detection from the file tree, with the distribution stored
- Screens: connect a repository, see detected language and file counts

## 10. Study checklist

1. Why is there no `get(project_id)` in the project repository?
2. What exactly does an attacker learn from a 403 that a 404 hides?
3. Where does `owner_id` come from, and why never from the request body?
4. Why is the project name unique per owner instead of globally?
5. What happens to a user's projects when the user is deleted, and which test proves it?
6. Why does searching for `%` not return every project?
7. Why does the audit log store field *names* but not their values?
8. Why is hiding the Accounts link not a security measure?
9. Which four controls did I break to check the tests, and what failed each time?
10. Why does the project page say scanning arrives in Phase 6 instead of showing an empty scan list?
