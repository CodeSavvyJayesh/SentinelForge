# Development setup (Windows)

Commands are for PowerShell from the repository root (`C:\SentinelForge`) unless noted.

## Prerequisites

| Tool | Version | Check |
| --- | --- | --- |
| Python | 3.13 | `python --version` |
| Node.js | 20+ (22 LTS recommended) | `node --version` |
| PostgreSQL | 16+ | `psql --version` |
| Git | any recent | `git --version` |

## 1. PostgreSQL: dedicated application role (recommended)

Do not run the app as the `postgres` superuser. Open **SQL Shell (psql)** or pgAdmin as `postgres`:

```sql
-- choose your own strong password
CREATE ROLE sentinelforge_app LOGIN PASSWORD 'choose-a-strong-password';

-- existing development database: hand it over to the app role
ALTER DATABASE sentinelforge OWNER TO sentinelforge_app;
\c sentinelforge
ALTER SCHEMA public OWNER TO sentinelforge_app;
ALTER TABLE users OWNER TO sentinelforge_app;
ALTER TABLE alembic_version OWNER TO sentinelforge_app;
\c postgres

-- separate test database (name MUST end with _test)
CREATE DATABASE sentinelforge_test OWNER sentinelforge_app;
\c sentinelforge_test
ALTER SCHEMA public OWNER TO sentinelforge_app;
```

If you prefer to keep using `postgres` locally, at minimum **change its password**
(`ALTER USER postgres WITH PASSWORD '…';`) — the old one is in the Git history.

## 2. Backend

```powershell
cd backend
python -m venv venv                  # skip if venv already exists
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
copy .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into JWT_SECRET
notepad .env                         # set DATABASE_URL, TEST_DATABASE_URL and JWT_SECRET
```

`JWT_SECRET` is required: the API refuses to start without it, and changing it
signs everyone out (existing access tokens stop verifying).

URL-encode special characters in passwords inside URLs (`@` → `%40`, `#` → `%23`, `%` → `%25`).

```powershell
python -m alembic current            # shows the applied revision
python -m alembic upgrade head       # apply new migrations
python -m alembic check              # "No new upgrade operations detected."
python -m uvicorn app.main:app --reload
```

- API root: <http://localhost:8000>
- Swagger: <http://localhost:8000/docs>
- Health: <http://localhost:8000/api/v1/health>

`LOG_FORMAT=text` in `.env` gives readable logs locally; `json` is for machines/production.

## 3. Frontend

```powershell
cd frontend
copy .env.example .env
npm install
npm run dev
```

Open <http://localhost:5173>. Create an account — **the first account becomes the
administrator** — then sign in. You should see the system status page, and the
Administration panel if you are the admin.
Stop PostgreSQL → Refresh → **Unhealthy / PostgreSQL Down**. Stop the backend → Refresh →
**API unavailable / NETWORK_ERROR**.

## 4. Tests and quality checks

```powershell
# backend (backend/, venv active)
python scripts/create_test_database.py   # once; needs CREATEDB or use the SQL above
python -m pytest                          # 82 tests; DB tests skip if TEST_DATABASE_URL missing
python -m pytest -m "not integration"     # fast tests, no database
python -m ruff check .
python -m ruff format --check .

# frontend (frontend/)
npm run lint
npm run test
npm run build
```

All at once: `.\scripts\verify.ps1`

### Test database safety

`tests/conftest.py` refuses to run if `TEST_DATABASE_URL` points to a database whose name
does not end in `_test`. Migration tests downgrade that database to empty and rebuild it,
so it must never be your development database.

## 5. Line endings

`.gitattributes` stores text files with LF. After pulling Phase 1, normalise once:

```powershell
git add --renormalize .
git status          # the earlier "every line changed" noise disappears
```

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `Field required: DATABASE_URL` on startup | `backend/.env` missing or has no `DATABASE_URL` |
| `password authentication failed` | wrong password, or special characters not URL-encoded |
| Health shows `Database connection failed` | PostgreSQL service stopped (Services → postgresql-x64-…) |
| UI shows `NOT_CONFIGURED` | `frontend/.env` missing `VITE_API_BASE_URL`; restart `npm run dev` |
| Startup error `JWT_SECRET Field required` | add `JWT_SECRET` (48 random characters) to `backend/.env` |
| Signed out on every reload | the refresh cookie was blocked: check `CORS_ALLOWED_ORIGINS` and that both apps use `localhost` (not `127.0.0.1` on one side) |
| `429 Too many attempts` while testing logins | the per-IP rate limit; wait `Retry-After` seconds or restart the API |
| UI shows `NETWORK_ERROR` but backend is up | `CORS_ALLOWED_ORIGINS` must include `http://localhost:5173` |
| `Refusing to run tests … must end with '_test'` | fix `TEST_DATABASE_URL` |
| `Activate.ps1 cannot be loaded` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
