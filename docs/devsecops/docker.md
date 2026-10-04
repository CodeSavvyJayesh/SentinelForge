# Running with Docker

Three containers: PostgreSQL, the API, and the web interface served by nginx.

```bash
cp docker.env.example .env      # Windows: copy docker.env.example .env
# edit .env: set POSTGRES_PASSWORD and JWT_SECRET
docker compose up --build
```

Then open <http://localhost:5173>.

> **These files have not been run.** The compose file is validated
> (`docker compose config`), and the backend's settings were loaded with exactly
> the environment it defines to confirm the API would accept it. No image was
> built: the environment this phase was written in has no Docker daemon. The
> first `docker compose up --build` is the test, and anything it turns up
> belongs in an issue.

## What you have to provide

`.env` needs two values, and compose refuses to start without them:

| Variable | What it is | How to make one |
| --- | --- | --- |
| `POSTGRES_PASSWORD` | the database password (letters and digits) | `python -c "import secrets; print(secrets.token_hex(24))"` |
| `JWT_SECRET` | the key that signs login tokens, at least 32 characters | `python -c "import secrets; print(secrets.token_urlsafe(48))"` |

There is **no default** for either, anywhere. A default password in a compose
file is a password every copy of the project shares.

`.env` is ignored by git. `docker.env.example` is the template and holds no
values.

## What is and is not exposed

- The web interface and the API are published on **127.0.0.1 only**. The stack
  is reachable from the machine it runs on, not from the network.
- The database is not published at all. Only the API container can reach it.
- Both application containers run as a non-root user.
- Nothing secret is in an image: `.env` files are excluded from the build
  context, and the frontend image contains only the API's address, which is
  public by nature.

## What works, and what needs more

Scanning, findings, risk scores, the dashboard and reports work as soon as the
stack is up.

| Feature | Needs |
| --- | --- |
| Explanations and proposed fixes | Ollama running on the host, listening on an address the container can reach. By default Ollama listens on `127.0.0.1` only; set `OLLAMA_HOST=0.0.0.0` for it, or point `OLLAMA_BASE_URL` in `.env` somewhere else |
| CWE / OWASP reference passages | the knowledge packages (`WITH_KNOWLEDGE=true` in `.env`, then rebuild) and the knowledge base built once inside the container |

Without them, those panels say what is missing rather than failing.

## Going beyond localhost

This stack serves plain HTTP, so it runs with `ENVIRONMENT=development`: the API
refuses to start as `production` unless the session cookie is marked `Secure`,
which needs TLS. To expose it:

1. put a TLS-terminating reverse proxy in front;
2. set `ENVIRONMENT=production` and `COOKIE_SECURE=true` in `.env`;
3. change the published addresses in `docker-compose.yml` deliberately.

Until then it is a way to run the project on one machine, not a deployment.

## Data

Two named volumes: `sentinelforge-db` (the database) and
`sentinelforge-workspaces` (uploaded and cloned code). `docker compose down`
keeps them; `docker compose down -v` deletes them.

Migrations run every time the API container starts.
