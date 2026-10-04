# SentinelForge API.
#
# Built to be run by docker compose (see ../docker-compose.yml), which supplies
# every setting. Nothing secret is baked into the image: there is no .env in
# the build context (see .dockerignore) and no default for the database
# password or the signing key.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# git is how a repository is cloned from a URL (Phase 4). Nothing else is
# installed: the analyser reads code, it never builds or runs it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt requirements-knowledge.txt ./
# The knowledge base (CWE/OWASP retrieval) needs a local embedding model and
# roughly 400 MB of extra packages. Off by default; turn it on with
#   docker compose build --build-arg WITH_KNOWLEDGE=true backend
ARG WITH_KNOWLEDGE=false
RUN python -m pip install -r requirements.txt \
    && if [ "$WITH_KNOWLEDGE" = "true" ]; then python -m pip install -r requirements-knowledge.txt; fi

COPY alembic.ini ./
COPY alembic ./alembic
COPY app ./app
COPY scripts ./scripts

# The API does not run as root. Uploaded and cloned code is written under
# /data/workspaces, which is the only place this user can write.
RUN useradd --system --create-home --uid 10001 sentinelforge \
    && mkdir -p /data/workspaces \
    && chown -R sentinelforge:sentinelforge /data
USER sentinelforge

ENV WORKSPACE_ROOT=/data/workspaces
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health/live', timeout=3).status == 200 else 1)"

# Migrations first, then the server. Written inline rather than as a script so
# that a Windows checkout cannot hand the container a file with CRLF endings.
CMD ["sh", "-c", "python -m alembic upgrade head && exec python -m uvicorn app.main:app --host 0.0.0.0 --port 8000"]
