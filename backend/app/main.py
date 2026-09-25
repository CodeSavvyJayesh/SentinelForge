"""FastAPI application entry point.

Run locally (from ``backend/``)::

    uvicorn app.main:app --reload
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import Settings, get_settings
from app.core.database import engine
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.middleware import (
    REQUEST_ID_HEADER,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from app.core.security import CSRF_HEADER_NAME
from app.schemas.error import ErrorResponse
from app.workers.scan_worker import ScanWorker

logger = get_logger("sentinelforge.app")

API_DESCRIPTION = (
    "SentinelForge — AI-powered DevSecOps platform for vulnerability detection, "
    "risk analysis, explanation, automated repair and patch validation.\n\n"
    'All errors use a standard envelope: `{"error": {code, message, details, request_id}}`. '
    f"Every response carries an `{REQUEST_ID_HEADER}` header for tracing."
)


def create_app(app_settings: Settings | None = None) -> FastAPI:
    """Application factory. Tests can build isolated app instances with it."""
    cfg = app_settings or get_settings()
    configure_logging(cfg.LOG_LEVEL, cfg.LOG_FORMAT)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        logger.info(
            "app_started",
            extra={"version": cfg.APP_VERSION, "environment": cfg.ENVIRONMENT},
        )
        # The scan worker lives with the application: started here, stopped on
        # shutdown. Turning it off (SCAN_WORKER_ENABLED=false) is supported and
        # is how the tests stay deterministic — they drive the worker directly.
        worker: ScanWorker | None = None
        if cfg.SCAN_WORKER_ENABLED:
            worker = ScanWorker(cfg)
            worker.start()
        application.state.scan_worker = worker
        try:
            yield
        finally:
            if worker is not None:
                worker.stop()
            engine.dispose()
            logger.info("app_stopped")

    docs_enabled = cfg.ENABLE_API_DOCS
    app = FastAPI(
        title=cfg.APP_NAME,
        description=API_DESCRIPTION,
        version=cfg.APP_VERSION,
        debug=cfg.DEBUG,
        lifespan=lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
        responses={
            422: {"model": ErrorResponse, "description": "Validation error"},
            500: {"model": ErrorResponse, "description": "Unexpected server error"},
        },
    )

    register_exception_handlers(app)

    # Middleware added LAST runs FIRST (outermost).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        # Cookies carry the refresh token, so credentialed requests must be
        # allowed. Safe because the origins are explicit (never "*").
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", REQUEST_ID_HEADER, CSRF_HEADER_NAME],
        expose_headers=[REQUEST_ID_HEADER],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestContextMiddleware)

    app.include_router(api_router, prefix=cfg.API_V1_PREFIX)

    @app.get("/", include_in_schema=False)
    def root() -> dict[str, str | None]:
        return {
            "name": cfg.APP_NAME,
            "version": cfg.APP_VERSION,
            "docs": "/docs" if docs_enabled else None,
        }

    return app


app = create_app()
