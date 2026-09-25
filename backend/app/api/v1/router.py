"""Aggregates every v1 endpoint router. New feature routers are registered here."""

from fastapi import APIRouter

from app.api.v1.analysis import router as analysis_router
from app.api.v1.auth import router as auth_router
from app.api.v1.health import router as health_router
from app.api.v1.projects import router as projects_router
from app.api.v1.repositories import router as repositories_router
from app.api.v1.scans import router as scans_router
from app.api.v1.users import router as users_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(projects_router)
api_router.include_router(repositories_router)
api_router.include_router(analysis_router)
api_router.include_router(scans_router)
api_router.include_router(users_router)
