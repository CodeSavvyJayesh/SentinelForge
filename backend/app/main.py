from fastapi import FastAPI

from app.core.config import settings
from app.api.v1.health import router as health_router


app = FastAPI(
    title=settings.APP_NAME,
    description="AI-powered Zero-Trust DevSecOps Security Engine",
    version=settings.APP_VERSION
)

app.include_router(
    health_router,
    prefix="/api/v1"
)


@app.get("/")
def root():
    return {
        "message": "SentinelForge API is running!"
    }