from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes.email import router as email_router
from app.api.routes.intelligence import (
    router as intelligence_router,
)
from app.api.routes.ip import router as ip_router

from app.core.config import get_settings


settings = get_settings()

APP_DIR = Path(__file__).resolve().parent
DASHBOARD_DIR = APP_DIR / "static" / "dashboard"
DASHBOARD_ASSETS_DIR = DASHBOARD_DIR / "assets"

DASHBOARD_ASSETS_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


app = FastAPI(
    title="CIPHER-X",
    description=(
        "AI-Powered Email Threat Detection, GeoLocation "
        "and Forensic Intelligence Platform"
    ),
    version="1.0.0",
)

app.mount(
    "/dashboard/assets",
    StaticFiles(directory=DASHBOARD_ASSETS_DIR),
    name="dashboard-assets",
)


# --------------------------------------------------
# Root Endpoint
# --------------------------------------------------

@app.get("/")
async def root():
    return {
        "name": "CIPHER-X",
        "status": "online",
        "version": "1.0.0",
    }


@app.get("/dashboard", include_in_schema=False)
@app.get("/dashboard/", include_in_schema=False)
async def dashboard():
    return FileResponse(
        DASHBOARD_DIR / "index.html"
    )


# --------------------------------------------------
# Health Check
# --------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "CIPHER-X API",
    }


# --------------------------------------------------
# API Routers
# --------------------------------------------------

# Email analysis
app.include_router(
    email_router,
    prefix="/api/v1",
)


# Threat Intelligence
app.include_router(
    intelligence_router,
    prefix="/api/v1",
)


# IP Intelligence
app.include_router(
    ip_router,
    prefix="/api/v1",
)
