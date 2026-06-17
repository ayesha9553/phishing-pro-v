"""PhishingPro — FastAPI application entry point."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend import database
from backend.api.routes_scan import router as scan_router
from backend.api.routes_history import router as history_router
from backend.api.routes_settings import router as settings_router
from backend.api.routes_intel import router as intel_router
from backend.api.routes_gateway import router as gateway_router
from backend.api.routes_ai import router as ai_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — init DB on startup, close on shutdown."""
    settings.ensure_data_dir()
    await database.get_db()  # Initialize database and create tables

    # Pre-warm OpenPhish feed in background (non-blocking)
    import asyncio
    from backend.services.openphish_service import openphish_service
    asyncio.create_task(openphish_service._refresh_feed())

    yield
    await database.close_db()


app = FastAPI(
    title="PhishingPro",
    description="Multi-layered email phishing detector with SOC dashboard, threat intelligence, domain reputation, AI analysis, and real-time email gateway",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routers
app.include_router(scan_router)
app.include_router(history_router)
app.include_router(settings_router)
app.include_router(intel_router)
app.include_router(gateway_router)
app.include_router(ai_router)

# Serve static frontend files
frontend_dir = settings.FRONTEND_DIR
if frontend_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(frontend_dir / "assets")), name="assets")
    app.mount("/css", StaticFiles(directory=str(frontend_dir / "css")), name="css")
    app.mount("/js", StaticFiles(directory=str(frontend_dir / "js")), name="js")


@app.get("/")
async def serve_frontend():
    """Serve the main frontend HTML file."""
    index_path = frontend_dir / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"message": "PhishingPro API is running. Frontend not found."}


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "2.0.0"}
