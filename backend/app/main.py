import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.exceptions import RequestValidationError
from backend.app.core.config import settings
from backend.app.core.errors import (
    AppError,
    app_error_handler,
    http_exception_handler,
    validation_exception_handler,
    unhandled_exception_handler,
)
from backend.app.api.v1.router import api_v1_router
from backend.app.models.schemas import HealthResponse
from backend.app.api.v1.endpoints.health import get_system_health
from backend.app.security.staging_guard import StagingSecurityMiddleware

# Setup logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("trustshield.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing TrustShield AI Security Microservice...")
    logger.info(f"Environment: {settings.ENVIRONMENT} | Version: {settings.APP_VERSION}")
    yield
    logger.info("TrustShield AI Security Microservice shutting down.")
    try:
        from backend.app.core.scanner import scan_engine
        scan_engine.shutdown(wait=False)
    except Exception:
        pass

app = FastAPI(
    title="TrustShield AI Engine",
    description="Intelligent platform for phishing detection, malicious website assessment, TLS certificate validation, and threat intelligence.",
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Configuration - Ensure wildcard is never permitted in production
safe_cors_origins = (
    [o for o in settings.CORS_ORIGINS if o != "*"]
    if settings.ENVIRONMENT.lower() == "production"
    else list(settings.CORS_ORIGINS)
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=safe_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(StagingSecurityMiddleware)

# Exception Handlers
app.add_exception_handler(AppError, app_error_handler)
app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)

# Mount Root & Fallback Health Probes
@app.get("/health", response_model=HealthResponse, tags=["System Health & Diagnostics"])
async def root_health():
    """Root health probe for platform health monitors (Render, GCP, Docker, Kubernetes)."""
    return await get_system_health()

@app.get("/api/health", response_model=HealthResponse, tags=["System Health & Diagnostics"])
async def api_health():
    """Alternative health endpoint path."""
    return await get_system_health()

# Mount API Routers (supports both /api/v1/... and direct /v1/...)
app.include_router(api_v1_router, prefix="/api")
app.include_router(api_v1_router)

@app.get("/")
def read_root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational",
        "docs": "/docs",
        "api_v1": "/api/v1/health"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host=settings.HOST, port=settings.PORT, reload=True)
