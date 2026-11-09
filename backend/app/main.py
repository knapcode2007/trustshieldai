import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.core.config import settings
from backend.app.core.errors import AppError, app_error_handler, unhandled_exception_handler
from backend.app.api.v1.router import api_v1_router

# Setup logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("trustshield.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing TrustShield AI Security Microservice...")
    logger.info(f"Environment: {settings.ENVIRONMENT} | Version: {settings.APP_VERSION}")
    yield
    logger.info("TrustShield AI Security Microservice shutting down.")

app = FastAPI(
    title="TrustShield AI Engine",
    description="Intelligent platform for phishing detection, malicious website assessment, TLS certificate validation, and threat intelligence.",
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exception Handlers
app.add_exception_handler(AppError, app_error_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)

# Mount API Routers
app.include_router(api_v1_router, prefix="/api")

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
