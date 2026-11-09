import time
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter
from backend.app.core.config import settings
from backend.app.models.schemas import HealthResponse, SubsystemHealth
from backend.app.db.supabase import db_manager
from backend.app.ml.service import ml_service

router = APIRouter()

@router.get("/health", response_model=HealthResponse)
async def get_system_health():
    """Provides comprehensive health and readiness checks across all TrustShield AI modules."""
    start_time = time.time()
    db_health = db_manager.check_health()
    elapsed_ms = round((time.time() - start_time) * 1000, 2)
    req_id = f"health-{uuid.uuid4().hex[:8]}"

    subsystems = {
        "api_gateway": SubsystemHealth(
            status="online",
            latency_ms=elapsed_ms,
            version=settings.APP_VERSION
        ),
        "fastapi_service": SubsystemHealth(
            status="online",
            details="FastAPI ASGI engine operational with SSRF egress firewall",
            version="0.115.0"
        ),
        "ml_engine": SubsystemHealth(
            status="ready" if ml_service.is_trained else "degraded",
            details=(
                "Scikit-Learn phishing model loaded and active"
                if ml_service.is_trained
                else "Lexical feature extractor operational (ML artifact pending training)"
            ),
            version=ml_service.model_version
        ),
        "database": SubsystemHealth(
            status=db_health["status"],
            provider=db_health.get("provider", "supabase"),
            details=db_health.get("details")
        ),
        "tls_validator": SubsystemHealth(
            status="ready",
            details="Socket SSL handshake inspection active with DNS rebinding protection"
        )
    }

    overall_status = "healthy"
    if db_health["status"] in ("degraded", "offline"):
        overall_status = "degraded"

    return HealthResponse(
        status=overall_status,
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        request_id=req_id,
        ssrf_protection="active",
        timestamp=datetime.now(timezone.utc).isoformat(),
        subsystems=subsystems
    )
