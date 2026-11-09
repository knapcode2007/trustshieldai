import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse
from fastapi import APIRouter
from backend.app.core.errors import ValidationError
from backend.app.models.schemas import ScanRequest, ScanResponse, TlsSummary
from backend.app.security.heuristics import heuristics_engine
from backend.app.ml.pipeline import ml_pipeline, PhishingFeatureExtractor
from backend.app.security.tls_inspector import tls_inspector

router = APIRouter()

@router.post("/scan", response_model=ScanResponse)
async def analyze_url(req: ScanRequest):
    """Deep analysis of target URL using heuristics, lexical features, ML probability, and TLS handshake."""
    target_url = req.url.strip()
    if not target_url:
        raise ValidationError("Target URL cannot be empty", details={"field": "url"})

    # Normalize URL
    normalized = target_url if "://" in target_url else f"https://{target_url}"
    try:
        parsed = urlparse(normalized)
        domain = parsed.netloc.lower().split(":")[0]
    except Exception as e:
        raise ValidationError("Malformed URL provided", details={"error": str(e)})

    # 1. Heuristics
    heuristics_result = heuristics_engine.evaluate(normalized)
    
    # 2. ML Prediction
    ml_features = PhishingFeatureExtractor.extract_features(normalized)
    ml_pred = ml_pipeline.predict(ml_features)

    # 3. TLS Inspection (optional)
    tls_summary = None
    if req.options and req.options.inspect_tls:
        tls_res = tls_inspector.inspect_host(domain)
        tls_summary = TlsSummary(
            valid=tls_res.connected and not tls_res.is_expired,
            issuer=tls_res.issuer,
            subject=tls_res.subject,
            days_remaining=tls_res.days_remaining,
            is_expired=tls_res.is_expired,
            is_self_signed=tls_res.is_self_signed,
            protocol_version=tls_res.protocol_version
        )

    # Calculate aggregate risk score (0 - 100)
    base_score = int(ml_pred["probability_phish"] * 60)
    heuristic_impact = sum(f.score_impact for f in heuristics_result.findings)
    risk_score = min(100, max(0, base_score + heuristic_impact))

    # Determine verdict
    if risk_score >= 70:
        verdict = "phishing" if any(b in heuristics_result.detected_brand_squats for b in ["paypal", "bank", "google", "apple", "login"]) or ml_pred["probability_phish"] > 0.6 else "malicious"
    elif risk_score >= 40:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return ScanResponse(
        scan_id=str(uuid.uuid4()),
        url=target_url,
        normalized_url=normalized,
        domain=domain,
        verdict=verdict,
        risk_score=risk_score,
        confidence=ml_pred["confidence"],
        heuristics=heuristics_result,
        ml_prediction=ml_pred,
        tls_summary=tls_summary,
        created_at=datetime.now(timezone.utc).isoformat()
    )
