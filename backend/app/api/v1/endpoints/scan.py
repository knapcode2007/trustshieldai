import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse
from fastapi import APIRouter, HTTPException, status
from backend.app.core.errors import ValidationError
from backend.app.models.schemas import (
    ScanRequest,
    ScanResponse,
    TlsSummary,
    MlPrediction,
    AnalysisCoverage,
    EvidenceItem,
    Recommendation,
)
from backend.app.core.url_normalizer import URLNormalizer
from backend.app.security.ssrf import SSRFValidator, SSRFSecurityException
from backend.app.security.heuristics import heuristics_engine
from backend.app.ml.service import ml_service
from backend.app.security.tls_inspector import tls_inspector

router = APIRouter()

@router.post("/scan", response_model=ScanResponse)
async def analyze_url(req: ScanRequest):
    """Deep synchronous analysis of target URL using heuristics, lexical features, ML probability, and TLS handshake."""
    target_url = req.url.strip() if req.url else ""
    if not target_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "EMPTY_URL", "message": "Target URL cannot be empty.", "field": "url"}
        )

    # 1. Canonicalize & normalize URL first
    try:
        canonical_url, url_hash, norm_meta = URLNormalizer.canonicalize(target_url)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_SCHEME", "message": f"Invalid URL structure: {str(e)}", "field": "url"}
        )

    # 2. Strict SSRF validation and destination IP pinning
    try:
        _, domain, port, pinned_ip = SSRFValidator.validate_url(canonical_url)
    except SSRFSecurityException as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": e.code, "message": e.message, "field": "url"}
        )

    # 3. Heuristics
    heuristics_result = heuristics_engine.evaluate(canonical_url)
    
    # 4. Honest ML Prediction via PhishingMLService
    ml_pred = ml_service.predict(canonical_url)

    # 5. TLS Inspection (optional)
    tls_summary = None
    tls_cov = 0
    if req.options and req.options.inspect_tls:
        try:
            tls_res = tls_inspector.inspect_host(domain)
            tls_summary = TlsSummary(
                valid=tls_res.connected and not tls_res.is_expired,
                issuer=tls_res.issuer,
                subject=tls_res.subject,
                days_remaining=tls_res.days_remaining,
                is_expired=tls_res.is_expired,
                is_self_signed=tls_res.is_self_signed,
                protocol_version=tls_res.protocol_version,
                grade=tls_res.grade
            )
            tls_cov = 100
        except Exception:
            tls_cov = 0

    # Calculate aggregate risk score honestly based on verified models and heuristics
    if ml_pred.get("is_trained") and ml_pred.get("probability_phish") is not None:
        base_score = int(ml_pred["probability_phish"] * 60)
        ml_cov = 100
    else:
        base_score = 0
        ml_cov = 0

    heuristic_impact = sum(f.score_impact for f in heuristics_result.findings)
    risk_score = min(100, max(0, base_score + heuristic_impact))

    # Determine verdict
    is_high_ml = (ml_pred.get("probability_phish") or 0.0) > 0.60
    if risk_score >= 70:
        verdict = "phishing" if (heuristics_result.detected_brand_squats or is_high_ml) else "malicious"
    elif risk_score >= 35:
        verdict = "suspicious"
    else:
        verdict = "clean"

    overall_cov = int((100 + ml_cov + tls_cov) / 3)

    confidence = ml_pred.get("confidence")
    if confidence is None:
        if overall_cov >= 80:
            confidence = 0.90 if heuristics_result.findings else 0.85
        else:
            base_conf = 0.50 + (overall_cov / 100.0) * 0.25
            confidence = round(base_conf, 2)

    evidence_items = [
        EvidenceItem(category="Host & DNS", key="Domain", value=domain, significance="Resolved and SSRF validated"),
        EvidenceItem(category="Information Theory", key="Shannon Entropy", value=f"{heuristics_result.url_entropy:.4f} bits/char", significance="Lexical distribution")
    ]

    if ml_cov == 0:
        evidence_items.append(
            EvidenceItem(
                category="Coverage Advisory",
                key="Evidence Breadth",
                value=f"{overall_cov}% overall pipeline coverage",
                significance="ML model offline/untrained; clean verdict indicates absence of observed signatures rather than guaranteed safety"
            )
        )

    recommendations = []
    if verdict in ("phishing", "malicious"):
        recommendations.append(Recommendation(
            id="rec-01",
            title="Block Target Egress",
            description="Add this destination domain to egress firewalls and secure DNS filters.",
            severity="critical",
            category="Incident Response"
        ))
    else:
        recommendations.append(Recommendation(
            id="rec-02",
            title="Maintain Continuous Telemetry",
            description="Target currently exhibits benign characteristics and standard cryptographic posture.",
            severity="low",
            category="Best Practice"
        ))

    return ScanResponse(
        scan_id=str(uuid.uuid4()),
        url=target_url,
        normalized_url=canonical_url,
        domain=domain,
        verdict=verdict,
        risk_score=risk_score,
        confidence=confidence,
        heuristics=heuristics_result,
        ml_prediction=MlPrediction(**ml_pred),
        tls_summary=tls_summary,
        analysis_coverage=AnalysisCoverage(
            lexical=100,
            ml=ml_cov,
            tls=tls_cov,
            headers=0,
            threat_feeds=0,
            overall=overall_cov
        ),
        evidence=evidence_items,
        recommendations=recommendations,
        created_at=datetime.now(timezone.utc).isoformat()
    )

