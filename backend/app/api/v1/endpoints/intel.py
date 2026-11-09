import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query, Depends, status
from backend.app.core.errors import ValidationError, ResourceNotFoundError
from backend.app.models.schemas import ThreatIndicator, ThreatIndicatorCreate, VerifyThreatIndicatorRequest
from backend.app.db.supabase import db_manager
from backend.app.core.auth import get_current_user_optional
from backend.app.api.v1.endpoints.admin import record_audit_log

router = APIRouter()

# In-memory verified baseline registry when database is in bootstrap mode
_BASELINE_INDICATORS: List[ThreatIndicator] = [
    ThreatIndicator(
        id="ioc-1001",
        indicator_value="secure-paypal-update-alert.xyz",
        indicator_type="domain",
        threat_category="Credential Harvester",
        severity="critical",
        confidence=98,
        source="TrustShield Threat Research",
        tags=["paypal", "credential-theft", "phishing"],
        is_verified=True,
        created_at="2026-11-08T18:22:10Z"
    ),
    ThreatIndicator(
        id="ioc-1002",
        indicator_value="account-verification-office365-login.net",
        indicator_type="domain",
        threat_category="Spearphishing Portal",
        severity="high",
        confidence=95,
        source="Community Telemetry",
        tags=["microsoft", "o365", "corporate-spoof"],
        is_verified=True,
        created_at="2026-11-09T01:45:00Z"
    ),
    ThreatIndicator(
        id="ioc-1003",
        indicator_value="185.220.101.5",
        indicator_type="ip",
        threat_category="Malicious C2 Node",
        severity="critical",
        confidence=92,
        source="AbuseIPDB Feed",
        tags=["c2", "bulletproof-hosting", "botnet"],
        is_verified=True,
        created_at="2026-11-09T04:12:30Z"
    )
]

@router.get("/intel/indicators", response_model=List[ThreatIndicator])
async def list_threat_indicators(
    indicator_type: Optional[str] = Query(None, description="Filter by type (url, domain, ip, sha256)"),
    severity: Optional[str] = Query(None, description="Filter by severity (low, medium, high, critical)"),
    search: Optional[str] = Query(None, description="Search query string")
):
    """Retrieve collaborative Threat Intelligence Indicators of Compromise (IOCs)."""
    actual_type = indicator_type if isinstance(indicator_type, str) else None
    actual_severity = severity if isinstance(severity, str) else None
    actual_search = search.lower() if isinstance(search, str) else None

    # If Supabase is active, fetch from PostgreSQL table
    if db_manager.is_configured:
        db_indicators = db_manager.list_threat_indicators(
            indicator_type=actual_type,
            severity=actual_severity,
            search=actual_search
        )
        if db_indicators is not None and len(db_indicators) > 0:
            return [ThreatIndicator(**item) for item in db_indicators]

    # Fallback to local verified baseline
    results = _BASELINE_INDICATORS
    if actual_type:
        results = [i for i in results if i.indicator_type == actual_type]
    if actual_severity:
        results = [i for i in results if i.severity == actual_severity]
    if actual_search:
        results = [i for i in results if actual_search in i.indicator_value.lower() or any(actual_search in t.lower() for t in i.tags)]
    return results

@router.post("/intel/indicators", response_model=ThreatIndicator, status_code=201)
async def submit_threat_indicator(
    req: ThreatIndicatorCreate,
    user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Submit a new Indicator of Compromise (IOC) to the collaborative threat intelligence registry."""
    actual_user = user if isinstance(user, dict) else None
    if not req.indicator_value.strip():
        raise ValidationError("Indicator value cannot be empty", details={"field": "indicator_value"})

    source = (
        actual_user.get("metadata", {}).get("full_name") or actual_user.get("email") or "Community Contributor"
        if actual_user else "Community Contributor"
    )

    new_ioc = ThreatIndicator(
        id=str(uuid.uuid4()),
        indicator_value=req.indicator_value.strip(),
        indicator_type=req.indicator_type,
        threat_category=req.threat_category,
        severity=req.severity,
        confidence=req.confidence,
        source=source,
        tags=req.tags,
        is_verified=False,
        created_at=datetime.now(timezone.utc).isoformat()
    )

    if db_manager.is_configured:
        user_id = actual_user.get("id") if actual_user else None
        db_manager.create_threat_indicator(
            new_ioc.model_dump() if hasattr(new_ioc, "model_dump") else new_ioc.__dict__,
            user_id=user_id
        )

    _BASELINE_INDICATORS.insert(0, new_ioc)
    return new_ioc

@router.patch("/intel/indicators/{indicator_id}/verify", response_model=ThreatIndicator)
async def verify_threat_indicator(
    indicator_id: str,
    req: VerifyThreatIndicatorRequest,
    user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Verifies or rejects a threat intelligence indicator, logging the administrative decision."""
    actual_user = user if isinstance(user, dict) else None
    if db_manager.is_configured and actual_user:
        if actual_user.get("role") not in ("admin", "moderator"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "FORBIDDEN", "message": "Administrative or moderator privileges required."}
            )

    target_item = None
    for item in _BASELINE_INDICATORS:
        if item.id == indicator_id:
            target_item = item
            break

    if not target_item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Threat indicator '{indicator_id}' not found."}
        )

    target_item.is_verified = bool(req.is_verified)
    actor = actual_user.get("email") if (actual_user and actual_user.get("email")) else "Admin Moderator"

    # Persist to database if available
    if db_manager.is_configured:
        db_manager.verify_threat_indicator(indicator_id, target_item.is_verified, verified_by=actor)

    record_audit_log(
        action="APPROVE_INDICATOR" if req.is_verified else "REJECT_INDICATOR",
        target_type="indicator",
        target_id=target_item.id,
        target_value=target_item.indicator_value,
        decision="approved" if req.is_verified else "rejected",
        actor=actor,
        reason=req.reason or "Moderation review decision applied."
    )

    return target_item
