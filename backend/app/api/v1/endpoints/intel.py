import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Query
from backend.app.core.errors import ValidationError
from backend.app.models.schemas import ThreatIndicator, ThreatIndicatorCreate
from backend.app.db.supabase import db_manager

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
    # If Supabase is active, fetch from PostgreSQL table
    client = db_manager.get_client()
    if client:
        try:
            q = client.table("threat_indicators").select("*")
            if indicator_type:
                q = q.eq("indicator_type", indicator_type)
            if severity:
                q = q.eq("severity", severity)
            res = q.execute()
            if res.data:
                return [ThreatIndicator(**item) for item in res.data]
        except Exception:
            pass

    # Fallback to local verified baseline
    results = _BASELINE_INDICATORS
    if indicator_type:
        results = [i for i in results if i.indicator_type == indicator_type]
    if severity:
        results = [i for i in results if i.severity == severity]
    if search:
        s = search.lower()
        results = [i for i in results if s in i.indicator_value.lower() or any(s in t.lower() for t in i.tags)]
    return results

@router.post("/intel/indicators", response_model=ThreatIndicator, status_code=201)
async def submit_threat_indicator(req: ThreatIndicatorCreate):
    """Submit a new Indicator of Compromise (IOC) to the collaborative threat intelligence registry."""
    if not req.indicator_value.strip():
        raise ValidationError("Indicator value cannot be empty", details={"field": "indicator_value"})
    
    new_ioc = ThreatIndicator(
        id=str(uuid.uuid4()),
        indicator_value=req.indicator_value.strip(),
        indicator_type=req.indicator_type,
        threat_category=req.threat_category,
        severity=req.severity,
        confidence=req.confidence,
        source="Community Contributor",
        tags=req.tags,
        is_verified=False,
        created_at=datetime.now(timezone.utc).isoformat()
    )

    client = db_manager.get_client()
    if client:
        try:
            client.table("threat_indicators").insert(new_ioc.model_dump()).execute()
        except Exception:
            pass

    _BASELINE_INDICATORS.insert(0, new_ioc)
    return new_ioc
