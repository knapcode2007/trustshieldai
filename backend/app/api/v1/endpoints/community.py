import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
from fastapi import APIRouter, HTTPException, Query, Depends, status
from backend.app.core.errors import ValidationError
from backend.app.models.schemas import (
    CommunityReport,
    CommunityReportCreate,
    CommunityReportModerateRequest,
)
from backend.app.db.supabase import db_manager
from backend.app.core.auth import get_current_user_optional
from backend.app.api.v1.endpoints.admin import record_audit_log

router = APIRouter()

# In-memory baseline community reports (for local fallback and test isolation)
_COMMUNITY_REPORTS: List[CommunityReport] = [
    CommunityReport(
        id="cr-101",
        target_url="https://support-netflix-billing-update.cc/login",
        domain="support-netflix-billing-update.cc",
        threat_type="Phishing / Billing Scam",
        targeted_brand="Netflix",
        description="SMS phishing message claiming membership payment was declined, redirecting to a cloned Netflix credential and credit card harvest form.",
        reporter_handle="infosec_hawk",
        severity="high",
        status="verified",
        confirmations_count=8,
        created_at=datetime.now(timezone.utc).isoformat(),
        moderated_at=datetime.now(timezone.utc).isoformat(),
        moderator_note="Confirmed active spearphishing credential kit."
    ),
    CommunityReport(
        id="cr-102",
        target_url="https://metamask-security-sync-auth.io",
        domain="metamask-security-sync-auth.io",
        threat_type="Web3 Seed Phrase Drainer",
        targeted_brand="MetaMask",
        description="Malicious crypto phishing site impersonating MetaMask recovery workflow to drain BIP-39 recovery seed phrases.",
        reporter_handle="crypto_sentry",
        severity="critical",
        status="pending",
        confirmations_count=4,
        created_at=datetime.now(timezone.utc).isoformat()
    )
]

@router.get("/community/reports", response_model=List[CommunityReport])
async def list_community_reports(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (pending, verified, dismissed, all)"),
    search: Optional[str] = Query(None, description="Search query string")
):
    """Retrieves crowd-sourced phishing and malicious URL reports from Supabase PostgreSQL with in-memory fallback."""
    actual_status = status_filter if isinstance(status_filter, str) else None
    actual_search = search.lower() if isinstance(search, str) else None

    # 1. Query Supabase if configured
    if db_manager.is_configured:
        db_items = db_manager.list_community_reports(status=actual_status, search=actual_search)
        if db_items is not None and len(db_items) > 0:
            return [CommunityReport(**item) for item in db_items]

    # 2. Local fallback
    items = list(_COMMUNITY_REPORTS)

    if actual_status and actual_status != "all":
        items = [r for r in items if r.status == actual_status]

    if actual_search:
        items = [
            r for r in items
            if actual_search in r.target_url.lower()
            or actual_search in r.domain.lower()
            or (r.targeted_brand and actual_search in r.targeted_brand.lower())
            or actual_search in r.threat_type.lower()
        ]

    return items

@router.post("/community/reports", response_model=CommunityReport, status_code=status.HTTP_201_CREATED)
async def submit_community_report(
    req: CommunityReportCreate,
    user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Submits a new threat report from community contributors."""
    actual_user = user if isinstance(user, dict) else None
    if not req.target_url or not req.target_url.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "VALIDATION_ERROR", "message": "Target URL cannot be empty", "field": "target_url"}
        )

    raw_url = req.target_url.strip()
    try:
        norm = raw_url if "://" in raw_url else f"https://{raw_url}"
        parsed = urlparse(norm)
        domain = parsed.netloc.lower().split(":")[0] or raw_url.split("/")[0]
    except Exception:
        domain = raw_url.split("/")[0]

    reporter_handle = req.reporter_handle.strip() if req.reporter_handle else (
        actual_user.get("metadata", {}).get("full_name") or actual_user.get("email") or "community_member"
        if actual_user else "community_member"
    )

    new_report = CommunityReport(
        id=f"cr-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
        target_url=raw_url,
        domain=domain,
        threat_type=req.threat_type or "Suspicious Phishing Lure",
        targeted_brand=req.targeted_brand.strip() if req.targeted_brand else None,
        description=req.description.strip() if req.description else "Reported by community contributor",
        reporter_handle=reporter_handle,
        severity=req.severity or "high",
        status="pending",
        confirmations_count=1,
        created_at=datetime.now(timezone.utc).isoformat()
    )

    # Persist to Supabase if configured
    if db_manager.is_configured:
        payload = new_report.model_dump() if hasattr(new_report, "model_dump") else new_report.__dict__
        user_id = actual_user.get("id") if actual_user else None
        db_manager.create_community_report(payload, user_id=user_id)

    _COMMUNITY_REPORTS.insert(0, new_report)
    return new_report

@router.patch("/community/reports/{report_id}/vote", response_model=CommunityReport)
async def vote_community_report(report_id: str):
    """Increments peer confirmation count on a community threat report."""
    target_report = None
    for r in _COMMUNITY_REPORTS:
        if r.id == report_id:
            target_report = r
            break

    if not target_report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Community report '{report_id}' not found."}
        )

    target_report.confirmations_count += 1

    if db_manager.is_configured:
        db_manager.vote_community_report(report_id, target_report.confirmations_count)

    return target_report

@router.patch("/community/reports/{report_id}/moderate", response_model=CommunityReport)
async def moderate_community_report(
    report_id: str,
    req: CommunityReportModerateRequest,
    user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Moderates a community report (verified or dismissed) and logs an administrative audit entry."""
    actual_user = user if isinstance(user, dict) else None
    if db_manager.is_configured and actual_user:
        if actual_user.get("role") not in ("admin", "moderator"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "FORBIDDEN", "message": "Administrative or moderator privileges required."}
            )

    target_report = None
    for r in _COMMUNITY_REPORTS:
        if r.id == report_id:
            target_report = r
            break

    if not target_report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Community report '{report_id}' not found."}
        )

    target_report.status = req.status
    target_report.moderated_at = datetime.now(timezone.utc).isoformat()
    target_report.moderator_note = req.moderator_note or f"Status updated to {req.status} by administrator."

    actor = actual_user.get("email") if (actual_user and actual_user.get("email")) else "Admin Moderator"

    if db_manager.is_configured:
        db_manager.moderate_community_report(report_id, req.status, target_report.moderator_note)

    record_audit_log(
        action="MODERATE_COMMUNITY_REPORT",
        target_type="report",
        target_id=target_report.id,
        target_value=target_report.target_url,
        decision="approved" if req.status == "verified" else "rejected",
        actor=actor,
        reason=target_report.moderator_note
    )

    return target_report
