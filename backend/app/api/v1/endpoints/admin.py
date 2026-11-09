import uuid
from datetime import datetime, timezone
from typing import List, Optional, Literal, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, status
from backend.app.models.schemas import AdminAuditEntry
from backend.app.db.supabase import db_manager
from backend.app.core.auth import get_current_user_optional

router = APIRouter()

# In-memory storage for admin audit entries (fallback & testing)
_AUDIT_LOGS: List[AdminAuditEntry] = [
    AdminAuditEntry(
        id="audit-01",
        action="MODERATE_COMMUNITY_REPORT",
        target_type="report",
        target_id="cr-101",
        target_value="support-netflix-billing-update.cc",
        decision="approved",
        timestamp=datetime.now(timezone.utc).isoformat(),
        actor="Senior Threat Analyst",
        reason="Verified live phishing kit harvesting credentials and payment cards."
    )
]

def record_audit_log(
    action: str,
    target_type: Literal["indicator", "report", "watchlist"],
    target_id: str,
    target_value: str,
    decision: Literal["approved", "rejected", "modified"],
    actor: str = "Admin Moderator",
    reason: Optional[str] = None,
    user_id: Optional[str] = None
) -> AdminAuditEntry:
    """Appends an immutable audit log entry to PostgreSQL and local fallback cache."""
    entry = AdminAuditEntry(
        id=f"audit-{int(datetime.now(timezone.utc).timestamp() * 1000)}-{uuid.uuid4().hex[:4]}",
        action=action,
        target_type=target_type,
        target_id=target_id,
        target_value=target_value,
        decision=decision,
        timestamp=datetime.now(timezone.utc).isoformat(),
        actor=actor,
        reason=reason or "Moderation review decision applied."
    )

    if db_manager.is_configured:
        payload = entry.model_dump() if hasattr(entry, "model_dump") else entry.__dict__
        db_manager.record_audit_log(payload, user_id=user_id)

    _AUDIT_LOGS.insert(0, entry)
    return entry

@router.get("/admin/audit-logs", response_model=List[AdminAuditEntry])
async def list_admin_audit_logs(
    user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Retrieves all security moderation and administrative audit logs."""
    actual_user = user if isinstance(user, dict) else None
    if db_manager.is_configured and actual_user:
        if actual_user.get("role") not in ("admin", "moderator"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "FORBIDDEN", "message": "Administrative or moderator privileges required."}
            )

    if db_manager.is_configured:
        db_logs = db_manager.list_admin_audit_logs()
        if db_logs is not None and len(db_logs) > 0:
            return [AdminAuditEntry(**entry) for entry in db_logs]

    return _AUDIT_LOGS
