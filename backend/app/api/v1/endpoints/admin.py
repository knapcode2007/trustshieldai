import uuid
from datetime import datetime, timezone
from typing import List, Optional, Literal
from fastapi import APIRouter
from backend.app.models.schemas import AdminAuditEntry

router = APIRouter()

# In-memory storage for admin audit entries
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
    reason: Optional[str] = None
) -> AdminAuditEntry:
    """Appends an immutable audit log entry."""
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
    _AUDIT_LOGS.insert(0, entry)
    return entry

@router.get("/admin/audit-logs", response_model=List[AdminAuditEntry])
async def list_admin_audit_logs():
    """Retrieves all security moderation and administrative audit logs."""
    return _AUDIT_LOGS

