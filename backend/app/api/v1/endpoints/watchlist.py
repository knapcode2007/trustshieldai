import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
from fastapi import APIRouter, HTTPException, Depends, status
from backend.app.models.schemas import (
    WatchlistItem,
    WatchlistItemCreate,
    GenericActionResponse,
)
from backend.app.db.supabase import db_manager
from backend.app.core.auth import get_current_user_optional

router = APIRouter()

# In-memory baseline watchlist items
_WATCHLIST_ITEMS: List[WatchlistItem] = [
    WatchlistItem(
        id="wl-01",
        target="https://github.com",
        domain="github.com",
        label="Developer Infrastructure",
        added_at=datetime.now(timezone.utc).isoformat(),
        last_scanned_at=datetime.now(timezone.utc).isoformat(),
        last_risk_score=2,
        last_verdict="clean",
        alert_threshold=40,
        status="active"
    ),
    WatchlistItem(
        id="wl-02",
        target="https://suspicious-billing-portal.top",
        domain="suspicious-billing-portal.top",
        label="Customer Phishing Report",
        added_at=datetime.now(timezone.utc).isoformat(),
        last_scanned_at=datetime.now(timezone.utc).isoformat(),
        last_risk_score=82,
        last_verdict="phishing",
        alert_threshold=30,
        status="active"
    )
]

@router.get("/watchlist", response_model=List[WatchlistItem])
async def list_watchlist(
    user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Retrieves all continuously monitored domain and URL watchlist targets."""
    actual_user = user if isinstance(user, dict) else None
    user_id = actual_user.get("id") if actual_user else None

    if db_manager.is_configured:
        db_items = db_manager.list_watchlist(user_id=user_id)
        if db_items is not None and len(db_items) > 0:
            return [WatchlistItem(**item) for item in db_items]

    return _WATCHLIST_ITEMS

@router.post("/watchlist", response_model=WatchlistItem, status_code=status.HTTP_201_CREATED)
async def add_to_watchlist(
    req: WatchlistItemCreate,
    user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Enrolls a new target domain or URL into automated continuous risk monitoring."""
    actual_user = user if isinstance(user, dict) else None
    if not req.target or not req.target.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "VALIDATION_ERROR", "message": "Target URL or domain is required", "field": "target"}
        )

    raw = req.target.strip()
    try:
        norm = raw if "://" in raw else f"https://{raw}"
        parsed = urlparse(norm)
        domain = parsed.netloc.lower().split(":")[0] or raw.split("/")[0]
    except Exception:
        domain = raw.split("/")[0]

    label = req.label.strip() if req.label and req.label.strip() else domain

    new_item = WatchlistItem(
        id=f"wl-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
        target=raw,
        domain=domain,
        label=label,
        added_at=datetime.now(timezone.utc).isoformat(),
        alert_threshold=req.alert_threshold or 40,
        status="active"
    )

    user_id = actual_user.get("id") if actual_user else None
    if db_manager.is_configured:
        payload = new_item.model_dump() if hasattr(new_item, "model_dump") else new_item.__dict__
        db_manager.add_watchlist_item(payload, user_id=user_id)

    _WATCHLIST_ITEMS.insert(0, new_item)
    return new_item

@router.delete("/watchlist/{item_id}", response_model=GenericActionResponse)
async def remove_from_watchlist(
    item_id: str,
    user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Removes a target from continuous automated monitoring."""
    global _WATCHLIST_ITEMS
    actual_user = user if isinstance(user, dict) else None
    user_id = actual_user.get("id") if actual_user else None

    if db_manager.is_configured:
        db_manager.remove_watchlist_item(item_id, user_id=user_id)

    _WATCHLIST_ITEMS = [w for w in _WATCHLIST_ITEMS if w.id != item_id]

    return {
        "success": True,
        "message": "Target removed from watchlist"
    }
