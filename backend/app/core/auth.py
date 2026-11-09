import logging
from typing import Optional, Dict, Any
from fastapi import Header, HTTPException, Depends, status
from backend.app.core.config import settings
from backend.app.db.supabase import db_manager

logger = logging.getLogger("trustshield.auth")

async def get_current_user_optional(
    authorization: Optional[str] = Header(None, description="Bearer token issued by Supabase Auth")
) -> Optional[Dict[str, Any]]:
    """
    Optional authentication dependency.
    If a Bearer token is provided, validates it authoritatively against Supabase GoTrue.
    If no token is provided, returns None to support anonymous scanning and telemetry access.
    """
    if not authorization:
        return None

    parts = authorization.strip().split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "INVALID_AUTH_HEADER",
                "message": "Authorization header must use format 'Bearer <token>'."
            }
        )

    token = parts[1].strip()
    if not token:
        return None

    # 1. Real Supabase GoTrue verification if database is configured
    if db_manager.is_configured:
        user = db_manager.get_user_from_token(token)
        if user:
            return user
        # In configured environments, an unverified token is an invalid token
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "INVALID_TOKEN",
                "message": "The provided authentication token is invalid or expired."
            }
        )

    # 2. Local development fallback (when Supabase credentials are not configured)
    # Allows offline tests and developer workflows without crashing
    if token.startswith("dev-admin-") or token == "admin-test-token":
        return {
            "id": "00000000-0000-0000-0000-000000000001",
            "email": "admin@trustshield.dev",
            "role": "admin",
            "metadata": {"full_name": "System Administrator"}
        }
    if token.startswith("dev-moderator-") or token == "moderator-test-token":
        return {
            "id": "00000000-0000-0000-0000-000000000002",
            "email": "moderator@trustshield.dev",
            "role": "moderator",
            "metadata": {"full_name": "Community Moderator"}
        }

    # Standard dev user
    return {
        "id": f"dev-user-{token[:8]}",
        "email": "user@trustshield.dev",
        "role": "user",
        "metadata": {"full_name": "Development Contributor"}
    }

async def get_current_user(
    user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
) -> Dict[str, Any]:
    """Requires an authenticated user session."""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "AUTHENTICATION_REQUIRED",
                "message": "An active authentication session is required to perform this action."
            }
        )
    return user

async def require_admin_or_moderator(
    user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Enforces administrative or moderator authorization."""
    role = user.get("role", "user")
    if role not in ("admin", "moderator"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "FORBIDDEN",
                "message": "You do not have permission to perform administrative actions. Role 'admin' or 'moderator' required."
            }
        )
    return user

