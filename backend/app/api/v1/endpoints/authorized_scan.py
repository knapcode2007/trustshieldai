"""
TrustShield AI - Authorized Domain Security Testing API Endpoints
Safe OWASP ZAP Integration & Cryptographic Ownership Verification
"""

import logging
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status

from backend.app.models.schemas import (
    AuthorizedScanChallengeRequest,
    AuthorizedScanChallengeResponse,
    AuthorizedScanVerifyRequest,
    AuthorizedScanVerifyResponse,
    AuthorizedScanDispatchRequest,
    AuthorizedScanDispatchResponse,
)
from backend.app.security.authorized_scanner import authorized_scanner

logger = logging.getLogger("trustshield.api.authorized_scan")
router = APIRouter(prefix="/authorized-scan", tags=["Authorized Domain Security Testing (OWASP ZAP)"])

@router.post("/challenge", response_model=AuthorizedScanChallengeResponse, status_code=status.HTTP_201_CREATED)
async def create_domain_challenge(req: AuthorizedScanChallengeRequest):
    """
    Generates domain ownership verification tokens (DNS TXT record and HTTP challenge file).
    Active security testing requires verifying domain ownership prior to authorization.
    """
    if not req.domain or "." not in req.domain:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"code": "INVALID_DOMAIN", "message": "A valid domain name is required (e.g. example.com)."}
        )

    challenge_info = authorized_scanner.generate_challenge(req.domain, req.owner_email)
    return challenge_info

@router.post("/verify", response_model=AuthorizedScanVerifyResponse)
async def verify_domain_ownership(req: AuthorizedScanVerifyRequest):
    """
    Verifies domain ownership via DNS TXT record or HTTP challenge file.
    If valid, returns an active scan authorization token valid for 7 days.
    """
    verified, message, auth_token = authorized_scanner.verify_ownership(req.domain, req.method)
    return {
        "domain": req.domain,
        "verified": verified,
        "verification_token": auth_token,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@router.post("/dispatch", response_model=AuthorizedScanDispatchResponse)
async def dispatch_authorized_scan(req: AuthorizedScanDispatchRequest):
    """
    Dispatches an authorized security scan (e.g. OWASP ZAP baseline / crawl).
    Safety checks:
    - Rejects if active scanning is disabled (default).
    - Returns 403 Forbidden if domain ownership has not been verified.
    """
    result = authorized_scanner.dispatch_authorized_scan(
        domain=req.domain,
        auth_token=req.verification_token,
        policy=req.scan_policy
    )

    if result["status"] == "disabled":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "ACTIVE_SCANNING_DISABLED",
                "message": result["message"],
                "zap_integration_status": result["zap_integration_status"]
            }
        )

    if result["status"] == "rejected":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "DOMAIN_NOT_VERIFIED",
                "message": result["message"],
                "zap_integration_status": result["zap_integration_status"]
            }
        )

    return result
