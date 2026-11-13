"""
TrustShield AI - Staging Security & Abuse Prevention Middleware (Phase 8B)
Protects the public staging deployment from unauthorized access and brute-force scanning:
1. Fail-Closed Staging Access Key Gate:
   - Requires valid X-Staging-Key or Bearer token for all non-exempt endpoints.
   - Uses constant-time comparison (hmac.compare_digest) to prevent timing attacks.
   - Fails closed if STAGING_ACCESS_KEY is empty or missing in a staging environment.
   - Exempts only minimal health check probes (/health, /api/health, /) required by Render.
2. Anti-Spoofing Rate Limiting:
   - Sliding-window in-memory rate limiter per verified client IP.
   - Prioritizes authoritative proxy headers (Render-Client-IP, CF-Connecting-IP, True-Client-IP).
   - Validates IP structure using ipaddress to prevent forwarding header injection/spoofing.
3. Inactive in Development & Production:
   - Activates strictly when ENVIRONMENT == "staging".
"""

import collections
import hmac
import ipaddress
import logging
import threading
import time
from typing import Dict, Deque
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from backend.app.core.config import settings

logger = logging.getLogger("trustshield.staging_guard")


class StagingSecurityMiddleware(BaseHTTPMiddleware):
    """
    Enforces fail-closed access control and anti-spoofing rate limiting on staging.
    Guarantees that public staging does not expose unprotected scanning endpoints.
    """

    def __init__(self, app):
        super().__init__(app)
        self._lock = threading.Lock()
        self._ip_request_times: Dict[str, Deque[float]] = collections.defaultdict(collections.deque)
        self._window_seconds = 60.0

    def _get_client_ip(self, request: Request) -> str:
        """
        Extracts verified client IP, preventing rate-limit bypass via spoofed forwarding headers.
        Prioritizes platform-authenticated headers set by Render and Cloudflare edge proxies.
        """
        # 1. Authoritative platform headers (injected by proxy, not client-spoofable)
        for header_name in ("render-client-ip", "cf-connecting-ip", "true-client-ip", "x-real-ip"):
            val = request.headers.get(header_name)
            if val:
                candidate = val.strip()
                try:
                    ipaddress.ip_address(candidate)
                    return candidate
                except ValueError:
                    pass

        # 2. X-Forwarded-For: Take rightmost IP to defeat client-prepended spoofed addresses
        x_forwarded_for = request.headers.get("x-forwarded-for")
        if x_forwarded_for:
            parts = [p.strip() for p in x_forwarded_for.split(",") if p.strip()]
            if parts:
                # Rightmost IP is appended by the nearest trusted edge proxy
                candidate = parts[-1]
                try:
                    ipaddress.ip_address(candidate)
                    return candidate
                except ValueError:
                    pass

        # 3. Direct socket peer fallback
        if request.client and request.client.host:
            return request.client.host
        return "127.0.0.1"

    def _is_rate_limited(self, client_ip: str) -> bool:
        """Sliding-window rate limiter per client IP."""
        max_req = settings.STAGING_RATE_LIMIT_PER_MINUTE
        if max_req <= 0:
            return False

        now = time.time()
        with self._lock:
            timestamps = self._ip_request_times[client_ip]
            # Prune timestamps older than window
            cutoff = now - self._window_seconds
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()

            if len(timestamps) >= max_req:
                return True

            timestamps.append(now)
            return False

    async def dispatch(self, request: Request, call_next) -> Response:
        # Only active in staging environment
        if (settings.ENVIRONMENT or "").lower() != "staging":
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        path = request.url.path

        # 1. Strictly minimal exempt operational routes (required by Render health check)
        # All API endpoints (/api/v1/..., /v1/..., /docs, /redoc, /openapi.json) require authentication
        exempt_paths = {"/", "/health", "/api/health"}
        is_exempt = path in exempt_paths

        # 2. Rate Limiting Check (applies across staging)
        if self._is_rate_limited(client_ip):
            logger.warning(f"Staging rate limit exceeded for client IP: {client_ip}")
            return JSONResponse(
                status_code=429,
                content={
                    "detail": {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": f"Rate limit exceeded. Maximum {settings.STAGING_RATE_LIMIT_PER_MINUTE} requests per minute in staging.",
                        "client_ip": client_ip,
                    }
                },
            )

        # 3. Access Key Gate (Fail Closed if STAGING_ACCESS_KEY missing or invalid)
        if not is_exempt:
            configured_key = (settings.STAGING_ACCESS_KEY or "").strip()
            if not configured_key:
                logger.error("Staging security violation: STAGING_ACCESS_KEY not configured. Failing closed.")
                return JSONResponse(
                    status_code=401,
                    content={
                        "detail": {
                            "code": "STAGING_ACCESS_DENIED",
                            "message": "Staging environment is locked. STAGING_ACCESS_KEY must be configured.",
                        }
                    },
                )

            key_header = request.headers.get("x-staging-key", "").strip()
            auth_header = request.headers.get("authorization", "").strip()
            bearer_token = ""
            if auth_header.lower().startswith("bearer ") and len(auth_header.split(" ")) == 2:
                bearer_token = auth_header.split(" ")[1].strip()

            presented_key = key_header or bearer_token

            # Constant-time comparison to prevent timing side-channel attacks
            if not presented_key or not hmac.compare_digest(presented_key, configured_key):
                logger.warning(f"Unauthorized staging access attempt on {path} from IP: {client_ip}")
                return JSONResponse(
                    status_code=401,
                    content={
                        "detail": {
                            "code": "STAGING_ACCESS_DENIED",
                            "message": "Access to staging environment requires a valid X-Staging-Key header or Bearer token.",
                        }
                    },
                )

        return await call_next(request)
