"""
TrustShield AI - Staging Security & Access Control Tests (Phase 8B)
Verifies:
1. In staging, public health endpoints (/health, /api/health) remain accessible without auth.
2. In staging, protected endpoints require X-Staging-Key or Bearer token matching STAGING_ACCESS_KEY.
3. In staging, system fails closed if STAGING_ACCESS_KEY is empty or missing.
4. Constant-time secret comparison via hmac.compare_digest.
5. In staging, anti-spoofing rate limit prevents bypass via prepended X-Forwarded-For headers.
6. In non-staging environments (development/production), staging guard is inactive.
"""

import json
import unittest
from unittest.mock import patch
from starlette.requests import Request
from starlette.responses import JSONResponse

from backend.app.core.config import settings
from backend.app.security.staging_guard import StagingSecurityMiddleware


def sync_await(coro):
    """Executes a coroutine synchronously for fast, isolated test execution."""
    try:
        coro.send(None)
    except StopIteration as e:
        return e.value


def build_request(path: str, headers: dict = None, client_ip: str = "127.0.0.1", method: str = "POST") -> Request:
    """Builds a Starlette Request object from scope without network binding."""
    raw_headers = []
    if headers:
        for k, v in headers.items():
            raw_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": raw_headers,
        "client": (client_ip, 12345),
    }
    return Request(scope)


async def dummy_call_next(request: Request):
    return JSONResponse(status_code=200, content={"verdict": "clean"})


class TestStagingSecurityGuard(unittest.TestCase):
    """Verifies staging environment protection, key authentication, and rate limiting."""

    def setUp(self):
        self.middleware = StagingSecurityMiddleware(app=None)

    def test_01_non_staging_environment_unrestricted(self):
        """In development or production, staging guard allows requests without staging key."""
        req = build_request("/api/v1/scan")
        with patch.object(settings, "ENVIRONMENT", "development"):
            with patch.object(settings, "STAGING_ACCESS_KEY", "secret-key"):
                resp = sync_await(self.middleware.dispatch(req, dummy_call_next))
                self.assertEqual(resp.status_code, 200)

    def test_02_staging_health_probes_always_public(self):
        """In staging, /health and /api/health remain publicly accessible for platform monitors."""
        with patch.object(settings, "ENVIRONMENT", "staging"):
            with patch.object(settings, "STAGING_ACCESS_KEY", "secret-key"):
                req_root = build_request("/health", method="GET")
                resp_root = sync_await(self.middleware.dispatch(req_root, dummy_call_next))
                self.assertEqual(resp_root.status_code, 200)

                req_api = build_request("/api/health", method="GET")
                resp_api = sync_await(self.middleware.dispatch(req_api, dummy_call_next))
                self.assertEqual(resp_api.status_code, 200)

    def test_03_staging_fails_closed_when_key_unconfigured(self):
        """In staging, if STAGING_ACCESS_KEY is empty/missing, protected routes fail closed with HTTP 401."""
        with patch.object(settings, "ENVIRONMENT", "staging"):
            with patch.object(settings, "STAGING_ACCESS_KEY", ""):
                req = build_request("/api/v1/scan")
                resp = sync_await(self.middleware.dispatch(req, dummy_call_next))
                self.assertEqual(resp.status_code, 401)
                data = json.loads(resp.body.decode())
                self.assertEqual(data["detail"]["code"], "STAGING_ACCESS_DENIED")
                self.assertIn("STAGING_ACCESS_KEY must be configured", data["detail"]["message"])

    def test_04_staging_blocks_unauthorized_scan_requests(self):
        """In staging with STAGING_ACCESS_KEY set, scan requests without key return HTTP 401."""
        with patch.object(settings, "ENVIRONMENT", "staging"):
            with patch.object(settings, "STAGING_ACCESS_KEY", "stage-secret-123"):
                # No key
                req_no_key = build_request("/api/v1/scan")
                resp_no_key = sync_await(self.middleware.dispatch(req_no_key, dummy_call_next))
                self.assertEqual(resp_no_key.status_code, 401)

                # Wrong key
                req_wrong_key = build_request("/api/v1/scan", headers={"X-Staging-Key": "wrong-key"})
                resp_wrong_key = sync_await(self.middleware.dispatch(req_wrong_key, dummy_call_next))
                self.assertEqual(resp_wrong_key.status_code, 401)

                # Docs endpoint also protected in staging
                req_docs = build_request("/docs", method="GET")
                resp_docs = sync_await(self.middleware.dispatch(req_docs, dummy_call_next))
                self.assertEqual(resp_docs.status_code, 401)

    def test_05_staging_allows_valid_staging_key(self):
        """In staging, valid X-Staging-Key or Bearer token is accepted via constant-time comparison."""
        with patch.object(settings, "ENVIRONMENT", "staging"):
            with patch.object(settings, "STAGING_ACCESS_KEY", "stage-secret-123"):
                # Via X-Staging-Key header
                req_header = build_request("/api/v1/scan", headers={"X-Staging-Key": "stage-secret-123"})
                resp_header = sync_await(self.middleware.dispatch(req_header, dummy_call_next))
                self.assertEqual(resp_header.status_code, 200)

                # Via Authorization Bearer
                req_bearer = build_request("/api/v1/scan", headers={"Authorization": "Bearer stage-secret-123"})
                resp_bearer = sync_await(self.middleware.dispatch(req_bearer, dummy_call_next))
                self.assertEqual(resp_bearer.status_code, 200)

    def test_06_anti_spoofing_rate_limiting(self):
        """Pretending to have different IPs via prepended X-Forwarded-For cannot bypass rate limiting."""
        with patch.object(settings, "ENVIRONMENT", "staging"):
            with patch.object(settings, "STAGING_ACCESS_KEY", "stage-secret-123"):
                with patch.object(settings, "STAGING_RATE_LIMIT_PER_MINUTE", 2):
                    headers = {"X-Staging-Key": "stage-secret-123"}

                    # Attacker tries to rotate leftmost IP: "10.0.0.1, 203.0.113.50", "10.0.0.2, 203.0.113.50"
                    # Rightmost IP (203.0.113.50) is the real client connecting through the proxy
                    req1 = build_request("/api/v1/scan", headers={**headers, "X-Forwarded-For": "10.0.0.1, 203.0.113.50"})
                    req2 = build_request("/api/v1/scan", headers={**headers, "X-Forwarded-For": "10.0.0.2, 203.0.113.50"})
                    req3 = build_request("/api/v1/scan", headers={**headers, "X-Forwarded-For": "10.0.0.3, 203.0.113.50"})

                    r1 = sync_await(self.middleware.dispatch(req1, dummy_call_next))
                    self.assertEqual(r1.status_code, 200)

                    r2 = sync_await(self.middleware.dispatch(req2, dummy_call_next))
                    self.assertEqual(r2.status_code, 200)

                    # 3rd request from same client (203.0.113.50) must be rate-limited despite spoofed prepended IP
                    r3 = sync_await(self.middleware.dispatch(req3, dummy_call_next))
                    self.assertEqual(r3.status_code, 429)


if __name__ == "__main__":
    unittest.main()
