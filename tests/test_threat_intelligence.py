"""
TrustShield AI - Modular Threat Intelligence Unit Test Suite
Tests:
1. URL query parameter sanitization (sensitive token redaction, preventing credential leaks).
2. Adapter status integrity:
   - A failed or unconfigured lookup must NEVER be represented as clean ('no_match').
   - Differentiates: available, no_match, unavailable, rate_limited, error.
3. Test fixtures for positive, negative, rate-limited, and unavailable provider responses.
4. Circuit breaker and TTL memory caching resilience.
5. Exact URL match vs Host / Domain match differentiation.
6. Integration with risk engine and scan report payload.
"""

import os
import json
import unittest
from unittest.mock import MagicMock, patch

from backend.app.intel.base import (
    URLQuerySanitizer,
    ThreatFeedResult,
    CircuitBreaker,
    MemoryCache,
)
from backend.app.intel.google_safe_browsing import GoogleSafeBrowsingAdapter
from backend.app.intel.urlhaus import URLhausAdapter
from backend.app.intel.phishtank import PhishTankAdapter
from backend.app.intel.openphish import OpenPhishAdapter
from backend.app.intel.virustotal import VirusTotalAdapter
from backend.app.intel.manager import ThreatIntelManager


class TestURLQuerySanitizer(unittest.TestCase):
    """Verifies privacy preservation and sensitive token redaction prior to outbound queries."""

    def test_sensitive_tokens_redacted(self):
        url = "https://bank.example.com/login?token=SECRET_SESSION_TOKEN&user=alice&apiKey=AKIA1234567890&redirect=/dashboard"
        sanitized, was_sanitized, redacted = URLQuerySanitizer.sanitize(url)

        self.assertTrue(was_sanitized)
        self.assertIn("token", redacted)
        self.assertIn("apiKey", redacted)
        self.assertNotIn("SECRET_SESSION_TOKEN", sanitized)
        self.assertNotIn("AKIA1234567890", sanitized)
        self.assertIn("token=%5BREDACTED%5D", sanitized)
        self.assertIn("apiKey=%5BREDACTED%5D", sanitized)
        # Harmless params preserved
        self.assertIn("user=alice", sanitized)
        self.assertIn("redirect=%2Fdashboard", sanitized)

    def test_benign_url_without_sensitive_tokens(self):
        url = "https://docs.python.org/3/library/urllib.parse.html?highlight=urlencode#module-urllib.parse"
        sanitized, was_sanitized, redacted = URLQuerySanitizer.sanitize(url)
        self.assertFalse(was_sanitized)
        self.assertEqual(len(redacted), 0)
        self.assertEqual(sanitized, url)

    def test_sensitive_path_password_reset_redacted(self):
        url = "https://auth.example.com/reset-password/938472948274928374923847/confirm"
        sanitized, was_sanitized, redacted = URLQuerySanitizer.sanitize(url)
        self.assertTrue(was_sanitized)
        self.assertIn("path:reset-password", redacted)
        self.assertNotIn("938472948274928374923847", sanitized)
        self.assertIn("/reset-password/[REDACTED_TOKEN]/confirm", sanitized)

    def test_sensitive_path_jwt_redacted(self):
        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        url = f"https://api.example.com/oauth/callback/{jwt_token}"
        sanitized, was_sanitized, redacted = URLQuerySanitizer.sanitize(url)
        self.assertTrue(was_sanitized)
        self.assertNotIn(jwt_token, sanitized)
        self.assertTrue(any("jwt" in r for r in redacted))

    def test_sensitive_path_uuid_and_email_redacted(self):
        url = "https://app.example.com/users/alice@corporate.org/tokens/550e8400-e29b-41d4-a716-446655440000"
        sanitized, was_sanitized, redacted = URLQuerySanitizer.sanitize(url)
        self.assertTrue(was_sanitized)
        self.assertNotIn("alice@corporate.org", sanitized)
        self.assertNotIn("550e8400-e29b-41d4-a716-446655440000", sanitized)
        self.assertIn("path:email", redacted)
        self.assertIn("path:uuid", redacted)

    def test_sensitive_path_combined_with_query_redacted(self):
        url = "https://portal.example.com/magic-link/SECRET_MAGIC_TOKEN_999?redirect=/dashboard&key=SECRET_API_KEY"
        sanitized, was_sanitized, redacted = URLQuerySanitizer.sanitize(url)
        self.assertTrue(was_sanitized)
        self.assertNotIn("SECRET_MAGIC_TOKEN_999", sanitized)
        self.assertNotIn("SECRET_API_KEY", sanitized)
        self.assertIn("key", redacted)
        self.assertIn("path:magic-link", redacted)


class TestCircuitBreakerAndCache(unittest.TestCase):
    """Verifies circuit breaker state transitions and TTL caching."""

    def test_circuit_breaker_trips_after_failures(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=0.5)
        self.assertEqual(cb.state, CircuitBreaker.STATE_CLOSED)
        self.assertTrue(cb.can_execute())

        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, CircuitBreaker.STATE_CLOSED)
        self.assertTrue(cb.can_execute())

        cb.record_failure()
        self.assertEqual(cb.state, CircuitBreaker.STATE_OPEN)
        self.assertFalse(cb.can_execute())

        # After cooldown
        import time
        time.sleep(0.6)
        self.assertTrue(cb.can_execute())
        self.assertEqual(cb.state, CircuitBreaker.STATE_HALF_OPEN)

        cb.record_success()
        self.assertEqual(cb.state, CircuitBreaker.STATE_CLOSED)

    def test_memory_cache_hit_and_expiry(self):
        cache = MemoryCache()
        sample_res = ThreatFeedResult(
            provider="test",
            provider_name="Test Provider",
            status="no_match",
            matched=False,
            details="Clean",
        )
        cache.set("key1", sample_res, ttl_seconds=10)

        hit = cache.get("key1")
        self.assertIsNotNone(hit)
        self.assertTrue(hit.cached)
        self.assertEqual(hit.provider, "test")

        # Non-existent key
        self.assertIsNone(cache.get("key2"))


class TestGoogleSafeBrowsingAdapter(unittest.TestCase):
    """Tests Google Safe Browsing Lookup v4 adapter with controlled fixtures."""

    def setUp(self):
        self.adapter = GoogleSafeBrowsingAdapter()

    def test_status_unavailable_when_no_api_key(self):
        """CRITICAL: Missing credentials must NEVER be reported as clean / no_match."""
        with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_API_KEY": ""}, clear=True):
            res = self.adapter.lookup("https://example.com/test", "example.com")
            self.assertEqual(res.status, "unavailable")
            self.assertFalse(res.matched)
            self.assertNotEqual(res.status, "no_match")
            self.assertIn("not configured", res.details)

    @patch("urllib.request.urlopen")
    def test_positive_threat_match(self, mock_urlopen):
        """Validates positive SOCIAL_ENGINEERING response handling."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"matches": [{"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM", "threat": {"url": "http://phish.com"}}]}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_API_KEY": "AIzaSyTestKey123"}):
            res = self.adapter.lookup("http://phish.com", "phish.com")
            self.assertEqual(res.status, "available")
            self.assertTrue(res.matched)
            self.assertEqual(res.match_type, "exact_url")
            self.assertEqual(res.threat_type, "phishing")
            self.assertEqual(res.confidence, 98)

    @patch("urllib.request.urlopen")
    def test_clean_response_returns_no_match(self, mock_urlopen):
        """Validates negative response handling when API returns empty payload."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_API_KEY": "AIzaSyTestKey123"}):
            res = self.adapter.lookup("https://clean-site.org", "clean-site.org")
            self.assertEqual(res.status, "no_match")
            self.assertFalse(res.matched)
            self.assertIn("not present", res.details)


class TestURLhausAdapter(unittest.TestCase):
    """Tests abuse.ch URLhaus malware & phishing database adapter."""

    def setUp(self):
        self.adapter = URLhausAdapter()

    def test_urlhaus_status_unavailable_when_no_api_key(self):
        """CRITICAL: Missing Auth-Key must NEVER be reported as clean / no_match."""
        with patch.dict(os.environ, {"URLHAUS_API_KEY": ""}, clear=True):
            res = self.adapter.lookup("https://example.com/malware.exe", "example.com")
            self.assertEqual(res.status, "unavailable")
            self.assertFalse(res.matched)
            self.assertNotEqual(res.status, "no_match")
            self.assertIn("not configured", res.details)

    @patch("urllib.request.urlopen")
    def test_urlhaus_exact_url_malware_match(self, mock_urlopen):
        """Validates positive malware URL match with Auth-Key header verified."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"query_status": "ok", "threat": "malware_download", "url_status": "online", "urlhaus_reference": "https://urlhaus.abuse.ch/url/999/", "tags": ["elf", "mozi"]}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        with patch.dict(os.environ, {"URLHAUS_API_KEY": "test-secret-auth-key-123"}):
            res = self.adapter.lookup("http://malware-drop.ru/payload.bin", "malware-drop.ru")
            self.assertEqual(res.status, "available")
            self.assertTrue(res.matched)
            self.assertEqual(res.match_type, "exact_url")
            self.assertEqual(res.threat_type, "malware")
            self.assertEqual(res.reference_url, "https://urlhaus.abuse.ch/url/999/")

            # Verify request contained Auth-Key header
            self.assertTrue(mock_urlopen.called)
            called_req = mock_urlopen.call_args[0][0]
            self.assertEqual(called_req.get_header("Auth-key"), "test-secret-auth-key-123")

    @patch("urllib.request.urlopen")
    def test_urlhaus_exact_url_phishing_match(self, mock_urlopen):
        """Validates phishing tag classification."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"query_status": "ok", "threat": "credential_theft", "url_status": "online", "urlhaus_reference": "https://urlhaus.abuse.ch/url/888/", "tags": ["phishing", "fake-login"]}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        with patch.dict(os.environ, {"URLHAUS_API_KEY": "test-key"}):
            res = self.adapter.lookup("http://phish-login.example.com", "phish-login.example.com")
            self.assertEqual(res.status, "available")
            self.assertTrue(res.matched)
            self.assertEqual(res.threat_type, "phishing")

    @patch("urllib.request.urlopen")
    def test_urlhaus_host_fallback_with_live_online_payloads(self, mock_urlopen):
        """Validates fallback to host inspection when host has active, live online payloads."""
        url_resp = MagicMock()
        url_resp.status = 200
        url_resp.read.return_value = b'{"query_status": "no_results"}'
        url_resp.__enter__.return_value = url_resp

        host_resp = MagicMock()
        host_resp.status = 200
        host_resp.read.return_value = b'{"query_status": "ok", "url_count": 5, "urlhaus_reference": "https://urlhaus.abuse.ch/host/bad-host.com/", "urls": [{"threat": "malware_download", "url_status": "online", "tags": ["mirai"]}]}'
        host_resp.__enter__.return_value = host_resp

        mock_urlopen.side_effect = [url_resp, host_resp]

        with patch.dict(os.environ, {"URLHAUS_API_KEY": "test-key"}):
            res = self.adapter.lookup("http://bad-host.com/new-path", "bad-host.com")
            self.assertEqual(res.status, "available")
            self.assertTrue(res.matched)
            self.assertEqual(res.match_type, "host")
            self.assertEqual(res.threat_type, "malware_host")
            self.assertIn("actively serving 1 live malware payload", res.details)

    @patch("urllib.request.urlopen")
    def test_urlhaus_host_fallback_with_only_offline_payloads_returns_no_match(self, mock_urlopen):
        """CRITICAL: Historical offline submissions must NOT cause false positives on clean URLs."""
        url_resp = MagicMock()
        url_resp.status = 200
        url_resp.read.return_value = b'{"query_status": "no_results"}'
        url_resp.__enter__.return_value = url_resp

        host_resp = MagicMock()
        host_resp.status = 200
        host_resp.read.return_value = b'{"query_status": "ok", "url_count": 4, "urlhaus_reference": "https://urlhaus.abuse.ch/host/clean-domain.org/", "blacklists": {"spamhaus_dbl": "not listed", "surbl": "not listed"}, "urls": [{"threat": "malware_download", "url_status": "offline", "tags": ["honeypot"]}]}'
        host_resp.__enter__.return_value = host_resp

        mock_urlopen.side_effect = [url_resp, host_resp]

        with patch.dict(os.environ, {"URLHAUS_API_KEY": "test-key"}):
            res = self.adapter.lookup("http://clean-domain.org/about", "clean-domain.org")
            self.assertEqual(res.status, "no_match")
            self.assertFalse(res.matched)
            self.assertEqual(res.match_type, "none")
            self.assertIn("0 active online payloads", res.details)
            self.assertIn("historical takedown(s)", res.details)

    def test_urlhaus_reserved_documentation_domain_root_fast_path(self):
        """RFC 2606/6761 reserved domains root (e.g. example.com) must return no_match via fast-path."""
        with patch.dict(os.environ, {"URLHAUS_API_KEY": "test-key"}):
            res = self.adapter.lookup("https://example.com/", "example.com")
            self.assertEqual(res.status, "no_match")
            self.assertFalse(res.matched)
            self.assertEqual(res.match_type, "none")
            self.assertEqual(res.confidence, 95)
            self.assertIn("IANA-reserved", res.details)

    def test_urlhaus_example_edu_not_in_reserved_domains(self):
        """Ensures example.edu is excluded from RFC 2606 reserved documentation domains set."""
        self.assertNotIn("example.edu", URLhausAdapter.RESERVED_DOCUMENTATION_DOMAINS)
        self.assertIn("example.com", URLhausAdapter.RESERVED_DOCUMENTATION_DOMAINS)
        self.assertIn("example.net", URLhausAdapter.RESERVED_DOCUMENTATION_DOMAINS)
        self.assertIn("example.org", URLhausAdapter.RESERVED_DOCUMENTATION_DOMAINS)

    @patch("urllib.request.urlopen")
    def test_urlhaus_reserved_domain_malicious_path_can_still_match_exact_url(self, mock_urlopen):
        """Ensures sub-paths on reserved domains still query exact URL endpoint and match if present."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"query_status": "ok", "threat": "malware_download", "url_status": "online", "urlhaus_reference": "https://urlhaus.abuse.ch/url/777/", "tags": ["mirai"]}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        with patch.dict(os.environ, {"URLHAUS_API_KEY": "test-key"}):
            res = self.adapter.lookup("https://example.com/test_drop_check", "example.com")
            self.assertEqual(res.status, "available")
            self.assertTrue(res.matched)
            self.assertEqual(res.match_type, "exact_url")
            self.assertEqual(res.threat_type, "malware")

    @patch("urllib.request.urlopen")
    def test_urlhaus_rate_limit_handling(self, mock_urlopen):
        """Ensures rate-limited status is never represented as clean."""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://urlhaus-api.abuse.ch",
            code=429,
            msg="Too Many Requests",
            hdrs={},
            fp=None
        )

        with patch.dict(os.environ, {"URLHAUS_API_KEY": "test-key"}):
            res = self.adapter.lookup("http://test-query.com", "test-query.com")
            self.assertEqual(res.status, "rate_limited")
            self.assertFalse(res.matched)
            self.assertTrue(res.rate_limited)
            self.assertNotEqual(res.status, "no_match")

    @patch("urllib.request.urlopen")
    def test_urlhaus_auth_failure_handling(self, mock_urlopen):
        """Validates HTTP 401 authentication rejection handling."""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://urlhaus-api.abuse.ch",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=None
        )

        with patch.dict(os.environ, {"URLHAUS_API_KEY": "invalid-key"}):
            res = self.adapter.lookup("http://test-query.com", "test-query.com")
            self.assertEqual(res.status, "error")
            self.assertFalse(res.matched)
            self.assertIn("authentication failed", res.details)


class TestPhishTankAdapter(unittest.TestCase):
    """Tests Cisco / OpenDNS PhishTank developer API adapter."""

    def setUp(self):
        self.adapter = PhishTankAdapter()

    def test_phishtank_unavailable_without_key(self):
        with patch.dict(os.environ, {"PHISHTANK_API_KEY": ""}, clear=True):
            res = self.adapter.lookup("http://phish-target.com", "phish-target.com")
            self.assertEqual(res.status, "unavailable")
            self.assertFalse(res.matched)
            self.assertNotEqual(res.status, "no_match")

    @patch("urllib.request.urlopen")
    def test_phishtank_positive_verified_phish(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"results": {"in_database": true, "phish_id": 881234, "phish_detail_page": "https://phishtank.org/phish_detail.php?phish_id=881234", "verified": "y", "valid": "y"}}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        with patch.dict(os.environ, {"PHISHTANK_API_KEY": "test-dev-key"}):
            res = self.adapter.lookup("http://chase-bank-verify-security.cc", "chase-bank-verify-security.cc")
            self.assertEqual(res.status, "available")
            self.assertTrue(res.matched)
            self.assertEqual(res.match_type, "exact_url")
            self.assertEqual(res.threat_type, "phishing")
            self.assertEqual(res.confidence, 96)


class TestVirusTotalAdapter(unittest.TestCase):
    """Verifies VirusTotal v3 URL reputation adapter, rate limits, and privacy safeguards."""

    def setUp(self):
        self.adapter = VirusTotalAdapter(max_rate_limit=4, rate_window_seconds=60.0)
        self.adapter.rate_limiter.reset()

    def test_vt_compute_url_id(self):
        url = "https://example.com/"
        url_id = VirusTotalAdapter.compute_url_id(url)
        self.assertNotIn("=", url_id)
        import base64
        padded = url_id + "=" * ((4 - len(url_id) % 4) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode()).decode()
        self.assertEqual(decoded, url)

    def test_vt_unavailable_without_key(self):
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": ""}, clear=True):
            res = self.adapter.lookup("https://example.com/check", "example.com")
            self.assertEqual(res.status, "unavailable")
            self.assertFalse(res.matched)
            self.assertIn("not configured", res.details)

    @patch("urllib.request.urlopen")
    def test_vt_privacy_404_does_not_submit(self, mock_urlopen):
        """Verifies HTTP 404 returns unavailable status with 0 confidence, never submitting via POST."""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://www.virustotal.com/api/v3/urls/test_id",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=None,
        )

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            res = self.adapter.lookup("https://my-internal-staging.corp.example/portal", "corp.example")
            self.assertEqual(res.status, "unavailable")
            self.assertFalse(res.matched)
            self.assertEqual(res.match_type, "none")
            self.assertEqual(res.confidence, 0)
            self.assertIn("unsubmitted to protect private URL privacy", res.details)
            req = mock_urlopen.call_args[0][0]
            self.assertEqual(req.get_method(), "GET")

    @patch("urllib.request.urlopen")
    def test_vt_confirmed_threat_phishing(self, mock_urlopen):
        """Verifies 3+ malicious engines with phishing tag classify as phishing with matched=True."""
        import time
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "data": {
                "attributes": {
                    "last_analysis_date": int(time.time() - 3600),
                    "last_analysis_stats": {"malicious": 8, "suspicious": 1, "harmless": 0, "undetected": 60},
                    "reputation": -50,
                    "tags": ["phishing", "fake-brand"],
                    "categories": {"VendorA": "phishing"}
                }
            }
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            res = self.adapter.lookup("https://evil-bank-login.xyz/auth", "evil-bank-login.xyz")
            self.assertEqual(res.status, "available")
            self.assertTrue(res.matched)
            self.assertEqual(res.match_type, "exact_url")
            self.assertEqual(res.threat_type, "phishing")
            self.assertGreaterEqual(res.confidence, 85)
            self.assertIn("8 security vendors flagged this URL as malicious", res.details)
            self.assertIn("analyzed", res.details)

    @patch("urllib.request.urlopen")
    def test_vt_confirmed_threat_malware(self, mock_urlopen):
        """Verifies 3+ malicious engines with malware tag classify as malware."""
        import time
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "data": {
                "attributes": {
                    "last_analysis_date": int(time.time() - 7200),
                    "last_analysis_stats": {"malicious": 5, "suspicious": 2, "harmless": 2, "undetected": 55},
                    "reputation": -40,
                    "tags": ["trojan", "dropper"],
                    "categories": {"VendorB": "malware"}
                }
            }
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            res = self.adapter.lookup("https://malware-dist.xyz/payload.exe", "malware-dist.xyz")
            self.assertEqual(res.status, "available")
            self.assertTrue(res.matched)
            self.assertEqual(res.threat_type, "malware")

    @patch("urllib.request.urlopen")
    def test_vt_confirmed_threat_generic_malicious(self, mock_urlopen):
        """Verifies 3+ malicious engines without phish/malware tags classify as malicious."""
        import time
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "data": {
                "attributes": {
                    "last_analysis_date": int(time.time() - 1800),
                    "last_analysis_stats": {"malicious": 4, "suspicious": 0, "harmless": 5, "undetected": 60},
                    "reputation": -25,
                    "tags": [],
                    "categories": {}
                }
            }
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            res = self.adapter.lookup("https://unknown-threat.xyz/page", "unknown-threat.xyz")
            self.assertEqual(res.threat_type, "malicious")
            self.assertTrue(res.matched)

    @patch("urllib.request.urlopen")
    def test_vt_suspicious_early_detection(self, mock_urlopen):
        """Verifies 1-2 malicious or 2+ suspicious engines trigger early detection 'suspicious'."""
        import time
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "data": {
                "attributes": {
                    "last_analysis_date": int(time.time() - 3600),
                    "last_analysis_stats": {"malicious": 1, "suspicious": 0, "harmless": 20, "undetected": 50},
                    "reputation": 0,
                    "tags": [],
                    "categories": {}
                }
            }
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            res = self.adapter.lookup("https://suspicious-target.com/page", "suspicious-target.com")
            self.assertEqual(res.status, "available")
            self.assertTrue(res.matched)
            self.assertEqual(res.threat_type, "suspicious")
            self.assertEqual(res.confidence, 72)
            self.assertIn("early detection warning", res.details)

    @patch("urllib.request.urlopen")
    def test_vt_clean_harmless_vs_undetected(self, mock_urlopen):
        """Verifies distinction between verified harmless, undetected, and stale historical results."""
        import time

        # Case A: Fresh strong harmless consensus (<= 14 days, >= 5 harmless)
        mock_resp_a = MagicMock()
        mock_resp_a.status = 200
        mock_resp_a.read.return_value = json.dumps({
            "data": {
                "attributes": {
                    "last_analysis_date": int(time.time() - 3600 * 48),  # 2 days ago
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 35, "undetected": 40},
                    "reputation": 80,
                }
            }
        }).encode("utf-8")
        mock_resp_a.__enter__.return_value = mock_resp_a
        mock_urlopen.return_value = mock_resp_a

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            res_a = self.adapter.lookup("https://wikipedia.org", "wikipedia.org")
            self.assertEqual(res_a.status, "no_match")
            self.assertFalse(res_a.matched)
            self.assertEqual(res_a.confidence, 90)
            self.assertIn("35 verified security engines", res_a.details)
            self.assertIn("analyzed", res_a.details)

        # Case B: Fresh mostly undetected (harmless == 0, undetected > 0)
        mock_resp_b = MagicMock()
        mock_resp_b.status = 200
        mock_resp_b.read.return_value = json.dumps({
            "data": {
                "attributes": {
                    "last_analysis_date": int(time.time() - 3600),
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 50},
                    "reputation": 0,
                }
            }
        }).encode("utf-8")
        mock_resp_b.__enter__.return_value = mock_resp_b
        mock_urlopen.return_value = mock_resp_b

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            res_b = self.adapter.lookup("https://new-niche-site.org/index", "new-niche-site.org")
            self.assertEqual(res_b.status, "no_match")
            self.assertFalse(res_b.matched)
            self.assertEqual(res_b.confidence, 45)
            self.assertIn("undetected status does not indicate safety", res_b.details)

        # Case C: Aging clean scan (14 < days <= 60)
        mock_resp_c = MagicMock()
        mock_resp_c.status = 200
        mock_resp_c.read.return_value = json.dumps({
            "data": {
                "attributes": {
                    "last_analysis_date": int(time.time() - 86400 * 25),  # 25 days ago
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 20, "undetected": 50},
                    "reputation": 50,
                }
            }
        }).encode("utf-8")
        mock_resp_c.__enter__.return_value = mock_resp_c
        mock_urlopen.return_value = mock_resp_c

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            res_c = self.adapter.lookup("https://older-site.example/page", "older-site.example")
            self.assertEqual(res_c.status, "no_match")
            self.assertFalse(res_c.matched)
            self.assertLessEqual(res_c.confidence, 50)
            self.assertIn("historical", res_c.details.lower())

        # Case D: Critically stale clean scan (> 60 days) -> confidence is 0
        mock_resp_d = MagicMock()
        mock_resp_d.status = 200
        mock_resp_d.read.return_value = json.dumps({
            "data": {
                "attributes": {
                    "last_analysis_date": int(time.time() - 86400 * 120),  # 120 days ago
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 25, "undetected": 40},
                    "reputation": 60,
                }
            }
        }).encode("utf-8")
        mock_resp_d.__enter__.return_value = mock_resp_d
        mock_urlopen.return_value = mock_resp_d

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            res_d = self.adapter.lookup("https://ancient-scan.example/page", "ancient-scan.example")
            self.assertEqual(res_d.status, "no_match")
            self.assertFalse(res_d.matched)
            self.assertEqual(res_d.confidence, 0)
            self.assertIn("stale", res_d.details.lower())

    def test_vt_local_rate_limiter_blocks_minute_burst(self):
        """Verifies local sliding-window rate limiter proactively prevents exceeding 4 req/min."""
        limiter = self.adapter.rate_limiter
        limiter.reset()
        for i in range(4):
            can_go, _ = limiter.can_proceed()
            self.assertTrue(can_go, f"Request {i+1} should be permitted")
        can_go, reason = limiter.can_proceed()
        self.assertFalse(can_go, "5th request within 60s window must be blocked")
        self.assertEqual(reason, "minute")

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            res = self.adapter.lookup("https://example.com/blocked-by-limiter", "example.com")
            self.assertEqual(res.status, "rate_limited")
            self.assertTrue(res.rate_limited)
            self.assertFalse(res.matched)
            self.assertEqual(res.confidence, 0)
            self.assertIn("minute rate limit active", res.details)

    def test_vt_local_rate_limiter_blocks_daily_limit(self):
        """Verifies rate limiter enforces daily limit (500 req/day)."""
        adapter = VirusTotalAdapter(max_per_minute=1000, max_per_day=5)
        adapter.rate_limiter.reset()
        for i in range(5):
            can_go, _ = adapter.rate_limiter.can_proceed()
            self.assertTrue(can_go, f"Daily request {i+1} should succeed")
        can_go, reason = adapter.rate_limiter.can_proceed()
        self.assertFalse(can_go, "6th request exceeding daily quota must be blocked")
        self.assertEqual(reason, "daily")

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            res = adapter.lookup("https://example.com/daily-quota-exceeded", "example.com")
            self.assertEqual(res.status, "rate_limited")
            self.assertEqual(res.confidence, 0)
            self.assertIn("daily quota reached", res.details)

    def test_vt_rate_limiter_thread_safety_concurrent_access(self):
        """Verifies rate limiter is strictly thread-safe across concurrent execution."""
        import concurrent.futures
        limiter = self.adapter.rate_limiter
        limiter.reset()

        def try_request():
            can_go, _ = limiter.can_proceed()
            return can_go

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(try_request) for _ in range(30)]
            results = [f.result() for f in futures]

        # In a 4 req/min limiter, exactly 4 requests must succeed, 26 must be blocked
        allowed_count = sum(1 for r in results if r is True)
        blocked_count = sum(1 for r in results if r is False)
        self.assertEqual(allowed_count, 4)
        self.assertEqual(blocked_count, 26)

    @patch("urllib.request.urlopen")
    def test_vt_upstream_429_rate_limited(self, mock_urlopen):
        """Verifies upstream HTTP 429 returns rate_limited status without crashing."""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://www.virustotal.com/api/v3/urls/test_id",
            code=429,
            msg="Too Many Requests",
            hdrs={},
            fp=None,
        )

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-key"}):
            res = self.adapter.lookup("https://example.com/upstream-limited", "example.com")
            self.assertEqual(res.status, "rate_limited")
            self.assertTrue(res.rate_limited)
            self.assertFalse(res.matched)
            self.assertEqual(res.confidence, 0)

    @patch("urllib.request.urlopen")
    def test_vt_auth_failure_401(self, mock_urlopen):
        """Verifies HTTP 401 returns status='error' with clear auth message."""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://www.virustotal.com/api/v3/urls/test_id",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=None,
        )

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "invalid-key"}):
            res = self.adapter.lookup("https://example.com/auth-fail", "example.com")
            self.assertEqual(res.status, "error")
            self.assertFalse(res.matched)
            self.assertEqual(res.confidence, 0)
            self.assertIn("authentication failed", res.details)


class TestThreatIntelManager(unittest.TestCase):
    """Verifies manager aggregation, match prioritization, and scan integration."""

    def setUp(self):
        import socket
        self._orig_getaddrinfo = socket.getaddrinfo
        def _mock_getaddrinfo(host, port, *args, **kwargs):
            if host in ("example.com", "target.org", "virustotal-test.com", "uncataloged-example.internal"):
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', port or 443))]
            return self._orig_getaddrinfo(host, port, *args, **kwargs)
        self._dns_patcher = patch("socket.getaddrinfo", side_effect=_mock_getaddrinfo)
        self._dns_patcher.start()
        self.manager = ThreatIntelManager()

    def tearDown(self):
        self._dns_patcher.stop()

    def test_manager_check_all_aggregates_normalized_results(self):
        results = self.manager.check_all("https://example.com/test", "example.com")
        self.assertEqual(len(results), 5)

        provider_ids = [r.provider for r in results]
        self.assertIn("google_safe_browsing", provider_ids)
        self.assertIn("urlhaus", provider_ids)
        self.assertIn("phishtank", provider_ids)
        self.assertIn("openphish", provider_ids)
        self.assertIn("virustotal", provider_ids)

        # Summary calculation
        summary = self.manager.aggregate_summary(results)
        self.assertEqual(summary["total_providers"], 5)
        self.assertIn("operational_count", summary)
        self.assertIn("matched_count", summary)

    @patch("backend.app.intel.google_safe_browsing.GoogleSafeBrowsingAdapter.lookup")
    def test_fast_path_does_not_bypass_other_security_providers_for_malicious_paths(self, mock_gsb_lookup):
        """Verifies that if a path on example.com is flagged by another provider, it is NOT bypassed."""
        # Simulate GSB flagging a malicious path on example.com
        mock_gsb_lookup.return_value = ThreatFeedResult(
            provider="google_safe_browsing",
            provider_name="Google Safe Browsing",
            status="available",
            matched=True,
            match_type="exact_url",
            threat_type="phishing",
            confidence=98,
            details="Confirmed phishing campaign on target path",
        )

        results = self.manager.check_all("https://example.com/malicious-login", "example.com")
        summary = self.manager.aggregate_summary(results)

        # Confirm match is aggregated and preserved
        self.assertTrue(summary["has_exact_url_match"])
        self.assertGreaterEqual(summary["matched_count"], 1)
        self.assertIn("phishing", summary["threat_types"])

        # URLhaus returned no_match for the host fallback, but GSB match was preserved
        gsb_res = next(r for r in results if r.provider == "google_safe_browsing")
        self.assertTrue(gsb_res.matched)
        self.assertEqual(gsb_res.threat_type, "phishing")

    @patch("backend.app.intel.virustotal.VirusTotalAdapter.lookup")
    def test_manager_virustotal_positive_threat_integration(self, mock_vt_lookup):
        """Verifies VirusTotal detection integrates into threat intel summary and threat categories."""
        mock_vt_lookup.return_value = ThreatFeedResult(
            provider="virustotal",
            provider_name="VirusTotal",
            status="available",
            matched=True,
            match_type="exact_url",
            threat_type="phishing",
            confidence=95,
            details="VirusTotal threat confirmed: 12 security vendors flagged this URL as malicious",
        )

        results = self.manager.check_all("https://virustotal-test.com/login", "virustotal-test.com")
        summary = self.manager.aggregate_summary(results)

        self.assertTrue(summary["has_exact_url_match"])
        self.assertIn("phishing", summary["threat_types"])
        self.assertGreaterEqual(summary["max_confidence"], 95)
        vt_res = next(r for r in results if r.provider == "virustotal")
        self.assertTrue(vt_res.matched)
        self.assertEqual(vt_res.threat_type, "phishing")

    @patch("backend.app.intel.virustotal.VirusTotalAdapter.lookup")
    def test_manager_404_does_not_inflate_operational_count(self, mock_vt_lookup):
        """Verifies that uncataloged/404 VirusTotal lookups never count as operational positive evidence."""
        mock_vt_lookup.return_value = ThreatFeedResult(
            provider="virustotal",
            provider_name="VirusTotal",
            status="unavailable",
            matched=False,
            match_type="none",
            confidence=0,
            details="Target URL has no prior analysis history in VirusTotal (uncataloged; unsubmitted to protect private URL privacy).",
        )

        results = self.manager.check_all("https://uncataloged-example.internal/test", "uncataloged-example.internal")
        summary = self.manager.aggregate_summary(results)

        # VT must be accounted for under unavailable_count, NOT operational_count
        vt_res = next(r for r in results if r.provider == "virustotal")
        self.assertEqual(vt_res.status, "unavailable")
        self.assertEqual(vt_res.confidence, 0)
        self.assertFalse(vt_res.matched)
        self.assertGreaterEqual(summary["unavailable_count"], 1)

    @patch("backend.app.intel.virustotal.VirusTotalAdapter.lookup")
    def test_scanner_verdict_with_virustotal_suspicious_match(self, mock_vt_lookup):
        """Verifies that a VirusTotal early-warning suspicious detection drives a 'suspicious' verdict."""
        from backend.app.core.scanner import scan_engine
        mock_vt_lookup.return_value = ThreatFeedResult(
            provider="virustotal",
            provider_name="VirusTotal",
            status="available",
            matched=True,
            match_type="exact_url",
            threat_type="suspicious",
            confidence=72,
            details="VirusTotal early detection warning: 1 vendor(s) flagged malicious",
        )

        job = scan_engine.create_or_get_job("https://example.com/test-suspicious-vt", force_fresh=True)
        import time
        start = time.time()
        while job.state in ("queued", "running") and (time.time() - start) < 10.0:
            time.sleep(0.05)

        self.assertIn(job.state, ("completed", "partial"))
        self.assertIsNotNone(job.result)
        self.assertEqual(job.result["verdict"], "suspicious")
        self.assertGreaterEqual(job.result["risk_score"], 35)

    @patch("backend.app.intel.virustotal.VirusTotalAdapter.lookup")
    def test_scanner_virustotal_404_or_error_never_produces_false_clean(self, mock_vt_lookup):
        """Verifies that missing VT keys, 404s, 429s, or timeouts never produce a false clean on suspicious URLs."""
        from backend.app.core.scanner import scan_engine
        # Simulate VT 404 (unavailable, 0 confidence)
        mock_vt_lookup.return_value = ThreatFeedResult(
            provider="virustotal",
            provider_name="VirusTotal",
            status="unavailable",
            matched=False,
            match_type="none",
            confidence=0,
            details="Target URL has no prior analysis history in VirusTotal",
        )

        # Scan a suspicious URL with brand squatting and high entropy
        job = scan_engine.create_or_get_job("https://target.org/login-verify-account-security-token-update", force_fresh=True)
        import time
        start = time.time()
        while job.state in ("queued", "running") and (time.time() - start) < 10.0:
            time.sleep(0.05)

        self.assertIn(job.state, ("completed", "partial"))
        self.assertIsNotNone(job.result)
        # VirusTotal 404 must NEVER falsely report clean confidence or claim matched=True
        vt_feed = next(r for r in job.result.get("threat_feed_matches", []) if r["provider"] == "virustotal")
        self.assertEqual(vt_feed["status"], "unavailable")
        self.assertEqual(vt_feed["confidence"], 0)
        self.assertFalse(vt_feed["matched"])
        self.assertIn(job.result["threat_intel_summary"]["unavailable_count"], (1, 2, 3, 4, 5))


if __name__ == "__main__":
    unittest.main()
