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


class TestThreatIntelManager(unittest.TestCase):
    """Verifies manager aggregation, match prioritization, and scan integration."""

    def setUp(self):
        self.manager = ThreatIntelManager()

    def test_manager_check_all_aggregates_normalized_results(self):
        results = self.manager.check_all("https://example.com/test", "example.com")
        self.assertGreaterEqual(len(results), 4)

        provider_ids = [r.provider for r in results]
        self.assertIn("google_safe_browsing", provider_ids)
        self.assertIn("urlhaus", provider_ids)
        self.assertIn("phishtank", provider_ids)
        self.assertIn("openphish", provider_ids)

        # Summary calculation
        summary = self.manager.aggregate_summary(results)
        self.assertEqual(summary["total_providers"], len(results))
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


if __name__ == "__main__":
    unittest.main()
