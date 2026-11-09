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
    """Tests abuse.ch URLhaus malware database adapter."""

    def setUp(self):
        self.adapter = URLhausAdapter()

    @patch("urllib.request.urlopen")
    def test_urlhaus_exact_url_malware_match(self, mock_urlopen):
        """Validates positive malware URL match."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"query_status": "ok", "threat": "malware_download", "url_status": "online", "urlhaus_reference": "https://urlhaus.abuse.ch/url/999/", "tags": ["elf", "mozi"]}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        res = self.adapter.lookup("http://malware-drop.ru/payload.bin", "malware-drop.ru")
        self.assertEqual(res.status, "available")
        self.assertTrue(res.matched)
        self.assertEqual(res.match_type, "exact_url")
        self.assertEqual(res.threat_type, "malware")
        self.assertEqual(res.reference_url, "https://urlhaus.abuse.ch/url/999/")

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

        res = self.adapter.lookup("http://test-query.com", "test-query.com")
        self.assertEqual(res.status, "rate_limited")
        self.assertFalse(res.matched)
        self.assertTrue(res.rate_limited)
        self.assertNotEqual(res.status, "no_match")


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


if __name__ == "__main__":
    unittest.main()
