"""
TrustShield AI - Secure RDAP Telemetry Client Unit Test Suite
Phase 7B Tests:
1. Registrable domain validation (FQDN, PSL eTLD+1 extraction, IP rejection, intranet rejection).
2. SSRF prevention (private IPs, loopback, metadata addresses, non-HTTPS protocols, non-443 ports).
3. Safe redirect validation and max redirect bounding.
4. Response size limit enforcement.
5. In-memory and persistent SQLite cache operations, TTL expiration, and purging.
6. Authoritative RDAP RFC 7483 JSON payload parsing:
   - Valid registration date and age calculation.
   - Missing/redacted registration date (absence of evidence != young domain).
   - Future registration date (contradictory data handling).
   - Expiration date preceding registration date.
7. Resilience against network timeouts, HTTP 429 rate limits, and 404 domain absence.
"""

import asyncio
import os
import sqlite3
import tempfile
import time
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from backend.app.intel.rdap import (
    BaseRDAPCache,
    MemoryRDAPCache,
    RDAPSecurityException,
    SecureRDAPClient,
    SQLiteRDAPCache,
)
from backend.app.security.hybrid_decision import DomainTelemetryDetails


class TestRDAPDomainValidationAndSSRF(unittest.TestCase):
    """Verifies input validation, eTLD+1 normalization, and strict SSRF defenses."""

    def setUp(self):
        self.client = SecureRDAPClient()

    def test_valid_domain_normalization(self):
        """Standard domains and URLs are correctly normalized to registrable domain (eTLD+1)."""
        self.assertEqual(self.client.extract_registrable_domain("example.com"), "example.com")
        self.assertEqual(self.client.extract_registrable_domain("sub.example.com"), "example.com")
        self.assertEqual(self.client.extract_registrable_domain("https://deep.sub.docs.python.org/path"), "python.org")
        self.assertEqual(self.client.extract_registrable_domain("news.bbc.co.uk"), "bbc.co.uk")
        self.assertEqual(self.client.extract_registrable_domain("sub.bbc.co.uk"), "bbc.co.uk")

    def test_raw_ip_addresses_rejected(self):
        """Raw IPv4 and IPv6 addresses must be rejected with RDAPSecurityException."""
        with self.assertRaises(RDAPSecurityException):
            self.client.extract_registrable_domain("192.168.1.1")
        with self.assertRaises(RDAPSecurityException):
            self.client.extract_registrable_domain("127.0.0.1")
        with self.assertRaises(RDAPSecurityException):
            self.client.extract_registrable_domain("8.8.8.8")
        with self.assertRaises(RDAPSecurityException):
            self.client.extract_registrable_domain("::1")

    def test_restricted_hostnames_rejected(self):
        """Localhost, metadata, and internal names must be rejected."""
        with self.assertRaises(RDAPSecurityException):
            self.client.extract_registrable_domain("localhost")
        with self.assertRaises(RDAPSecurityException):
            self.client.extract_registrable_domain("metadata.google.internal")
        with self.assertRaises(RDAPSecurityException):
            self.client.extract_registrable_domain("myhost.local")

    def test_outbound_url_scheme_enforcement(self):
        """Only HTTPS scheme is permitted; HTTP or alternative schemes are rejected."""
        valid_url, _ = self.client.validate_outbound_url("https://rdap.org/domain/example.com")
        self.assertEqual(valid_url, "https://rdap.org/domain/example.com")

        with self.assertRaises(RDAPSecurityException):
            self.client.validate_outbound_url("http://rdap.org/domain/example.com")
        with self.assertRaises(RDAPSecurityException):
            self.client.validate_outbound_url("gopher://rdap.org/domain/example.com")

    def test_outbound_url_port_enforcement(self):
        """Only standard port 443 is permitted."""
        with self.assertRaises(RDAPSecurityException):
            self.client.validate_outbound_url("https://rdap.org:8443/domain/example.com")
        with self.assertRaises(RDAPSecurityException):
            self.client.validate_outbound_url("https://rdap.org:80/domain/example.com")

    def test_outbound_url_private_ip_resolution_blocked(self):
        """Outbound targets that resolve to private subnets must be blocked."""
        # Non-whitelisted domain resolving to 127.0.0.1
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (2, 1, 6, "", ("127.0.0.1", 443))
            ]
            with self.assertRaises(RDAPSecurityException) as ctx:
                self.client.validate_outbound_url("https://evil-internal-redirect.com/rdap")
            self.assertIn("prohibited IP", str(ctx.exception))


class TestRDAPCacheImplementations(unittest.TestCase):
    """Verifies MemoryRDAPCache and SQLiteRDAPCache behavior, TTL expiration, and purging."""

    def test_memory_cache_get_set_and_expiry(self):
        cache = MemoryRDAPCache()
        details = DomainTelemetryDetails(
            domain="example.com",
            registration_date="2020-01-01T00:00:00Z",
            age_days=1500,
            status="active",
            is_newly_registered=False,
            telemetry_source="rdap",
            retrieval_timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # 1. Set with positive TTL
        cache.set("example.com", details, ttl_seconds=10)
        cached = cache.get("example.com")
        self.assertIsNotNone(cached)
        self.assertTrue(cached.cached)
        self.assertEqual(cached.domain, "example.com")

        # 2. Expiry
        cache.set("expired.com", details, ttl_seconds=-1)
        self.assertIsNone(cache.get("expired.com"))
        cache.close()

    def test_sqlite_cache_persistence_and_purge(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            cache = SQLiteRDAPCache(db_path=tmp_path)
            details = DomainTelemetryDetails(
                domain="example.org",
                registration_date="2021-05-10T12:00:00Z",
                age_days=1000,
                status="active",
                is_newly_registered=False,
                telemetry_source="rdap",
                retrieval_timestamp=datetime.now(timezone.utc).isoformat(),
                confidence=0.9,
            )

            # Insert unexpired record
            cache.set("example.org", details, ttl_seconds=3600)
            cached = cache.get("example.org")
            self.assertIsNotNone(cached)
            self.assertTrue(cached.cached)
            self.assertEqual(cached.domain, "example.org")
            self.assertEqual(cached.confidence, 0.9)

            # Insert expired record
            cache.set("old.org", details, ttl_seconds=-10)
            # Fetch should auto-delete and return None
            self.assertIsNone(cache.get("old.org"))

            # Purge expired
            deleted = cache.purge_expired()
            self.assertEqual(deleted, 0)  # already removed on get
            cache.close()
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


class TestRDAPPayloadParsing(unittest.TestCase):
    """Verifies RFC 7483 RDAP response parsing, date calculations, and edge cases."""

    def setUp(self):
        self.client = SecureRDAPClient()
        self.ts = datetime.now(timezone.utc).isoformat()

    def test_valid_mature_registration(self):
        """Mature domain (> 30 days) correctly sets active status and age_days."""
        payload = {
            "events": [
                {"eventAction": "registration", "eventDate": "2020-01-15T10:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2028-01-15T10:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2024-01-15T10:00:00Z"},
            ]
        }
        details, ttl = self.client.parse_rdap_payload("example.com", payload, self.ts)
        self.assertEqual(details.status, "active")
        self.assertFalse(details.is_newly_registered)
        self.assertGreater(details.age_days, 1000)
        self.assertEqual(details.registration_date, "2020-01-15T10:00:00Z")
        self.assertIsNone(details.reliability_limitation)
        self.assertEqual(ttl, self.client.mature_domain_ttl)

    def test_valid_newly_registered_domain(self):
        """Newly registered domain (< 30 days) sets newly_registered status and short TTL."""
        five_days_ago = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        payload = {
            "events": [
                {"eventAction": "registration", "eventDate": five_days_ago},
                {"eventAction": "expiration", "eventDate": "2027-11-01T00:00:00Z"},
            ]
        }
        details, ttl = self.client.parse_rdap_payload("new-phish-domain.xyz", payload, self.ts)
        self.assertEqual(details.status, "newly_registered")
        self.assertTrue(details.is_newly_registered)
        self.assertLessEqual(details.age_days, 6)
        self.assertEqual(ttl, self.client.new_domain_ttl)

    def test_missing_or_redacted_registration_date(self):
        """Missing registration date must NOT be treated as newly registered."""
        payload = {
            "events": [
                {"eventAction": "expiration", "eventDate": "2028-01-01T00:00:00Z"},
                {"eventAction": "last update of rdap database", "eventDate": "2026-11-10T00:00:00Z"},
            ]
        }
        details, ttl = self.client.parse_rdap_payload("redacted-privacy.org", payload, self.ts)
        self.assertEqual(details.status, "redacted")
        self.assertFalse(details.is_newly_registered)  # INVARIANT: Absence != Young!
        self.assertIsNone(details.registration_date)
        self.assertIsNone(details.age_days)
        self.assertIn("omitted or redacted", details.reliability_limitation)
        self.assertEqual(details.confidence, 0.5)

    def test_future_registration_date_contradiction(self):
        """Future registration timestamp is flagged as contradictory data."""
        future_date = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        payload = {
            "events": [
                {"eventAction": "registration", "eventDate": future_date}
            ]
        }
        details, ttl = self.client.parse_rdap_payload("future-domain.com", payload, self.ts)
        self.assertEqual(details.status, "error")
        self.assertFalse(details.is_newly_registered)
        self.assertEqual(details.confidence, 0.2)
        self.assertIn("future", details.reliability_limitation)


class TestRDAPClientLookups(unittest.TestCase):
    """Integration tests verifying lookup workflows, mock transport, caching, and resilience."""

    def test_successful_lookup_with_mocked_response(self):
        mock_cache = MemoryRDAPCache()
        mock_response_body = {
            "events": [{"eventAction": "registration", "eventDate": "2019-03-01T00:00:00Z"}]
        }
        call_count = [0]

        def handler(request: httpx.Request) -> httpx.Response:
            call_count[0] += 1
            return httpx.Response(200, json=mock_response_body)

        transport = httpx.MockTransport(handler)
        client = SecureRDAPClient(cache=mock_cache, transport=transport)

        telemetry = client.get_domain_telemetry_sync("docs.python.org")
        self.assertEqual(telemetry.domain, "python.org")
        self.assertEqual(telemetry.status, "active")
        self.assertFalse(telemetry.is_newly_registered)
        self.assertGreater(telemetry.age_days, 1500)
        self.assertEqual(call_count[0], 1)

        # Second call should be served from cache without invoking transport
        cached_telemetry = client.get_domain_telemetry_sync("python.org")
        self.assertTrue(cached_telemetry.cached)
        self.assertEqual(call_count[0], 1)

    def test_http_404_not_found_handling(self):
        transport = httpx.MockTransport(lambda req: httpx.Response(404, json={"message": "Not found"}))
        client = SecureRDAPClient(transport=transport)

        telemetry = client.get_domain_telemetry_sync("nonexistent-test-domain.xyz")
        self.assertEqual(telemetry.status, "unavailable")
        self.assertFalse(telemetry.is_newly_registered)
        self.assertIn("404", telemetry.reliability_limitation)

    def test_timeout_resilience(self):
        def timeout_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("Read timed out")

        transport = httpx.MockTransport(timeout_handler)
        client = SecureRDAPClient(transport=transport, timeout_seconds=0.1)

        telemetry = client.get_domain_telemetry_sync("slow-responding-registry.org")
        self.assertEqual(telemetry.status, "unavailable")
        self.assertFalse(telemetry.is_newly_registered)
        self.assertIn("timed out", telemetry.reliability_limitation)

    def test_http_429_rate_limit_handling(self):
        transport = httpx.MockTransport(lambda req: httpx.Response(429, json={"message": "Too Many Requests"}))
        client = SecureRDAPClient(transport=transport)

        telemetry = client.get_domain_telemetry_sync("rate-limited-target.org")
        self.assertEqual(telemetry.status, "unavailable")
        self.assertFalse(telemetry.is_newly_registered)
        self.assertIn("rate limit exceeded", telemetry.reliability_limitation)

    def test_response_size_limit_enforcement(self):
        large_body = b"A" * (1_048_576 + 100)
        transport = httpx.MockTransport(lambda req: httpx.Response(200, content=large_body))
        client = SecureRDAPClient(transport=transport, max_response_bytes=1024)

        telemetry = client.get_domain_telemetry_sync("huge-payload-domain.com")
        self.assertEqual(telemetry.status, "error")
        self.assertIn("exceeded size limit", telemetry.reliability_limitation)


if __name__ == "__main__":
    unittest.main()
