"""
TrustShield AI Security & Backend Verification Test Suite
Tests SSRF controls, URL normalization, duplicate handling, scan job state machine,
module statuses, and failure resilience.
"""

import unittest
import time
import socket
import unittest.mock
from backend.app.security.ssrf import SSRFValidator, SSRFSecurityException
from backend.app.core.url_normalizer import URLNormalizer
from backend.app.core.scanner import ScanEngine, ScanJob

class TestSSRFAndSecurityControls(unittest.TestCase):
    """Verifies strict SSRF prevention rules."""

    def test_permit_only_http_and_https(self):
        """Rejects non-HTTP/HTTPS protocols."""
        disallowed_schemes = [
            "file:///etc/passwd",
            "gopher://127.0.0.1:70/",
            "ftp://files.example.com/",
            "data:text/html,<script>alert(1)</script>",
            "javascript:void(0)",
            "dict://127.0.0.1:11211/",
        ]
        for url in disallowed_schemes:
            with self.subTest(url=url):
                with self.assertRaises(SSRFSecurityException) as ctx:
                    SSRFValidator.validate_url(url)
                self.assertEqual(ctx.exception.code, "INVALID_SCHEME")

    def test_reject_embedded_credentials(self):
        """Rejects URLs containing username or password tokens."""
        cred_urls = [
            "http://admin:secret@example.com/",
            "https://user:password@target.org/path",
            "http://api_key:@example.com/data",
        ]
        for url in cred_urls:
            with self.subTest(url=url):
                with self.assertRaises(SSRFSecurityException) as ctx:
                    SSRFValidator.validate_url(url)
                self.assertEqual(ctx.exception.code, "CREDENTIALS_DISALLOWED")

    def test_reject_localhost_and_internal_hostnames(self):
        """Blocks localhost and cloud metadata hostnames."""
        forbidden_hosts = [
            "http://localhost/",
            "http://localhost:80/",
            "http://sub.localhost/",
            "http://metadata.google.internal/",
            "http://metadata.internal/",
            "http://169.254.169.254/",
        ]
        for url in forbidden_hosts:
            with self.subTest(url=url):
                with self.assertRaises(SSRFSecurityException) as ctx:
                    SSRFValidator.validate_url(url)
                self.assertIn(ctx.exception.code, ("FORBIDDEN_HOST", "PRIVATE_IP_BLOCKED", "DNS_REBINDING_BLOCKED"))

    def test_reject_private_and_reserved_ips(self):
        """Blocks private RFC 1918, link-local, loopback, and broadcast IPv4 & IPv6 addresses."""
        blocked_ips = [
            "http://127.0.0.1/",
            "http://127.0.0.2/",
            "http://10.0.0.1/",
            "http://10.254.254.254/",
            "http://172.16.0.1/",
            "http://172.31.255.255/",
            "http://192.168.1.1/",
            "http://192.168.100.50/",
            "http://169.254.169.254/",
            "http://0.0.0.0/",
            "http://[::1]/",
            "http://[fe80::1]/",
            "http://[fc00::1]/",
        ]
        for url in blocked_ips:
            with self.subTest(url=url):
                with self.assertRaises(SSRFSecurityException) as ctx:
                    SSRFValidator.validate_url(url)
                self.assertIn(ctx.exception.code, ("PRIVATE_IP_BLOCKED", "DNS_REBINDING_BLOCKED", "FORBIDDEN_HOST"))

    def test_reject_unsafe_ports(self):
        """Permits only standard web ports (80, 443) and blocks dangerous service ports."""
        unsafe_ports = [
            "http://example.com:22/",     # SSH
            "http://example.com:25/",     # SMTP
            "http://example.com:3306/",   # MySQL
            "http://example.com:5432/",   # PostgreSQL
            "http://example.com:6379/",   # Redis
            "http://example.com:2375/",   # Docker daemon
            "http://example.com:8080/",   # Non-standard proxy
        ]
        for url in unsafe_ports:
            with self.subTest(url=url):
                with self.assertRaises(SSRFSecurityException) as ctx:
                    SSRFValidator.validate_url(url)
                self.assertEqual(ctx.exception.code, "FORBIDDEN_PORT")

    def test_malformed_urls(self):
        """Properly rejects malformed and empty URLs."""
        invalid_urls = [
            "",
            "   ",
            "http://",
            "://missing-scheme.com",
            "https://",
        ]
        for url in invalid_urls:
            with self.subTest(url=url):
                with self.assertRaises((SSRFSecurityException, ValueError)):
                    SSRFValidator.validate_url(url)


class TestURLNormalizationAndDeduplication(unittest.TestCase):
    """Verifies canonicalization and deduplication logic."""

    def test_canonicalize_equivalent_urls(self):
        """Ensures semantically equivalent URLs produce identical canonical strings and hashes."""
        url1 = "https://EXAMPLE.COM:443/auth/login?b=2&a=1#section"
        url2 = "https://example.com/auth/login?a=1&b=2"

        can1, hash1, meta1 = URLNormalizer.canonicalize(url1)
        can2, hash2, meta2 = URLNormalizer.canonicalize(url2)

        self.assertEqual(can1, can2)
        self.assertEqual(hash1, hash2)
        self.assertEqual(meta1["domain"], "example.com")
        self.assertEqual(meta1["path"], "/auth/login")

    def test_domain_and_subdomain_extraction(self):
        """Correctly parses domains and subdomain depth."""
        _, _, meta = URLNormalizer.canonicalize("https://secure.banking.portal.example.com/")
        self.assertEqual(meta["domain"], "secure.banking.portal.example.com")
        self.assertEqual(meta["root_domain"], "example.com")
        self.assertEqual(meta["subdomains"], "secure.banking.portal")
        self.assertEqual(meta["subdomain_count"], 3)


class TestScanJobLifecycleAndState(unittest.TestCase):
    """Tests the asynchronous scan engine state machine, module statuses, and deduplication."""

    def setUp(self):
        self.engine = ScanEngine(max_workers=2)
        # Mock DNS resolution for external public domains used in offline/sandboxed lifecycle tests
        self._orig_getaddrinfo = socket.getaddrinfo
        def _mock_getaddrinfo(host, port, *args, **kwargs):
            if host in ("github.com", "example.com", "target.org", "files.example.com"):
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('140.82.121.4', port or 443))]
            return self._orig_getaddrinfo(host, port, *args, **kwargs)
        self._dns_patcher = unittest.mock.patch("socket.getaddrinfo", side_effect=_mock_getaddrinfo)
        self._dns_patcher.start()

    def tearDown(self):
        self._dns_patcher.stop()

    def test_naked_domain_normalization_in_scan_engine(self):
        """Regression test: URLs without scheme (e.g. example.com) must normalize to https:// without SSRF scheme violation."""
        job = self.engine.create_or_get_job("example.com", force_fresh=True)
        self.assertEqual(job.canonical_url, "https://example.com/")
        self.assertEqual(job.domain, "example.com")
        self.assertIn(job.state, ("queued", "running", "completed"))

    def test_naked_private_hosts_still_strictly_blocked(self):
        """Regression test: Naked host inputs attempting SSRF on internal/loopback destinations are strictly blocked."""
        forbidden = ["localhost", "127.0.0.1", "169.254.169.254", "metadata.google.internal"]
        for target in forbidden:
            with self.subTest(target=target):
                with self.assertRaises(SSRFSecurityException):
                    self.engine.create_or_get_job(target, force_fresh=True)

    def test_scan_states_and_module_statuses(self):
        """Verifies state transitions from queued -> running -> completed or partial."""
        # Using a reliable public target (github.com)
        job = self.engine.create_or_get_job(raw_url="https://github.com", force_fresh=True)
        self.assertIn(job.state, ("queued", "running", "completed"))
        self.assertTrue(job.scan_id.startswith("scan-"))
        self.assertTrue(job.request_id.startswith("req-"))

        # Wait for completion (bounded timeout)
        start = time.time()
        while job.state in ("queued", "running") and (time.time() - start) < 6.0:
            time.sleep(0.1)

        self.assertIn(job.state, ("completed", "partial"))
        self.assertEqual(job.progress_percent, 100)
        self.assertIsNotNone(job.started_at)
        self.assertIsNotNone(job.completed_at)

        # Module statuses must be populated
        self.assertIn(job.module_statuses["lexical"]["status"], ("completed", "running"))
        self.assertIn(job.module_statuses["ml"]["status"], ("completed", "running", "skipped"))
        self.assertIsNotNone(job.result)
        self.assertEqual(job.result["domain"], "github.com")

    def test_duplicate_request_deduplication(self):
        """Submitting the same canonical target reuses active/cached job."""
        job1 = self.engine.create_or_get_job("https://github.com/login?param=1", force_fresh=True)
        job2 = self.engine.create_or_get_job("https://github.com/login?param=1", force_fresh=False)

        self.assertEqual(job1.scan_id, job2.scan_id)

    def test_force_fresh_bypasses_cache(self):
        """force_fresh=True creates a distinct scan instance."""
        job1 = self.engine.create_or_get_job("https://github.com/about", force_fresh=True)
        # slight sleep to guarantee timestamp millisecond increment
        time.sleep(0.01)
        job2 = self.engine.create_or_get_job("https://github.com/about", force_fresh=True)

        self.assertNotEqual(job1.scan_id, job2.scan_id)

    def test_partial_failure_resilience(self):
        """Simulates non-responsive TLS/header probe without crashing lexical/ML modules."""
        job = ScanJob(
            scan_id="test-scan-partial",
            raw_url="https://non-existent-domain-test-123456.org",
            canonical_url="https://non-existent-domain-test-123456.org",
            domain="non-existent-domain-test-123456.org",
            options={"inspect_tls": True, "inspect_headers": True}
        )
        # Execute scan with dummy IP (which will fail TLS connection gracefully)
        self.engine._execute_scan(job, pinned_ip="198.51.100.1")

        # The job should conclude as partial or completed (not uncaught exception)
        self.assertIn(job.state, ("partial", "completed", "failed"))
        self.assertIsNotNone(job.completed_at)
        # Lexical and ML should have executed gracefully
        self.assertEqual(job.module_statuses["lexical"]["status"], "completed")
        self.assertIn(job.module_statuses["ml"]["status"], ("completed", "skipped"))


if __name__ == "__main__":
    unittest.main()
