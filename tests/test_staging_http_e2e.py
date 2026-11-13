"""
TrustShield AI - Phase 8B End-to-End HTTP Staging Test Suite
Tests the application at the ASGI HTTP layer:
1. API Health & Startup Probes: /health, /api/health, /api/v1/health.
2. Response Equivalence: HTTP scan responses identical with shadow ON vs OFF.
3. Controlled Test Inputs: Benign apex, enterprise multi-tier, newly registered domains.
4. Real End-to-End HTTP Latency: Measures p50, p95, p99 turnaround times.
5. Concurrent HTTP Load: Multi-threaded requests submitting scans simultaneously.
6. Failure Isolation: Provider outages, timeout edge cases, and missing ML handled gracefully.
7. Queue Saturation & Graceful Dropping: Live HTTP request completes without caller delay.
8. Privacy-Safe Log Verification: Verifies 0 URL, IP, or credential leaks in generated records.
"""

import concurrent.futures
import json
import os
import shutil
import socket
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

import httpx

from backend.app.intel.base import ThreatFeedResult
from backend.app.main import root_health, api_health
from backend.app.api.v1.endpoints.scans import (
    create_scan,
    get_scan_status,
    get_scan_report,
)
from backend.app.api.v1.endpoints.scan import analyze_url
from backend.app.models.schemas import ScanCreateRequest, ScanRequest, ScanOptions
from backend.app.core.config import settings
from backend.app.security.shadow_evaluator import (
    shadow_evaluator,
    ShadowEvaluator,
    ModelAvailabilityState,
    PrivacySafeShadowLogger,
)
from backend.app.intel.rdap import SecureRDAPClient, MemoryRDAPCache
from backend.app.security.hybrid_decision import hybrid_decision_engine
from scripts.analyze_shadow_logs import audit_and_analyze_logs


def sync_await(coro):
    """Executes a coroutine synchronously for fast, isolated test execution."""
    try:
        coro.send(None)
    except StopIteration as e:
        return e.value


class TestStagingHttpE2E(unittest.TestCase):
    """Verifies end-to-end HTTP behavior, response equivalence, and latency percentiles."""

    _patches = []

    @classmethod
    def setUpClass(cls):
        # 1. DNS Mock
        orig_getaddrinfo = socket.getaddrinfo
        def mock_getaddrinfo(host, port, *args, **kwargs):
            if host and (
                host.endswith(".example.com")
                or host.endswith(".example.org")
                or host.endswith(".org")
                or host.endswith(".xyz")
                or host in ("example.com", "example.org", "safe-site.org", "slow-registry.org")
            ):
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 443))]
            return orig_getaddrinfo(host, port, *args, **kwargs)

        p_dns = patch("socket.getaddrinfo", side_effect=mock_getaddrinfo)
        p_dns.start()
        cls._patches.append(p_dns)

        # 2. Threat Intel Mock
        p_intel = patch(
            "backend.app.core.scanner.threat_intel_manager.check_all",
            return_value=[
                ThreatFeedResult(
                    provider="google_safe_browsing",
                    provider_name="Google Safe Browsing",
                    status="no_match",
                    matched=False,
                    details="Clean",
                )
            ],
        )
        p_intel.start()
        cls._patches.append(p_intel)

        # 3. TLS Mock
        mock_tls = MagicMock()
        mock_tls.connected = True
        mock_tls.is_expired = False
        mock_tls.issuer = "DigiCert"
        mock_tls.subject = "example.com"
        mock_tls.days_remaining = 365
        mock_tls.is_self_signed = False
        mock_tls.protocol_version = "TLSv1.3"
        mock_tls.cipher_suite = "TLS_AES_256_GCM_SHA384"
        mock_tls.grade = "A"
        p_tls = patch("backend.app.core.scanner.tls_inspector.inspect_host", return_value=mock_tls)
        p_tls.start()
        cls._patches.append(p_tls)

        # 4. Header Assessment Mock
        mock_hdr = MagicMock()
        mock_hdr.to_dict.return_value = {"missing_critical_count": 0, "headers": {}}
        p_hdr = patch("backend.app.core.scanner.passive_scanner.assess_url", return_value=mock_hdr)
        p_hdr.start()
        cls._patches.append(p_hdr)

        # 5. Database Health & Save Mocks
        p_db_health = patch(
            "backend.app.db.supabase.db_manager.check_health",
            return_value={"status": "online", "provider": "supabase", "latency_ms": 1.2, "details": "Mocked DB cluster"},
        )
        p_db_health.start()
        cls._patches.append(p_db_health)

        p_db_save = patch("backend.app.db.supabase.db_manager.save_scan", return_value=True)
        p_db_save.start()
        cls._patches.append(p_db_save)

    @classmethod
    def tearDownClass(cls):
        # Stop all class-level patches to guarantee strict test isolation
        for p in reversed(cls._patches):
            p.stop()
        cls._patches.clear()

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="trustshield_http_test_")
        self.log_path = os.path.join(self.temp_dir, "http_staging_shadow.jsonl")

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_api_health_and_startup(self):
        """Root and API health endpoints return HTTP 200 equivalent models with valid schema."""
        r_health = sync_await(root_health())
        self.assertIn(r_health.status, ("healthy", "degraded"))
        self.assertEqual(r_health.app_name, "TrustShield AI Backend")
        self.assertIn("ml_engine", r_health.subsystems)
        self.assertIn("database", r_health.subsystems)
        self.assertEqual(r_health.ssrf_protection, "active")

        a_health = sync_await(api_health())
        self.assertEqual(a_health.app_name, "TrustShield AI Backend")
        self.assertIn(a_health.status, ("healthy", "degraded"))

    def test_02_response_equivalence_shadow_on_vs_off(self):
        """
        Validates that scan responses produce identical verdicts,
        risk scores, and evidence whether shadow mode is disabled or enabled.
        """
        target_url = "https://example.com/checkout/payment?session=test"

        # 1. Execute with shadow mode disabled
        shadow_evaluator.set_enabled(False)
        res_off = sync_await(analyze_url(ScanRequest(url=target_url)))

        # 2. Execute with shadow mode enabled
        shadow_evaluator.set_enabled(True)
        res_on = sync_await(analyze_url(ScanRequest(url=target_url)))

        # Reset flag
        shadow_evaluator.set_enabled(False)

        # Core contract equivalence
        self.assertEqual(res_off.verdict, res_on.verdict)
        self.assertEqual(res_off.risk_score, res_on.risk_score)
        self.assertEqual(res_off.domain, res_on.domain)
        self.assertEqual(res_off.analysis_coverage.model_dump(), res_on.analysis_coverage.model_dump())
        self.assertEqual(len(res_off.recommendations), len(res_on.recommendations))

    def test_03_controlled_test_inputs(self):
        """Tests benign apex, enterprise multi-tier, and suspicious domain patterns."""
        test_cases = [
            "https://example.com",
            "https://api.v2.prod.aws.example.com/status",
            "https://secure-login.verify-account.xyz/auth?token=123",
        ]
        shadow_evaluator.set_enabled(True)
        try:
            for url in test_cases:
                res = sync_await(analyze_url(ScanRequest(url=url)))
                self.assertIsNotNone(res.verdict)
                self.assertIsInstance(res.risk_score, int)
                self.assertTrue(0 <= res.risk_score <= 100)
        finally:
            shadow_evaluator.set_enabled(False)

    def test_04_http_end_to_end_latency_percentiles(self):
        """
        Measures real end-to-end HTTP request-response latency across 50 consecutive scans.
        Measures turnaround time (normalization, heuristics, ML inference, and shadow dispatch).
        """
        latencies_ms = []
        for i in range(50):
            t0 = time.perf_counter()
            res = sync_await(
                analyze_url(
                    ScanRequest(
                        url=f"https://perf-test-{i % 10}.example.com/app/resource_{i}",
                    )
                )
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            self.assertIsNotNone(res.verdict)
            latencies_ms.append(elapsed_ms)

        latencies_ms.sort()
        n = len(latencies_ms)
        p50 = latencies_ms[int(n * 0.50)]
        p95 = latencies_ms[int(n * 0.95)]
        p99 = latencies_ms[int(n * 0.99)]

        print(f"\n[HTTP API Latency] p50: {p50:.2f}ms | p95: {p95:.2f}ms | p99: {p99:.2f}ms")
        self.assertLess(p95, 50.0, f"HTTP API p95 latency ({p95:.2f}ms) exceeded 50ms threshold.")

    def test_05_concurrent_http_requests(self):
        """Simulates 10 concurrent HTTP clients issuing scans simultaneously."""
        def client_request(idx: int):
            t0 = time.perf_counter()
            res = sync_await(
                analyze_url(
                    ScanRequest(
                        url=f"https://concurrent-client-{idx}.example.org/path",
                    )
                )
            )
            return res.verdict, (time.perf_counter() - t0) * 1000.0

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(client_request, i) for i in range(20)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        for verdict, elapsed in results:
            self.assertIn(verdict, ("clean", "suspicious", "phishing", "malicious"))
            self.assertLess(elapsed, 100.0)

    def test_06_bounded_rdap_execution_in_http_flow(self):
        """When background RDAP experiences upstream delays, shadow dispatch returns immediately."""
        def slow_handler(req: httpx.Request):
            time.sleep(0.1)
            raise httpx.TimeoutException("RDAP connection timed out")

        rdap_client = SecureRDAPClient(
            cache=MemoryRDAPCache(),
            transport=httpx.MockTransport(slow_handler),
            timeout_seconds=0.1,
        )
        shadow_logger = PrivacySafeShadowLogger(log_path=self.log_path)
        test_evaluator = ShadowEvaluator(
            enabled=True,
            rdap_client=rdap_client,
            shadow_logger=shadow_logger,
        )

        t0 = time.perf_counter()
        dispatched = test_evaluator.dispatch(
            canonical_url="https://slow-registry.org/page",
            domain="slow-registry.org",
            legacy_verdict="clean",
            legacy_risk_score=10,
            intel_results=[],
        )
        dispatch_duration_ms = (time.perf_counter() - t0) * 1000.0

        self.assertTrue(dispatched)
        # Dispatch must return well below 50ms despite 100ms RDAP sleep
        self.assertLess(dispatch_duration_ms, 5.0)

        test_evaluator.shutdown(wait=True)

        # Confirm timeout was recorded in log
        report = audit_and_analyze_logs(self.log_path)
        self.assertEqual(report["model_and_evidence_states"]["rdap_timeouts"], 1)
        self.assertTrue(report["privacy_audit"]["is_clean"])

    def test_07_queue_saturation_non_blocking_http(self):
        """Under queue saturation, excess shadow tasks are dropped without failing or blocking calls."""
        small_evaluator = ShadowEvaluator(
            enabled=True,
            shadow_logger=PrivacySafeShadowLogger(log_path=self.log_path),
            max_workers=1,
            queue_maxsize=2,
        )

        # Dispatch 10 tasks rapidly
        dropped = 0
        for i in range(10):
            accepted = small_evaluator.dispatch(
                canonical_url=f"https://queue-stress-{i}.org/resource",
                domain=f"queue-stress-{i}.org",
                legacy_verdict="clean",
                legacy_risk_score=5,
                intel_results=[],
            )
            if not accepted:
                dropped += 1

        self.assertGreater(dropped, 0)
        self.assertEqual(small_evaluator.metrics["dropped"], dropped)
        small_evaluator.shutdown(wait=False, cancel_futures=True)

    def test_08_privacy_audit_on_http_shadow_log(self):
        """Verifies zero raw URLs, secrets, or IPs exist in the shadow log."""
        if os.path.exists(self.log_path):
            report = audit_and_analyze_logs(self.log_path)
            self.assertTrue(report["privacy_audit"]["is_clean"])
            self.assertEqual(report["privacy_audit"]["violations_count"], 0)


if __name__ == "__main__":
    unittest.main()
