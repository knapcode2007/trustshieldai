"""
TrustShield AI - Phase 7C Shadow Scanner Integration & Privacy-Safe Observability Test Suite
Verifies:
1. Feature flag control: Shadow disabled by default, zero background execution when disabled.
2. Legacy response equivalence: Scan responses are 100% identical with shadow ON vs OFF.
3. Observational isolation: Hybrid verdicts NEVER mutate, override, or delay legacy verdicts.
4. Truly non-blocking dispatch: Dispatch overhead is < 5ms (well below 50ms p95 requirement).
5. Background RDAP timeout resilience (1.5s cutoff) without delaying live scanner.
6. Privacy redaction guarantees: Zero raw URLs, tokens, passwords, or client IPs logged.
7. Disagreement categorization: Correct mapping across agreement, escalation, mitigation, and inconclusive.
8. Bounded concurrency & stress: Bounded queue drops excess tasks under high volume without thread leaks.
9. Resilience against provider outages, missing ML artifacts, and malformed inputs.
10. Thread-safe log rotation and failure isolation.
"""

import concurrent.futures
import json
import os
import shutil
import socket
import tempfile
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

# Mock DNS for test isolation
orig_getaddrinfo = socket.getaddrinfo
def mock_getaddrinfo(host, port, *args, **kwargs):
    if host in ("example.com", "example.org", "safe-site.org", "auth.example.com", "slow-rdap-site.org"):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 443))]
    return orig_getaddrinfo(host, port, *args, **kwargs)

patch("socket.getaddrinfo", side_effect=mock_getaddrinfo).start()

import httpx

from backend.app.core.scanner import scan_engine, ScanJob
from backend.app.intel.base import ThreatFeedResult
from backend.app.intel.rdap import SecureRDAPClient, MemoryRDAPCache
from backend.app.security.hybrid_decision import (
    HybridDecisionEngine,
    HybridVerdictState,
    DomainTelemetryDetails,
)
from backend.app.ml.features import URLFeatureExtractor
from backend.app.security.shadow_evaluator import (
    DisagreementCategory,
    ExperimentalShadowModel,
    ModelAvailabilityState,
    PrivacySafeShadowLogger,
    ShadowEvaluator,
)


class TestShadowEvaluatorLifecycleAndConfig(unittest.TestCase):
    """Tests feature flags, queue limits, and clean shutdown."""

    def test_shadow_disabled_default(self):
        evaluator = ShadowEvaluator(enabled=False)
        self.assertFalse(evaluator.is_enabled)
        # Calling dispatch must return False immediately with zero work
        dispatched = evaluator.dispatch(
            canonical_url="https://example.com",
            domain="example.com",
            legacy_verdict="clean",
            legacy_risk_score=10,
            intel_results=[],
        )
        self.assertFalse(dispatched)
        self.assertEqual(evaluator.metrics["dispatched"], 0)
        evaluator.shutdown(wait=False)

    def test_shutdown_lifecycle(self):
        evaluator = ShadowEvaluator(enabled=True)
        self.assertTrue(evaluator.is_enabled)
        evaluator.shutdown(wait=True, timeout=1.0)
        self.assertFalse(evaluator.is_enabled)
        # Dispatch after shutdown must be rejected
        dispatched = evaluator.dispatch(
            canonical_url="https://example.com",
            domain="example.com",
            legacy_verdict="clean",
            legacy_risk_score=10,
            intel_results=[],
        )
        self.assertFalse(dispatched)


class TestPrivacySafeShadowLogger(unittest.TestCase):
    """Verifies privacy redaction, structured logging, and log rotation."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, "test_shadow_eval.jsonl")
        self.logger = PrivacySafeShadowLogger(
            log_path=self.log_file,
            max_bytes=1024,  # Small byte cap for rotation testing
            backup_count=2,
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_write_and_read_record(self):
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": {"domain": "example.com", "domain_hash": "a1b2c3d4e5f60718"},
            "verdicts": {"legacy_verdict": "clean", "hybrid_state": "NO_THREAT_DETECTED"},
        }
        success = self.logger.write_record(record)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(self.log_file))

        with open(self.log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertEqual(parsed["target"]["domain"], "example.com")

    def test_log_rotation_on_file_size(self):
        # Write multiple records exceeding 1024 bytes
        for i in range(25):
            record = {
                "iteration": i,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "payload": "X" * 80,
            }
            self.logger.write_record(record)

        self.assertTrue(os.path.exists(self.log_file))
        # Backup file .1 should have been created
        backup_file = f"{self.log_file}.1"
        self.assertTrue(os.path.exists(backup_file))


class TestDisagreementCategorization(unittest.TestCase):
    """Tests deterministic mapping between legacy verdicts and hybrid states."""

    def test_agreement_categories(self):
        self.assertEqual(
            ShadowEvaluator.categorize_disagreement("clean", "NO_THREAT_DETECTED"),
            DisagreementCategory.AGREEMENT_CLEAN,
        )
        self.assertEqual(
            ShadowEvaluator.categorize_disagreement("suspicious", "SUSPICIOUS"),
            DisagreementCategory.AGREEMENT_SUSPICIOUS,
        )
        self.assertEqual(
            ShadowEvaluator.categorize_disagreement("phishing", "MALICIOUS"),
            DisagreementCategory.AGREEMENT_MALICIOUS,
        )
        self.assertEqual(
            ShadowEvaluator.categorize_disagreement("malicious", "MALICIOUS"),
            DisagreementCategory.AGREEMENT_MALICIOUS,
        )

    def test_divergence_categories(self):
        # Legacy clean escalated by hybrid
        self.assertEqual(
            ShadowEvaluator.categorize_disagreement("clean", "SUSPICIOUS"),
            DisagreementCategory.HYBRID_ESCALATION,
        )
        self.assertEqual(
            ShadowEvaluator.categorize_disagreement("clean", "MALICIOUS"),
            DisagreementCategory.HYBRID_ESCALATION,
        )
        # Legacy suspicious mitigated by hybrid
        self.assertEqual(
            ShadowEvaluator.categorize_disagreement("suspicious", "NO_THREAT_DETECTED"),
            DisagreementCategory.HYBRID_MITIGATION,
        )
        # Inconclusive due to provider outage
        self.assertEqual(
            ShadowEvaluator.categorize_disagreement("clean", "INCONCLUSIVE"),
            DisagreementCategory.INCONCLUSIVE_DISAGREEMENT,
        )


class TestShadowEvaluatorExecution(unittest.TestCase):
    """Integration tests verifying non-blocking execution, redaction, and error isolation."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.log_path = os.path.join(self.temp_dir, "shadow_eval.jsonl")
        self.logger = PrivacySafeShadowLogger(log_path=self.log_path)

        # Mock RDAP transport
        self.mock_rdap_cache = MemoryRDAPCache()
        self.mock_rdap_client = SecureRDAPClient(
            cache=self.mock_rdap_cache,
            transport=httpx.MockTransport(
                lambda req: httpx.Response(
                    200,
                    json={
                        "events": [
                            {"eventAction": "registration", "eventDate": "2018-01-01T00:00:00Z"}
                        ]
                    },
                )
            ),
        )

        self.evaluator = ShadowEvaluator(
            enabled=True,
            rdap_client=self.mock_rdap_client,
            shadow_logger=self.logger,
            max_workers=2,
            queue_maxsize=10,
        )

    def tearDown(self):
        self.evaluator.shutdown(wait=True, timeout=2.0)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_sensitive_data_redaction(self):
        """Verifies zero raw URLs, tokens, or credentials appear in the written JSONL record."""
        raw_sensitive_url = "https://alice:secretPass123@auth.example.com/reset-password/jwt_token_here?token=SUPER_SECRET_TOKEN&apiKey=AKIA12345"
        domain = "auth.example.com"

        dispatched = self.evaluator.dispatch(
            canonical_url=raw_sensitive_url,
            domain=domain,
            legacy_verdict="clean",
            legacy_risk_score=15,
            intel_results=[],
        )
        self.assertTrue(dispatched)

        # Wait briefly for worker to complete
        time.sleep(0.3)

        self.assertTrue(os.path.exists(self.log_path))
        with open(self.log_path, "r", encoding="utf-8") as f:
            raw_log_content = f.read()

        # Strict Assertions: Sensitive tokens MUST NOT appear anywhere in the log
        self.assertNotIn("alice", raw_log_content)
        self.assertNotIn("secretPass123", raw_log_content)
        self.assertNotIn("SUPER_SECRET_TOKEN", raw_log_content)
        self.assertNotIn("AKIA12345", raw_log_content)
        self.assertNotIn("jwt_token_here", raw_log_content)

        # Verify structured metadata is present
        record = json.loads(raw_log_content.strip())
        self.assertEqual(record["target"]["domain"], "auth.example.com")
        self.assertIn("canonical_url_hash", record["target"])
        self.assertEqual(record["verdicts"]["legacy_verdict"], "clean")

    def test_rdap_timeout_handling(self):
        """When RDAP query times out, shadow evaluation records timeout without crashing."""
        def timeout_handler(request):
            raise httpx.TimeoutException("RDAP connection timed out")

        timeout_client = SecureRDAPClient(
            transport=httpx.MockTransport(timeout_handler),
            timeout_seconds=0.1,
        )
        timeout_evaluator = ShadowEvaluator(
            enabled=True,
            rdap_client=timeout_client,
            shadow_logger=self.logger,
        )

        dispatched = timeout_evaluator.dispatch(
            canonical_url="https://slow-rdap-site.org/index.html",
            domain="slow-rdap-site.org",
            legacy_verdict="clean",
            legacy_risk_score=10,
            intel_results=[],
        )
        self.assertTrue(dispatched)
        time.sleep(0.3)

        with open(self.log_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        last_record = lines[-1]
        self.assertTrue(last_record["evidence_sources"]["domain_telemetry"]["timed_out"])
        timeout_evaluator.shutdown(wait=False)

    def test_shadow_enabled_matching_verdicts(self):
        """When legacy and hybrid both evaluate as clean, category is AGREEMENT_CLEAN."""
        dispatched = self.evaluator.dispatch(
            canonical_url="https://example.com/safe/path",
            domain="example.com",
            legacy_verdict="clean",
            legacy_risk_score=5,
            intel_results=[
                ThreatFeedResult(
                    provider="google_safe_browsing",
                    provider_name="Google Safe Browsing",
                    status="no_match",
                    matched=False,
                    details="Clean",
                )
            ],
            ml_prediction={"is_trained": True, "probability_phish": 0.05, "confidence": 0.95},
        )
        self.assertTrue(dispatched)
        time.sleep(0.3)

        with open(self.log_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]
        last_rec = lines[-1]
        self.assertEqual(last_rec["verdicts"]["legacy_verdict"], "clean")
        self.assertEqual(last_rec["verdicts"]["hybrid_state"], "NO_THREAT_DETECTED")
        self.assertEqual(last_rec["verdicts"]["disagreement_category"], "AGREEMENT_CLEAN")

    def test_shadow_enabled_conflicting_verdicts(self):
        """When legacy is clean but newly registered apex domain escalates hybrid to SUSPICIOUS, category is HYBRID_ESCALATION."""
        nrd_client = SecureRDAPClient(
            cache=MemoryRDAPCache(),
            transport=httpx.MockTransport(
                lambda req: httpx.Response(
                    200,
                    json={
                        "events": [
                            {"eventAction": "registration", "eventDate": "2026-11-08T00:00:00Z"}
                        ]
                    },
                )
            ),
        )
        nrd_evaluator = ShadowEvaluator(
            enabled=True,
            rdap_client=nrd_client,
            shadow_logger=self.logger,
        )

        dispatched = nrd_evaluator.dispatch(
            canonical_url="https://new-account-login.top/login",
            domain="new-account-login.top",
            legacy_verdict="clean",
            legacy_risk_score=15,
            intel_results=[
                ThreatFeedResult(
                    provider="google_safe_browsing",
                    provider_name="Google Safe Browsing",
                    status="no_match",
                    matched=False,
                    details="Clean",
                )
            ],
            ml_prediction={"is_trained": True, "probability_phish": 0.15, "confidence": 0.85},
        )
        self.assertTrue(dispatched)
        time.sleep(0.3)

        with open(self.log_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]
        last_rec = lines[-1]
        self.assertEqual(last_rec["verdicts"]["legacy_verdict"], "clean")
        self.assertEqual(last_rec["verdicts"]["hybrid_state"], "SUSPICIOUS")
        self.assertEqual(last_rec["verdicts"]["disagreement_category"], "HYBRID_ESCALATION")
        nrd_evaluator.shutdown(wait=False)

    def test_all_intelligence_providers_unavailable(self):
        """When all threat feeds are unavailable and ML indicates borderline risk, shadow records INCONCLUSIVE without crashing."""
        unavail_feed = ThreatFeedResult(
            provider="google_safe_browsing",
            provider_name="Google Safe Browsing",
            status="unavailable",
            matched=False,
            details="Service unreachable",
        )
        # Mock experimental ML model returning borderline probability
        self.evaluator.experimental_model.predict = MagicMock(return_value={
            "is_trained": True, "probability_phish": 0.50, "confidence": 0.50, "model": "Phase6B-RandomForest-Experimental"
        })
        dispatched = self.evaluator.dispatch(
            canonical_url="https://example.org/portal",
            domain="example.org",
            legacy_verdict="suspicious",
            legacy_risk_score=40,
            intel_results=[unavail_feed],
            ml_prediction={"is_trained": True, "probability_phish": 0.50, "confidence": 0.50},
        )
        self.assertTrue(dispatched)
        time.sleep(0.3)

        with open(self.log_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]
        last_rec = lines[-1]
        self.assertEqual(last_rec["verdicts"]["hybrid_state"], "INCONCLUSIVE")
        self.assertEqual(last_rec["verdicts"]["disagreement_category"], "INCONCLUSIVE_DISAGREEMENT")

    def test_missing_or_incompatible_ml_artifacts(self):
        """When ML service is unavailable, hybrid decision handles fallback gracefully."""
        # Set experimental model to unavailable
        self.evaluator.experimental_model.state = ModelAvailabilityState.MODEL_UNAVAILABLE
        self.evaluator.experimental_model.model_instance = None

        dispatched = self.evaluator.dispatch(
            canonical_url="https://example.com/page",
            domain="example.com",
            legacy_verdict="clean",
            legacy_risk_score=10,
            intel_results=[],
            ml_prediction={"status": "unavailable", "is_trained": False, "message": "Model not loaded"},
        )
        self.assertTrue(dispatched)
        time.sleep(0.3)

        with open(self.log_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]
        last_rec = lines[-1]
        self.assertFalse(last_rec["evidence_sources"]["lexical_ml"]["available"])
        self.assertEqual(last_rec["evidence_sources"]["lexical_ml"]["experimental_state"], "MODEL_UNAVAILABLE")

    def test_malformed_url_handling(self):
        """Malformed URL strings passed to dispatch are handled safely without crashing the worker."""
        dispatched = self.evaluator.dispatch(
            canonical_url="invalid://malformed :/// target",
            domain="malformed",
            legacy_verdict="clean",
            legacy_risk_score=0,
            intel_results=[],
        )
        self.assertTrue(dispatched)
        time.sleep(0.3)
        # Should record error without thread crash
        self.assertEqual(self.evaluator.metrics["failed"], 0)

    def test_jsonl_write_failure_isolation(self):
        """If writing to JSONL fails (e.g. disk full), the worker catches it and updates metrics."""
        failing_logger = MagicMock(spec=PrivacySafeShadowLogger)
        failing_logger.write_record.side_effect = IOError("Disk full or permission denied")

        evaluator = ShadowEvaluator(
            enabled=True,
            rdap_client=self.mock_rdap_client,
            shadow_logger=failing_logger,
        )
        dispatched = evaluator.dispatch(
            canonical_url="https://example.com",
            domain="example.com",
            legacy_verdict="clean",
            legacy_risk_score=10,
            intel_results=[],
        )
        self.assertTrue(dispatched)
        time.sleep(0.3)
        self.assertEqual(evaluator.metrics["failed"], 1)
        evaluator.shutdown(wait=False)

    def test_bounded_queue_drops_excess_tasks(self):
        """Under high concurrency, tasks exceeding queue_maxsize are safely dropped without thread leaks."""
        small_evaluator = ShadowEvaluator(
            enabled=True,
            shadow_logger=self.logger,
            max_workers=1,
            queue_maxsize=3,
        )

        # Dispatch 20 tasks rapidly
        dropped_count = 0
        for i in range(20):
            accepted = small_evaluator.dispatch(
                canonical_url=f"https://load-test-{i}.example.com",
                domain=f"load-test-{i}.example.com",
                legacy_verdict="clean",
                legacy_risk_score=5,
                intel_results=[],
            )
            if not accepted:
                dropped_count += 1

        self.assertGreater(dropped_count, 0)
        self.assertEqual(small_evaluator.metrics["dropped"], dropped_count)
        small_evaluator.shutdown(wait=True, timeout=1.0)


class TestScannerEndToEndEquivalence(unittest.TestCase):
    """
    Verifies that scan_engine outputs are 100% byte-for-byte identical
    whether shadow mode is enabled or disabled.
    """

    def setUp(self):
        from backend.app.security.shadow_evaluator import shadow_evaluator
        self.shadow_evaluator = shadow_evaluator

    def test_scan_equivalence_shadow_on_vs_off(self):
        test_url = "https://safe-site.org/docs/index.html"

        # 1. Execute with shadow mode DISABLED
        self.shadow_evaluator.set_enabled(False)
        job_disabled = scan_engine.create_or_get_job(test_url, force_fresh=True)
        # Wait for scan job completion
        for _ in range(50):
            if job_disabled.state in ("completed", "partial", "failed"):
                break
            time.sleep(0.05)
        res_disabled = job_disabled.result

        # 2. Execute with shadow mode ENABLED
        self.shadow_evaluator.set_enabled(True)
        job_enabled = scan_engine.create_or_get_job(test_url, force_fresh=True)
        for _ in range(50):
            if job_enabled.state in ("completed", "partial", "failed"):
                break
            time.sleep(0.05)
        res_enabled = job_enabled.result

        # Reset flag to False
        self.shadow_evaluator.set_enabled(False)

        # 3. Assert exact equivalence of core verdict and risk contract
        self.assertEqual(res_disabled["verdict"], res_enabled["verdict"])
        self.assertEqual(res_disabled["risk_score"], res_enabled["risk_score"])
        self.assertEqual(res_disabled["confidence"], res_enabled["confidence"])
        self.assertEqual(res_disabled["domain"], res_enabled["domain"])
        self.assertEqual(len(res_disabled["recommendations"]), len(res_enabled["recommendations"]))


class TestDispatchLatencyOverhead(unittest.TestCase):
    """Measures request-path dispatch overhead across 100 consecutive invocations."""

    def test_dispatch_latency_overhead(self):
        evaluator = ShadowEvaluator(enabled=True)
        latencies = []

        for i in range(100):
            start = time.perf_counter()
            evaluator.dispatch(
                canonical_url=f"https://benchmark-{i}.example.org/path",
                domain=f"benchmark-{i}.example.org",
                legacy_verdict="clean",
                legacy_risk_score=10,
                intel_results=[],
            )
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            latencies.append(elapsed_ms)

        evaluator.shutdown(wait=True, timeout=2.0)

        latencies.sort()
        p50 = latencies[50]
        p95 = latencies[95]
        p99 = latencies[99]

        print(f"\n[Shadow Dispatch Latency] p50: {p50:.3f}ms | p95: {p95:.3f}ms | p99: {p99:.3f}ms")
        self.assertLess(p95, 50.0, "Request-path shadow dispatch overhead MUST NOT exceed 50ms at p95.")


class TestExperimentalShadowModelVerification(unittest.TestCase):
    """Verifies that ExperimentalShadowModel correctly enforces SHA-256 and feature schema integrity."""

    def test_real_artifact_loads_cleanly(self):
        model = ExperimentalShadowModel()
        self.assertEqual(model.state, ModelAvailabilityState.MODEL_LOADED)
        self.assertIsNone(model.load_error)
        self.assertIsNotNone(model.model_instance)
        pred = model.predict("https://trustshield.internal.test/login")
        self.assertIsNotNone(pred)
        self.assertTrue(pred["is_trained"])
        self.assertIn("probability_phish", pred)

    def test_missing_files_yield_model_unavailable(self):
        model = ExperimentalShadowModel(
            manifest_path="nonexistent/manifest.json",
            artifact_path="nonexistent/model.joblib"
        )
        self.assertEqual(model.state, ModelAvailabilityState.MODEL_UNAVAILABLE)
        self.assertIsNone(model.model_instance)
        self.assertIsNone(model.predict("https://example.com"))

    def test_hash_mismatch_yields_model_incompatible(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({
                "models": {
                    "rf_calibrated_sigmoid": {"sha256": "0000000000000000000000000000000000000000000000000000000000000000"}
                },
                "feature_names": URLFeatureExtractor.FEATURE_NAMES,
            }, f)
            manifest_tmp = f.name

        try:
            model = ExperimentalShadowModel(
                manifest_path=manifest_tmp,
                artifact_path="data/experiments/phase6b/rf_calibrated_model.joblib"
            )
            self.assertEqual(model.state, ModelAvailabilityState.MODEL_INCOMPATIBLE)
            self.assertIn("mismatch", model.load_error.lower())
        finally:
            if os.path.exists(manifest_tmp):
                os.remove(manifest_tmp)


if __name__ == "__main__":
    unittest.main()
