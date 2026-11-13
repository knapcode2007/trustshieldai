"""
TrustShield AI - Phase 7A Hybrid Decision Engine Unit Test Suite
Verifies:
1. L1 Authoritative threat feed override (exact URL threat feed match overrides low ML).
2. Conflicting threat feeds (clean vs malicious resolves to MALICIOUS).
3. No automatic authority bypass (multi-tier corporate console has no hardcoded exemption).
4. Multi-tenant hosting platform detection (pages.dev, github.io) and tenant boundary isolation.
5. Domain telemetry integration (newly registered apex escalation).
6. Fail-closed behavior on provider outage/rate-limiting (INCONCLUSIVE or degraded confidence).
7. Transparent audit trail, evidence chain, and JSON serialization.
"""

import unittest
from datetime import datetime, timezone

from backend.app.intel.base import ThreatFeedResult
from backend.app.security.hybrid_decision import (
    HierarchyType,
    HybridVerdictState,
    HybridDecisionEngine,
    HostStructureInterpreter,
    DomainTelemetryDetails,
    DecisionEvidence,
    HybridDecisionResult,
)


class TestHostStructureInterpreter(unittest.TestCase):
    """Tests Public Suffix List structural deconstruction and hierarchy typing."""

    def test_apex_root(self):
        details = HostStructureInterpreter.analyze_host("amazon.com")
        self.assertEqual(details.hostname, "amazon.com")
        self.assertEqual(details.hierarchy_type, HierarchyType.APEX_ROOT)
        self.assertEqual(details.subdomain_count, 0)
        self.assertFalse(details.is_multi_tenant_platform)

    def test_single_subdomain(self):
        details = HostStructureInterpreter.analyze_host("docs.python.org")
        self.assertEqual(details.hostname, "docs.python.org")
        self.assertEqual(details.hierarchy_type, HierarchyType.SINGLE_SUBDOMAIN)
        self.assertEqual(details.subdomain_count, 1)

    def test_corporate_multi_tier(self):
        details = HostStructureInterpreter.analyze_host("us-east-1.console.aws.amazon.com")
        self.assertEqual(details.hostname, "us-east-1.console.aws.amazon.com")
        self.assertEqual(details.hierarchy_type, HierarchyType.CORPORATE_MULTI_TIER)
        self.assertGreaterEqual(details.subdomain_count, 2)
        self.assertFalse(details.is_multi_tenant_platform)

    def test_multi_tenant_platform_namespace(self):
        details = HostStructureInterpreter.analyze_host("user123.github.io")
        self.assertEqual(details.hostname, "user123.github.io")
        self.assertEqual(details.hierarchy_type, HierarchyType.TENANT_NAMESPACE)
        self.assertTrue(details.is_multi_tenant_platform)
        self.assertEqual(details.tenant_boundary, "user123.github.io")
        self.assertEqual(details.private_suffix, "github.io")

    def test_multi_tenant_nested(self):
        details = HostStructureInterpreter.analyze_host("sub.tenant.pages.dev")
        self.assertEqual(details.hierarchy_type, HierarchyType.NESTED_TENANT)
        self.assertTrue(details.is_multi_tenant_platform)
        self.assertEqual(details.private_suffix, "pages.dev")


class TestHybridDecisionEngine(unittest.TestCase):
    """Verifies deterministic multi-source evidence correlation and decision rules."""

    def setUp(self):
        self.engine = HybridDecisionEngine()

    def test_l1_feed_override_over_low_ml(self):
        """Confirmed L1 threat feed match must override low lexical ML probability."""
        l1_feed = ThreatFeedResult(
            provider="google_safe_browsing",
            provider_name="Google Safe Browsing",
            status="match",
            matched=True,
            threat_type="social_engineering",
            match_type="exact_url",
            confidence=95,
            details="Known phishing page on compromised host",
        )
        # Lexical ML erroneously predicts very low phishing probability
        ml_prediction = {
            "model": "RandomForest",
            "is_trained": True,
            "prediction": 0,
            "probability_phish": 0.05,
            "confidence": 0.90,
        }

        result = self.engine.evaluate(
            raw_url="https://legitimate-looking.org/login",
            intel_results=[l1_feed],
            ml_prediction=ml_prediction,
        )

        self.assertEqual(result.state, HybridVerdictState.MALICIOUS)
        self.assertEqual(result.legacy_verdict, "phishing")
        self.assertGreaterEqual(result.risk_score, 85)
        self.assertIn("social_engineering", result.threat_types)
        # Verify evidence chain captures L1 feed
        levels = [e.level for e in result.evidence_chain]
        self.assertIn("L1_AUTHORITATIVE_INTEL", levels)

    def test_conflicting_feeds_resolve_to_malicious(self):
        """When one provider is clean and another reports an exact URL match, verdict is MALICIOUS."""
        clean_feed = ThreatFeedResult(
            provider="phishtank",
            provider_name="PhishTank",
            status="no_match",
            matched=False,
            confidence=0,
            details="No active phishing report found",
        )
        malicious_feed = ThreatFeedResult(
            provider="urlhaus",
            provider_name="URLhaus",
            status="match",
            matched=True,
            threat_type="malware_download",
            match_type="exact_url",
            confidence=98,
            details="Confirmed malware payload distribution URL",
        )

        result = self.engine.evaluate(
            raw_url="https://suspicious-distribution.net/payload.exe",
            intel_results=[clean_feed, malicious_feed],
            ml_prediction=None,
        )

        self.assertEqual(result.state, HybridVerdictState.MALICIOUS)
        self.assertEqual(result.legacy_verdict, "malicious")
        self.assertGreaterEqual(result.risk_score, 85)

    def test_no_authority_bypass_on_corporate_multi_tier(self):
        """Corporate multi-tier URLs must be flagged as MALICIOUS if flagged by L1 threat feed."""
        l1_feed = ThreatFeedResult(
            provider="virustotal",
            provider_name="VirusTotal",
            status="match",
            matched=True,
            threat_type="malware",
            match_type="exact_url",
            confidence=92,
            details="Compromised cloud resource hosting malicious script",
        )

        result = self.engine.evaluate(
            raw_url="https://us-east-1.console.aws.amazon.com/malicious/path",
            intel_results=[l1_feed],
            ml_prediction=None,
        )

        # Must NOT be bypassed due to amazon.com domain
        self.assertEqual(result.state, HybridVerdictState.MALICIOUS)
        self.assertEqual(result.host_structure.hierarchy_type, HierarchyType.CORPORATE_MULTI_TIER)

    def test_corporate_multi_tier_mitigates_lexical_false_alarm(self):
        """Corporate multi-tier URL with clean feeds and moderate ML score is SUSPICIOUS, not hardcoded clean."""
        clean_feed_1 = ThreatFeedResult(
            provider="google_safe_browsing",
            provider_name="Google Safe Browsing",
            status="no_match",
            matched=False,
            confidence=0,
            details="Clean",
        )
        clean_feed_2 = ThreatFeedResult(
            provider="urlhaus",
            provider_name="URLhaus",
            status="no_match",
            matched=False,
            confidence=0,
            details="Clean",
        )
        # Moderate ML score due to many dots and hyphens
        ml_prediction = {
            "model": "RandomForest",
            "is_trained": True,
            "prediction": 1,
            "probability_phish": 0.55,
            "confidence": 0.70,
        }

        result = self.engine.evaluate(
            raw_url="https://us-east-1.console.aws.amazon.com/ec2/v2/home?region=us-east-1#Instances:",
            intel_results=[clean_feed_1, clean_feed_2],
            ml_prediction=ml_prediction,
        )

        # Feeds are clean, but borderline ML score is noted without granting a hardcoded bypass
        self.assertEqual(result.state, HybridVerdictState.SUSPICIOUS)
        self.assertIn("indeterminate_lexical_risk", result.threat_types)

    def test_clean_feeds_and_low_ml_yields_no_threat_detected(self):
        """Clean feeds and low ML probability yield NO_THREAT_DETECTED."""
        clean_feed = ThreatFeedResult(
            provider="google_safe_browsing",
            provider_name="Google Safe Browsing",
            status="no_match",
            matched=False,
            confidence=0,
            details="Clean",
        )
        ml_prediction = {
            "model": "RandomForest",
            "is_trained": True,
            "prediction": 0,
            "probability_phish": 0.08,
            "confidence": 0.95,
        }

        result = self.engine.evaluate(
            raw_url="https://docs.python.org/3/library/index.html",
            intel_results=[clean_feed],
            ml_prediction=ml_prediction,
        )

        self.assertEqual(result.state, HybridVerdictState.NO_THREAT_DETECTED)
        self.assertEqual(result.legacy_verdict, "clean")
        self.assertLess(result.risk_score, 15)

    def test_newly_registered_apex_domain_escalation(self):
        """Newly registered apex domain (< 30 days) escalates even with low lexical ML score."""
        clean_feed = ThreatFeedResult(
            provider="google_safe_browsing",
            provider_name="Google Safe Browsing",
            status="no_match",
            matched=False,
            confidence=0,
            details="Clean",
        )
        ml_prediction = {
            "model": "RandomForest",
            "is_trained": True,
            "prediction": 0,
            "probability_phish": 0.20,
            "confidence": 0.85,
        }
        telemetry = DomainTelemetryDetails(
            domain="account-security-update.top",
            registration_date="2026-11-05",
            age_days=8,
            status="active",
            is_newly_registered=True,
            telemetry_source="rdap",
        )

        result = self.engine.evaluate(
            raw_url="https://account-security-update.top/login",
            intel_results=[clean_feed],
            ml_prediction=ml_prediction,
            telemetry=telemetry,
        )

        self.assertEqual(result.state, HybridVerdictState.SUSPICIOUS)
        self.assertEqual(result.legacy_verdict, "suspicious")
        self.assertIn("disposable_infrastructure_risk", result.threat_types)
        self.assertTrue(any("Apex domain registered < 30 days ago" in c for c in result.caveats))

    def test_complete_provider_outage_fail_closed(self):
        """When all external threat feeds are unavailable or errored, system does NOT claim clean safety."""
        unavail_feed = ThreatFeedResult(
            provider="google_safe_browsing",
            provider_name="Google Safe Browsing",
            status="unavailable",
            matched=False,
            confidence=0,
            details="API unreachable",
        )
        rate_limited_feed = ThreatFeedResult(
            provider="virustotal",
            provider_name="VirusTotal",
            status="rate_limited",
            matched=False,
            confidence=0,
            details="Daily quota exhausted",
        )

        # Case A: Borderline ML probability with no available feeds -> INCONCLUSIVE
        ml_prediction = {
            "model": "RandomForest",
            "is_trained": True,
            "prediction": 1,
            "probability_phish": 0.50,
            "confidence": 0.60,
        }

        result = self.engine.evaluate(
            raw_url="https://unverified-domain.org/portal",
            intel_results=[unavail_feed, rate_limited_feed],
            ml_prediction=ml_prediction,
        )

        self.assertEqual(result.state, HybridVerdictState.INCONCLUSIVE)
        self.assertTrue(len(result.caveats) >= 2)
        self.assertIn("Borderline lexical probability with insufficient external feed corroboration.", result.caveats)

        # Case B: Low ML probability with no available feeds -> NO_THREAT_DETECTED with explicit caveat
        ml_low = {
            "model": "RandomForest",
            "is_trained": True,
            "prediction": 0,
            "probability_phish": 0.12,
            "confidence": 0.85,
        }
        result_low = self.engine.evaluate(
            raw_url="https://unverified-domain.org/about",
            intel_results=[unavail_feed, rate_limited_feed],
            ml_prediction=ml_low,
        )
        self.assertEqual(result_low.state, HybridVerdictState.NO_THREAT_DETECTED)
        self.assertEqual(result_low.confidence, 0.60)  # Degraded confidence
        self.assertTrue(any("Zero threat feeds available" in c for c in result_low.caveats))

    def test_mature_compromised_domain_not_bypassed_by_age(self):
        """A mature domain (age 10 years) hosting confirmed malware/phishing CANNOT be bypassed by age or low ML."""
        l1_feed = ThreatFeedResult(
            provider="google_safe_browsing",
            provider_name="Google Safe Browsing",
            status="match",
            matched=True,
            threat_type="social_engineering",
            match_type="exact_url",
            confidence=95,
            details="Compromised legitimate domain hosting phishing kit",
        )
        ml_prediction = {
            "model": "RandomForest",
            "is_trained": True,
            "prediction": 0,
            "probability_phish": 0.05,
            "confidence": 0.90,
        }
        telemetry = DomainTelemetryDetails(
            domain="university.edu",
            registration_date="2014-01-01T00:00:00Z",
            age_days=3650,
            status="active",
            is_newly_registered=False,
            telemetry_source="rdap",
            confidence=0.95,
        )

        result = self.engine.evaluate(
            raw_url="https://university.edu/~compromised_faculty/login.html",
            intel_results=[l1_feed],
            ml_prediction=ml_prediction,
            telemetry=telemetry,
        )

        # INVARIANT: Age > 3000 days and low ML (0.05) NEVER override confirmed L1 feed
        self.assertEqual(result.state, HybridVerdictState.MALICIOUS)
        self.assertEqual(result.legacy_verdict, "phishing")
        self.assertGreaterEqual(result.risk_score, 85)
        self.assertEqual(result.telemetry.age_days, 3650)

    def test_tenant_hosted_phishing_isolated(self):
        """Phishing on a multi-tenant platform (pages.dev) is marked MALICIOUS and isolates tenant boundary."""
        l1_feed = ThreatFeedResult(
            provider="urlhaus",
            provider_name="URLhaus",
            status="match",
            matched=True,
            threat_type="phishing",
            match_type="exact_url",
            confidence=90,
            details="Phishing portal hosted on Cloudflare Pages",
        )

        result = self.engine.evaluate(
            raw_url="https://secure-login-update.pages.dev/auth/index.php",
            intel_results=[l1_feed],
            ml_prediction=None,
        )

        self.assertEqual(result.state, HybridVerdictState.MALICIOUS)
        self.assertEqual(result.host_structure.hierarchy_type, HierarchyType.TENANT_NAMESPACE)
        self.assertEqual(result.host_structure.tenant_boundary, "secure-login-update.pages.dev")
        self.assertTrue(result.host_structure.is_multi_tenant_platform)

    def test_rdap_failure_graceful_handling(self):
        """RDAP failure (timeout or error) is handled safely: does NOT assume young domain or crash."""
        clean_feed = ThreatFeedResult(
            provider="google_safe_browsing",
            provider_name="Google Safe Browsing",
            status="no_match",
            matched=False,
            confidence=0,
            details="Clean",
        )
        ml_prediction = {
            "model": "RandomForest",
            "is_trained": True,
            "prediction": 0,
            "probability_phish": 0.10,
            "confidence": 0.90,
        }
        telemetry = DomainTelemetryDetails(
            domain="slow-rdap-domain.org",
            status="error",
            is_newly_registered=False,  # CRITICAL: Missing != Young!
            telemetry_source="rdap",
            reliability_limitation="RDAP query timed out after 3.0s.",
            confidence=0.1,
        )

        result = self.engine.evaluate(
            raw_url="https://slow-rdap-domain.org/about",
            intel_results=[clean_feed],
            ml_prediction=ml_prediction,
            telemetry=telemetry,
        )

        self.assertEqual(result.state, HybridVerdictState.NO_THREAT_DETECTED)
        self.assertEqual(result.telemetry.status, "error")
        self.assertFalse(result.telemetry.is_newly_registered)

    def test_audit_trail_serialization(self):
        """Verifies full dictionary serialization for API consumers."""
        clean_feed = ThreatFeedResult(
            provider="google_safe_browsing",
            provider_name="Google Safe Browsing",
            status="no_match",
            matched=False,
            confidence=0,
            details="Clean",
        )
        result = self.engine.evaluate(
            raw_url="https://example.com/index.html",
            intel_results=[clean_feed],
            ml_prediction=None,
        )

        payload = result.to_dict()
        self.assertIn("state", payload)
        self.assertIn("legacy_verdict", payload)
        self.assertIn("risk_score", payload)
        self.assertIn("confidence", payload)
        self.assertIn("host_structure", payload)
        self.assertIn("telemetry", payload)
        self.assertIn("evidence_chain", payload)
        self.assertIn("caveats", payload)
        self.assertIn("created_at", payload)


if __name__ == "__main__":
    unittest.main()
