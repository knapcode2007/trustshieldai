"""
Unit Test Suite for TrustShield AI TLS & Certificate Intelligence Engine
Validates:
1. Hostname matching rules (RFC 6125 exact and wildcard matches).
2. Controlled fixtures for valid, expired, self-signed, and mismatched certificates.
3. Observable anomaly detection (ANOMALY_EXPIRED, ANOMALY_HOSTNAME_MISMATCH, ANOMALY_SELF_SIGNED).
4. SSRF firewall blocking for forbidden hostnames and internal IP destinations.
5. Separation of transport encryption validity from website legitimacy.
"""

import unittest
from backend.app.security.tls_inspector import TlsCertificateInspector


class TestTlsCertificateIntelligence(unittest.TestCase):
    """Test suite for TLS certificate inspection and anomaly detection."""

    def test_hostname_matching_exact(self):
        """Validates exact hostname match against Subject CN and SANs."""
        matches, details = TlsCertificateInspector.match_hostname(
            "github.com", "github.com", ["www.github.com", "github.com"]
        )
        self.assertTrue(matches)
        self.assertIn("matched", details.lower())

    def test_hostname_matching_wildcard(self):
        """Validates RFC 6125 single-level wildcard matching rules."""
        # Single level matches wildcard
        matches_single, _ = TlsCertificateInspector.match_hostname(
            "api.example.com", "example.com", ["*.example.com"]
        )
        self.assertTrue(matches_single)

        # Multi-level does NOT match single-level wildcard
        matches_multi, _ = TlsCertificateInspector.match_hostname(
            "v1.api.example.com", "example.com", ["*.example.com"]
        )
        self.assertFalse(matches_multi)

        # Root apex does NOT match *.example.com wildcard
        matches_apex, _ = TlsCertificateInspector.match_hostname(
            "example.com", "other.com", ["*.example.com"]
        )
        self.assertFalse(matches_apex)

    def test_hostname_mismatch(self):
        """Detects hostname mismatch when target is not covered by certificate."""
        matches, details = TlsCertificateInspector.match_hostname(
            "phish-target.com", "legitimate-bank.com", ["legitimate-bank.com", "www.legitimate-bank.com"]
        )
        self.assertFalse(matches)
        self.assertIn("does not match", details)

    def test_controlled_fixture_valid(self):
        """Validates standard trusted certificate fixture with CT evidence."""
        res = TlsCertificateInspector.get_controlled_fixture("valid")
        self.assertTrue(res.connected)
        self.assertTrue(res.hostname_matches)
        self.assertFalse(res.is_expired)
        self.assertFalse(res.is_self_signed)
        self.assertEqual(res.grade, "A+")
        self.assertEqual(len(res.anomalies), 0)
        self.assertGreaterEqual(len(res.certificate_chain), 2)
        self.assertTrue(res.certificate_transparency.is_verified)
        self.assertEqual(res.certificate_transparency.status, "verified_embedded_scts")

    def test_controlled_fixture_expired(self):
        """Validates expired certificate detection and critical anomaly."""
        res = TlsCertificateInspector.get_controlled_fixture("expired")
        self.assertTrue(res.connected)
        self.assertTrue(res.is_expired)
        self.assertLess(res.days_remaining, 0)
        self.assertEqual(res.grade, "F")

        codes = [a.code for a in res.anomalies]
        self.assertIn("ANOMALY_EXPIRED", codes)
        self.assertFalse(res.certificate_validity.valid_dates)

    def test_controlled_fixture_self_signed(self):
        """Validates self-signed certificate detection and untrusted root status."""
        res = TlsCertificateInspector.get_controlled_fixture("self_signed")
        self.assertTrue(res.connected)
        self.assertTrue(res.is_self_signed)
        self.assertEqual(res.grade, "F")

        codes = [a.code for a in res.anomalies]
        self.assertIn("ANOMALY_SELF_SIGNED", codes)
        self.assertFalse(res.certificate_validity.chain_trusted)

    def test_controlled_fixture_hostname_mismatch(self):
        """Validates hostname mismatch anomaly detection."""
        res = TlsCertificateInspector.get_controlled_fixture("hostname_mismatch")
        self.assertTrue(res.connected)
        self.assertFalse(res.hostname_matches)
        self.assertEqual(res.grade, "F")

        codes = [a.code for a in res.anomalies]
        self.assertIn("ANOMALY_HOSTNAME_MISMATCH", codes)

    def test_ssrf_blocking_on_tls_probe(self):
        """Confirms that internal and loopback hosts are blocked prior to socket creation."""
        res_loopback = TlsCertificateInspector.inspect_host("127.0.0.1")
        self.assertFalse(res_loopback.connected)
        self.assertEqual(res_loopback.grade, "F")
        anomaly_codes = [a.code for a in res_loopback.anomalies]
        self.assertIn("SSRF_DESTINATION_BLOCKED", anomaly_codes)

        res_metadata = TlsCertificateInspector.inspect_host("169.254.169.254")
        self.assertFalse(res_metadata.connected)
        anomaly_codes_meta = [a.code for a in res_metadata.anomalies]
        self.assertIn("SSRF_DESTINATION_BLOCKED", anomaly_codes_meta)

    def test_phishing_separation_principle(self):
        """Guarantees that certificate validity is never equated to website legitimacy."""
        res = TlsCertificateInspector.get_controlled_fixture("valid")
        # Phishing risk note must exist and provide clear guidance
        self.assertIsNotNone(res.phishing_risk_note)
        self.assertIn("domain validation", res.phishing_risk_note.lower())
        self.assertIn("not website trustworthiness", res.phishing_risk_note.lower())


if __name__ == "__main__":
    unittest.main()
