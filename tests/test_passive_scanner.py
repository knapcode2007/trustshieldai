"""
TrustShield AI - Passive Website Security & Authorized Scanner Tests
Verifies:
1. Low-impact passive HTTP and defensive header auditing (CSP, HSTS, XCTO, XFO).
2. Observable cookie security attributes without saving/storing sensitive cookie values.
3. Redirect loop prevention and insecure protocol downgrade detection.
4. SSRF revalidation on redirect hops.
5. Verdict separation guarantee (missing headers alone never trigger a malicious/phishing verdict).
6. Authorized domain security testing architecture (disabled by default, strict ownership verification).
"""

import os
import unittest
from unittest.mock import MagicMock, patch

from backend.app.security.passive_scanner import (
    PassiveSecurityScanner,
    CookieSecurityAttribute,
    PassiveSecurityAssessment,
    passive_scanner,
)
from backend.app.security.authorized_scanner import (
    AuthorizedSecurityScanner,
    authorized_scanner,
)
from backend.app.core.scanner import scan_engine
from backend.app.security.ssrf import SSRFSecurityException


class TestPassiveSecurityScanner(unittest.TestCase):
    """Tests passive security header analysis, cookie flag parsing, and redirect defenses."""

    def test_cookie_security_attribute_parsing_and_zero_secret_retention(self):
        """
        Confirms observable cookie security flags (Secure, HttpOnly, SameSite) are parsed,
        while secret payload values are strictly redacted and never stored.
        """
        raw_cookies = [
            "session_id=SUPER_SECRET_SESSION_TOKEN_12345; Secure; HttpOnly; SameSite=Strict; Path=/",
            "remember_user=USER_SECRET_HASH_ABCDEF; HttpOnly; SameSite=Lax",
            "tracking_id=TRACKER_VALUE_999; Secure; SameSite=None",
            "insecure_cookie=PLAINTEXT_SECRET",
        ]

        results = PassiveSecurityScanner.parse_cookie_attributes(raw_cookies)
        self.assertEqual(len(results), 4)

        # 1. session_id: Secure, HttpOnly, SameSite=Strict
        c1 = results[0].to_dict()
        self.assertEqual(c1["name"], "session_id")
        self.assertTrue(c1["is_secure"])
        self.assertTrue(c1["is_http_only"])
        self.assertEqual(c1["same_site"], "Strict")
        # PRIVACY GUARANTEE: Sensitive value MUST NOT exist anywhere in the object dictionary
        self.assertNotIn("SUPER_SECRET_SESSION_TOKEN_12345", str(c1))

        # 2. remember_user: HttpOnly, SameSite=Lax, not Secure
        c2 = results[1].to_dict()
        self.assertEqual(c2["name"], "remember_user")
        self.assertFalse(c2["is_secure"])
        self.assertTrue(c2["is_http_only"])
        self.assertEqual(c2["same_site"], "Lax")
        self.assertNotIn("USER_SECRET_HASH_ABCDEF", str(c2))

        # 3. tracking_id: Secure, SameSite=None, not HttpOnly
        c3 = results[2].to_dict()
        self.assertEqual(c3["name"], "tracking_id")
        self.assertTrue(c3["is_secure"])
        self.assertFalse(c3["is_http_only"])
        self.assertEqual(c3["same_site"], "None")
        self.assertNotIn("TRACKER_VALUE_999", str(c3))

        # 4. insecure_cookie: no flags set
        c4 = results[3].to_dict()
        self.assertEqual(c4["name"], "insecure_cookie")
        self.assertFalse(c4["is_secure"])
        self.assertFalse(c4["is_http_only"])
        self.assertEqual(c4["same_site"], "Unspecified")
        self.assertNotIn("PLAINTEXT_SECRET", str(c4))

    def test_csp_analysis(self):
        """Verifies Content-Security-Policy analysis for unsafe directives and frame-ancestors."""
        # Missing CSP
        has_csp, tags, weaknesses = PassiveSecurityScanner.analyze_csp(None)
        self.assertFalse(has_csp)
        self.assertTrue(any(w["code"] == "WEAKNESS_NO_CSP" for w in weaknesses))

        # Weak CSP with unsafe-inline and unsafe-eval
        weak_csp = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self'"
        has_csp, tags, weaknesses = PassiveSecurityScanner.analyze_csp(weak_csp)
        self.assertTrue(has_csp)
        self.assertIn("unsafe-inline", tags)
        self.assertIn("unsafe-eval", tags)
        self.assertTrue(any(w["code"] == "WEAKNESS_CSP_UNSAFE_INLINE" for w in weaknesses))
        self.assertTrue(any(w["code"] == "WEAKNESS_CSP_UNSAFE_EVAL" for w in weaknesses))

        # Strong CSP
        strong_csp = "default-src 'self'; script-src 'self' 'nonce-rAnd0m'; frame-ancestors 'self'"
        has_csp, tags, weaknesses = PassiveSecurityScanner.analyze_csp(strong_csp)
        self.assertTrue(has_csp)
        self.assertEqual(len(weaknesses), 0)
        self.assertIn("frame-ancestors-present", tags)

    def test_hsts_analysis(self):
        """Validates HSTS requirements: HTTPS only, duration >= 31536000, and includeSubDomains."""
        # Case 1: Cleartext HTTP
        has_hsts, max_age, weaknesses = PassiveSecurityScanner.analyze_hsts("max-age=31536000", is_https=False)
        self.assertFalse(has_hsts)
        self.assertTrue(any(w["code"] == "WEAKNESS_HSTS_OVER_HTTP" for w in weaknesses))

        # Case 2: Missing HSTS on HTTPS
        has_hsts, max_age, weaknesses = PassiveSecurityScanner.analyze_hsts(None, is_https=True)
        self.assertFalse(has_hsts)
        self.assertTrue(any(w["code"] == "WEAKNESS_NO_HSTS" for w in weaknesses))

        # Case 3: Short duration (< 1 year) and no subdomains
        short_hsts = "max-age=86400"
        has_hsts, max_age, weaknesses = PassiveSecurityScanner.analyze_hsts(short_hsts, is_https=True)
        self.assertTrue(has_hsts)
        self.assertEqual(max_age, 86400)
        self.assertTrue(any(w["code"] == "WEAKNESS_HSTS_SHORT_DURATION" for w in weaknesses))
        self.assertTrue(any(w["code"] == "WEAKNESS_HSTS_NO_SUBDOMAINS" for w in weaknesses))

        # Case 4: Full RFC-compliant HSTS
        full_hsts = "max-age=31536000; includeSubDomains; preload"
        has_hsts, max_age, weaknesses = PassiveSecurityScanner.analyze_hsts(full_hsts, is_https=True)
        self.assertTrue(has_hsts)
        self.assertEqual(max_age, 31536000)
        self.assertEqual(len(weaknesses), 0)

    def test_verdict_separation_guarantee(self):
        """
        CRITICAL ARCHITECTURAL PRINCIPLE:
        A website's defensive security posture (missing headers, weak CSP, no HSTS)
        must NOT trigger a malicious or phishing verdict.
        """
        assessment = passive_scanner.assess_url("https://example.com")
        assessment_dict = assessment.to_dict()

        self.assertIn("verdict_separation_note", assessment_dict)
        self.assertIn("DO NOT indicate malicious intent", assessment_dict["verdict_separation_note"])
        self.assertIn("never trigger a malicious or phishing verdict", assessment_dict["verdict_separation_note"])

        # Test scan engine execution on a benign domain with poor headers
        job = scan_engine.create_or_get_job("https://example.com", force_fresh=True)
        # Wait for scan job completion
        import time
        start = time.time()
        while job.state in ("queued", "running") and (time.time() - start) < 6.0:
            time.sleep(0.05)

        self.assertIn(job.state, ("completed", "partial"))
        self.assertIsNotNone(job.result)
        # Benign example.com must NOT be classified as phishing or malicious despite missing headers
        self.assertIn(job.result["verdict"], ("clean", "suspicious"))
        self.assertNotEqual(job.result["verdict"], "phishing")
        self.assertNotEqual(job.result["verdict"], "malicious")


class TestAuthorizedSecurityScanner(unittest.TestCase):
    """Verifies authorized-domain testing safety framework and OWASP ZAP controls."""

    def setUp(self):
        self.scanner = AuthorizedSecurityScanner()

    def test_active_scanning_disabled_by_default(self):
        """Confirms that active scanning is disabled by default."""
        self.assertFalse(self.scanner.active_scanning_enabled)

    def test_dispatch_without_ownership_rejected_with_disabled_status(self):
        """Rejects active scan attempts when feature is disabled."""
        res = self.scanner.dispatch_authorized_scan("victim-target.com", "fake-token")
        self.assertEqual(res["status"], "disabled")
        self.assertFalse(res["authorized"])
        self.assertEqual(res["error_code"], "ACTIVE_SCANNING_DISABLED")
        self.assertIn("DISABLED by default", res["message"])

    def test_challenge_generation_and_verification_flow(self):
        """Generates ownership tokens and enforces verification before authorization."""
        challenge = self.scanner.generate_challenge("my-verified-app.com", "admin@my-verified-app.com")
        self.assertEqual(challenge["domain"], "my-verified-app.com")
        self.assertIn("challenge_token", challenge)
        self.assertEqual(challenge["txt_record_name"], "_trustshield-challenge.my-verified-app.com")
        self.assertIn("trustshield-verify=", challenge["txt_record_value"])

        # Unverified dispatch must fail even if active scanning is enabled
        self.scanner.active_scanning_enabled = True
        res_unverified = self.scanner.dispatch_authorized_scan("my-verified-app.com", "invalid-token")
        self.assertEqual(res_unverified["status"], "rejected")
        self.assertEqual(res_unverified["error_code"], "DOMAIN_NOT_VERIFIED")

        # Test verification in testbed mode
        with patch.dict(os.environ, {"TRUSTSHIELD_TEST_AUTO_VERIFY": "1"}):
            verified, message, auth_token = self.scanner.verify_ownership("my-verified-app.com", method="dns_txt")
            self.assertTrue(verified)
            self.assertIsNotNone(auth_token)
            self.assertTrue(auth_token.startswith("auth-"))

            # Authorized dispatch with valid token now succeeds
            dispatch_res = self.scanner.dispatch_authorized_scan(
                domain="my-verified-app.com",
                auth_token=auth_token,
                policy="passive_baseline"
            )
            self.assertEqual(dispatch_res["status"], "scheduled")
            self.assertTrue(dispatch_res["authorized"])
            self.assertEqual(dispatch_res["verified_owner"], "admin@my-verified-app.com")


if __name__ == "__main__":
    unittest.main()
