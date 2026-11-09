import unittest
import socket
import time
from unittest.mock import patch
from fastapi import HTTPException

# Mock DNS for test isolation
orig_getaddrinfo = socket.getaddrinfo
def mock_getaddrinfo(host, port, *args, **kwargs):
    if host in ("example.com", "github.com", "target.org", "safe-site.org"):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', port or 443))]
    return orig_getaddrinfo(host, port, *args, **kwargs)

patch("socket.getaddrinfo", side_effect=mock_getaddrinfo).start()

from backend.app.main import root_health, api_health
from backend.app.api.v1.endpoints.scans import (
    create_scan,
    get_scan_status,
    get_scan_report,
    get_scan_history,
    list_scans,
    delete_scan,
    clear_scans,
)
from backend.app.api.v1.endpoints.scan import analyze_url
from backend.app.api.v1.endpoints.tls import inspect_tls_certificate
from backend.app.api.v1.endpoints.intel import list_threat_indicators, submit_threat_indicator, verify_threat_indicator
from backend.app.api.v1.endpoints.community import (
    list_community_reports,
    submit_community_report,
    vote_community_report,
    moderate_community_report,
)
from backend.app.api.v1.endpoints.watchlist import list_watchlist, add_to_watchlist, remove_from_watchlist
from backend.app.api.v1.endpoints.admin import list_admin_audit_logs, record_audit_log
from backend.app.models.schemas import (
    ScanCreateRequest,
    ScanRequest,
    TlsInspectRequest,
    ThreatIndicatorCreate,
    VerifyThreatIndicatorRequest,
    CommunityReportCreate,
    CommunityReportModerateRequest,
    WatchlistItemCreate,
)

def sync_await(coro):
    """Executes a coroutine synchronously for test execution."""
    try:
        coro.send(None)
    except StopIteration as e:
        return e.value


class FullStackIntegrationTestCase(unittest.TestCase):
    """End-to-end integration test suite verifying all TrustShield AI API contracts."""

    def test_health_endpoints(self):
        """Verifies root and API health contracts."""
        r_health = sync_await(root_health())
        self.assertIn(r_health.status, ("healthy", "degraded"))
        self.assertEqual(r_health.app_name, "TrustShield AI Backend")
        self.assertIn("ml_engine", r_health.subsystems)
        self.assertIn("database", r_health.subsystems)

        a_health = sync_await(api_health())
        self.assertEqual(a_health.app_name, "TrustShield AI Backend")

    def test_ssrf_protections_on_both_endpoints(self):
        """Verifies that SSRF violations are strictly blocked on both async and sync endpoints."""
        malicious_targets = [
            "http://127.0.0.1:8000/internal",
            "http://localhost:3000",
            "http://169.254.169.254/latest/meta-data",
            "http://10.0.0.1/admin",
            "http://192.168.1.1/",
            "file:///etc/passwd",
        ]

        for target in malicious_targets:
            # Test async submission
            with self.assertRaises(HTTPException) as ctx:
                sync_await(create_scan(ScanCreateRequest(url=target)))
            self.assertEqual(ctx.exception.status_code, 400)

            # Test sync endpoint
            with self.assertRaises(HTTPException) as ctx:
                sync_await(analyze_url(ScanRequest(url=target)))
            self.assertEqual(ctx.exception.status_code, 400)

    def test_end_to_end_async_scan_workflow(self):
        """Tests full asynchronous job lifecycle: submit -> poll -> retrieve report."""
        # 1. Submit scan job
        job_state = sync_await(create_scan(ScanCreateRequest(url="example.com", force_fresh=True)))
        scan_id = job_state["scan_id"]
        self.assertTrue(scan_id.startswith("scan-"))
        self.assertEqual(job_state["canonical_url"], "https://example.com/")

        # 2. Wait up to 3 seconds for background worker completion
        max_wait = 3.0
        start = time.time()
        completed = False
        final_state = None
        while time.time() - start < max_wait:
            final_state = sync_await(get_scan_status(scan_id))
            if final_state["state"] in ("completed", "partial"):
                completed = True
                break
            time.sleep(0.1)

        self.assertTrue(completed, f"Job did not complete in time, final state: {final_state['state']}")

        # 3. Retrieve final report
        report = sync_await(get_scan_report(scan_id))
        self.assertEqual(report["domain"], "example.com")
        self.assertIn(report["verdict"], ("clean", "suspicious", "phishing", "malicious"))
        self.assertIsInstance(report["risk_score"], int)
        self.assertIsNotNone(report["analysis_coverage"])

        # 4. Verify honest coverage and confidence
        coverage = report["analysis_coverage"]
        self.assertEqual(coverage["lexical"], 100)
        # ML is untrained, so ML coverage must be 0
        self.assertEqual(coverage["ml"], 0)
        # Threat feeds without API keys must be 0
        self.assertEqual(coverage["threat_feeds"], 0)
        # Overall coverage should honestly reflect partial pipeline
        self.assertLess(coverage["overall"], 80)
        # Confidence must not be inflated to 0.90
        self.assertLessEqual(report["confidence"], 0.75)

    def test_scans_history_and_deletion(self):
        """Verifies GET /scans, DELETE /scans/{id}, and DELETE /scans."""
        # Ensure at least one scan exists
        sync_await(create_scan(ScanCreateRequest(url="github.com", force_fresh=True)))
        time.sleep(0.5)

        # GET /scans legacy list
        scans_list = sync_await(list_scans(limit=10))
        self.assertIsInstance(scans_list, list)

        # GET /history pagination
        history = sync_await(get_scan_history(limit=5, offset=0))
        self.assertGreaterEqual(history["total"], 1)

        # DELETE /scans/{id}
        if scans_list:
            del_id = scans_list[0]["scan_id"]
            res = sync_await(delete_scan(del_id))
            self.assertTrue(res["success"])

        # DELETE /scans (clear history)
        clear_res = sync_await(clear_scans())
        self.assertTrue(clear_res["success"])
        cleared_history = sync_await(get_scan_history(limit=5, offset=0))
        self.assertEqual(cleared_history["total"], 0)

    def test_community_reports_workflow(self):
        """Verifies Community Reports creation, voting, and moderation."""
        # 1. List reports
        reports = sync_await(list_community_reports())
        self.assertGreaterEqual(len(reports), 2)

        # 2. Submit new report
        new_rep = sync_await(submit_community_report(CommunityReportCreate(
            target_url="https://fake-login-security-portal.xyz",
            threat_type="Phishing Credential Lure",
            targeted_brand="TestBrand",
            description="Cloned login form attempting credential harvesting.",
            reporter_handle="test_researcher",
            severity="high"
        )))
        self.assertEqual(new_rep.domain, "fake-login-security-portal.xyz")
        self.assertEqual(new_rep.status, "pending")
        self.assertEqual(new_rep.confirmations_count, 1)

        # 3. Vote on report
        voted = sync_await(vote_community_report(new_rep.id))
        self.assertEqual(voted.confirmations_count, 2)

        # 4. Moderate report (verify)
        moderated = sync_await(moderate_community_report(
            new_rep.id,
            CommunityReportModerateRequest(
                status="verified",
                moderator_note="Confirmed phishing kit targeting TestBrand users."
            )
        ))
        self.assertEqual(moderated.status, "verified")
        self.assertIsNotNone(moderated.moderated_at)

        # 5. Verify audit log entry was created
        audit_logs = sync_await(list_admin_audit_logs())
        self.assertTrue(any(a.target_id == new_rep.id for a in audit_logs))

    def test_watchlist_workflow(self):
        """Verifies Target Domain Watchlist additions and deletions."""
        # 1. List watchlist
        items = sync_await(list_watchlist())
        self.assertGreaterEqual(len(items), 1)

        # 2. Add to watchlist
        added = sync_await(add_to_watchlist(WatchlistItemCreate(
            target="https://target.org/login",
            label="Target Monitoring",
            alert_threshold=50
        )))
        self.assertEqual(added.domain, "target.org")
        self.assertEqual(added.status, "active")

        # 3. Remove from watchlist
        del_res = sync_await(remove_from_watchlist(added.id))
        self.assertTrue(del_res["success"])

    def test_threat_intelligence_workflow(self):
        """Verifies Threat Intelligence listing, submission, and verification."""
        # 1. List indicators
        indicators = sync_await(list_threat_indicators())
        self.assertGreaterEqual(len(indicators), 3)

        # 2. Submit indicator
        new_ioc = sync_await(submit_threat_indicator(ThreatIndicatorCreate(
            indicator_value="malicious-payload-drop.org",
            indicator_type="domain",
            threat_category="Payload Delivery",
            severity="critical",
            confidence=95,
            tags=["trojan", "dropper"]
        )))
        self.assertEqual(new_ioc.indicator_value, "malicious-payload-drop.org")
        self.assertFalse(new_ioc.is_verified)

        # 3. Verify indicator
        verified = sync_await(verify_threat_indicator(
            new_ioc.id,
            VerifyThreatIndicatorRequest(is_verified=True, reason="Sandbox dynamic execution confirmed payload delivery.")
        ))
        self.assertTrue(verified.is_verified)

        # 4. Verify admin audit log entry was recorded
        audit_logs = sync_await(list_admin_audit_logs())
        self.assertTrue(any(a.target_id == new_ioc.id for a in audit_logs))

    def test_tls_inspection_endpoint(self):
        """Verifies TLS Inspection endpoint behavior."""
        tls_res = sync_await(inspect_tls_certificate(TlsInspectRequest(hostname="example.com", port=443)))
        self.assertEqual(tls_res.hostname, "example.com")
        self.assertEqual(tls_res.port, 443)


if __name__ == "__main__":
    unittest.main()

