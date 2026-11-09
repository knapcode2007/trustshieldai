import unittest
import urllib.request
import urllib.error
import json
import time

LIVE_BACKEND_URL = "https://trustshield-api-zsv1.onrender.com"

def is_live_backend_reachable():
    try:
        req = urllib.request.Request(f"{LIVE_BACKEND_URL}/health", headers={"User-Agent": "Prober/1.0"})
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.getcode() == 200
    except Exception:
        return False

@unittest.skipUnless(is_live_backend_reachable(), "Live Render backend is not reachable from this test environment")
class LiveRenderIntegrationTestCase(unittest.TestCase):
    """End-to-end integration tests executed directly against the live deployed Render backend."""

    def test_01_health_and_subsystems(self):
        """Verifies root /health and /api/v1/health on live deployment."""
        req = urllib.request.Request(f"{LIVE_BACKEND_URL}/health", headers={"User-Agent": "LiveTester/1.0"})
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            self.assertEqual(resp.getcode(), 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["app_name"], "TrustShield AI Backend")
            self.assertIn("ml_engine", data["subsystems"])
            self.assertIn("fastapi_service", data["subsystems"])

        req_v1 = urllib.request.Request(f"{LIVE_BACKEND_URL}/api/v1/health", headers={"User-Agent": "LiveTester/1.0"})
        with urllib.request.urlopen(req_v1, timeout=10.0) as resp:
            self.assertEqual(resp.getcode(), 200)

    def test_02_async_scan_lifecycle(self):
        """Verifies full scan flow: POST /api/v1/scans -> GET status -> GET report."""
        submit_req = urllib.request.Request(
            f"{LIVE_BACKEND_URL}/api/v1/scans",
            data=json.dumps({"url": "example.com", "force_fresh": True}).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "LiveTester/1.0"}
        )

        with urllib.request.urlopen(submit_req, timeout=10.0) as resp:
            self.assertEqual(resp.getcode(), 202)
            job = json.loads(resp.read().decode("utf-8"))
            scan_id = job["scan_id"]
            self.assertTrue(scan_id.startswith("scan-"))
            self.assertEqual(job["domain"], "example.com")

        # Poll for completion (up to 15s)
        completed = False
        final_state = None
        for _ in range(30):
            time.sleep(0.5)
            poll_req = urllib.request.Request(f"{LIVE_BACKEND_URL}/api/v1/scans/{scan_id}")
            with urllib.request.urlopen(poll_req, timeout=10.0) as resp:
                poll_res = json.loads(resp.read().decode("utf-8"))
                final_state = poll_res["state"]
                if final_state in ("completed", "partial"):
                    completed = True
                    break

        self.assertTrue(completed, f"Scan job did not complete in time, final state: {final_state}")

        # Fetch report
        report_req = urllib.request.Request(f"{LIVE_BACKEND_URL}/api/v1/reports/{scan_id}")
        with urllib.request.urlopen(report_req, timeout=10.0) as resp:
            self.assertEqual(resp.getcode(), 200)
            report = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(report["domain"], "example.com")
            self.assertIn(report["verdict"], ("clean", "suspicious", "phishing", "malicious"))
            self.assertIsInstance(report["risk_score"], int)
            self.assertIsNotNone(report["analysis_coverage"])
            self.assertLessEqual(report["confidence"], 0.75)

    def test_03_ssrf_protection_live(self):
        """Verifies SSRF is strictly blocked on live backend."""
        blocked_urls = [
            "http://127.0.0.1:8000",
            "http://localhost:3000",
            "http://169.254.169.254/latest/meta-data",
        ]
        for url in blocked_urls:
            time.sleep(0.5)
            ssrf_req = urllib.request.Request(
                f"{LIVE_BACKEND_URL}/api/v1/scans",
                data=json.dumps({"url": url}).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "LiveTester/1.0"}
            )
            try:
                urllib.request.urlopen(ssrf_req, timeout=10.0)
                self.fail(f"Should have failed SSRF for {url}")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 400)
                err_data = json.loads(e.read().decode("utf-8"))
                self.assertIn("error", err_data)

    def test_04_community_reports_live(self):
        """Verifies Community Reports endpoints on live backend."""
        req = urllib.request.Request(f"{LIVE_BACKEND_URL}/api/v1/community/reports")
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            self.assertEqual(resp.getcode(), 200)
            reports = json.loads(resp.read().decode("utf-8"))
            self.assertIsInstance(reports, list)
            self.assertGreaterEqual(len(reports), 2)

    def test_05_watchlist_live(self):
        """Verifies Watchlist endpoints on live backend."""
        req = urllib.request.Request(f"{LIVE_BACKEND_URL}/api/v1/watchlist")
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            self.assertEqual(resp.getcode(), 200)
            items = json.loads(resp.read().decode("utf-8"))
            self.assertIsInstance(items, list)
            self.assertGreaterEqual(len(items), 1)

    def test_06_admin_audit_logs_live(self):
        """Verifies Admin Audit Logs on live backend."""
        req = urllib.request.Request(f"{LIVE_BACKEND_URL}/api/v1/admin/audit-logs")
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            self.assertEqual(resp.getcode(), 200)
            logs = json.loads(resp.read().decode("utf-8"))
            self.assertIsInstance(logs, list)

    def test_07_threat_indicators_live(self):
        """Verifies Threat Indicators on live backend."""
        req = urllib.request.Request(f"{LIVE_BACKEND_URL}/api/v1/intel/indicators")
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            self.assertEqual(resp.getcode(), 200)
            indicators = json.loads(resp.read().decode("utf-8"))
            self.assertIsInstance(indicators, list)
            self.assertGreaterEqual(len(indicators), 3)

    def test_08_tls_inspect_live(self):
        """Verifies TLS Inspector on live backend."""
        tls_req = urllib.request.Request(
            f"{LIVE_BACKEND_URL}/api/v1/tls/inspect",
            data=json.dumps({"hostname": "example.com", "port": 443}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(tls_req, timeout=10.0) as resp:
            self.assertEqual(resp.getcode(), 200)
            tls_data = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(tls_data.get("connected"))


if __name__ == "__main__":
    unittest.main()
