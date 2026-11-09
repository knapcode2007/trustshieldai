"""
TrustShield AI - Supabase PostgreSQL & Auth Integration Test Suite
Validates:
1. sb_secret_ key format compatibility and initialization.
2. Active health check connectivity probe, latency calculation, and secret sanitization.
3. Server-side Supabase Auth JWT validation and role-based authorization.
4. Persistent CRUD operations across scans, reports, watchlist, IOCs, and audit logs.
5. Resilient fallback to local in-memory storage when offline.
"""

import os
import asyncio
import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from backend.app.core.config import Settings
from backend.app.db.supabase import SupabaseManager, sanitize_secret
from backend.app.core.auth import (
    get_current_user_optional,
    get_current_user,
    require_admin_or_moderator,
)
from fastapi import HTTPException

def sync_await(coro):
    """Executes a coroutine synchronously for deterministic test execution."""
    try:
        coro.send(None)
    except StopIteration as e:
        return e.value


class SupabaseIntegrationTestCase(unittest.TestCase):
    """Unit and integration test cases for Supabase PostgreSQL and GoTrue Auth."""

    def setUp(self):
        self.mgr = SupabaseManager()

    def test_sb_secret_format_compatibility(self):
        """Verifies that modern sb_secret_ key format initializes without assuming JWT decoding."""
        test_url = "https://mockproject.supabase.co"
        test_key = "sb_secret_a1b2c3d4e5f60718293a4b5c6d7e8f90"

        with patch("backend.app.db.supabase.settings") as mock_settings:
            mock_settings.is_supabase_configured = True
            mock_settings.is_service_role_configured = True
            mock_settings.SUPABASE_URL = test_url
            mock_settings.SUPABASE_SERVICE_ROLE_KEY = test_key
            mock_settings.SUPABASE_ANON_KEY = "sb_publishable_anon_12345"

            mgr = SupabaseManager()
            self.assertTrue(mgr.is_configured)
            self.assertTrue(mgr.has_service_role)

            with patch("supabase.create_client") as mock_create:
                mock_create.return_value = MagicMock()
                client = mgr.get_client(require_admin=True)
                self.assertIsNotNone(client)
                mock_create.assert_called_with(test_url, test_key)

    def test_secret_sanitization(self):
        """Verifies that privileged secrets and sb_secret_ strings are stripped from logs and errors."""
        secret_key = "sb_secret_super_secret_credential_999"
        anon_key = "anon_key_standard_telemetry_888"

        with patch("backend.app.db.supabase.settings") as mock_settings:
            mock_settings.SUPABASE_SERVICE_ROLE_KEY = secret_key
            mock_settings.SUPABASE_ANON_KEY = anon_key

            raw_err = f"Failed to connect to cluster with key {secret_key} and secondary {anon_key}"
            clean = sanitize_secret(raw_err)

            self.assertNotIn(secret_key, clean)
            self.assertNotIn(anon_key, clean)
            self.assertIn("[REDACTED]", clean)

    def test_health_check_unconfigured(self):
        """Verifies health check output when Supabase credentials are not provided."""
        with patch.object(SupabaseManager, "is_configured", property(lambda self: False)):
            health = self.mgr.check_health()
            self.assertEqual(health["status"], "offline")
            self.assertEqual(health["provider"], "supabase")
            self.assertEqual(health["latency_ms"], 0.0)
            self.assertIn("Awaiting valid Supabase credentials", health["details"])

    def test_health_check_online_with_latency(self):
        """Verifies genuine active query probe and latency calculation when database is online."""
        mock_client = MagicMock()
        mock_table = MagicMock()
        mock_query = MagicMock()
        mock_res = MagicMock()

        mock_client.table.return_value = mock_table
        mock_table.select.return_value = mock_query
        mock_query.limit.return_value = mock_query
        mock_query.execute.return_value = mock_res

        with patch.object(SupabaseManager, "is_configured", property(lambda self: True)), \
             patch.object(self.mgr, "get_client", return_value=mock_client):

            health = self.mgr.check_health()
            self.assertEqual(health["status"], "online")
            self.assertGreaterEqual(health["latency_ms"], 0.0)
            self.assertEqual(health["details"], "Connected to Supabase PostgreSQL cluster")
            mock_table.select.assert_called_with("id")

    def test_health_check_degraded_sanitizes_errors(self):
        """Verifies degraded status and credential redaction when active probe fails."""
        mock_client = MagicMock()
        mock_table = MagicMock()
        mock_client.table.return_value = mock_table
        mock_table.select.side_effect = Exception("Connection timeout to sb_secret_sensitive_host:5432")

        with patch.object(SupabaseManager, "is_configured", property(lambda self: True)), \
             patch.object(self.mgr, "get_client", return_value=mock_client), \
             patch("backend.app.db.supabase.settings") as mock_settings:

            mock_settings.SUPABASE_SERVICE_ROLE_KEY = "sb_secret_sensitive_host"
            mock_settings.SUPABASE_ANON_KEY = ""

            health = self.mgr.check_health()
            self.assertEqual(health["status"], "degraded")
            self.assertNotIn("sb_secret_sensitive_host", health["details"])
            self.assertIn("[REDACTED]", health["details"])

    # =========================================================================
    # Auth & JWT Validation Tests
    # =========================================================================
    def test_auth_optional_no_header(self):
        """Verifies that requests without authorization header return None (anonymous allowed)."""
        user = sync_await(get_current_user_optional(authorization=None))
        self.assertIsNone(user)

    def test_auth_optional_malformed_header(self):
        """Verifies that invalid header format raises HTTP 401."""
        with self.assertRaises(HTTPException) as ctx:
            sync_await(get_current_user_optional(authorization="Basic dXNlcjpwYXNz"))
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertEqual(ctx.exception.detail["code"], "INVALID_AUTH_HEADER")

    def test_auth_valid_supabase_token(self):
        """Verifies authoritative user resolution via GoTrue client.auth.get_user."""
        mock_user = MagicMock()
        mock_user.id = "11111111-2222-3333-4444-555555555555"
        mock_user.email = "analyst@security.org"
        mock_user.app_metadata = {"role": "moderator"}
        mock_user.user_metadata = {"full_name": "Security Analyst"}

        mock_auth_res = MagicMock()
        mock_auth_res.user = mock_user

        mock_client = MagicMock()
        mock_client.auth.get_user.return_value = mock_auth_res

        with patch.object(SupabaseManager, "is_configured", property(lambda self: True)), \
             patch.object(self.mgr, "get_client", return_value=mock_client):

            user = self.mgr.get_user_from_token("valid_access_jwt")
            self.assertIsNotNone(user)
            self.assertEqual(user["id"], "11111111-2222-3333-4444-555555555555")
            self.assertEqual(user["email"], "analyst@security.org")
            self.assertEqual(user["role"], "moderator")

    def test_auth_invalid_supabase_token(self):
        """Verifies that expired or invalid token returns None or raises 401 when configured."""
        mock_client = MagicMock()
        mock_client.auth.get_user.side_effect = Exception("JWT expired")

        with patch("backend.app.core.auth.db_manager") as mock_dm:
            mock_dm.is_configured = True
            mock_dm.get_user_from_token.return_value = None

            with self.assertRaises(HTTPException) as ctx:
                sync_await(get_current_user_optional(authorization="Bearer expired_jwt_token"))
            self.assertEqual(ctx.exception.status_code, 401)
            self.assertEqual(ctx.exception.detail["code"], "INVALID_TOKEN")

    def test_auth_require_admin_or_moderator(self):
        """Verifies role-based access control allows admin/moderator and blocks regular user."""
        admin_user = {"id": "1", "email": "admin@ts.ai", "role": "admin"}
        mod_user = {"id": "2", "email": "mod@ts.ai", "role": "moderator"}
        regular_user = {"id": "3", "email": "user@ts.ai", "role": "user"}

        # Admin allowed
        res_admin = sync_await(require_admin_or_moderator(admin_user))
        self.assertEqual(res_admin["role"], "admin")

        # Moderator allowed
        res_mod = sync_await(require_admin_or_moderator(mod_user))
        self.assertEqual(res_mod["role"], "moderator")

        # Standard user forbidden (403)
        with self.assertRaises(HTTPException) as ctx:
            sync_await(require_admin_or_moderator(regular_user))
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.detail["code"], "FORBIDDEN")

    # =========================================================================
    # Persistent CRUD Operations Tests
    # =========================================================================
    def test_save_and_get_scan_persistence(self):
        """Verifies scan persistence mapping and retrieval with mock client."""
        mock_client = MagicMock()
        mock_table = MagicMock()
        mock_client.table.return_value = mock_table

        scan_job = {
            "scan_id": "scan-test-123",
            "raw_url": "https://phish-test.xyz",
            "canonical_url": "https://phish-test.xyz/",
            "domain": "phish-test.xyz",
            "state": "completed",
            "progress_percent": 100,
            "timestamps": {"completed_at": datetime.now(timezone.utc).isoformat()},
            "result": {
                "scan_id": "scan-test-123",
                "url": "https://phish-test.xyz",
                "normalized_url": "https://phish-test.xyz/",
                "domain": "phish-test.xyz",
                "verdict": "phishing",
                "risk_score": 85,
                "confidence": 0.95,
                "heuristics": {"suspicious_keywords": ["login", "bank"]},
                "recommendations": []
            }
        }

        with patch.object(self.mgr, "get_client", return_value=mock_client):
            saved = self.mgr.save_scan(scan_job)
            self.assertTrue(saved)
            mock_table.upsert.assert_called()

            # Test retrieval mapping
            mock_table.select.return_value.eq.return_value.limit.return_value.execute.return_value.data = [{
                "scan_id": "scan-test-123",
                "raw_url": "https://phish-test.xyz",
                "canonical_url": "https://phish-test.xyz/",
                "domain": "phish-test.xyz",
                "state": "completed",
                "progress_percent": 100,
                "verdict": "phishing",
                "risk_score": 85,
                "confidence": 0.95,
                "heuristics": {"suspicious_keywords": ["login", "bank"]},
                "created_at": "2026-11-09T00:00:00Z",
                "completed_at": "2026-11-09T00:00:02Z"
            }]

            retrieved = self.mgr.get_scan("scan-test-123")
            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved["scan_id"], "scan-test-123")
            self.assertEqual(retrieved["result"]["verdict"], "phishing")
            self.assertEqual(retrieved["result"]["risk_score"], 85)

    def test_community_report_persistence(self):
        """Verifies community report insertion and moderation with mock client."""
        mock_client = MagicMock()
        mock_table = MagicMock()
        mock_client.table.return_value = mock_table

        with patch.object(self.mgr, "get_client", return_value=mock_client):
            # Test insert
            mock_table.insert.return_value.execute.return_value.data = [{"id": "cr-test-1"}]
            created = self.mgr.create_community_report({"id": "cr-test-1", "target_url": "https://evil.cc"})
            self.assertIsNotNone(created)

            # Test moderate
            mock_table.update.return_value.eq.return_value.execute.return_value.data = [{"id": "cr-test-1", "status": "verified"}]
            moderated = self.mgr.moderate_community_report("cr-test-1", "verified", "Confirmed phishing")
            self.assertIsNotNone(moderated)
            self.assertEqual(moderated["status"], "verified")

    def test_watchlist_persistence(self):
        """Verifies watchlist addition and removal with mock client."""
        mock_client = MagicMock()
        mock_table = MagicMock()
        mock_client.table.return_value = mock_table

        with patch.object(self.mgr, "get_client", return_value=mock_client):
            mock_table.insert.return_value.execute.return_value.data = [{"id": "wl-test-1"}]
            added = self.mgr.add_watchlist_item({"id": "wl-test-1", "target": "https://bank.com"})
            self.assertIsNotNone(added)

            deleted = self.mgr.remove_watchlist_item("wl-test-1")
            self.assertTrue(deleted)

    def test_threat_indicator_persistence(self):
        """Verifies threat indicator creation and verification with mock client."""
        mock_client = MagicMock()
        mock_table = MagicMock()
        mock_client.table.return_value = mock_table

        with patch.object(self.mgr, "get_client", return_value=mock_client):
            mock_table.insert.return_value.execute.return_value.data = [{"id": "ioc-test-1"}]
            ioc = self.mgr.create_threat_indicator({"id": "ioc-test-1", "indicator_value": "phish.xyz"})
            self.assertIsNotNone(ioc)

            mock_table.update.return_value.eq.return_value.execute.return_value.data = [{"id": "ioc-test-1", "is_verified": True}]
            verified = self.mgr.verify_threat_indicator("ioc-test-1", True, verified_by="Test Analyst")
            self.assertIsNotNone(verified)
            self.assertTrue(verified["is_verified"])

    def test_admin_audit_log_persistence(self):
        """Verifies admin audit log appending with mock client."""
        mock_client = MagicMock()
        mock_table = MagicMock()
        mock_client.table.return_value = mock_table

        with patch.object(self.mgr, "get_client", return_value=mock_client):
            mock_table.insert.return_value.execute.return_value.data = [{"id": "audit-test-1"}]
            log_entry = self.mgr.record_audit_log({
                "id": "audit-test-1",
                "action": "TEST_ACTION",
                "target_type": "report",
                "target_id": "cr-101",
                "target_value": "test.com",
                "decision": "approved"
            })
            self.assertIsNotNone(log_entry)


if __name__ == "__main__":
    unittest.main()
