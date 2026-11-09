import time
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

from backend.app.core.config import settings

logger = logging.getLogger("trustshield.db")

def sanitize_secret(text: Optional[str]) -> str:
    """Strips privileged credentials, tokens, and API keys from error outputs."""
    if not text:
        return ""
    sanitized = str(text)
    for secret in (settings.SUPABASE_SERVICE_ROLE_KEY, settings.SUPABASE_ANON_KEY):
        if secret and len(secret) > 6:
            sanitized = sanitized.replace(secret, "[REDACTED]")
    return sanitized

class SupabaseManager:
    """
    Manages genuine Supabase client initialization, active connection health checks,
    and PostgreSQL CRUD persistence operations with graceful local in-memory fallback.
    Fully compatible with modern sb_secret_ keys as well as legacy JWT service_role keys.
    """
    def __init__(self):
        self._admin_client = None
        self._anon_client = None

    @property
    def is_configured(self) -> bool:
        """Indicates whether valid Supabase configuration is present."""
        return settings.is_supabase_configured

    @property
    def has_service_role(self) -> bool:
        """Indicates whether an administrative service role key is present."""
        return settings.is_service_role_configured

    def get_client(self, require_admin: bool = True):
        """
        Retrieves the Supabase client instance.
        Defaults to administrative service role client if available, falling back to anon client.
        """
        if not self.is_configured:
            return None

        # Prefer administrative client for backend persistence
        if require_admin and settings.SUPABASE_SERVICE_ROLE_KEY:
            if self._admin_client is None:
                try:
                    from supabase import create_client
                    self._admin_client = create_client(
                        settings.SUPABASE_URL,
                        settings.SUPABASE_SERVICE_ROLE_KEY
                    )
                    logger.info("Initialized administrative Supabase client.")
                except Exception as e:
                    logger.warning(f"Failed to initialize administrative Supabase client: {sanitize_secret(str(e))}")
                    self._admin_client = None
            if self._admin_client:
                return self._admin_client

        # Fallback to anon client
        if self._anon_client is None and settings.SUPABASE_ANON_KEY:
            try:
                from supabase import create_client
                self._anon_client = create_client(
                    settings.SUPABASE_URL,
                    settings.SUPABASE_ANON_KEY
                )
                logger.info("Initialized public/anon Supabase client.")
            except Exception as e:
                logger.warning(f"Failed to initialize public Supabase client: {sanitize_secret(str(e))}")
                self._anon_client = None

        return self._anon_client or self._admin_client

    def check_health(self) -> Dict[str, Any]:
        """
        Actively probes the Supabase PostgreSQL database by executing a minimal query.
        Returns genuine connectivity status, measured round-trip latency, and sanitized details.
        """
        if not self.is_configured:
            return {
                "status": "offline",
                "provider": "supabase",
                "latency_ms": 0.0,
                "details": "Awaiting valid Supabase credentials in environment"
            }

        client = self.get_client()
        if not client:
            return {
                "status": "degraded",
                "provider": "supabase",
                "latency_ms": 0.0,
                "details": "Supabase client initialization failed"
            }

        start_time = time.time()
        try:
            # Active probe: select single row from scans or threat_indicators table
            res = client.table("threat_indicators").select("id").limit(1).execute()
            latency_ms = round((time.time() - start_time) * 1000, 2)
            return {
                "status": "online",
                "provider": "supabase",
                "latency_ms": latency_ms,
                "details": "Connected to Supabase PostgreSQL cluster"
            }
        except Exception as e:
            latency_ms = round((time.time() - start_time) * 1000, 2)
            clean_err = sanitize_secret(str(e))
            logger.warning(f"Supabase active health check failed: {clean_err}")
            return {
                "status": "degraded",
                "provider": "supabase",
                "latency_ms": latency_ms,
                "details": f"Database unreachable: {clean_err[:120]}"
            }

    # =========================================================================
    # Auth & JWT Validation (Compatible with sb_secret_ & legacy JWT keys)
    # =========================================================================
    def get_user_from_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Authoritatively validates a Supabase user access token via GoTrue client.auth.get_user.
        Does NOT rely on manual jwt.decode, guaranteeing compatibility with all key formats.
        """
        if not token or not self.is_configured:
            return None

        client = self.get_client(require_admin=False)
        if not client:
            return None

        try:
            res = client.auth.get_user(token)
            if res and hasattr(res, "user") and res.user:
                u = res.user
                return {
                    "id": str(getattr(u, "id", "")),
                    "email": getattr(u, "email", None),
                    "role": (
                        getattr(u, "app_metadata", {}).get("role")
                        or getattr(u, "user_metadata", {}).get("role")
                        or "user"
                    ),
                    "metadata": getattr(u, "user_metadata", {}) or {}
                }
        except Exception as e:
            logger.debug(f"Auth token verification failed: {sanitize_secret(str(e))}")
        return None

    # =========================================================================
    # Scans & Reports Persistence
    # =========================================================================
    def save_scan(self, job_dict: Dict[str, Any], user_id: Optional[str] = None) -> bool:
        """Persists or updates a scan job and forensic report in PostgreSQL."""
        client = self.get_client()
        if not client:
            return False

        try:
            res = job_dict.get("result") or {}
            record = {
                "scan_id": job_dict.get("scan_id"),
                "user_id": user_id,
                "raw_url": job_dict.get("raw_url"),
                "canonical_url": job_dict.get("canonical_url"),
                "domain": job_dict.get("domain"),
                "state": job_dict.get("state", "completed"),
                "progress_percent": job_dict.get("progress_percent", 100),
                "verdict": res.get("verdict", "clean"),
                "risk_score": res.get("risk_score", 0),
                "confidence": res.get("confidence", 0.85),
                "heuristics": res.get("heuristics") or {},
                "ml_prediction": res.get("ml_prediction") or {},
                "tls_summary": res.get("tls_summary"),
                "security_headers": res.get("security_headers"),
                "analysis_coverage": res.get("analysis_coverage"),
                "threat_feed_matches": res.get("threat_feed_matches") or [],
                "threat_intel_summary": res.get("threat_intel_summary") or {},
                "evidence": res.get("evidence") or [],
                "recommendations": res.get("recommendations") or [],
                "module_statuses": job_dict.get("module_statuses") or {},
                "error_payload": job_dict.get("error"),
                "completed_at": (
                    job_dict.get("timestamps", {}).get("completed_at")
                    or (datetime.now(timezone.utc).isoformat() if job_dict.get("state") in ("completed", "partial") else None)
                )
            }
            client.table("scans").upsert(record).execute()
            return True
        except Exception as e:
            logger.warning(f"Failed to persist scan {job_dict.get('scan_id')}: {sanitize_secret(str(e))}")
            return False

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single scan from PostgreSQL."""
        client = self.get_client()
        if not client:
            return None
        try:
            res = client.table("scans").select("*").eq("scan_id", scan_id).limit(1).execute()
            if res.data and len(res.data) > 0:
                row = res.data[0]
                return self._row_to_scan_job_state(row)
        except Exception as e:
            logger.warning(f"Failed to query scan {scan_id}: {sanitize_secret(str(e))}")
        return None

    def list_scans(self, limit: int = 50, verdict: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
        """Retrieves completed scan forensic reports for scan history lists."""
        client = self.get_client()
        if not client:
            return None
        try:
            q = client.table("scans").select("*").in_("state", ["completed", "partial"]).order("created_at", desc=True)
            if verdict and verdict != "all":
                q = q.eq("verdict", verdict)
            res = q.limit(limit).execute()
            if res.data is not None:
                results = []
                for row in res.data:
                    job_state = self._row_to_scan_job_state(row)
                    if job_state.get("result"):
                        results.append(job_state["result"])
                return results
        except Exception as e:
            logger.warning(f"Failed to list scans from Supabase: {sanitize_secret(str(e))}")
        return None

    def list_history(self, limit: int = 50, offset: int = 0, verdict: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves paginated scan job states from PostgreSQL."""
        client = self.get_client()
        if not client:
            return None
        try:
            q = client.table("scans").select("*", count="exact").order("created_at", desc=True)
            if verdict and verdict != "all":
                q = q.eq("verdict", verdict)
            res = q.range(offset, offset + limit - 1).execute()
            items = [self._row_to_scan_job_state(r) for r in (res.data or [])]
            total = res.count if res.count is not None else len(items)
            return {"items": items, "total": total, "limit": limit, "offset": offset}
        except Exception as e:
            logger.warning(f"Failed to list scan history from Supabase: {sanitize_secret(str(e))}")
        return None

    def delete_scan(self, scan_id: str) -> bool:
        """Deletes a scan record from PostgreSQL."""
        client = self.get_client()
        if not client:
            return False
        try:
            client.table("scans").delete().eq("scan_id", scan_id).execute()
            return True
        except Exception as e:
            logger.warning(f"Failed to delete scan {scan_id}: {sanitize_secret(str(e))}")
            return False

    def clear_scans(self) -> bool:
        """Clears all scan records from PostgreSQL."""
        client = self.get_client()
        if not client:
            return False
        try:
            # Delete all rows where scan_id is not null
            client.table("scans").delete().neq("scan_id", "").execute()
            return True
        except Exception as e:
            logger.warning(f"Failed to clear scans: {sanitize_secret(str(e))}")
            return False

    def _row_to_scan_job_state(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Maps a PostgreSQL scans row back to ScanJobStateResponse dictionary format."""
        result = None
        if row.get("state") in ("completed", "partial"):
            result = {
                "scan_id": row.get("scan_id"),
                "url": row.get("raw_url"),
                "normalized_url": row.get("canonical_url"),
                "domain": row.get("domain"),
                "verdict": row.get("verdict"),
                "risk_score": row.get("risk_score"),
                "confidence": float(row.get("confidence", 0.85)),
                "heuristics": row.get("heuristics") or {},
                "ml_prediction": row.get("ml_prediction") or {},
                "tls_summary": row.get("tls_summary"),
                "security_headers": row.get("security_headers"),
                "analysis_coverage": row.get("analysis_coverage"),
                "threat_feed_matches": row.get("threat_feed_matches") or [],
                "threat_intel_summary": row.get("threat_intel_summary") or {},
                "evidence": row.get("evidence") or [],
                "recommendations": row.get("recommendations") or [],
                "created_at": str(row.get("created_at") or "")
            }

        return {
            "scan_id": row.get("scan_id"),
            "request_id": f"req-{row.get('scan_id')}",
            "raw_url": row.get("raw_url"),
            "canonical_url": row.get("canonical_url"),
            "domain": row.get("domain"),
            "state": row.get("state", "completed"),
            "progress_percent": row.get("progress_percent", 100),
            "module_statuses": row.get("module_statuses") or {},
            "timestamps": {
                "created_at": str(row.get("created_at") or ""),
                "started_at": str(row.get("created_at") or ""),
                "completed_at": str(row.get("completed_at") or "") if row.get("completed_at") else None
            },
            "error": row.get("error_payload"),
            "result": result
        }

    # =========================================================================
    # Community Reports Persistence
    # =========================================================================
    def list_community_reports(self, status: Optional[str] = None, search: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
        client = self.get_client()
        if not client:
            return None
        try:
            q = client.table("community_reports").select("*").order("created_at", desc=True)
            if status and status != "all":
                q = q.eq("status", status)
            if search:
                # Search target_url, domain, or targeted_brand
                q = q.or_(f"target_url.ilike.%{search}%,domain.ilike.%{search}%,targeted_brand.ilike.%{search}%,threat_type.ilike.%{search}%")
            res = q.execute()
            return res.data
        except Exception as e:
            logger.warning(f"Failed to query community reports: {sanitize_secret(str(e))}")
            return None

    def create_community_report(self, report_dict: Dict[str, Any], user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        client = self.get_client()
        if not client:
            return None
        try:
            data = dict(report_dict)
            if user_id:
                data["user_id"] = user_id
            res = client.table("community_reports").insert(data).execute()
            if res.data and len(res.data) > 0:
                return res.data[0]
            return data
        except Exception as e:
            logger.warning(f"Failed to insert community report: {sanitize_secret(str(e))}")
            return None

    def vote_community_report(self, report_id: str, new_count: int) -> Optional[Dict[str, Any]]:
        client = self.get_client()
        if not client:
            return None
        try:
            res = client.table("community_reports").update({"confirmations_count": new_count}).eq("id", report_id).execute()
            if res.data and len(res.data) > 0:
                return res.data[0]
        except Exception as e:
            logger.warning(f"Failed to vote on community report: {sanitize_secret(str(e))}")
        return None

    def moderate_community_report(self, report_id: str, status: str, note: Optional[str] = None) -> Optional[Dict[str, Any]]:
        client = self.get_client()
        if not client:
            return None
        try:
            payload = {
                "status": status,
                "moderated_at": datetime.now(timezone.utc).isoformat(),
                "moderator_note": note
            }
            res = client.table("community_reports").update(payload).eq("id", report_id).execute()
            if res.data and len(res.data) > 0:
                return res.data[0]
        except Exception as e:
            logger.warning(f"Failed to moderate community report: {sanitize_secret(str(e))}")
        return None

    # =========================================================================
    # Watchlist Persistence
    # =========================================================================
    def list_watchlist(self, user_id: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
        client = self.get_client()
        if not client:
            return None
        try:
            q = client.table("watchlist").select("*").order("added_at", desc=True)
            if user_id:
                q = q.or_(f"user_id.is.null,user_id.eq.{user_id}")
            res = q.execute()
            return res.data
        except Exception as e:
            logger.warning(f"Failed to query watchlist: {sanitize_secret(str(e))}")
            return None

    def add_watchlist_item(self, item_dict: Dict[str, Any], user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        client = self.get_client()
        if not client:
            return None
        try:
            data = dict(item_dict)
            if user_id:
                data["user_id"] = user_id
            res = client.table("watchlist").insert(data).execute()
            if res.data and len(res.data) > 0:
                return res.data[0]
            return data
        except Exception as e:
            logger.warning(f"Failed to add watchlist item: {sanitize_secret(str(e))}")
            return None

    def remove_watchlist_item(self, item_id: str, user_id: Optional[str] = None) -> bool:
        client = self.get_client()
        if not client:
            return False
        try:
            q = client.table("watchlist").delete().eq("id", item_id)
            if user_id:
                q = q.or_(f"user_id.is.null,user_id.eq.{user_id}")
            q.execute()
            return True
        except Exception as e:
            logger.warning(f"Failed to remove watchlist item: {sanitize_secret(str(e))}")
            return False

    # =========================================================================
    # Threat Indicators Persistence
    # =========================================================================
    def list_threat_indicators(
        self,
        indicator_type: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None
    ) -> Optional[List[Dict[str, Any]]]:
        client = self.get_client()
        if not client:
            return None
        try:
            q = client.table("threat_indicators").select("*").order("created_at", desc=True)
            if indicator_type:
                q = q.eq("indicator_type", indicator_type)
            if severity:
                q = q.eq("severity", severity)
            if search:
                q = q.or_(f"indicator_value.ilike.%{search}%,threat_category.ilike.%{search}%")
            res = q.execute()
            return res.data
        except Exception as e:
            logger.warning(f"Failed to query threat indicators: {sanitize_secret(str(e))}")
            return None

    def create_threat_indicator(self, indicator_dict: Dict[str, Any], user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        client = self.get_client()
        if not client:
            return None
        try:
            data = dict(indicator_dict)
            if user_id:
                data["user_id"] = user_id
            res = client.table("threat_indicators").insert(data).execute()
            if res.data and len(res.data) > 0:
                return res.data[0]
            return data
        except Exception as e:
            logger.warning(f"Failed to insert threat indicator: {sanitize_secret(str(e))}")
            return None

    def verify_threat_indicator(self, indicator_id: str, is_verified: bool, verified_by: Optional[str] = "Admin Moderator") -> Optional[Dict[str, Any]]:
        client = self.get_client()
        if not client:
            return None
        try:
            payload = {
                "is_verified": is_verified,
                "verified_at": datetime.now(timezone.utc).isoformat() if is_verified else None,
                "verified_by": verified_by if is_verified else None
            }
            res = client.table("threat_indicators").update(payload).eq("id", indicator_id).execute()
            if res.data and len(res.data) > 0:
                return res.data[0]
        except Exception as e:
            logger.warning(f"Failed to update threat indicator: {sanitize_secret(str(e))}")
        return None

    # =========================================================================
    # Admin Audit Logs Persistence
    # =========================================================================
    def record_audit_log(self, entry_dict: Dict[str, Any], user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        client = self.get_client()
        if not client:
            return None
        try:
            data = dict(entry_dict)
            if user_id:
                data["user_id"] = user_id
            res = client.table("admin_audit_logs").insert(data).execute()
            if res.data and len(res.data) > 0:
                return res.data[0]
            return data
        except Exception as e:
            logger.warning(f"Failed to record audit log: {sanitize_secret(str(e))}")
            return None

    def list_admin_audit_logs(self, limit: int = 100) -> Optional[List[Dict[str, Any]]]:
        client = self.get_client()
        if not client:
            return None
        try:
            res = client.table("admin_audit_logs").select("*").order("timestamp", desc=True).limit(limit).execute()
            return res.data
        except Exception as e:
            logger.warning(f"Failed to query audit logs: {sanitize_secret(str(e))}")
            return None

    # =========================================================================
    # Authorized Domain Security Testing Persistence (OWASP ZAP)
    # =========================================================================
    def save_authorized_challenge(self, challenge_dict: Dict[str, Any], user_id: Optional[str] = None) -> bool:
        client = self.get_client()
        if not client:
            return False
        try:
            record = {
                "domain": challenge_dict["domain"],
                "owner_email": challenge_dict.get("owner_email", ""),
                "challenge_token": challenge_dict["challenge_token"],
                "txt_record_name": challenge_dict["txt_record_name"],
                "txt_record_value": challenge_dict["txt_record_value"],
                "http_challenge_path": challenge_dict["http_challenge_path"],
                "http_challenge_content": challenge_dict["http_challenge_content"],
                "expires_at": challenge_dict["expires_at"],
                "verified": False,
                "user_id": user_id
            }
            client.table("authorized_domains").upsert(record).execute()
            return True
        except Exception as e:
            logger.warning(f"Failed to save domain challenge: {sanitize_secret(str(e))}")
            return False

    def update_authorized_verification(self, domain: str, verified: bool, auth_token: Optional[str] = None) -> bool:
        client = self.get_client()
        if not client:
            return False
        try:
            payload = {"verified": verified, "auth_token": auth_token}
            client.table("authorized_domains").update(payload).eq("domain", domain).execute()
            return True
        except Exception as e:
            logger.warning(f"Failed to update domain verification: {sanitize_secret(str(e))}")
            return False

db_manager = SupabaseManager()
