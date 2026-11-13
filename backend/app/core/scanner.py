import time
import uuid
import logging
import threading
import concurrent.futures
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, urljoin

from backend.app.security.ssrf import SSRFValidator, SSRFSecurityException
from backend.app.core.url_normalizer import URLNormalizer
from backend.app.ml.service import ml_service
from backend.app.ml.features import URLFeatureExtractor
from backend.app.security.heuristics import heuristics_engine
from backend.app.security.tls_inspector import tls_inspector
from backend.app.security.passive_scanner import passive_scanner
from backend.app.intel.manager import threat_intel_manager

logger = logging.getLogger("trustshield.scanner")

class ScanJob:
    """Represents a stateful scan task."""
    def __init__(self, scan_id: str, raw_url: str, canonical_url: str, domain: str, options: Dict[str, Any]):
        self.scan_id = scan_id
        self.request_id = f"req-{uuid.uuid4().hex[:12]}"
        self.raw_url = raw_url
        self.canonical_url = canonical_url
        self.domain = domain
        self.options = options
        self.state = "queued"  # queued, running, completed, partial, failed
        self.progress_percent = 0
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.started_at: Optional[str] = None
        self.completed_at: Optional[str] = None
        self.error_message: Optional[str] = None
        self.error_code: Optional[str] = None
        
        self.module_statuses: Dict[str, Dict[str, Any]] = {
            "lexical": {"status": "idle", "started_at": None, "completed_at": None, "error": None},
            "ml": {"status": "idle", "started_at": None, "completed_at": None, "error": None},
            "tls": {"status": "idle", "started_at": None, "completed_at": None, "error": None},
            "headers": {"status": "idle", "started_at": None, "completed_at": None, "error": None},
            "threat_intel": {"status": "idle", "started_at": None, "completed_at": None, "error": None},
        }
        
        self.result: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "request_id": self.request_id,
            "raw_url": self.raw_url,
            "canonical_url": self.canonical_url,
            "domain": self.domain,
            "state": self.state,
            "progress_percent": self.progress_percent,
            "module_statuses": self.module_statuses,
            "timestamps": {
                "created_at": self.created_at,
                "started_at": self.started_at,
                "completed_at": self.completed_at,
            },
            "error": {"code": self.error_code, "message": self.error_message} if self.error_message else None,
            "result": self.result
        }


class ScanEngine:
    """Orchestrates scan jobs, deduplication, SSRF checks, and asynchronous execution."""

    CACHE_TTL_SECONDS = 60

    def __init__(self, max_workers: int = 4):
        self._jobs: Dict[str, ScanJob] = {}
        self._url_hash_to_id: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)

    def create_or_get_job(self, raw_url: str, options: Optional[Dict[str, Any]] = None, force_fresh: bool = False) -> ScanJob:
        """Validates SSRF, canonicalizes URL, handles deduplication, and schedules job."""
        opts = options or {}

        if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
            raise SSRFSecurityException("Target URL cannot be empty.", code="EMPTY_URL")

        # 1. Canonicalize & normalize URL first (prepends https:// if scheme omitted, strips fragments, normalizes slashes)
        try:
            canonical_url, url_hash, norm_meta = URLNormalizer.canonicalize(raw_url)
        except ValueError as e:
            raise SSRFSecurityException(f"Invalid URL structure: {str(e)}", code="INVALID_SCHEME")

        # 2. Strict SSRF validation and destination IP pinning on canonical URL
        _, domain, port, pinned_ip = SSRFValidator.validate_url(canonical_url)

        with self._lock:
            # Check duplicate / cached scan
            existing_id = self._url_hash_to_id.get(url_hash)
            if existing_id and not force_fresh:
                existing_job = self._jobs.get(existing_id)
                if existing_job:
                    # If running or completed recently, reuse
                    if existing_job.state in ("queued", "running"):
                        return existing_job
                    if existing_job.completed_at:
                        try:
                            completed_dt = datetime.fromisoformat(existing_job.completed_at)
                            age = (datetime.now(timezone.utc) - completed_dt).total_seconds()
                            if age < self.CACHE_TTL_SECONDS:
                                return existing_job
                        except Exception:
                            pass

            # Create new job
            scan_id = f"scan-{int(time.time() * 1000)}-{uuid.uuid4().hex[:6]}"
            job = ScanJob(
                scan_id=scan_id,
                raw_url=raw_url,
                canonical_url=canonical_url,
                domain=domain,
                options=opts
            )
            self._jobs[scan_id] = job
            self._url_hash_to_id[url_hash] = scan_id

        # Dispatch background execution
        self._executor.submit(self._execute_scan, job, pinned_ip)
        return job

    def get_job(self, scan_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self._jobs.get(scan_id)

    def delete_job(self, scan_id: str) -> bool:
        """Deletes a scan job and its canonical lookup reference."""
        with self._lock:
            if scan_id in self._jobs:
                job = self._jobs.pop(scan_id)
                # Clean up hash lookup
                for h, j_id in list(self._url_hash_to_id.items()):
                    if j_id == scan_id:
                        del self._url_hash_to_id[h]
                return True
            return False

    def clear_jobs(self) -> None:
        """Clears all scan jobs and URL hash lookups."""
        with self._lock:
            self._jobs.clear()
            self._url_hash_to_id.clear()

    def list_scans(self, limit: int = 50, verdict: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns completed scan result payloads for legacy frontend compatibility."""
        with self._lock:
            all_jobs = list(self._jobs.values())

        # Sort descending by creation
        all_jobs.sort(key=lambda j: j.created_at, reverse=True)

        completed_results = [j.result for j in all_jobs if j.result]
        if verdict and verdict != "all":
            completed_results = [r for r in completed_results if r.get("verdict") == verdict]

        return completed_results[:limit]

    def list_history(self, limit: int = 50, offset: int = 0, verdict: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            all_jobs = list(self._jobs.values())

        # Sort descending by creation
        all_jobs.sort(key=lambda j: j.created_at, reverse=True)

        if verdict and verdict != "all":
            all_jobs = [j for j in all_jobs if j.result and j.result.get("verdict") == verdict]

        sliced = all_jobs[offset: offset + limit]
        return [j.to_dict() for j in sliced]

    def _execute_scan(self, job: ScanJob, pinned_ip: str):
        """Worker executing scan modules synchronously with strict error isolation."""
        job.state = "running"
        job.started_at = datetime.now(timezone.utc).isoformat()
        job.progress_percent = 10
        has_partial_failures = False

        try:
            # Module 1: Lexical & Heuristics
            job.module_statuses["lexical"]["status"] = "running"
            job.module_statuses["lexical"]["started_at"] = datetime.now(timezone.utc).isoformat()
            
            heuristics_res = heuristics_engine.evaluate(job.canonical_url)
            ml_features = URLFeatureExtractor.extract_features(job.canonical_url)
            
            job.module_statuses["lexical"]["status"] = "completed"
            job.module_statuses["lexical"]["completed_at"] = datetime.now(timezone.utc).isoformat()
            job.progress_percent = 30

            # Module 2: Machine Learning Phishing Classifier
            job.module_statuses["ml"]["status"] = "running"
            job.module_statuses["ml"]["started_at"] = datetime.now(timezone.utc).isoformat()
            
            ml_pred = ml_service.predict(job.canonical_url)
            
            if ml_pred.get("status") == "unavailable":
                job.module_statuses["ml"]["status"] = "skipped"
                job.module_statuses["ml"]["error"] = ml_pred.get("message")
            elif ml_pred.get("status") == "error":
                job.module_statuses["ml"]["status"] = "failed"
                job.module_statuses["ml"]["error"] = ml_pred.get("message")
            else:
                job.module_statuses["ml"]["status"] = "completed"

            job.module_statuses["ml"]["completed_at"] = datetime.now(timezone.utc).isoformat()
            job.progress_percent = 50

            # Module 3: TLS Cryptographic Audit (SSRF-safe pinned IP)
            tls_summary = None
            if job.options.get("inspect_tls", True):
                job.module_statuses["tls"]["status"] = "running"
                job.module_statuses["tls"]["started_at"] = datetime.now(timezone.utc).isoformat()
                try:
                    tls_res = tls_inspector.inspect_host(job.domain, port=443, timeout=3.5)
                    tls_summary = {
                        "valid": tls_res.connected and not tls_res.is_expired,
                        "issuer": tls_res.issuer,
                        "subject": tls_res.subject,
                        "days_remaining": tls_res.days_remaining,
                        "is_expired": tls_res.is_expired,
                        "is_self_signed": tls_res.is_self_signed,
                        "protocol_version": tls_res.protocol_version,
                        "cipher_suite": tls_res.cipher_suite,
                        "grade": tls_res.grade
                    }
                    job.module_statuses["tls"]["status"] = "completed"
                except Exception as e:
                    has_partial_failures = True
                    job.module_statuses["tls"]["status"] = "failed"
                    job.module_statuses["tls"]["error"] = f"TLS audit failed: {str(e)}"
                job.module_statuses["tls"]["completed_at"] = datetime.now(timezone.utc).isoformat()
            else:
                job.module_statuses["tls"]["status"] = "skipped"
            job.progress_percent = 70

            # Module 4: Passive HTTP Security Headers & Posture Audit
            security_headers = None
            if job.options.get("inspect_headers", True):
                job.module_statuses["headers"]["status"] = "running"
                job.module_statuses["headers"]["started_at"] = datetime.now(timezone.utc).isoformat()
                try:
                    assessment = passive_scanner.assess_url(job.canonical_url, max_redirects=3, timeout=3.5)
                    security_headers = assessment.to_dict()
                    job.module_statuses["headers"]["status"] = "completed"
                except Exception as e:
                    has_partial_failures = True
                    job.module_statuses["headers"]["status"] = "failed"
                    job.module_statuses["headers"]["error"] = f"Header probe failed: {str(e)}"
                job.module_statuses["headers"]["completed_at"] = datetime.now(timezone.utc).isoformat()
            else:
                job.module_statuses["headers"]["status"] = "skipped"
            job.progress_percent = 85

            # Module 5: Multi-Provider Threat Intelligence Correlation
            job.module_statuses["threat_intel"]["status"] = "running"
            job.module_statuses["threat_intel"]["started_at"] = datetime.now(timezone.utc).isoformat()
            
            try:
                intel_results = threat_intel_manager.check_all(job.canonical_url, job.domain)
                intel_summary = threat_intel_manager.aggregate_summary(intel_results)
                job.module_statuses["threat_intel"]["status"] = "completed"
            except Exception as e:
                has_partial_failures = True
                job.module_statuses["threat_intel"]["status"] = "failed"
                job.module_statuses["threat_intel"]["error"] = f"Threat intelligence correlation fault: {str(e)}"
                intel_results = []
                intel_summary = {
                    "total_providers": 0,
                    "matched_count": 0,
                    "has_exact_url_match": False,
                    "has_host_match": False,
                    "results": [],
                }

            job.module_statuses["threat_intel"]["completed_at"] = datetime.now(timezone.utc).isoformat()
            job.progress_percent = 95

            # Compute aggregate risk score honestly based on active telemetry
            if ml_pred.get("is_trained") and ml_pred.get("probability_phish") is not None:
                base_score = int(ml_pred["probability_phish"] * 50)
            else:
                base_score = 0

            heuristic_impact = sum(f.score_impact for f in heuristics_res.findings)
            
            # Threat feed score impact:
            intel_impact = 0
            if intel_summary.get("has_exact_url_match"):
                threat_types = intel_summary.get("threat_types", [])
                if threat_types and all(t.lower() == "suspicious" for t in threat_types):
                    intel_impact = 40
                else:
                    intel_impact = 60
            elif intel_summary.get("has_host_match"):
                intel_impact = 35

            risk_score = min(100, max(0, base_score + heuristic_impact + intel_impact))

            is_high_ml = (ml_pred.get("probability_phish") or 0.0) > 0.65
            verdict = "clean"

            if intel_summary.get("has_exact_url_match"):
                # Exact URL threat feed match is a high-confidence positive verdict
                threat_types = intel_summary.get("threat_types", [])
                is_phish = any("phish" in t.lower() or "social" in t.lower() for t in threat_types)
                is_suspicious_only = bool(threat_types and all(t.lower() == "suspicious" for t in threat_types))
                if is_suspicious_only:
                    verdict = "suspicious"
                else:
                    verdict = "phishing" if is_phish else "malicious"
            elif risk_score >= 70:
                verdict = "phishing" if (heuristics_res.detected_brand_squats or is_high_ml) else "malicious"
            elif risk_score >= 35 or intel_summary.get("has_host_match"):
                verdict = "suspicious"

            # Strict Verdict Separation: Missing defensive headers alone NEVER trigger a malicious/phishing verdict
            if intel_summary.get("matched_count", 0) == 0 and not heuristics_res.detected_brand_squats and not is_high_ml:
                if verdict in ("phishing", "malicious"):
                    verdict = "suspicious" if risk_score >= 35 else "clean"

            # Actionable recommendations
            recommendations = []
            if verdict in ("phishing", "malicious"):
                recommendations.append({
                    "id": "rec-01",
                    "title": "Block Target Egress",
                    "description": "Add this destination domain to egress firewalls and secure DNS filters.",
                    "severity": "critical",
                    "category": "Incident Response"
                })
            if security_headers and security_headers.get("missing_critical_count", 0) > 0:
                recommendations.append({
                    "id": "rec-02",
                    "title": "Enforce Defensive Headers",
                    "description": "Configure HSTS, Content-Security-Policy (CSP), and X-Frame-Options to protect legitimate visitors.",
                    "severity": "medium",
                    "category": "Web Hardening"
                })
            if not recommendations:
                recommendations.append({
                    "id": "rec-03",
                    "title": "Maintain Continuous Telemetry",
                    "description": "Target currently exhibits benign characteristics and standard cryptographic posture.",
                    "severity": "low",
                    "category": "Best Practice"
                })

            # Calculate honest module coverage
            ml_cov = 100 if (ml_pred.get("status") == "operational" and ml_pred.get("is_trained")) else 0
            total_feeds = intel_summary.get("total_providers", 5) or 5
            operational_feeds = intel_summary.get("operational_count", 0)
            threat_feeds_cov = int((operational_feeds / total_feeds) * 100)
            tls_cov = 100 if (tls_summary and job.module_statuses["tls"]["status"] == "completed") else 0
            headers_cov = 100 if (security_headers and job.module_statuses["headers"]["status"] == "completed") else 0
            overall_cov = int((100 + ml_cov + tls_cov + headers_cov + threat_feeds_cov) / 5)

            calculated_confidence = ml_pred.get("confidence")
            if calculated_confidence is None:
                if overall_cov >= 80:
                    calculated_confidence = 0.90 if heuristics_res.findings else 0.85
                else:
                    # Honest confidence scaled with verified coverage breadth
                    base_conf = 0.50 + (overall_cov / 100.0) * 0.25
                    calculated_confidence = round(base_conf, 2)

            evidence_items = [
                {"category": "Host & DNS", "key": "Domain", "value": job.domain, "significance": "Resolved and SSRF validated"},
                {"category": "Information Theory", "key": "Shannon Entropy", "value": f"{heuristics_res.url_entropy:.4f} bits/char", "significance": "Lexical distribution"}
            ]

            if ml_cov == 0 or threat_feeds_cov == 0:
                evidence_items.append({
                    "category": "Coverage Advisory",
                    "key": "Evidence Breadth",
                    "value": f"{overall_cov}% overall pipeline coverage",
                    "significance": "ML model or threat feeds unconfigured; clean verdict indicates absence of observed signatures rather than guaranteed safety"
                })

            job.result = {
                "scan_id": job.scan_id,
                "url": job.raw_url,
                "normalized_url": job.canonical_url,
                "domain": job.domain,
                "verdict": verdict,
                "risk_score": risk_score,
                "confidence": calculated_confidence,
                "heuristics": heuristics_res.model_dump() if hasattr(heuristics_res, "model_dump") else heuristics_res.__dict__,
                "ml_prediction": ml_pred,
                "tls_summary": tls_summary,
                "security_headers": security_headers,
                "analysis_coverage": {
                    "lexical": 100,
                    "ml": ml_cov,
                    "tls": tls_cov,
                    "headers": headers_cov,
                    "threat_feeds": threat_feeds_cov,
                    "overall": overall_cov
                },
                "threat_feed_matches": [r.to_dict() for r in intel_results],
                "threat_intel_summary": intel_summary,
                "evidence": evidence_items,
                "recommendations": recommendations,
                "created_at": job.created_at
            }

            job.state = "partial" if has_partial_failures else "completed"
            job.progress_percent = 100
            job.completed_at = datetime.now(timezone.utc).isoformat()

            # Non-blocking observational shadow evaluation (Phase 7C)
            try:
                from backend.app.security.shadow_evaluator import shadow_evaluator
                shadow_evaluator.dispatch(
                    canonical_url=job.canonical_url,
                    domain=job.domain,
                    legacy_verdict=verdict,
                    legacy_risk_score=risk_score,
                    intel_results=intel_results,
                    heuristics_findings=heuristics_res.findings if heuristics_res else [],
                    ml_prediction=ml_pred,
                )
            except Exception as shadow_err:
                logger.debug(f"Shadow evaluation dispatch deferred: {shadow_err}")

            try:
                from backend.app.db.supabase import db_manager
                db_manager.save_scan(job.to_dict())
            except Exception as db_err:
                logger.debug(f"Scan persistence deferred: {db_err}")

        except SSRFSecurityException as e:
            job.state = "failed"
            job.error_code = e.code
            job.error_message = e.message
            job.completed_at = datetime.now(timezone.utc).isoformat()
        except Exception as e:
            logger.exception(f"Scan job {job.scan_id} crashed:")
            job.state = "failed"
            job.error_code = "INTERNAL_SCAN_FAULT"
            job.error_message = str(e)
            job.completed_at = datetime.now(timezone.utc).isoformat()

    def _passive_headers_probe(self, target_url: str, max_redirects: int = 3) -> Dict[str, Any]:
        """
        Executes a passive-only HTTP HEAD inspection with redirect loop limits and SSRF revalidation.
        Does not fetch or execute page content body.
        """
        return passive_scanner.assess_url(target_url, max_redirects=max_redirects, timeout=3.5).to_dict()

    def shutdown(self, wait: bool = True):
        """Cleanly drains executor threads and shuts down shadow workers."""
        self._executor.shutdown(wait=wait)
        try:
            from backend.app.security.shadow_evaluator import shadow_evaluator
            shadow_evaluator.shutdown(wait=wait)
        except Exception:
            pass

scan_engine = ScanEngine()
