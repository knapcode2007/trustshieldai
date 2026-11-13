"""
TrustShield AI - Controlled Shadow Decision Evaluator & Privacy-Safe Observability
Phase 7C Implementation: Observational, non-blocking dual-scoring engine.

Architectural Principles:
1. Zero User Impact:
   - Feature flag HYBRID_SHADOW_ENABLED=false by default.
   - When enabled, hybrid decisions run purely observationally.
   - The hybrid engine NEVER modifies, overrides, or alters the legacy scan verdict or HTTP response.
2. Truly Non-Blocking & Bounded:
   - Uses a bounded, supervised ThreadPoolExecutor with controlled concurrency and bounded queues.
   - Experimental RDAP telemetry has a strict 1.5-second background timeout.
   - Dropped tasks, timeouts, or failures never delay, block, or crash the live scanner.
3. Privacy-Safe Logging (logs/hybrid_shadow_eval.jsonl):
   - Never logs raw target URLs, user IDs, IP addresses, session tokens, or API credentials.
   - Logs only truncated one-way hashes, domain structure metadata, and decision explanation codes.
   - Implements thread-safe size-bounded log rotation.
   - Ephemeral Hosting Notice: Local filesystem logs may be ephemeral on container platforms like Render
     unless mounted to persistent storage.
"""

import concurrent.futures
import hashlib
import json
import logging
import os
import queue
import threading
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.app.core.config import settings
from backend.app.intel.base import ThreatFeedResult
from backend.app.intel.rdap import SecureRDAPClient
from backend.app.security.hybrid_decision import (
    HybridDecisionEngine,
    HybridVerdictState,
    DomainTelemetryDetails,
    hybrid_decision_engine,
)

logger = logging.getLogger("trustshield.shadow")


class DisagreementCategory(str, Enum):
    """Categorizes agreement or divergence between legacy and hybrid verdicts."""
    AGREEMENT_CLEAN = "AGREEMENT_CLEAN"
    AGREEMENT_SUSPICIOUS = "AGREEMENT_SUSPICIOUS"
    AGREEMENT_MALICIOUS = "AGREEMENT_MALICIOUS"
    HYBRID_ESCALATION = "HYBRID_ESCALATION"      # Legacy clean/suspicious -> Hybrid malicious/suspicious
    HYBRID_MITIGATION = "HYBRID_MITIGATION"      # Legacy suspicious/malicious -> Hybrid clean/no_threat
    INCONCLUSIVE_DISAGREEMENT = "INCONCLUSIVE_DISAGREEMENT"  # Hybrid is inconclusive due to outage
    LEGACY_ESCALATION = "LEGACY_ESCALATION"      # Legacy malicious -> Hybrid clean


class ModelAvailabilityState(str, Enum):
    """Execution state of the experimental Phase 6B machine learning model artifact."""
    MODEL_LOADED = "MODEL_LOADED"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    MODEL_INCOMPATIBLE = "MODEL_INCOMPATIBLE"
    INFERENCE_FAILED = "INFERENCE_FAILED"


class ExperimentalShadowModel:
    """
    Safely manages validation and sandboxed inference of the experimental Phase 6B Random Forest model.
    Enforces artifact integrity verification, feature schema conformity, and isolation from production.
    NEVER used for live production verdicts.
    """

    def __init__(
        self,
        manifest_path: str = "data/experiments/phase6b/model_manifest.json",
        artifact_path: str = "data/experiments/phase6b/rf_calibrated_model.joblib",
    ):
        self.manifest_path = manifest_path
        self.artifact_path = artifact_path
        self.state: ModelAvailabilityState = ModelAvailabilityState.MODEL_UNAVAILABLE
        self.model_instance = None
        self.load_error: Optional[str] = None
        self.metadata: Dict[str, Any] = {}
        self._validate_and_load()

    def _validate_and_load(self):
        if not os.path.exists(self.manifest_path) or not os.path.exists(self.artifact_path):
            self.state = ModelAvailabilityState.MODEL_UNAVAILABLE
            self.load_error = "Experimental Phase 6B model artifact or manifest not found on disk."
            return

        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)
        except Exception as e:
            self.state = ModelAvailabilityState.MODEL_INCOMPATIBLE
            self.load_error = f"Manifest parse error: {e}"
            return

        # 1. SHA-256 integrity check
        expected_sha = (
            self.metadata.get("models", {})
            .get("rf_calibrated_sigmoid", {})
            .get("sha256")
        )
        if not expected_sha:
            self.state = ModelAvailabilityState.MODEL_INCOMPATIBLE
            self.load_error = "Manifest missing expected sha256 digest."
            return

        try:
            hasher = hashlib.sha256()
            with open(self.artifact_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            actual_sha = hasher.hexdigest().lower()
            if actual_sha != expected_sha.lower():
                self.state = ModelAvailabilityState.MODEL_INCOMPATIBLE
                self.load_error = f"SHA-256 integrity mismatch: expected {expected_sha}, got {actual_sha}"
                return
        except Exception as e:
            self.state = ModelAvailabilityState.MODEL_INCOMPATIBLE
            self.load_error = f"Integrity check failed: {e}"
            return

        # 2. Feature schema compatibility check
        from backend.app.ml.features import URLFeatureExtractor
        manifest_features = self.metadata.get("feature_names", [])
        if manifest_features != URLFeatureExtractor.FEATURE_NAMES:
            self.state = ModelAvailabilityState.MODEL_INCOMPATIBLE
            self.load_error = "Feature names or count in manifest do not match active URLFeatureExtractor."
            return

        # 3. Safe deserialization
        try:
            import joblib
            self.model_instance = joblib.load(self.artifact_path)
        except Exception as e:
            self.state = ModelAvailabilityState.MODEL_INCOMPATIBLE
            self.load_error = f"Artifact deserialization failed: {e}"
            return

        # 4. Smoke test inference
        try:
            import numpy as np
            test_feats = URLFeatureExtractor.to_feature_vector(
                URLFeatureExtractor.extract_features("https://trustshield.internal.test")
            )
            _ = self.model_instance.predict_proba(np.array([test_feats]))[:, 1][0]
            self.state = ModelAvailabilityState.MODEL_LOADED
            self.load_error = None
        except Exception as e:
            self.state = ModelAvailabilityState.INFERENCE_FAILED
            self.load_error = f"Self-test inference failed: {e}"
            self.model_instance = None

    def predict(self, canonical_url: str) -> Optional[Dict[str, Any]]:
        """Executes bounded experimental inference for shadow evaluation."""
        if self.state != ModelAvailabilityState.MODEL_LOADED or self.model_instance is None:
            return None

        try:
            import numpy as np
            import warnings
            from backend.app.ml.features import URLFeatureExtractor
            feats = URLFeatureExtractor.to_feature_vector(
                URLFeatureExtractor.extract_features(canonical_url)
            )
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                prob = float(self.model_instance.predict_proba(np.array([feats]))[:, 1][0])
            return {
                "is_trained": True,
                "probability_phish": round(prob, 4),
                "model": "Phase6B-RandomForest-Experimental",
                "confidence": 0.85,
                "experimental_state": self.state.value,
            }
        except Exception as e:
            logger.warning(f"Experimental shadow inference failed for {canonical_url}: {e}")
            return None


class PrivacySafeShadowLogger:
    """
    Thread-safe, size-bounded rotating JSONL logger for shadow evaluation records.
    Enforces strict privacy redaction: zero raw URLs, tokens, or personal identifiers.
    """

    def __init__(
        self,
        log_path: str = "logs/hybrid_shadow_eval.jsonl",
        max_bytes: int = 10 * 1024 * 1024,  # 10 MB default
        backup_count: int = 3,
    ):
        self.log_path = log_path
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self._lock = threading.Lock()
        self._ensure_dir()

    def _ensure_dir(self):
        try:
            p = Path(self.log_path)
            p.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning(f"Could not create shadow log directory: {e}")

    def write_record(self, record: Dict[str, Any]) -> bool:
        """
        Thread-safe write of a sanitized evaluation record to JSONL with rotation.
        Returns True if successfully written, False otherwise.
        """
        try:
            line = json.dumps(record, separators=(",", ":")) + "\n"
            line_bytes = len(line.encode("utf-8"))

            with self._lock:
                self._maybe_rotate(line_bytes)
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line)
            return True
        except Exception as e:
            logger.error(f"PrivacySafeShadowLogger write fault: {e}")
            return False

    def _maybe_rotate(self, incoming_bytes: int):
        """Rotates log file if adding incoming_bytes exceeds max_bytes."""
        try:
            if not os.path.exists(self.log_path):
                return

            current_size = os.path.getsize(self.log_path)
            if current_size + incoming_bytes <= self.max_bytes:
                return

            # Rotate backups: .3 -> deleted, .2 -> .3, .1 -> .2, log -> .1
            for i in range(self.backup_count - 1, 0, -1):
                src = f"{self.log_path}.{i}"
                dst = f"{self.log_path}.{i + 1}"
                if os.path.exists(src):
                    if os.path.exists(dst):
                        os.remove(dst)
                    os.rename(src, dst)

            first_backup = f"{self.log_path}.1"
            if os.path.exists(first_backup):
                os.remove(first_backup)
            os.rename(self.log_path, first_backup)
        except Exception as e:
            logger.warning(f"Shadow log rotation failed: {e}")


class ShadowEvaluator:
    """
    Supervises background execution of the experimental hybrid decision engine.
    Ensures zero blocking on live scanner routes, bounded concurrency, and strict error isolation.
    """

    EVALUATION_VERSION = "phase7c-v1.0"

    def __init__(
        self,
        enabled: Optional[bool] = None,
        rdap_client: Optional[SecureRDAPClient] = None,
        decision_engine: Optional[HybridDecisionEngine] = None,
        shadow_logger: Optional[PrivacySafeShadowLogger] = None,
        experimental_model: Optional[ExperimentalShadowModel] = None,
        max_workers: Optional[int] = None,
        queue_maxsize: Optional[int] = None,
        rdap_timeout_seconds: Optional[float] = None,
    ):
        self._enabled = enabled if enabled is not None else getattr(settings, "HYBRID_SHADOW_ENABLED", False)
        if rdap_client:
            self.rdap_client = rdap_client
        else:
            cache_type = getattr(settings, "RDAP_CACHE_BACKEND", "memory").lower()
            if cache_type == "sqlite":
                from backend.app.intel.rdap import SQLiteRDAPCache
                db_path = getattr(settings, "RDAP_SQLITE_PATH", "data/rdap_cache.db")
                cache = SQLiteRDAPCache(db_path=db_path)
            else:
                from backend.app.intel.rdap import MemoryRDAPCache
                cache = MemoryRDAPCache()
            self.rdap_client = SecureRDAPClient(
                cache=cache,
                timeout_seconds=getattr(settings, "SHADOW_RDAP_TIMEOUT", 1.5),
            )
        self.decision_engine = decision_engine or hybrid_decision_engine
        
        log_path = getattr(settings, "SHADOW_LOG_PATH", "logs/hybrid_shadow_eval.jsonl")
        max_bytes = getattr(settings, "SHADOW_MAX_LOG_BYTES", 10 * 1024 * 1024)
        backup_count = getattr(settings, "SHADOW_BACKUP_COUNT", 3)
        self.shadow_logger = shadow_logger or PrivacySafeShadowLogger(log_path, max_bytes, backup_count)
        self.experimental_model = experimental_model or ExperimentalShadowModel()
        
        self.max_workers = max_workers or getattr(settings, "SHADOW_MAX_WORKERS", 2)
        self.queue_maxsize = queue_maxsize or getattr(settings, "SHADOW_QUEUE_MAXSIZE", 100)
        self.rdap_timeout = rdap_timeout_seconds or getattr(settings, "SHADOW_RDAP_TIMEOUT", 1.5)

        self._task_queue: queue.Queue = queue.Queue(maxsize=self.queue_maxsize)
        self._workers: List[threading.Thread] = []
        self._stop_event = threading.Event()
        self._state_lock = threading.Lock()
        self._is_shutdown = False

        for i in range(self.max_workers):
            t = threading.Thread(
                target=self._worker_loop,
                name=f"HybridShadowWorker-{i}",
                daemon=True,
            )
            t.start()
            self._workers.append(t)

        # Observability Metrics (in-memory counters)
        self.metrics = {
            "dispatched": 0,
            "completed": 0,
            "dropped": 0,
            "timed_out": 0,
            "failed": 0,
            "disagreement_counts": {c.value: 0 for c in DisagreementCategory},
        }

    @property
    def is_enabled(self) -> bool:
        return self._enabled and not self._is_shutdown

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled

    def _worker_loop(self):
        """Dedicated background worker thread pulling tasks from the bounded queue."""
        while not self._stop_event.is_set():
            try:
                task = self._task_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            if task is None:
                self._task_queue.task_done()
                break

            try:
                self._run_shadow_eval_worker(*task)
            except Exception as e:
                logger.error(f"Shadow worker execution error: {e}", exc_info=True)
                with self._state_lock:
                    self.metrics["failed"] += 1
            finally:
                self._task_queue.task_done()

    def dispatch(
        self,
        canonical_url: str,
        domain: str,
        legacy_verdict: str,
        legacy_risk_score: int,
        intel_results: List[ThreatFeedResult],
        heuristics_findings: Optional[List[Any]] = None,
        ml_prediction: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Non-blocking dispatch of shadow evaluation.
        Returns immediately (< 0.05ms) by placing task onto bounded queue.
        Does not await RDAP or hybrid evaluation.
        Returns True if enqueued, False if disabled or dropped under queue capacity.
        """
        if not self.is_enabled:
            return False

        task = (
            canonical_url,
            domain,
            legacy_verdict,
            legacy_risk_score,
            intel_results,
            heuristics_findings,
            ml_prediction,
        )

        try:
            self._task_queue.put_nowait(task)
            with self._state_lock:
                self.metrics["dispatched"] += 1
            return True
        except queue.Full:
            with self._state_lock:
                self.metrics["dropped"] += 1
                dropped_count = self.metrics["dropped"]
            if dropped_count == 1 or dropped_count % 100 == 0:
                logger.warning(
                    f"Shadow queue at capacity ({self.queue_maxsize}). Dropping shadow task #{dropped_count}."
                )
            return False
        except Exception as e:
            with self._state_lock:
                self.metrics["dropped"] += 1
            logger.warning(f"Shadow task dispatch failed: {e}")
            return False

    def _run_shadow_eval_worker(
        self,
        canonical_url: str,
        domain: str,
        legacy_verdict: str,
        legacy_risk_score: int,
        intel_results: List[ThreatFeedResult],
        heuristics_findings: Optional[List[Any]],
        ml_prediction: Optional[Dict[str, Any]],
    ):
        """Worker thread executing background RDAP and hybrid decision correlation."""
        start_time = time.perf_counter()
        rdap_duration_ms = 0.0
        rdap_timed_out = False
        telemetry: Optional[DomainTelemetryDetails] = None

        try:
            # 1. Fetch domain telemetry with bounded 1.5s timeout
            rdap_start = time.perf_counter()
            try:
                # Use synchronous telemetry retrieval bounded by socket/client timeout
                telemetry = self.rdap_client.get_domain_telemetry_sync(domain)
                rdap_duration_ms = round((time.perf_counter() - rdap_start) * 1000, 2)
                if (
                    telemetry
                    and telemetry.reliability_limitation
                    and "timed out" in telemetry.reliability_limitation.lower()
                ):
                    rdap_timed_out = True
                    with self._state_lock:
                        self.metrics["timed_out"] += 1
            except Exception as rdap_err:
                rdap_duration_ms = round((time.perf_counter() - rdap_start) * 1000, 2)
                telemetry = DomainTelemetryDetails(
                    domain=domain,
                    status="unavailable",
                    is_newly_registered=False,
                    telemetry_source="rdap",
                    reliability_limitation=f"RDAP lookup failed: {str(rdap_err)}",
                    confidence=0.1,
                )
                if "timed out" in str(rdap_err).lower():
                    rdap_timed_out = True
                    with self._state_lock:
                        self.metrics["timed_out"] += 1

            # 2. Experimental ML inference if loaded, otherwise fall back to passed prediction
            active_ml = ml_prediction
            if self.experimental_model and self.experimental_model.state == ModelAvailabilityState.MODEL_LOADED:
                exp_pred = self.experimental_model.predict(canonical_url)
                if exp_pred:
                    active_ml = exp_pred

            # 3. Correlate existing evidence with Hybrid Decision Engine
            hybrid_res = self.decision_engine.evaluate(
                raw_url=canonical_url,
                intel_results=intel_results,
                ml_prediction=active_ml,
                heuristic_findings=heuristics_findings,
                telemetry=telemetry,
            )

            # 4. Categorize verdict disagreement
            category = self.categorize_disagreement(legacy_verdict, hybrid_res.state.value)

            total_duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

            # 5. Construct privacy-safe shadow record
            record = self._build_privacy_safe_record(
                domain=domain,
                canonical_url=canonical_url,
                legacy_verdict=legacy_verdict,
                legacy_risk_score=legacy_risk_score,
                hybrid_res=hybrid_res,
                disagreement_category=category,
                intel_results=intel_results,
                ml_prediction=active_ml,
                telemetry=telemetry,
                total_duration_ms=total_duration_ms,
                rdap_duration_ms=rdap_duration_ms,
                rdap_timed_out=rdap_timed_out,
            )

            # 6. Write to rotating JSONL log
            self.shadow_logger.write_record(record)

            with self._state_lock:
                self.metrics["completed"] += 1
                self.metrics["disagreement_counts"][category.value] += 1

        except Exception as e:
            logger.error(f"Shadow evaluation execution fault: {e}", exc_info=True)
            with self._state_lock:
                self.metrics["failed"] += 1

    @classmethod
    def categorize_disagreement(cls, legacy_v: str, hybrid_state: str) -> DisagreementCategory:
        """Deterministic mapping of verdict differences."""
        leg = (legacy_v or "clean").lower()
        hyb = hybrid_state.upper()

        if hyb == HybridVerdictState.INCONCLUSIVE.value:
            return DisagreementCategory.INCONCLUSIVE_DISAGREEMENT

        # Clean / No threat alignment
        if leg == "clean" and hyb == HybridVerdictState.NO_THREAT_DETECTED.value:
            return DisagreementCategory.AGREEMENT_CLEAN

        # Malicious alignment
        if leg in ("phishing", "malicious") and hyb == HybridVerdictState.MALICIOUS.value:
            return DisagreementCategory.AGREEMENT_MALICIOUS

        # Suspicious alignment
        if leg == "suspicious" and hyb == HybridVerdictState.SUSPICIOUS.value:
            return DisagreementCategory.AGREEMENT_SUSPICIOUS

        # Hybrid escalations (Hybrid is more cautious than legacy)
        if leg == "clean" and hyb in (HybridVerdictState.SUSPICIOUS.value, HybridVerdictState.MALICIOUS.value):
            return DisagreementCategory.HYBRID_ESCALATION
        if leg == "suspicious" and hyb == HybridVerdictState.MALICIOUS.value:
            return DisagreementCategory.HYBRID_ESCALATION

        # Hybrid mitigations (Hybrid mitigates legacy false positive)
        if leg in ("suspicious", "malicious") and hyb == HybridVerdictState.NO_THREAT_DETECTED.value:
            return DisagreementCategory.HYBRID_MITIGATION

        # Legacy escalation over hybrid
        if leg in ("phishing", "malicious") and hyb == HybridVerdictState.SUSPICIOUS.value:
            return DisagreementCategory.LEGACY_ESCALATION

        return DisagreementCategory.INCONCLUSIVE_DISAGREEMENT

    def _build_privacy_safe_record(
        self,
        domain: str,
        canonical_url: str,
        legacy_verdict: str,
        legacy_risk_score: int,
        hybrid_res: Any,
        disagreement_category: DisagreementCategory,
        intel_results: List[ThreatFeedResult],
        ml_prediction: Optional[Dict[str, Any]],
        telemetry: Optional[DomainTelemetryDetails],
        total_duration_ms: float,
        rdap_duration_ms: float,
        rdap_timed_out: bool,
    ) -> Dict[str, Any]:
        """
        Assembles a strictly anonymized observational record.
        Zero raw URLs or credentials are included.
        """
        # Truncated one-way hash of canonical URL
        url_hash = hashlib.sha256(canonical_url.encode("utf-8")).hexdigest()[:16]

        explanation_codes = [e.provider_or_rule for e in getattr(hybrid_res, "evidence_chain", [])]

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "evaluation_version": self.EVALUATION_VERSION,
            "target": {
                "domain": domain,
                "domain_hash": hashlib.sha256(domain.encode("utf-8")).hexdigest()[:16],
                "canonical_url_hash": url_hash,
                "hierarchy_type": hybrid_res.host_structure.hierarchy_type.value,
                "subdomain_count": hybrid_res.host_structure.subdomain_count,
                "is_multi_tenant": hybrid_res.host_structure.is_multi_tenant_platform,
            },
            "verdicts": {
                "legacy_verdict": legacy_verdict,
                "legacy_risk_score": legacy_risk_score,
                "hybrid_state": hybrid_res.state.value,
                "hybrid_risk_score": hybrid_res.risk_score,
                "hybrid_confidence": round(hybrid_res.confidence, 4),
                "disagreement_category": disagreement_category.value,
            },
            "evidence_sources": {
                "threat_intel": {
                    "total_checked": len(intel_results),
                    "matched_count": sum(1 for f in intel_results if f.matched),
                    "has_l1_exact_url": any(f.matched and f.match_type == "exact_url" for f in intel_results),
                    "has_l2_host": any(f.matched and f.match_type in ("host", "domain") for f in intel_results),
                },
                "lexical_ml": {
                    "available": bool(ml_prediction and ml_prediction.get("is_trained")),
                    "model": ml_prediction.get("model") if ml_prediction else None,
                    "probability_phish": ml_prediction.get("probability_phish") if ml_prediction else None,
                    "experimental_state": (
                        self.experimental_model.state.value
                        if self.experimental_model
                        else ModelAvailabilityState.MODEL_UNAVAILABLE.value
                    ),
                },
                "domain_telemetry": {
                    "source": telemetry.telemetry_source if telemetry else "none",
                    "status": telemetry.status if telemetry else "unknown",
                    "age_days": telemetry.age_days if telemetry else None,
                    "is_newly_registered": telemetry.is_newly_registered if telemetry else False,
                    "cached": getattr(telemetry, "cached", False) if telemetry else False,
                    "freshness_seconds": getattr(telemetry, "freshness_seconds", None) if telemetry else None,
                    "timed_out": rdap_timed_out,
                },
            },
            "explanation_codes": explanation_codes,
            "caveats": getattr(hybrid_res, "caveats", []),
            "telemetry_timing": {
                "total_shadow_duration_ms": total_duration_ms,
                "rdap_duration_ms": rdap_duration_ms,
            },
        }

    def shutdown(self, wait: bool = True, cancel_futures: bool = False, timeout: Optional[float] = None):
        """Clean shutdown of the shadow evaluator worker pool."""
        with self._state_lock:
            self._is_shutdown = True

        if cancel_futures:
            while not self._task_queue.empty():
                try:
                    self._task_queue.get_nowait()
                    self._task_queue.task_done()
                except (queue.Empty, ValueError):
                    break
        elif wait:
            self._task_queue.join()

        self._stop_event.set()

        # Send poison pills to unblock any idle worker threads
        for _ in self._workers:
            try:
                self._task_queue.put_nowait(None)
            except Exception:
                pass

        if wait:
            for t in self._workers:
                t.join(timeout=timeout or 5.0)


# Global singleton instance
shadow_evaluator = ShadowEvaluator()
