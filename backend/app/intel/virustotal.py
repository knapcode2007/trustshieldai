"""
TrustShield AI - VirusTotal v3 Threat Intelligence Adapter
Complies with VirusTotal API v3 specification for URL analysis.

Integration Requirements:
- Read-Only Endpoint: GET https://www.virustotal.com/api/v3/urls/{id}
- URL Identifier: Base64 URL-safe encoding without padding (=)
- Header: x-apikey: <VIRUSTOTAL_API_KEY>
- Rate Limits (Free Public Tier): 4 requests/minute, 500 requests/day
- Privacy Safeguards:
    1. NEVER automatically submits unknown/unseen URLs (POST /api/v3/urls is strictly prohibited).
    2. HTTP 404 (URL not found) is treated as uncataloged to prevent private URL leakage.
    3. Sensitive URL query parameters (tokens, keys, passwords) are sanitized prior to lookup.
    4. Undetected vendor classifications are never treated as confirmed safe.
- License: Subject to VirusTotal Terms of Service for non-commercial/personal security testing.
"""

import os
import json
import base64
import time
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple

from backend.app.intel.base import BaseThreatIntelAdapter, ThreatFeedResult


class VirusTotalRateLimiter:
    """
    Thread-safe rate limiter enforcing VirusTotal public free-tier quotas:
    1. Minute limit: maximum 4 requests per rolling 60-second window.
    2. Daily limit: maximum 500 requests per rolling 24-hour (86,400-second) window.

    Proactively protects API quota across concurrent worker threads and scan jobs.

    In-Memory Architecture Limitations:
    - Process Scoping: Quotas are tracked in-process using Python thread synchronization.
      In multi-worker production deployments (e.g. multi-process Gunicorn/Uvicorn or
      horizontally autoscaled container replicas), each process maintains its own sliding
      window. For multi-node deployments exceeding single-process scaling, an external
      distributed cache (e.g. Redis sliding window or token bucket) should be integrated.
    - Volatility: In-memory counters reset upon process restart or container redeployment.
    """

    def __init__(self, max_per_minute: int = 4, max_per_day: int = 500):
        self.max_per_minute = max_per_minute
        self.max_per_day = max_per_day
        self.minute_window = 60.0
        self.day_window = 86400.0
        self.minute_timestamps: List[float] = []
        self.day_timestamps: List[float] = []
        self._lock = threading.Lock()

    def can_proceed(self) -> Tuple[bool, Optional[str]]:
        now = time.time()
        with self._lock:
            # Expire timestamps outside the rolling windows
            self.minute_timestamps = [t for t in self.minute_timestamps if now - t < self.minute_window]
            self.day_timestamps = [t for t in self.day_timestamps if now - t < self.day_window]

            if len(self.minute_timestamps) >= self.max_per_minute:
                return False, "minute"

            if len(self.day_timestamps) >= self.max_per_day:
                return False, "daily"

            self.minute_timestamps.append(now)
            self.day_timestamps.append(now)
            return True, None

    def reset(self):
        """Resets the rate limiter windows (useful for unit test isolation)."""
        with self._lock:
            self.minute_timestamps.clear()
            self.day_timestamps.clear()


class VirusTotalAdapter(BaseThreatIntelAdapter):
    """Adapter for VirusTotal API v3 multi-engine URL threat reputation."""

    API_BASE = "https://www.virustotal.com/api/v3/urls"

    def __init__(
        self,
        max_per_minute: int = 4,
        max_per_day: int = 500,
        max_rate_limit: Optional[int] = None,
        rate_window_seconds: Optional[float] = None,
    ):
        if max_rate_limit is not None:
            max_per_minute = max_rate_limit
        super().__init__(
            provider_id="virustotal",
            provider_name="VirusTotal",
            attribution="VirusTotal © Chronicle Security Ireland Ltd. / Google LLC. Subject to VirusTotal Terms of Service.",
            failure_threshold=3,
            recovery_timeout=45.0,
        )
        self.rate_limiter = VirusTotalRateLimiter(max_per_minute=max_per_minute, max_per_day=max_per_day)

    @staticmethod
    def get_api_key() -> str:
        """Retrieves VIRUSTOTAL_API_KEY from environment or settings safely."""
        key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        if not key:
            try:
                from backend.app.core.config import settings
                key = getattr(settings, "VIRUSTOTAL_API_KEY", "").strip()
            except Exception:
                pass
        return key

    def is_configured(self) -> bool:
        return bool(self.get_api_key())

    @staticmethod
    def compute_url_id(url: str) -> str:
        """Computes base64 URL identifier without padding per VirusTotal v3 specification."""
        encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8")
        return encoded.strip("=")

    def _execute_lookup(self, sanitized_url: str, domain: str) -> ThreatFeedResult:
        # Enforce proactive free-tier rate limits (4 req/min, 500 req/day)
        can_call, limit_reason = self.rate_limiter.can_proceed()
        if not can_call:
            if limit_reason == "daily":
                details = (
                    f"VirusTotal daily quota reached (max {self.rate_limiter.max_per_day} queries/day). "
                    "Request deferred to protect quota."
                )
            else:
                details = (
                    f"VirusTotal minute rate limit active (max {self.rate_limiter.max_per_minute} queries/min). "
                    "Request deferred to protect quota."
                )
            return ThreatFeedResult(
                provider=self.provider_id,
                provider_name=self.provider_name,
                status="rate_limited",
                matched=False,
                match_type="none",
                confidence=0,
                rate_limited=True,
                details=details,
                attribution=self.attribution,
                raw_evidence={"rate_limited": True, "reason": limit_reason},
            )

        api_key = self.get_api_key()
        url_id = self.compute_url_id(sanitized_url)
        endpoint = f"{self.API_BASE}/{url_id}"

        headers = {
            "x-apikey": api_key,
            "Accept": "application/json",
            "User-Agent": "TrustShieldAI/1.0 (+https://trustshield.ai)",
        }

        # Privacy Rule: Read-only GET request ONLY. Never POST unknown URLs.
        req = urllib.request.Request(endpoint, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                body = resp.read().decode("utf-8")
                payload = json.loads(body) if body.strip() else {}

                data = payload.get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                malicious = int(stats.get("malicious", 0))
                suspicious = int(stats.get("suspicious", 0))
                harmless = int(stats.get("harmless", 0))
                undetected = int(stats.get("undetected", 0))
                reputation = attributes.get("reputation", 0)
                tags = attributes.get("tags") or []
                categories = attributes.get("categories") or {}
                last_analysis_date = attributes.get("last_analysis_date")

                gui_url = f"https://www.virustotal.com/gui/url/{url_id}"

                # Evaluate analysis age and staleness
                now = time.time()
                if last_analysis_date and isinstance(last_analysis_date, (int, float)) and last_analysis_date > 0:
                    age_seconds = max(0.0, now - float(last_analysis_date))
                    age_days = int(age_seconds // 86400)
                    analysis_dt = datetime.fromtimestamp(last_analysis_date, timezone.utc)
                    analysis_date_str = analysis_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                else:
                    age_seconds = None
                    age_days = None
                    analysis_date_str = "unknown date"

                evidence_base = {
                    "stats": stats,
                    "tags": tags,
                    "reputation": reputation,
                    "last_analysis_date": last_analysis_date,
                    "analysis_date": analysis_date_str,
                    "age_days": age_days,
                }

                # 1. Confirmed Threat: 3+ malicious engines OR combined malicious + suspicious flags
                if malicious >= 3 or (malicious >= 1 and suspicious >= 2):
                    tag_str = " ".join(tags).lower() + " " + " ".join(str(c) for c in categories.values()).lower()
                    if any(term in tag_str for term in ("phish", "social", "credential", "fake-login", "impersonation")):
                        threat_type = "phishing"
                    elif any(term in tag_str for term in ("malware", "trojan", "ransomware", "botnet", "c2", "exploit", "dropper")):
                        threat_type = "malware"
                    else:
                        threat_type = "malicious"

                    confidence = min(99, max(80, 80 + malicious * 2))
                    age_note = f" (analyzed {analysis_date_str}, {age_days}d ago)" if age_days is not None else ""

                    return ThreatFeedResult(
                        provider=self.provider_id,
                        provider_name=self.provider_name,
                        status="available",
                        matched=True,
                        match_type="exact_url",
                        threat_type=threat_type,
                        confidence=confidence,
                        details=(
                            f"VirusTotal threat confirmed{age_note}: {malicious} security vendors flagged this URL as malicious, "
                            f"{suspicious} as suspicious (Reputation: {reputation})."
                        ),
                        reference_url=gui_url,
                        attribution=self.attribution,
                        raw_evidence=evidence_base,
                    )

                # 2. Early Detection Alert: 1-2 engines flagged malicious or 2+ suspicious
                if malicious > 0 or suspicious >= 2:
                    age_note = f" (analyzed {analysis_date_str}, {age_days}d ago)" if age_days is not None else ""
                    return ThreatFeedResult(
                        provider=self.provider_id,
                        provider_name=self.provider_name,
                        status="available",
                        matched=True,
                        match_type="exact_url",
                        threat_type="suspicious",
                        confidence=72,
                        details=(
                            f"VirusTotal early detection warning{age_note}: {malicious} vendor(s) flagged malicious, "
                            f"{suspicious} vendor(s) flagged suspicious."
                        ),
                        reference_url=gui_url,
                        attribution=self.attribution,
                        raw_evidence=evidence_base,
                    )

                # 3. Clean / Benign Analysis (Strict Staleness & Undetected Rules)
                # Stale or aging results are NEVER presented as current clean assertions.
                is_critically_stale = (age_days is None or age_days > 60)
                is_aging = (age_days is not None and 14 < age_days <= 60)

                if is_critically_stale:
                    # Critically stale clean results contribute ZERO positive evidence of safety
                    confidence = 0
                    details = (
                        f"VirusTotal report is stale (last analyzed {age_days if age_days is not None else 'unknown'} "
                        f"days ago on {analysis_date_str}). Historical scan cannot be used as evidence of current safety."
                    )
                elif is_aging:
                    # Historical result (> 14 days old): confidence is heavily discounted
                    confidence = 50 if harmless >= 5 else 35
                    details = (
                        f"VirusTotal analysis is historical (last analyzed {age_days} days ago on {analysis_date_str}; "
                        f"{harmless} harmless, {undetected} undetected). Historical clean status cannot confirm current safety."
                    )
                else:
                    # Fresh result (<= 14 days old)
                    if harmless >= 5:
                        confidence = 90
                        details = (
                            f"Target URL evaluated clean across {harmless} verified security engines "
                            f"(analyzed {analysis_date_str}, {age_days}d ago; 0 malicious)."
                        )
                    elif (harmless + undetected) > 0:
                        if harmless == 0:
                            confidence = 45
                            details = (
                                f"Target URL had 0 vendor detections (analyzed {analysis_date_str}, {age_days}d ago; "
                                f"all {undetected} engines undetected; undetected status does not indicate safety)."
                            )
                        else:
                            confidence = 70
                            details = (
                                f"Target URL had 0 malicious detections across {harmless + undetected} engines "
                                f"(analyzed {analysis_date_str}, {age_days}d ago; {undetected} undetected, {harmless} harmless; "
                                "lack of detection does not guarantee safety)."
                            )
                    else:
                        confidence = 0
                        details = "VirusTotal report contains 0 vendor observations for this target."

                return ThreatFeedResult(
                    provider=self.provider_id,
                    provider_name=self.provider_name,
                    status="no_match",
                    matched=False,
                    match_type="none",
                    confidence=confidence,
                    details=details,
                    reference_url=gui_url,
                    attribution=self.attribution,
                    raw_evidence=evidence_base,
                )

        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Privacy Protection & Safety Truth: URL is uncataloged in VirusTotal.
                # Strictly DO NOT submit the URL via POST.
                # An unknown URL has ZERO evidence of safety: status is 'unavailable', confidence is 0.
                # It must NEVER be treated as clean ('no_match') or inflate overall scan confidence.
                return ThreatFeedResult(
                    provider=self.provider_id,
                    provider_name=self.provider_name,
                    status="unavailable",
                    matched=False,
                    match_type="none",
                    confidence=0,
                    details="Target URL has no prior analysis history in VirusTotal (uncataloged; unsubmitted to protect private URL privacy).",
                    attribution=self.attribution,
                    raw_evidence={"uncataloged": True, "http_status": 404},
                )
            elif e.code == 429:
                return ThreatFeedResult(
                    provider=self.provider_id,
                    provider_name=self.provider_name,
                    status="rate_limited",
                    matched=False,
                    match_type="none",
                    confidence=0,
                    rate_limited=True,
                    details="VirusTotal API query rate limit or monthly quota reached (HTTP 429).",
                    attribution=self.attribution,
                    raw_evidence={"http_status": 429},
                )
            elif e.code in (401, 403):
                return ThreatFeedResult(
                    provider=self.provider_id,
                    provider_name=self.provider_name,
                    status="error",
                    matched=False,
                    match_type="none",
                    confidence=0,
                    details=f"VirusTotal API authentication failed (HTTP {e.code}). Verify VIRUSTOTAL_API_KEY.",
                    attribution=self.attribution,
                    raw_evidence={"http_status": e.code},
                )
            else:
                return ThreatFeedResult(
                    provider=self.provider_id,
                    provider_name=self.provider_name,
                    status="error",
                    matched=False,
                    match_type="none",
                    confidence=0,
                    details=f"VirusTotal upstream HTTP error: {e.code}",
                    attribution=self.attribution,
                    raw_evidence={"http_status": e.code},
                )
        except urllib.error.URLError as e:
            return ThreatFeedResult(
                provider=self.provider_id,
                provider_name=self.provider_name,
                status="error",
                matched=False,
                match_type="none",
                confidence=0,
                details=f"VirusTotal connection error: {str(e.reason)}",
                attribution=self.attribution,
            )
        except Exception as e:
            return ThreatFeedResult(
                provider=self.provider_id,
                provider_name=self.provider_name,
                status="error",
                matched=False,
                match_type="none",
                confidence=0,
                details=f"VirusTotal lookup fault: {str(e)}",
                attribution=self.attribution,
            )

