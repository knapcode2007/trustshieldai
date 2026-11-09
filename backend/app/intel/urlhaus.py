"""
TrustShield AI - abuse.ch URLhaus Adapter
Complies with abuse.ch URLhaus API documentation.

Integration Requirements:
- Endpoints: https://urlhaus-api.abuse.ch/v1/url/ and https://urlhaus-api.abuse.ch/v1/host/
- Credentials: Optional server-side URLHAUS_API_KEY for elevated rate tiers (Auth-Key header).
- License: abuse.ch URLhaus is licensed under CC0 / Open Source and dedicated to sharing malware URLs.
"""

import os
import json
import urllib.parse
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from backend.app.intel.base import BaseThreatIntelAdapter, ThreatFeedResult


class URLhausAdapter(BaseThreatIntelAdapter):
    """Adapter for abuse.ch URLhaus Malware URL & Host Database."""

    URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
    HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"

    def __init__(self):
        super().__init__(
            provider_id="urlhaus",
            provider_name="abuse.ch URLhaus",
            attribution="URLhaus © abuse.ch. Project dedicated to sharing malicious URLs used for malware distribution.",
            failure_threshold=3,
            recovery_timeout=45.0,
        )

    def is_configured(self) -> bool:
        # Public lookups are supported without a mandatory key, but can be explicitly disabled via URLHAUS_ENABLED=false
        return os.getenv("URLHAUS_ENABLED", "true").lower() in ("true", "1", "yes")

    def _execute_lookup(self, sanitized_url: str, domain: str) -> ThreatFeedResult:
        auth_key = os.getenv("URLHAUS_API_KEY", "").strip()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "TrustShieldAI/1.0 (+https://trustshield.ai)",
        }
        if auth_key:
            headers["Auth-Key"] = auth_key

        # 1. Exact URL lookup
        form_data = urllib.parse.urlencode({"url": sanitized_url}).encode("utf-8")
        req = urllib.request.Request(self.URL_ENDPOINT, data=form_data, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                query_status = data.get("query_status")

                if query_status == "ok":
                    threat = data.get("threat", "malware_download")
                    url_status = data.get("url_status", "unknown")
                    reference = data.get("urlhaus_reference")
                    tags = data.get("tags") or []

                    return ThreatFeedResult(
                        provider=self.provider_id,
                        provider_name=self.provider_name,
                        status="available",
                        matched=True,
                        match_type="exact_url",
                        threat_type="malware" if "malware" in threat.lower() else threat,
                        confidence=96,
                        details=f"URLhaus confirmed active malware distribution URL: {threat} (Host status: {url_status}, Tags: {', '.join(tags) if tags else 'none'})",
                        reference_url=reference,
                        attribution=self.attribution,
                        raw_evidence=data,
                    )

                if query_status == "no_results":
                    # Fallback to host check to detect malicious infrastructure
                    host_res = self._check_host(domain, headers)
                    if host_res:
                        return host_res

                    return ThreatFeedResult(
                        provider=self.provider_id,
                        provider_name=self.provider_name,
                        status="no_match",
                        matched=False,
                        match_type="none",
                        confidence=90,
                        details="Target URL and host not indexed in URLhaus malware database.",
                        attribution=self.attribution,
                    )

                return ThreatFeedResult(
                    provider=self.provider_id,
                    provider_name=self.provider_name,
                    status="no_match",
                    matched=False,
                    match_type="none",
                    details=f"URLhaus query status: {query_status}",
                    attribution=self.attribution,
                )

        except urllib.error.HTTPError as e:
            if e.code == 429:
                return ThreatFeedResult(
                    provider=self.provider_id,
                    provider_name=self.provider_name,
                    status="rate_limited",
                    matched=False,
                    match_type="none",
                    rate_limited=True,
                    details="URLhaus API rate limit reached (HTTP 429).",
                    attribution=self.attribution,
                )
            return ThreatFeedResult(
                provider=self.provider_id,
                provider_name=self.provider_name,
                status="error",
                matched=False,
                match_type="none",
                details=f"URLhaus HTTP error: {e.code}",
                attribution=self.attribution,
            )
        except Exception as e:
            return ThreatFeedResult(
                provider=self.provider_id,
                provider_name=self.provider_name,
                status="error",
                matched=False,
                match_type="none",
                details=f"URLhaus connection error: {str(e)}",
                attribution=self.attribution,
            )

    def _check_host(self, domain: str, headers: Dict[str, str]) -> Optional[ThreatFeedResult]:
        """Checks if host or domain has widespread malware distribution history."""
        try:
            form_data = urllib.parse.urlencode({"host": domain}).encode("utf-8")
            req = urllib.request.Request(self.HOST_ENDPOINT, data=form_data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=3.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("query_status") == "ok":
                    url_count = data.get("url_count", 0)
                    if url_count and int(url_count) > 0:
                        reference = data.get("urlhaus_reference")
                        return ThreatFeedResult(
                            provider=self.provider_id,
                            provider_name=self.provider_name,
                            status="available",
                            matched=True,
                            match_type="host",
                            threat_type="malware_host",
                            confidence=88,
                            details=f"Host '{domain}' is associated with {url_count} active malware distribution payloads in URLhaus.",
                            reference_url=reference,
                            attribution=self.attribution,
                            raw_evidence=data,
                        )
        except Exception:
            pass
        return None
