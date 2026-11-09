"""
TrustShield AI - Google Safe Browsing Adapter
Complies with Google Safe Browsing Lookup API v4 specification.

Integration Requirements:
- Server-side API key: GOOGLE_SAFE_BROWSING_API_KEY
- Endpoint: https://safebrowsing.googleapis.com/v4/threatMatches:find
- License: Google Safe Browsing API Terms of Service (commercial/non-commercial restrictions apply).
"""

import os
import json
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from backend.app.intel.base import BaseThreatIntelAdapter, ThreatFeedResult


class GoogleSafeBrowsingAdapter(BaseThreatIntelAdapter):
    """Adapter for Google Safe Browsing Lookup API v4."""

    API_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(self):
        super().__init__(
            provider_id="google_safe_browsing",
            provider_name="Google Safe Browsing",
            attribution="Google Safe Browsing © Google LLC. Subject to Google Safe Browsing Terms of Service.",
            failure_threshold=3,
            recovery_timeout=45.0,
        )

    def is_configured(self) -> bool:
        return bool(os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip())

    def _execute_lookup(self, sanitized_url: str, domain: str) -> ThreatFeedResult:
        api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
        endpoint = f"{self.API_ENDPOINT}?key={api_key}"

        payload = {
            "client": {
                "clientId": "trustshield-ai",
                "clientVersion": "1.0.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": sanitized_url}],
            },
        }

        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "TrustShieldAI/1.0 (+https://trustshield.ai)",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                status_code = resp.status
                body = resp.read().decode("utf-8")
                data = json.loads(body) if body.strip() else {}

                matches = data.get("matches", [])
                if matches:
                    primary_match = matches[0]
                    threat_raw = primary_match.get("threatType", "MALICIOUS")
                    threat_mapped = {
                        "SOCIAL_ENGINEERING": "phishing",
                        "MALWARE": "malware",
                        "UNWANTED_SOFTWARE": "unwanted_software",
                        "POTENTIALLY_HARMFUL_APPLICATION": "harmful_application",
                    }.get(threat_raw, threat_raw.lower())

                    return ThreatFeedResult(
                        provider=self.provider_id,
                        provider_name=self.provider_name,
                        status="available",
                        matched=True,
                        match_type="exact_url",
                        threat_type=threat_mapped,
                        confidence=98,
                        details=f"Threat match confirmed by Google Safe Browsing: {threat_raw}",
                        reference_url="https://transparencyreport.google.com/safe-browsing/search",
                        attribution=self.attribution,
                        raw_evidence={"matches": matches},
                    )

                return ThreatFeedResult(
                    provider=self.provider_id,
                    provider_name=self.provider_name,
                    status="no_match",
                    matched=False,
                    match_type="none",
                    confidence=95,
                    details="Target URL is not present in Google Safe Browsing active threat lists.",
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
                    details="Google Safe Browsing API rate limit or quota exceeded (HTTP 429).",
                    attribution=self.attribution,
                )
            elif e.code in (400, 403):
                return ThreatFeedResult(
                    provider=self.provider_id,
                    provider_name=self.provider_name,
                    status="error",
                    matched=False,
                    match_type="none",
                    details=f"Google Safe Browsing authentication or authorization failed (HTTP {e.code}). Check GOOGLE_SAFE_BROWSING_API_KEY.",
                    attribution=self.attribution,
                )
            else:
                return ThreatFeedResult(
                    provider=self.provider_id,
                    provider_name=self.provider_name,
                    status="error",
                    matched=False,
                    match_type="none",
                    details=f"Google Safe Browsing upstream error: HTTP {e.code}",
                    attribution=self.attribution,
                )
        except Exception as e:
            return ThreatFeedResult(
                provider=self.provider_id,
                provider_name=self.provider_name,
                status="error",
                matched=False,
                match_type="none",
                details=f"Google Safe Browsing network error: {str(e)}",
                attribution=self.attribution,
            )
